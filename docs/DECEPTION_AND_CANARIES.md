# 🎭 Motor de Decepción y Trampas Canario (Deception Engine)

> **Documento de especificación de la capa de decepción activa de Dimensión Espejo.**  
> La decepción activa (*Active Defense / Cyber Deception*) no busca levantar muros impenetrables, sino sembrar el entorno de desarrollo con trampas de alta fidelidad que eludan falsos positivos y delaten al atacante en las primeras etapas de reconocimiento (*Discovery*) o acceso a credenciales (*Credential Access*).

---

## 📑 Tabla de Contenidos
1. [Filosofía: Detección con Cero Falso Positivo](#1-filosofía-detección-con-cero-falso-positivo)
2. [Honeypots en Puertos de Red (Decoy Services)](#2-honeypots-en-puertos-de-red-decoy-services)
3. [Archivos Canario y File Integrity Monitoring (FIM)](#3-archivos-canario-y-file-integrity-monitoring-fim)
4. [Sanitización de Secretos y Entropía de Shannon](#4-sanitización-de-secretos-y-entropía-de-shannon)
5. [Configuración Declarativa (`canary_profiles.yaml`)](#5-configuración-declarativa-canary_profilesyaml)

---

## 1. Filosofía: Detección con Cero Falso Positivo

Los sistemas de detección basados en firmas o anomalías estadísticas (como antivirus tradicionales o heurísticas de red) sufren de **fatiga de alertas**: generan miles de alertas sobre actividades legítimas de desarrolladores (compilaciones masivas, peticiones curl de depuración, escaneos locales de puertos).

La regla de oro de Dimensión Espejo es:
> **"Un recurso canario no tiene ningún uso legítimo en el flujo de trabajo."**

* Si un proceso lee el archivo `.env.backup` en la raíz del proyecto, es porque un actor hostil o un script automatizado está buscando credenciales (`MITRE T1552.001`).
* Si una IP interna intenta conectarse al puerto `16379` (puerto señuelo de Redis) o `12222` (SSH), está ejecutando un escaneo de puertos de red (`MITRE T1046`).

Por diseño, **la tasa de falso positivo es matemáticamente cercana al 0%**, lo que justifica ejecutar acciones inmediatas y automáticas de contención (`EMERGENCY_FREEZE` o `ISOLATE`).

---

## 2. Honeypots en Puertos de Red (Decoy Services)

Implementado en [`deception/decoy_services.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/deception/decoy_services.py) mediante `DecoyServiceManager`.

### Arquitectura de los Servicios Señuelo
El administrador de servicios inicia servidores asíncronos nativos en `127.0.0.1` sin requerir instalar daemons pesados externos:

```text
Atacante (Port Scanner / nmap / nc)
         │
         ├───► 127.0.0.1:16379 (Fake Redis) ──► Devuelve "-ERR authentication required" ──► Alerta HIGH (Discovery)
         ├───► 127.0.0.1:12222 (Fake SSH)   ──► Envía banner OpenSSH + Cierra socket    ──► Alerta HIGH (Discovery)
         └───► 127.0.0.1:18080 (Fake HTTP)  ──► Simula panel de login falso (admin/nas) ──► Alerta HIGH (Discovery)
```

### Protocolos Soportados
1. **Fake Redis Honeypot (Puerto 16379)**:
   * Acepta la conexión entrante.
   * Lee hasta 1024 bytes (generalmente comandos como `PING`, `INFO` o `AUTH`).
   * Registra la IP de origen y el payload en el `MirrorEvent`.
   * Responde con `-ERR authentication required\r\n` y cierra la conexión limpiamente.
2. **Fake SSH Honeypot (Puerto 12222)**:
   * Emite el banner oficial de OpenSSH: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n`.
   * Captura el cliente SSH utilizado por el atacante (ej. `SSH-2.0-Paramiko` o `libssh`).
   * Dispara un evento de intrusión al EventBus.
3. **Fake HTTP Admin Honeypot (Puerto 18080)**:
   * Responde con cabeceras `HTTP/1.1 200 OK` simulando un portal web o consola de administración interna.

---

## 3. Archivos Canario y File Integrity Monitoring (FIM)

Implementado en [`deception/decoy_files.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/deception/decoy_files.py) mediante `DecoyFileManager` y `CanaryFileEventHandler`.

### Mecanismo de Vigilancia a Nivel de Kernel
Utiliza la biblioteca multiplataforma `watchdog`, que interactúa directamente con los subsistemas de notificación de archivos del sistema operativo:
* **macOS:** `FSEvents` / `kqueue`.
* **Linux:** `inotify`.

### Archivos Trampa Desplegados
El sistema siembra automáticamente archivos con apariencia atractiva para un intruso:
* `.env.backup` (credenciales simuladas de AWS, Stripe y bases de datos).
* `.aws/credentials.canary` (tokens canario con formato estándar de AWS).
* `secrets/fake_api_keys.json` (tokens simulados de servicios cloud).

### Detección y Eventos
Cuando cualquier proceso ejecuta una acción de lectura (`opened`), modificación (`modified`) o borrado (`deleted`) sobre un archivo canario:
1. `CanaryFileEventHandler` captura la ruta y el tipo de evento.
2. Extrae el ID del activo comprometido (ej. `secrets` o `api`).
3. Construye un `MirrorEvent` con severidad `CRITICAL` y confianza `0.99`.
4. El `EventBus` publica el evento en microsegundos, disparando el aislamiento inmediato antes de que el contenido del archivo pueda ser usado.

---

## 4. Sanitización de Secretos y Entropía de Shannon

Implementado en [`mirror/sanitization.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/mirror/sanitization.py) mediante `MirrorSanitizer`.

Cuando la orquestación decide clonar un contenedor hacia la **Dimensión Espejo**, es vital que el clon **NO contenga los secretos reales de producción o desarrollo**. Si el atacante ya tiene una shell interactiva en el clon, solo debe encontrar señuelos.

El sanitizador aplica una **defensa en 3 capas**:

```text
Variables de Entorno del Contenedor Original
                      │
                      ▼
 ┌──────────────────────────────────────────────┐
 │ Capa 1: Expresiones Regulares de Firmas      │ ──► GitHub, Stripe, Slack, GCP, PEM Keys, DB URLs
 └──────────────────────┬───────────────────────┘
                        ▼
 ┌──────────────────────────────────────────────┐
 │ Capa 2: Lista de Palabras Clave Sensibles    │ ──► PASSWD, TOKEN, API_KEY, AUTH, DATABASE_URL, etc.
 └──────────────────────┬───────────────────────┘
                        ▼
 ┌──────────────────────────────────────────────┐
 │ Capa 3: Análisis de Entropía de Shannon      │ ──► H > 3.8 bits/char (Detecta secretos no catalogados)
 └──────────────────────┬───────────────────────┘
                        ▼
 Variables Sanitizadas con Tokens Sintéticos en el Espejo
```

### Cálculo Matemático de la Entropía de Shannon
La fórmula implementada para medir la aleatoriedad de un valor $S$ de longitud $N$ es:

$$H(S) = - \sum_{i=1}^{k} \frac{c_i}{N} \log_2 \left( \frac{c_i}{N} \right)$$

Donde $c_i$ es el conteo de frecuencia de cada carácter único.
* Las cadenas con **alta entropía** ($H \ge 3.8$) como `d83f9a7b1c4e2098...` son clasificadas automáticamente como secretos criptográficos y reemplazadas por cadenas señuelo con la misma longitud.

---

## 5. Configuración Declarativa (`canary_profiles.yaml`)

Ubicación: [`config/canary_profiles.yaml`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/config/canary_profiles.yaml)

Permite definir nuevos señuelos y puertos trampa sin tocar una sola línea de código:

```yaml
version: "1.0"
profiles:
  filesystem_traps:
    - path: ".env.backup"
      criticality: CRITICAL
      alert_action: EMERGENCY_FREEZE
    - path: ".aws/credentials"
      criticality: HIGH
      alert_action: ISOLATE

  network_honeypots:
    - name: fake_redis
      port: 16379
      protocol: redis
      response: "-ERR authentication required\r\n"
    - name: fake_ssh
      port: 12222
      protocol: ssh
      banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
```
