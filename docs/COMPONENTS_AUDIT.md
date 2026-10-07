# 🔍 Auditoría Exhaustiva de Componentes: Real vs. Sintético vs. Simulación

> **Documento de transparencia técnica y estado de madurez de cada componente en Dimensión Espejo.**  
> Este documento detalla con precisión quirúrgica qué partes del sistema interactúan con infraestructura real del sistema operativo, cuáles operan con datos sintéticos por diseño de seguridad, cuáles corresponden a simulaciones de laboratorio y cuál es el estado de la carpeta de dependencias `repos/`.

---

## 📊 Matriz Global de Componentes

| Componente | Archivo Fuente | Clasificación | Estado Técnico | Dependencia Real |
| :--- | :--- | :--- | :--- | :--- |
| **Reverse Proxy & Traffic Switch** | [`mirror/traffic_switch.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/mirror/traffic_switch.py) | 🟢 **100% Real** | Operativo (HTTP + TLS) | Python `asyncio.start_server`, Sockets TCP, OpenSSL |
| **Aislamiento Docker (Procesos)** | [`isolation/docker.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/isolation/docker.py) | 🟢 **100% Real** | Operativo | Docker Engine API (`docker-py`, `container.pause`) |
| **Aislamiento de Red (Blackhole)** | [`isolation/network.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/isolation/network.py) | 🟢 **100% Real** | Operativo | Docker Network API (`bridge internal=True`) |
| **Runtime del Entorno Espejo** | [`mirror/runtime.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/mirror/runtime.py) | 🟢 **100% Real** | Operativo | Docker Engine API (`containers.run` imagen limpia) |
| **Honeypots en Puertos de Red** | [`deception/decoy_services.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/deception/decoy_services.py) | 🟢 **100% Real** | Operativo | Sockets TCP en `127.0.0.1` (16379, 12222, 18080) |
| **Vigilancia de Archivos Canario (FIM)** | [`deception/decoy_files.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/deception/decoy_files.py) | 🟢 **100% Real** | Operativo | `watchdog` (Inotify / Kqueue / FSEvents) |
| **Base de Datos Transaccional** | [`core/storage.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/core/storage.py) | 🟢 **100% Real** | Operativo | SQLite WAL en disco (`mirror_shield.db`) |
| **Evidencia Forense & Sellado SHA-256** | [`evidence/forensics_collector.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/evidence/forensics_collector.py) | 🟢 **100% Real** | Operativo | `container.diff()`, Criptografía SHA-256, JSON en disco |
| **Motor de Recuperación & Rollback** | [`recovery/manager.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/recovery/manager.py) | 🟢 **100% Real** | Operativo | Reversión de rutas en proxy, reactivación de contenedor |
| **Daemon Supervisor** | [`core/daemon.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/core/daemon.py) | 🟢 **100% Real** | Operativo (Solo Proxy) | Procesos POSIX, PID files, Señales OS |
| **Telemetría osquery** | [`adapters/osquery/client.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/adapters/osquery/client.py) | 🟢 **100% Real** | Condicional | Requiere binario `osqueryi` en PATH del host |
| **Sanitización de Secretos** | [`mirror/sanitization.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/mirror/sanitization.py) | 🪞 **Sintético / Engaño** | Operativo | Algoritmo Entropía Shannon + Regex de firmas |
| **Respuestas de Banners Honeypot** | [`deception/decoy_services.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/deception/decoy_services.py) | 🪞 **Sintético / Engaño** | Operativo | Protocolos mínimos simulados (Redis auth error, SSH banner) |
| **Laboratorio Red Team (`espejo lab`)** | [`lab/scenarios/`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/lab/scenarios) | 🧪 **Simulación / Demo** | Operativo | Genera `MirrorEvent` sintéticos hacia el bus de eventos |
| **Pruebas Automatizadas (`pytest`)** | [`tests/`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/tests) | 🧪 **Simulación / Mocks** | 50/50 Tests OK | `unittest.mock` para ejecutar sin Docker Desktop activo |
| **Subcarpeta de Repositorios `repos/`** | [`repos/`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/repos) | 📦 **Dependencias / Ref** | Parcial | Ver detalle en Sección 4 |

---

## 1. Componentes Reales en Profundidad

### A. Dynamic Reverse Proxy (`TrafficSwitch`)
* **Código:** [`mirror/traffic_switch.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/mirror/traffic_switch.py)
* **Realidad:** Abre sockets TCP reales usando `asyncio.start_server`. Escucha peticiones reales entrantes.
* **Manejo de Tráfico:** Inspecciona bytes entrantes, inyecta cabeceras HTTP de proxy (`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Mirror-Shield`) y mantiene un túnel bidireccional asíncrono con el contenedor destino.
* **Seguridad:** Soporta terminación TLS con certificados generados o provistos por el usuario mediante `ssl.SSLContext`.
* **Conmutación:** Si la política ordena desvío a espejo, el puntero en memoria de la ruta cambia instantáneamente sin desconectar a los clientes.

### B. Primitivas de Docker Engine (`DockerIsolationManager` y `MirrorRuntime`)
* **Código:** [`isolation/docker.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/isolation/docker.py), [`mirror/runtime.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/mirror/runtime.py)
* **Realidad:** Se comunica con el daemon de Docker (`/var/run/docker.sock`).
* **Acciones:**
  * `freeze_container(id)`: Invoca la API cgroups de Docker para pausar (`container.pause()`), congelando en seco los procesos del atacante sin perder la memoria RAM para análisis.
  * `isolate_container(id)`: Desconecta el contenedor de la red `bridge` pública o de producción y lo conecta a una red Docker creada con `internal=True` (sin gateway de salida hacia internet ni a la LAN).
  * `instantiate_mirror(...)`: Invoca `client.containers.run()` levantando una imagen base limpia verificada (`known-good image`) en la red `mirror_world_net`.

### C. Trampas Activas en Puertos y Archivos
* **Código:** [`deception/decoy_services.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/deception/decoy_services.py), [`deception/decoy_files.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/deception/decoy_files.py)
* **Realidad:** 
  * Los puertos `16379`, `12222` y `18080` son sockets TCP reales escuchando en `127.0.0.1`.
  * Los archivos trampa (como `.env.backup` o credenciales falsas) son monitoreados a nivel de kernel mediante `watchdog`. Cualquier lectura, apertura o modificación dispara un evento con severidad crítica.

---

## 2. Componentes Sintéticos / Engaño (Por Diseño)

En ciberdefensa activa (*Deception Technology*), no se debe entregar información real al intruso. Por tanto, estos componentes son sintéticos deliberadamente:

1. **Generación de Secretos Sintéticos (`DecoySecretGenerator` y `MirrorSanitizer`)**:
   * Cuando se clona el contenedor a la "Dimensión Espejo", las variables de entorno reales son interceptadas.
   * Si una variable contiene una clave privada, token JWT, clave de Stripe, AWS o Slack, el sanitizador la reemplaza por una clave señuelo idéntica en longitud y entropía, pero falsa.
   * El atacante cree haber exfiltrado credenciales válidas, pero son tokens inertes o canarytokens que alertan si intenta usarlos fuera.
2. **Respuestas de Protocolo en Honeypots**:
   * El servidor en puerto `16379` no corre una base de datos Redis en C, sino una implementación mínima en Python que responde `-ERR authentication required\r\n`.
   * El servidor en puerto `12222` envía el banner `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n` y cierra la conexión tras registrar la IP y la versión del cliente del atacante.

---

## 3. Componentes de Simulación (Laboratorio Red Team)

* **Código:** [`lab/runners/atomic_runner.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/lab/runners/atomic_runner.py), [`lab/scenarios/`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/lab/scenarios)
* **Finalidad:** Permitir al equipo de desarrollo validar el pipeline de contención sin ejecutar malware destructivo en su propia estación de trabajo.
* **Comandos como `espejo lab aggressive-apt` o `espejo lab canary-trigger`:**
  * Crean instancias de la clase `MirrorEvent` con telemetría idéntica a la que emitiría un sensor real y la publican en el `EventBus`.
  * Toda la cadena subsiguiente (decisión, incidente en SQLite, congelamiento de Docker, switch de proxy) se ejecuta de forma real sobre la infraestructura configurada.

---

## 4. Estado Detallado de la Carpeta `repos/`

La carpeta `repos/` contiene 10 repositorios externos de código abierto clonados como referencia y herramientas auxiliares:

| Repositorio en `repos/` | Propósito Original | Estado de Integración en Dimensión Espejo |
| :--- | :--- | :--- |
| **`atomic-red-team`** | Matriz de pruebas de ciberseguridad MITRE | ✅ **Activo**: `AtomicRedTeamRunner` lee directamente los YAMLs de técnicas (ej. T1552.001) para el laboratorio. |
| **`opencanary`** | Honeypot modular de Thinkst | ⚠️ **Parcial**: `OpenCanaryAdapter` provee esquemas de config y mapeo de logs, pero Dimensión Espejo utiliza su propio `DecoyServiceManager` en Python. |
| **`canarytokens`** | Generador de tokens trampa | 💤 **Referencia**: No se ejecutan sus servicios; se utiliza lógica nativa de tokens sintéticos. |
| **`caldera`** | Sistema de emulación de adversarios | 💤 **Referencia**: No integrado en el runtime directo. |
| **`cowrie`** | Honeypot SSH/Telnet | 💤 **Referencia**: Sustituido por el honeypot ligero `fake_ssh` en puerto 12222. |
| **`openbao`** | Gestor de secretos seguro (Fork de Vault) | 💤 **Referencia**: No integrado en el runtime de desarrollo. |
| **`restic`** | Backup seguro y encriptado | 💤 **Referencia**: Se utiliza `RecoveryManager` nativo con SQLite y sellos SHA-256. |
| **`OpenSandbox`** | Entorno de sandboxing | 💤 **Referencia**: Sustituido por las redes internas `bridge` de Docker. |
| **`aide`** | Advanced Intrusion Detection Environment | 💤 **Referencia**: Sustituido por `DecoyFileManager` basado en `watchdog`. |
| **`osquery-python`** | Bindings de osquery | ⚠️ **Parcial**: Sustituido por ejecución directa de `osqueryi --json` en [`adapters/osquery/client.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/adapters/osquery/client.py). |

---

## 5. Deuda Técnica y Hoja de Ruta hacia V2

Para alcanzar el 100% de madurez de grado empresarial (producción):
1. **Unificación del Supervisor en Background:** Modificar `DaemonSupervisor` para que `espejo daemon start` levante de forma concurrente el `TrafficSwitch` junto con `DockerEventListener`, `DecoyServiceManager` y `DecoyFileManager` bajo un único proceso maestro.
2. **Bucle Activo en `espejo up`:** Dotar a `espejo up` de un bucle `asyncio.run(_engine.start())` que capture `SIGINT` (`Ctrl+C`) para operación interactiva en primer plano.
3. **Canal IPC para Señalización en Caliente:** Implementar un Unix Domain Socket local para comunicar eventos entre el CLI interactivo y el demonio residente en memoria.
