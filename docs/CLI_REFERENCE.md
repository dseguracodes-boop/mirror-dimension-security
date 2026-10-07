# 💻 Referencia Completa del CLI (`espejo`) y Gestión del Demonio

> **Manual de usuario y referencia de comandos de la interfaz de línea de comandos `espejo`.**  
> Desarrollado con Typer y renderizado con componentes enriquecidos de terminal en Rich.

---

## 📑 Tabla de Comandos

| Comando | Sintaxis | Descripción |
| :--- | :--- | :--- |
| **`status`** | `espejo status` | Muestra la matriz de activos protegidos, nivel de amenaza global y estado de Docker/canarios. |
| **`routes`** | `espejo routes` | Muestra la tabla de enrutamiento activo (primario vs espejo) y peticiones desviadas. |
| **`proxy`** | `espejo proxy [ASSET] [OPTIONS]` | Inicia el Reverse Proxy dinámico con soporte opcional de cifrado TLS/HTTPS. |
| **`daemon start`** | `espejo daemon start [OPTIONS]` | Inicia el escudo protector supervisado en segundo plano (24/7). |
| **`daemon status`**| `espejo daemon status` | Consulta la salud, PID y estado del socket del proceso demonio en segundo plano. |
| **`daemon stop`**  | `espejo daemon stop` | Detiene limpiamente el proceso demonio en segundo plano. |
| **`incidents`** | `espejo incidents` | Lista todos los incidentes de seguridad correlacionados por el Core. |
| **`verify`** | `espejo verify <INCIDENT_ID>` | Comprueba la integridad del sello criptográfico SHA-256 de una evidencia forense. |
| **`rollback`** | `espejo rollback <INCIDENT_ID>` | Ejecuta la remediación y rollback seguro a la línea base limpia. |
| **`lab`** | `espejo lab <SCENARIO>` | Ejecuta un escenario de ataque controlado o técnica MITRE ATT&CK en el laboratorio. |
| **`up`** | `espejo up` | Inicia el Developer Shield en primer plano. |

---

## 1. Inspección y Estado

### `espejo status`
Muestra el panel general de telemetría y salud del escudo:
```bash
espejo status
```
* **Indicadores:** Estado del motor (`ONLINE`/`STANDBY`), nivel de amenaza global (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), cantidad de eventos en el bus, estado del daemon de Docker y número de trampas activas.

### `espejo routes`
Consulta la tabla de conmutación en caliente del `TrafficSwitch`:
```bash
espejo routes
```
* Muestra el upstream original (`api:8000`), el upstream espejo (`mirror-api:8000`), el target que está recibiendo las conexiones actualmente y la cantidad de peticiones desviadas (*diverted requests*).

---

## 2. Reverse Proxy Dinámico (`espejo proxy`)

Inicia el servidor proxy que intercepta el tráfico público y lo enruta al servicio protegido o al espejo.

```bash
# Modo HTTP básico para desarrollo local (puerto 8080 hacia asset 'api'):
espejo proxy api --port 8080

# Escuchando en una IP o interfaz específica:
espejo proxy api --host 0.0.0.0 --port 8080

# Modo seguro con terminación TLS y generación automática de certificados X.509:
espejo proxy api --port 8443 --tls

# Modo seguro con certificados comerciales propios (PEM):
espejo proxy api --port 8443 --tls --cert /ruta/al/cert.pem --key /ruta/al/key.pem
```

---

## 3. Demonio en Segundo Plano (`espejo daemon`)

Administra el ciclo de vida del escudo para que funcione 24/7 sin bloquear tu terminal interactiva.

```bash
# 1. Iniciar el demonio en background:
espejo daemon start --asset api --port 8080

# Con cifrado TLS activado:
espejo daemon start --asset api --port 8443 --tls

# 2. Consultar el estado del demonio:
espejo daemon status
# Salida esperada:
# ● Shield Daemon ACTIVE (PID 4921)
#    Health: HEALTHY (Responsive)
#    Endpoint: 127.0.0.1:8080
#    Asset: api

# 3. Detener el demonio:
espejo daemon stop
# Salida esperada:
# ✔ Daemon process 4921 terminated cleanly.
```

---

## 4. Gestión de Incidentes, Evidencia y Rollback

### Listar incidentes:
```bash
espejo incidents
```
Muestra la tabla de incidentes generados con ID (`INC-2026-XXXX`), severidad, activos afectados y estado (`OPEN`, `CONTAINED`, `RESOLVED`).

### Verificar integridad forense:
```bash
espejo verify INC-2026-0001
```
* Recalcula el SHA-256 de `evidence_vault/INC-2026-0001/manifest.json`.
* Si no fue alterado, confirma validez forense.

### Ejecutar rollback seguro:
```bash
espejo rollback INC-2026-0001
```
* Desactiva el desvío de tráfico en el proxy.
* Destruye el contenedor espejo temporal.
* Descongela o restaura el contenedor primario desde la imagen base limpia.
* Marca el incidente como `RESOLVED`.
