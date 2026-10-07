# 🚀 Guía Práctica y Tutorial Paso a Paso (Walkthrough)

> **Tutorial integral para probar y operar Dimensión Espejo en un entorno local real con Docker.**  
> Esta guía te lleva desde el registro de un contenedor hasta la simulación de una intrusión, conmutación automática al clon espejo, verificación criptográfica forense y rollback a estado limpio.

---

## 📑 Índice
1. [Escenario de Prueba](#1-escenario-de-prueba)
2. [Paso 1: Levantar un Servicio Real en Docker](#paso-1-levantar-un-servicio-real-en-docker)
3. [Paso 2: Registrar el Activo en `config/assets.yaml`](#paso-2-registrar-el-activo-en-configassetsyaml)
4. [Paso 3: Levantar el Escudo Protector en Vivo](#paso-3-levantar-el-escudo-protector-en-vivo)
5. [Paso 4: Iniciar el Dynamic Reverse Proxy](#paso-4-iniciar-el-dynamic-reverse-proxy)
6. [Paso 5: Simular la Intrusión y Observar la Reacción](#paso-5-simular-la-intrusión-y-observar-la-reacción)
7. [Paso 6: Auditoría Forense y Verificación SHA-256](#paso-6-auditoría-forense-y-verificación-sha-256)
8. [Paso 7: Remediación y Rollback Seguro](#paso-7-remediación-y-rollback-seguro)

---

## 1. Escenario de Prueba

Imaginemos que tenemos una API web de desarrollo corriendo en un contenedor llamado `mi-api-service` en el puerto `8000`. Queremos:
* Exponerla públicamente en el puerto `8080` a través de **Dimensión Espejo**.
* Protegerla contra robo de credenciales y escaneo de puertos.
* Si un atacante accede o toca un canario, congelar el contenedor real y transferir el atacante al contenedor espejo sin que la conexión se caiga.

---

## Paso 1: Levantar un Servicio Real en Docker

Inicia un contenedor de prueba ligero en tu Docker local:

```bash
docker run -d --name mi-api-service -p 8000:80 nginx:alpine
```
Verifica que responda:
```bash
curl http://localhost:8000
```

---

## Paso 2: Registrar el Activo en `config/assets.yaml`

Abre [`config/assets.yaml`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/config/assets.yaml) y asegúrate de que el contenedor esté registrado con su nivel de criticidad:

```yaml
version: "1.0"
assets:
  - id: "api"
    name: "Core API Gateway"
    type: "container"
    criticality: "HIGH"
    container:
      name: "mi-api-service"
      image: "nginx:alpine"
      ports:
        - 8000
    protections:
      isolate_on_critical: true
      freeze_on_critical: true
      redirect_to_mirror: true
```

---

## Paso 3: Levantar el Escudo Protector en Vivo

En una primera terminal, arranca el motor interactivo en primer plano:

```bash
espejo up
```
* **Qué sucede:**
  * Se activa el `DockerEventListener` sobre `/var/run/docker.sock`.
  * Se abren los puertos trampa locales: Redis (`16379`), SSH (`12222`), HTTP (`18080`).
  * El vigilante de archivos (`watchdog`) comienza a monitorear `.env.backup` y credenciales trampa.
  * La terminal se mantiene viva escuchando eventos en tiempo real.

---

## Paso 4: Iniciar el Dynamic Reverse Proxy

En una segunda terminal, inicia el proxy inverso para enrutar el tráfico:

```bash
espejo proxy api --port 8080
```
Comprueba que el proxy enruta correctamente hacia tu contenedor real:
```bash
curl http://localhost:8080
```
Verás la respuesta del Nginx real enriquecida con las cabeceras `X-Forwarded-For` y `X-Mirror-Shield`.

---

## Paso 5: Simular la Intrusión y Observar la Reacción

Ahora simulamos que un intruso ingresó a la máquina o al proyecto:

### Opción A: Tocar un archivo trampa (FIM Tripwire)
```bash
cat .env.backup
```
### Opción B: Escanear un puerto señuelo (Network Honeypot)
```bash
nc -vz 127.0.0.1 16379
```
### Opción C: Ejecutar un ataque MITRE desde el Lab
```bash
espejo lab T1552.001
```

### ⚡ ¿Qué ocurre de inmediato en microsegundos?
1. **Detección:** El sensor detecta la interacción y emite un `MirrorEvent` con severidad `CRITICAL`.
2. **Decisión:** El `PolicyEngine` evalúa que el activo `api` tiene criticidad `HIGH` y ordena `EMERGENCY_FREEZE`.
3. **Congelamiento:** Docker ejecuta `container.pause()` sobre `mi-api-service`. Si ejecutas `docker ps`, verás su estado como `Up ... (Paused)`.
4. **Blackhole de Red:** El contenedor real se desconecta de su red y se envía a `mirror_isolated_net`.
5. **Espejo Levantado:** Se inicia un contenedor gemelo limpio (`mirror-mi-api-service`) con secretos falsificados.
6. **Conmutación:** El proxy conmuta en memoria el puerto `8080` hacia el espejo. La próxima petición `curl http://localhost:8080` ahora va al espejo.

---

## Paso 6: Auditoría Forense y Verificación SHA-256

Consulta el historial de incidentes:
```bash
espejo incidents
```
Obtendrás una tabla con el identificador del incidente generado (ej. `INC-2026-0001`).

Verifica la integridad del sello forense en disco:
```bash
espejo verify INC-2026-0001
```
Salida esperada:
```text
✔ EVIDENCE INTEGRITY CONFIRMED for INC-2026-0001
   Target: api
   Captured At: 2026-10-07T...
   SHA-256 Seal: 8a9f2b1c4e7...
   Manifest File: .../evidence_vault/INC-2026-0001/forensics_manifest.json
```

---

## Paso 7: Remediación y Rollback Seguro

Una vez analizada la evidencia, restaura el entorno con un solo comando:
```bash
espejo rollback INC-2026-0001
```
* **Acciones ejecutadas:**
  * El proxy restaura la ruta primaria hacia el contenedor original.
  * El contenedor espejo temporal se apaga y destruye limpiamente.
  * El contenedor original es descongelado (`container.unpause()`).
  * El incidente se marca formalmente como `RESOLVED` en SQLite.

---

## 🧹 Limpieza del Entorno de Prueba
Para remover el contenedor de prueba de Docker:
```bash
docker rm -f mi-api-service
```
