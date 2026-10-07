# 🧊 Aislamiento de Contenedores y el Entorno Espejo (Mirror World)

> **Documento de especificación sobre los mecanismos de contención quirúrgica, redes blackhole y el runtime del entorno clonado.**  
> Cuando un sistema está comprometido, matarlo (*kill*) o reiniciar la máquina destruye la evidencia en memoria y notifica al atacante. Dimensión Espejo aplica contención asimétrica: congela el proceso, aísla la red y levanta un gemelo idéntico (*Mirror World*) con tráfico desviado en caliente.

---

## 📑 Tabla de Contenidos
1. [Contención a Nivel de Proceso: Congelamiento vs. Terminación](#1-contención-a-nivel-de-proceso-congelamiento-vs-terminación)
2. [Aislamiento de Red: El Puente Blackhole (`mirror_isolated_net`)](#2-aislamiento-de-red-el-puente-blackhole-mirror_isolated_net)
3. [Instanciación del Entorno Espejo (Clean Mirror Runtime)](#3-instanciación-del-entorno-espejo-clean-mirror-runtime)
4. [Reverse Proxy Dinámico y Conmutación de Tráfico Zero-Drop](#4-reverse-proxy-dinámico-y-conmutación-de-tráfico-zero-drop)
5. [Terminación TLS y Cifrado en Tránsito](#5-terminación-tls-y-cifrado-en-tránsito)

---

## 1. Contención a Nivel de Proceso: Congelamiento vs. Terminación

Implementado en [`isolation/docker.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/isolation/docker.py) mediante `DockerIsolationManager`.

### ¿Por qué congelar (`container.pause()`) y no matar (`container.kill()`)?
* **Preservación Forense Inmediata:** La memoria volátil del proceso contiene llaves criptográficas cargadas, cadenas de inyección, scripts temporales en `/dev/shm` o `/tmp`, y sockets de red abiertos. Al pausar el contenedor mediante los cgroups del kernel de Linux, el estado se congela en microsegundos.
* **Cero Consumo de CPU:** El proceso congelado no puede ejecutar ni un ciclo más de CPU, frenando en seco scripts de ransomware, cifrado de archivos o propagación de exploits.
* **Reversibilidad Segura:** Si la investigación concluye que fue un falso positivo o se desea restaurar el servicio, basta con llamar a `container.unpause()`, restaurando el contenedor exactamente en su estado previo sin pérdida de contexto.

```python
# Extracto representativo de isolation/docker.py
container = self.client.containers.get(container_identifier)
if container.status == "running":
    container.pause() # Cgroups SIGSTOP a nivel de kernel
```

---

## 2. Aislamiento de Red: El Puente Blackhole (`mirror_isolated_net`)

Implementado en [`isolation/network.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/isolation/network.py) mediante `NetworkIsolationManager`.

Incluso si un contenedor está congelado o en investigación, no debe poder comunicarse con ninguna otra máquina de la red local (evitando movimiento lateral hacia bases de datos, APIs internas o el host).

### Procedimiento Quirúrgico de Aislamiento
1. **Creación de la Red Interna Blackhole:**
   El gestor crea una red Docker con el flag `internal=True`:
   ```bash
   docker network create --driver bridge --internal mirror_isolated_net
   ```
   Una red `internal` no tiene configurada ninguna ruta por defecto (*default gateway*) hacia el host ni hacia interfaces externas (Internet/LAN).
2. **Corte de Enlaces de Red Activos:**
   El gestor inspecciona todas las redes a las que el contenedor está conectado (`bridge`, `host`, redes de docker-compose) y ejecuta `disconnect(container, force=True)`.
3. **Conexión a la Cuarentena:**
   El contenedor se asocia a `mirror_isolated_net`. Si el proceso fuera reactivado para análisis interactivo en sandbox, cualquier paquete IP enviado caerá en un agujero negro local.

---

## 3. Instanciación del Entorno Espejo (Clean Mirror Runtime)

Implementado en [`mirror/runtime.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/mirror/runtime.py) y [`mirror/builder.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/mirror/builder.py).

Para mantener la disponibilidad de la aplicación o engañar al atacante haciéndole creer que su acceso sigue activo, se levanta una instancia gemela:

1. **Selección de la Imagen Base Limpia (`Known-Good Image`):**
   No se clona el contenedor infectado (que podría tener binarios troyanizados), sino que se toma la imagen base original registrada en la baseline limpia (ej. `node:20-alpine` o la imagen construida en CI/CD).
2. **Inyección de Secretos Sanitizados:**
   Las variables de entorno se pasan por `MirrorSanitizer` (ver [`docs/DECEPTION_AND_CANARIES.md`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/docs/DECEPTION_AND_CANARIES.md)), inyectando credenciales señuelo y configuraciones seguras.
3. **Aislamiento en `mirror_world_net`:**
   El contenedor espejo se arranca dentro de una red dedicada para que sus interacciones queden encapsuladas y monitoreadas.

---

## 4. Reverse Proxy Dinámico y Conmutación de Tráfico Zero-Drop

Implementado en [`mirror/traffic_switch.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/mirror/traffic_switch.py) mediante `TrafficSwitch`.

El Reverse Proxy de Dimensión Espejo se ubica entre el tráfico público y los servicios backend protegidos:

```text
Tráfico Público (Navegadores / Clientes / Atacante)
                        │
                        ▼
         ┌───────────────────────────────┐
         │ TrafficSwitch (Proxy 8080)    │
         │ - Terminación TLS             │
         │ - Inyección X-Forwarded-*     │
         └──────────────┬────────────────┘
                        │
       Estado Normal    │    Estado Comprometido
     (is_diverted=False)│    (is_diverted=True)
         ┌──────────────┴──────────────┐
         ▼                             ▼
 ┌───────────────┐             ┌───────────────┐
 │ BACKEND REAL  │             │ CLON ESPEJO   │
 │ (api:8000)    │             │ (mirror:8000) │
 └───────────────┘             └───────────────┘
```

### Conmutación en Caliente (Hot-Switching Zero-Drop)
* El proxy administra una tabla de rutas en memoria (`self._routes`).
* Cuando se dispara un incidente crítico, el `MirrorOrchestrator` invoca `divert_to_mirror(asset_id)`.
* La ruta activa conmuta el puntero del socket upstream desde el host primario hacia el host espejo.
* **Sin caída de conexión (Zero-drop):** Los clientes HTTP no reciben `502 Bad Gateway` ni cortes de TCP; las conexiones en curso se transfieren transparentemente al nuevo destino.

### Inyección de Cabeceras Forenses
El proxy enriquece las peticiones HTTP con metadatos útiles para la investigación:
* `X-Forwarded-For`: IP real del cliente.
* `X-Forwarded-Proto`: `http` o `https`.
* `X-Mirror-Shield`: Identificador de versión del escudo activo.

---

## 5. Terminación TLS y Cifrado en Tránsito

El `TrafficSwitch` incluye soporte completo para cifrado TLS/HTTPS nativo:
* **Modo Certificados Propios:** Admite certificados comerciales o corporativos en formato PEM mediante flags `--cert` y `--key`.
* **Modo Auto-Generación Staging:** Si se habilita `--tls` sin especificar rutas de archivos, genera automáticamente un par de claves y certificado autofirmado X.509 utilizando OpenSSL o la biblioteca `cryptography`.
