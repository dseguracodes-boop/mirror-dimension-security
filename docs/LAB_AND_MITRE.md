# 🧪 Laboratorio Red Team y Simulación MITRE ATT&CK

> **Documento de especificación sobre el módulo de simulación de ataques y pruebas controladas.**  
> Para validar la eficacia de un sistema de ciberdefensa sin poner en riesgo la máquina del desarrollador, Dimensión Espejo incorpora un laboratorio (*Red Team Simulator*) capaz de disparar técnicas atómicas reales basadas en el framework MITRE ATT&CK.

---

## 📑 Tabla de Contenidos
1. [Filosofía del Laboratorio: Emulación Sin Daño](#1-filosofía-del-laboratorio-emulación-sin-daño)
2. [Integración con Atomic Red Team (`repos/atomic-red-team`)](#2-integración-con-atomic-red-team-reposatomic-red-team)
3. [Escenarios de Ataque Disponibles](#3-escenarios-de-ataque-disponibles)
4. [Escenario Avanzado: Emulación APT Multi-Etapa (`aggressive-apt`)](#4-escenario-avanzado-emulación-apt-multi-etapa-aggressive-apt)
5. [Ejecución de la Suite de Tests Automatizados](#5-ejecución-de-la-suite-de-tests-automatizados)

---

## 1. Filosofía del Laboratorio: Emulación Sin Daño

En pruebas de penetración o ejercicios de *Purple Teaming*, ejecutar binarios reales de malware (ej. mineros de criptomonedas, troyanos o ransomware) en una estación de trabajo de desarrollo puede ocasionar pérdidas de datos o bloqueos del sistema.

El módulo `lab/` resuelve este dilema mediante **emulación semántica de eventos**:
* Genera y transmite eventos [MirrorEvent](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/core/models.py) con telemetría idéntica a la que produciría un atacante real.
* Permite validar de punta a punta la matriz de decisiones, las políticas declarativas, el congelamiento de Docker y el desvío de tráfico en el proxy.

---

## 2. Integración con Atomic Red Team (`repos/atomic-red-team`)

Implementado en [`lab/runners/atomic_runner.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/lab/runners/atomic_runner.py) mediante `AtomicRedTeamRunner`.

El runner se conecta con el repositorio clonado `repos/atomic-red-team/atomics/` e interpreta las definiciones oficiales de técnicas MITRE en formato YAML:

```bash
# Simular técnica MITRE T1552.001 (Credentials in Files):
espejo lab T1552.001
```

### Proceso Interno
1. `AtomicRedTeamRunner.load_technique("T1552.001")` lee `repos/atomic-red-team/atomics/T1552.001/T1552.001.yaml`.
2. Extrae el comando de prueba (ej. búsqueda de credenciales en archivos locales).
3. Mapea la técnica a un `MirrorEvent` normalizado:
   * **Attack Stage:** `credential_access`.
   * **Event Type:** `canary_trigger`.
   * **Severity:** `critical`.
   * **Confidence:** `0.96`.
4. El evento entra al `EventBus`, desencadenando la respuesta automática del escudo.

---

## 3. Escenarios de Ataque Disponibles

El comando `espejo lab` incluye escenarios preconfigurados:

| Escenario | Comando | Táctica MITRE | Resultado Esperado |
| :--- | :--- | :--- | :--- |
| **Canario Tocado** | `espejo lab canary-trigger` | `T1552.001` (Credential Access) | Incidente CRITICAL, congelamiento inmediato y desvío a espejo. |
| **Escape de Contenedor** | `espejo lab container-escape` | `T1611` (Privilege Escalation) | Incidente CRITICAL, aislamiento forzado de red blackhole. |
| **Sondeo de Puertos** | `espejo lab port-probe` | `T1046` (Network Service Discovery) | Incidente HIGH en honeypot, registro de origen y alerta. |
| **Proceso Sospechoso** | `espejo lab process-anomaly` | `T1059` (Command Execution) | Incidente HIGH, telemetría de comando anómalo capturada. |
| **Técnicas Atómicas** | `espejo lab <T-ID>` | Mapeo dinámico | Lectura de archivo YAML de Atomic Red Team y ejecución. |

---

## 4. Escenario Avanzado: Emulación APT Multi-Etapa (`aggressive-apt`)

El escenario `aggressive-apt` emula el ciclo de vida completo de un grupo de ciberespionaje o amenaza persistente avanzada (APT):

```bash
espejo lab aggressive-apt
```

### Fases de la Emulación
1. **Fase 1 (Reconocimiento / Discovery):** Escaneo de puertos sobre los honeypots locales (puerto 16379 / 12222).
2. **Fase 2 (Acceso Inicial / Initial Access):** Detección de ejecución anómala en un contenedor.
3. **Fase 3 (Acceso a Credenciales / Credential Access):** Apertura indebida de un archivo señuelo `.env.backup`.
4. **Fase 4 (Movimiento Lateral / Lateral Movement):** Intento de sondeo interno de red.
5. **Respuesta Automatizada:** El orquestador escala el incidente de `LOW` a `CRITICAL`, activa el puente `mirror_isolated_net`, congela el contenedor comprometido, preserva el manifiesto forense sellado en SHA-256 y conmuta el proxy al entorno espejo.

---

## 5. Ejecución de la Suite de Tests Automatizados

La suite de tests valida la solidez de todos los módulos sin requerir Docker encendido:

```bash
# Activar entorno virtual:
source .venv/bin/activate

# Ejecutar las 50 pruebas con pytest:
pytest -q
```

### Cobertura de la Suite (50 Tests)
* **Base de datos transaccional SQLite WAL:** Verificación de concurrencia y prevención de bloqueos.
* **Modelos y EventBus:** Tipado Pydantic y enrutamiento pub/sub asíncrono con wildcards.
* **Políticas y Decisiones:** Verificación de las tablas de decisión y umbrales de severidad.
* **Aislamiento y Red:** Mocks de pausado y desconexión de interfaces en Docker.
* **Proxy y Terminación TLS:** Sockets TCP asíncronos y verificación de cabeceras HTTP.
* **Sanitización y Entropía:** Detección de claves de alta aleatoriedad y reemplazo por señuelos.
* **Escenarios del Laboratorio:** Flujo completo de incidentes simulados.
