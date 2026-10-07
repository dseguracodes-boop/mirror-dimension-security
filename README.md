# 🪞 Dimensión Espejo (Developer Shield)

[![Tests](https://img.shields.io/badge/tests-50%20passing-brightgreen.svg)](docs/LAB_AND_MITRE.md)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.14-blue.svg)](pyproject.toml)
[![Architecture](https://img.shields.io/badge/architecture-active%20defense-purple.svg)](docs/ARCHITECTURE.md)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-aligned-orange.svg)](docs/LAB_AND_MITRE.md)
[![License](https://img.shields.io/badge/license-Custom%20%7C%20Review%20Only-blueviolet.svg)](LICENSE)

> **Ciberresiliencia Activa, Decepción y Entornos Espejo para Entornos de Desarrollo y Producción Local.**

Dimensión Espejo es una plataforma de defensa activa (*Cyber Deception & Active Defense*) diseñada para desarrolladores. En lugar de limitarse a alertar pasivamente tras una intrusión o intentar parchear sistemas ya comprometidos, Dimensión Espejo:

1. **Despliega Decepción Preventiva**: Trampas y señuelos (`.env.backup`, credenciales canario, puertos trampa) con ratio de falso positivo prácticamente nulo.
2. **Desacopla Amenaza de Acción**: Un motor de políticas declarativo (`Policy Engine`) traduce señales de telemetría y criticidad de activos en acciones quirúrgicas (`ALLOW`, `MONITOR`, `DECOY`, `ISOLATE`, `QUARANTINE`, `EMERGENCY_FREEZE`).
3. **Aísla y Congela de Inmediato**: Preserva la evidencia forense del activo real congelando el proceso (`container.pause()`) antes de que se produzca movimiento lateral.
4. **Construye la Dimensión Espejo**: Levanta una instancia señuelo desde una imagen base limpia conocida (`Known-Good Image`) con datos sintéticos y secretos falsificados mediante entropía de Shannon en una red estanca.
5. **Conmuta el Tráfico sin Caída (Zero-Drop)**: Un Reverse Proxy dinámico con soporte TLS desvía las conexiones del atacante en caliente hacia el contenedor espejo.
6. **Permite Recuperación Segura**: Facilita el rollback a la baseline limpia validada mediante sellado criptográfico SHA-256.

---

## 📚 Documentación Técnica Completa

Para un registro exhaustivo de la arquitectura, componentes, funcionamiento y guías de uso, consulta los documentos especializados en el directorio [`docs/`](docs/):

| Documento | Descripción |
| :--- | :--- |
| 🏛️ [**Arquitectura Integral**](docs/ARCHITECTURE.md) | Diagrama global de componentes, diagramas de secuencia Mermaid, ciclo de vida de eventos y modelo de amenazas. |
| 🔍 [**Auditoría de Componentes**](docs/COMPONENTS_AUDIT.md) | Desglose honesto: qué es 100% real (Docker, sockets, SQLite), qué es sintético (secretos espejo) y qué es simulación (lab). |
| 🎭 [**Motor de Decepción & Canarios**](docs/DECEPTION_AND_CANARIES.md) | Honeypots en puertos (Redis 16379, SSH 12222, HTTP 18080), FIM con watchdog y cálculo de entropía de Shannon. |
| 🧊 [**Aislamiento & Entorno Espejo**](docs/ISOLATION_AND_MIRROR.md) | Congelamiento de procesos, red blackhole `mirror_isolated_net`, runtime del espejo y reverse proxy con TLS. |
| 🔬 [**Forense, Integridad & Rollback**](docs/FORENSICS_AND_RECOVERY.md) | Sellado criptográfico SHA-256, extracción de diffs en Docker, base de datos SQLite WAL y remediación en un clic. |
| 💻 [**Referencia Completa del CLI**](docs/CLI_REFERENCE.md) | Manual de comandos `espejo` (`status`, `routes`, `proxy`, `daemon`, `incidents`, `verify`, `rollback`). |
| 🚀 [**Tutorial Paso a Paso**](docs/TUTORIAL_PASO_A_PASO.md) | Guía práctica completa: levantar un contenedor real, simular una intrusión, conmutar al espejo y rollback. |
| 🧪 [**Laboratorio Red Team & MITRE**](docs/LAB_AND_MITRE.md) | Integración con Atomic Red Team (`T1552.001`), simulaciones APT multi-etapa y suite de pruebas automatizadas. |

---

## 🏛️ Arquitectura del Sistema (V1)

```text
                         ┌─────────────────────────┐
                         │      DEVELOPER HOST     │
                         │      macOS / Linux      │
                         └────────────┬────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │     MIRROR CORE         │
                         │                         │
                         │ Asset Registry          │
                         │ Event Bus (Asyncio)     │
                         │ Policy Engine           │
                         │ Threat Decision Engine  │
                         │ Incident Lifecycle      │
                         │ Master Orchestrator     │
                         │ Storage Engine (WAL)    │
                         └───────┬────────┬────────┘
                                 │        │
                    ┌────────────┘        └─────────────┐
                    ▼                                   ▼
             ┌──────────────┐                    ┌──────────────┐
             │   SENSORES   │                    │   DECEPCIÓN  │
             │ Docker Socket│                    │ Archivos FIM │
             │ osquery      │                    │ Fake secrets │
             │ Tráfico Red  │                    │ Honeypots TCP│
             │ Canarios     │                    │ Canarytokens │
             └──────┬───────┘                    └──────┬───────┘
                    │                                   │
                    └────────────────┬──────────────────┘
                                     ▼
                              ┌──────────────┐
                              │  POLÍTICAS   │
                              │      Y       │
                              │  DECISIONES  │
                              └──────┬───────┘
                                     ▼
                         ┌────────────────────────┐
                         │      ORQUESTADOR       │
                         └───────┬────────┬───────┘
                                 │        │
                    ┌────────────┘        └────────────┐
                    ▼                                 ▼
             ┌──────────────┐                   ┌──────────────┐
             │  ACTIVO REAL │                   │ MUNDO ESPEJO │
             │ FREEZE Cgroup│                   │ Imagen limpia│
             │ BLACKHOLE NET│                   │ Fake Secrets │
             │ FORENSIC DIFF│                   │ Tráfico Prox │
             │ BASELINE SEAL│                   │ Red estanca  │
             └──────────────┘                   └──────────────┘
                    │                                 │
                    └──────────────┬──────────────────┘
                                   ▼
                          ┌──────────────────┐
                          │ EVIDENCE VAULT   │
                          │ SHA-256 Seals    │
                          │ Timeline SQLite  │
                          │ Manifests JSON   │
                          └──────────────────┘
```

---

## 🚀 Inicio Rápido

### 1. Requisitos
* Python 3.11+ (Recomendado 3.12 o 3.14)
* Docker Desktop / Docker Engine

### 2. Instalación en Modo Desarrollo
```bash
git clone https://github.com/tu-usuario/DIMENCION-ESPEJO.git
cd DIMENCION-ESPEJO
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 3. Comandos Esenciales del CLI `espejo`

#### Ver el estado de protección y matriz de activos:
```bash
espejo status
```

#### Ver la tabla de enrutamiento dinámico (Real vs Espejo):
```bash
espejo routes
```

#### Iniciar el Reverse Proxy dinámico hacia tu aplicación protegida:
```bash
# Modo HTTP estándar (puerto 8080 hacia asset 'api'):
espejo proxy api --port 8080

# Modo seguro HTTPS/TLS con auto-generación de certificados X.509:
espejo proxy api --port 8443 --tls

# Modo seguro HTTPS/TLS con certificados propios:
espejo proxy api --port 8443 --tls --cert /etc/ssl/cert.pem --key /etc/ssl/key.pem
```

#### Operación en Segundo Plano 24/7 (Daemon Supervisor):
```bash
# Iniciar el servicio en segundo plano:
espejo daemon start --port 8080

# Consultar estado de salud y socket del demonio:
espejo daemon status

# Detener el servicio:
espejo daemon stop
```

#### Ver incidentes de seguridad registrados:
```bash
espejo incidents
```

#### Verificar el sello criptográfico SHA-256 de una evidencia forense:
```bash
espejo verify INC-2026-0001
```

#### Remediar y ejecutar Rollback seguro a la línea base limpia:
```bash
espejo rollback INC-2026-0001
```

#### Simular un ataque controlado en el Lab (Red Team):
```bash
# Ataque simulando APT multi-etapa MITRE ATT&CK:
espejo lab aggressive-apt

# O escenarios específicos:
espejo lab canary-trigger
espejo lab container-escape
espejo lab port-probe
espejo lab process-anomaly
espejo lab T1552.001
```

---

## 🧪 Ejecución de Tests Automatizados

```bash
source .venv/bin/activate
pytest -q
```
```text
..................................................                       [100%]
50 passed in 0.80s
```
*Incluye 50 pruebas automatizadas de extremo a extremo cubriendo base de datos transaccional SQLite WAL, concurrencia multihilo, terminación TLS/HTTPS, inyección de headers de proxy, ciclo de vida del demonio en segundo plano, aislamiento de red, sanitización con entropía Shannon y escenarios MITRE ATT&CK.*

---

## License

Copyright © 2026 Dany. All rights reserved.

This project is publicly available for review and educational purposes.
Commercial use, redistribution, modification, or incorporation into
commercial products requires prior written permission from the copyright holder.

Consulta el archivo [LICENSE](LICENSE) para conocer los términos completos.
