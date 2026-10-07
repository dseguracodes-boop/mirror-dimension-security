# 🔬 Forense Digital, Integridad Criptográfica y Recuperación (Recovery Engine)

> **Documento de especificación sobre recolección de evidencia, sellado SHA-256, base de datos transaccional SQLite WAL y rollback seguro.**  
> En una intrusión de seguridad, la evidencia que no puede demostrarse inalterada es inútil en un informe pericial o auditoría de cumplimiento. Dimensión Espejo implementa cadena de custodia criptográfica automatizada y restauración controlada a una línea base limpia.

---

## 📑 Tabla de Contenidos
1. [Cadena de Custodia y Manifiestos Forenses](#1-cadena-de-custodia-y-manifiestos-forenses)
2. [Sellado Criptográfico SHA-256 y Verificación de Integridad](#2-sellado-criptográfico-sha-256-y-verificación-de-integridad)
3. [Diferencial del Sistema de Archivos (`container.diff`)](#3-diferencial-del-sistema-de-archivos-containerdiff)
4. [Persistencia ACID en SQLite con Modo WAL](#4-persistencia-acid-en-sqlite-con-modo-wal)
5. [Procedimiento de Rollback a la Línea Base Limpia](#5-procedimiento-de-rollback-a-la-línea-base-limpia)

---

## 1. Cadena de Custodia y Manifiestos Forenses

Implementado en [`evidence/forensics_collector.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/evidence/forensics_collector.py) mediante `ForensicsCollector`.

Cuando el motor de políticas clasifica un evento como amenaza `HIGH` o `CRITICAL`, se genera de forma inmediata un snapshot en la bóveda de evidencia (`evidence_vault/<INCIDENT_ID>/`).

### Estructura del Manifiesto Forense (`manifest.json`)
Cada incidente contiene un manifiesto estructurado en JSON con metadatos de auditoría:
```json
{
  "incident_id": "INC-2026-0001",
  "captured_at": "2026-10-07T08:15:22.104928+00:00",
  "target": "api",
  "trigger_reason": "canary_trigger (Threat: CRITICAL)",
  "filesystem_diff": [
    {"path": "/tmp/netcat_payload.sh", "action": "ADDED"},
    {"path": "/etc/shadow", "action": "MODIFIED"}
  ],
  "inspection": {
    "id": "c7a8b9d0e1f2...",
    "name": "/api-service-prod",
    "image": "myorg/api:v1.2.0",
    "created": "2026-10-05T12:00:00Z"
  },
  "sha256_integrity_seal": "a8f5f167f44f4964e6c998dee827110c...",
  "verified_status": "SEALED"
}
```

---

## 2. Sellado Criptográfico SHA-256 y Verificación de Integridad

Para asegurar que los registros forenses no puedan ser alterados a posteriori por un atacante o usuario malintencionado:
1. Se serializa el contenido completo de la evidencia con claves ordenadas canónicamente (`json.dumps(data, sort_keys=True)`).
2. Se genera el hash **SHA-256** del bloque de datos.
3. El hash se incrusta en el archivo `manifest.json` y se persiste simultáneamente en la base de datos relacional protegida `mirror_shield.db`.

### Verificación mediante CLI
Cualquier auditor puede verificar la integridad del archivo en cualquier momento ejecutando:
```bash
espejo verify INC-2026-0001
```
El comando re-calcula el hash SHA-256 en tiempo real sobre el manifiesto en disco y lo compara con el sello persistido:
* Si coinciden: emite `✔ EVIDENCE INTEGRITY CONFIRMED`.
* Si un solo byte fue alterado: emite `✖ INTEGRITY COMPROMISED / INVALID` con código de salida `1`.

---

## 3. Diferencial del Sistema de Archivos (`container.diff`)

Docker mantiene internamente un registro de capas Copy-on-Write (CoW). `ForensicsCollector` consulta la API de Docker mediante `container.diff()` para extraer todos los cambios realizados en el sistema de archivos desde que el contenedor fue iniciado:
* **`ADDED` (Kind 1):** Archivos descargados o creados por el atacante (exploits, scripts, herramientas de post-explotación).
* **`MODIFIED` (Kind 0):** Archivos de configuración o binarios del sistema alterados.
* **`DELETED` (Kind 2):** Logs o archivos eliminados por el atacante para borrar huellas.

---

## 4. Persistencia ACID en SQLite con Modo WAL

Implementado en [`core/storage.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/core/storage.py) mediante `StorageEngine`.

A diferencia de archivos JSON planos propensos a condiciones de carrera (*race conditions*) y corrupción durante caídas imprevistas de energía, Dimensión Espejo implementa una base de datos relacional embebida:
* **Ubicación:** `evidence_vault/mirror_shield.db`.
* **Modo WAL (Write-Ahead Logging):** Permite lecturas y escrituras concurrentes sin bloquear los hilos de red del proxy.
* **Tolerancia a Concurrencia:** `PRAGMA busy_timeout=5000` previene bloqueos en situaciones de alta carga.
* **Tablas Administradas:**
  * `incidents`: Registro histórico de incidentes con su ciclo de vida y niveles de amenaza.
  * `events`: Flujo correlacionado de eventos de telemetría.
  * `baselines`: Sellos de integridad y configuración de imágenes limpias.
  * `routes`: Estado de enrutamiento del reverse proxy (primario vs espejo).
  * `audit_log`: Pista de auditoría inmutable de todas las acciones tomadas por el orquestador.

---

## 5. Procedimiento de Rollback a la Línea Base Limpia

Implementado en [`recovery/manager.py`](file:///Users/fabiodanielsegura/DIMENCION-ESPEJO/recovery/manager.py) mediante `RecoveryManager`.

Una vez que el equipo de seguridad o el desarrollador termina el análisis del incidente, la remediación se realiza en un solo comando:
```bash
espejo rollback INC-2026-0001
```

### Pasos de Ejecución del Rollback
1. **Verificación de Baseline Sellada:** Valida que exista una línea base registrada (`known_good_image` y hash de configuración).
2. **Destrucción del Entorno Espejo:** Se apaga y destruye el contenedor espejo temporal para liberar puertos y memoria.
3. **Reversión del Tráfico (Proxy Restored):** El `TrafficSwitch` restaura el upstream hacia el servicio principal.
4. **Descongelamiento / Reinicio Limpio:** Si el contenedor real sigue disponible, se remueve el estado de pausa o se levanta una nueva instancia limpia desde la imagen base certificada.
5. **Cierre Formal del Incidente:** El estado del incidente en la base SQLite cambia a `RESOLVED` con timestamp de resolución y registro de auditoría.
