# 🛡️ Política de Seguridad (Security Policy)

## Versiones Soportadas

Dimensión Espejo proporciona actualizaciones de seguridad y soporte para las siguientes ramas:

| Versión | Soportada | Parches de Seguridad |
| :--- | :--- | :--- |
| **0.3.x (Actual / V1)** | ✅ Sí | Sí |
| < 0.2.0 | ❌ No | No |

---

## Reporte Responsable de Vulnerabilidades (Responsible Disclosure)

La seguridad es el núcleo fundamental de este proyecto. Si descubres una vulnerabilidad de seguridad en Dimensión Espejo (por ejemplo, bypass de la red de aislamiento, fuga de variables reales hacia el entorno espejo, o denegación de servicio en el proxy asíncrono):

1. **Por favor NO abras un Issue público en GitHub.**
2. Envía un reporte privado directamente al mantenedor del proyecto (**Dany**) con:
   * Descripción detallada de la vulnerabilidad.
   * Pasos reproducibles o script de Prueba de Concepto (PoC).
   * Impacto potencial y versiones afectadas.
3. Se confirmará la recepción del reporte en un plazo máximo de **48 horas**.
4. Se acordará un período de remediación antes de cualquier divulgación pública.

---

## Buenas Prácticas al Usar Dimensión Espejo
* **Acceso a Docker Socket:** Dimensión Espejo interactúa con `/var/run/docker.sock`. Asegúrate de ejecutar el software con los permisos mínimos requeridos y nunca exponer sockets de Docker a redes públicas no autenticadas.
* **Archivos Canario:** Los archivos trampa generados por el sistema (como `.env.backup`) contienen secretos sintéticos falsos con fines de engaño. No agregues secretos de producción reales en dichos archivos trampa.
