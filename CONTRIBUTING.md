# 🤝 Guía de Contribución y Revisión (Contributing Guidelines)

Gracias por tu interés en **Dimensión Espejo (Mirror Dimension)**.

---

## 📜 Licencia y Propiedad Intelectual

Antes de contribuir, ten en cuenta que este proyecto está protegido por una **Licencia Personalizada (Copyright © 2026 Dany. All rights reserved)**.
* El repositorio está abierto para **revisión, auditoría y aprendizaje educativo**.
* Las contribuciones, sugerencias, reportes de bugs o Pull Requests que envíes se aceptarán bajo el entendimiento de que el código pasará a formar parte del proyecto sin transferir reclamos de propiedad comercial externa sobre el núcleo de la plataforma.

---

## 🛠️ Entorno de Desarrollo Local

### 1. Prerrequisitos
* Python 3.11 o superior.
* Docker Desktop o Docker Engine activo.
* Git.

### 2. Instalación
```bash
git clone https://github.com/tu-usuario/DIMENCION-ESPEJO.git
cd DIMENCION-ESPEJO
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 3. Ejecutar las Pruebas Unitarias
Todas las modificaciones deben mantener el 100% de la suite de pruebas en verde:
```bash
pytest -q
```

---

## 📋 Reglas de Estilo de Código
* **Tipado Estricto:** Todo el código nuevo debe incluir anotaciones de tipo (`typing` / Type Hints).
* **Manejo de Excepciones:** Las llamadas a la API de Docker y a sockets deben manejar adecuadamente excepciones de red o indisponibilidad del daemon.
* **Sin Dependencias Innecesarias:** Evitar agregar dependencias pesadas; preferir la biblioteca estándar de Python (`asyncio`, `socket`, `hashlib`, `sqlite3`, `pathlib`).
