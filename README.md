# NEXORA ADMIN + API

Servicio Flask que aloja el panel privado y la API consumida por NEXORA WEB.

## Requisitos
- Python 3.11+
- Una base de datos Turso (URL y token)
- Render Web Service

## Variables en Render
- `SECRET_KEY`: secreto largo aleatorio.
- `ADMIN_USERNAME`: usuario administrador inicial.
- `ADMIN_PASSWORD`: contraseña inicial (mínimo 12 caracteres recomendado).
- `TURSO_DATABASE_URL`: URL `libsql://...` de Turso.
- `TURSO_AUTH_TOKEN`: token de acceso de Turso.
- `ALLOWED_ORIGINS`: URL pública del servicio web, por ejemplo `https://nexora-web.onrender.com`.

La cuenta admin inicial se crea automáticamente en el primer arranque si no existe. Cambia la contraseña antes de publicar y no compartas el token de Turso.

## Despliegue
Sube esta carpeta a un repositorio GitHub. En Render crea un Web Service desde ese repositorio:
- Build: `pip install -r requirements.txt`
- Start: `gunicorn app:app --workers 2 --threads 4 --timeout 120`

También puedes usar el `render.yaml` incluido. Configura los secretos desde Environment. Health check: `/health`.

## Funciones incluidas
Login admin, productos y planes, usuarios, ajustes de créditos con ledger, inventario de claves, compra con débito de saldo y órdenes. El generador de esta primera versión entrega claves previamente cargadas en inventario. Para generadores externos hace falta conocer su API y autenticación.

## Notas de producción
- Turso es la persistencia principal cuando ambas variables `TURSO_DATABASE_URL` y `TURSO_AUTH_TOKEN` están configuradas.
- Sin esas variables se usa SQLite local solo para desarrollo; el disco efímero de Render no debe usarse como almacenamiento de producción.
- Realiza backups de Turso y guarda los secretos fuera del repositorio.
- Para cobros reales integra un proveedor de pagos y valida webhooks del lado del servidor. La recarga manual de saldo se realiza desde ADMIN.
