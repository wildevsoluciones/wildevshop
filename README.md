# WilDev Ecommerce (demo) — Flask + SQLite

Ecommerce responsive con:
- Catálogo, búsqueda, detalle de producto
- Carrito en sesión, “checkout” de demo (crea orden en DB)
- Login/Logout + usuarios
- Panel Admin: CRUD de productos y usuarios (solo admins)

## Requisitos
- Python 3.10+ recomendado (funciona con 3.9+)

## Cómo correr (VS Code / terminal)
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
# source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Abrí: http://127.0.0.1:5000

## Credenciales demo
- Admin: **admin** / **admin123!**
- Usuario: **demo** / **demo123!**

> Cambiá estas credenciales en cuanto lo pruebes.

## Notas
- La base se crea en `instance/app.db`
- Para resetear todo: borrá la carpeta `instance/` y reiniciá.
