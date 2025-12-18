from __future__ import annotations
from flask import Flask
import json
import os
from datetime import datetime
from uuid import uuid4
import mercadopago
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


# app
app = Flask(__name__)

# ======================
# CATEGORÍAS (helpers)
# ======================

def _categories_path():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, "data", "categories.json")

def load_categories():
    path = _categories_path()

    # crear archivo si no existe
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"categories": ["General"]}, f, ensure_ascii=False, indent=2)

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    cats = data.get("categories", [])
    cats = [str(c).strip() for c in cats if str(c).strip()]

    # asegurar General primero
    if "General" not in cats:
        cats.insert(0, "General")

    # dedupe manteniendo orden
    seen = set()
    out = []
    for c in cats:
        if c not in seen:
            seen.add(c)
            out.append(c)

    return out

def save_categories(categories):
    path = _categories_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)

    cats = [str(c).strip() for c in categories if str(c).strip()]
    if "General" not in cats:
        cats.insert(0, "General")

    seen = set()
    out = []
    for c in cats:
        if c not in seen:
            seen.add(c)
            out.append(c)

    with open(path, "w", encoding="utf-8") as f:
        json.dump({"categories": out}, f, ensure_ascii=False, indent=2)

# ======================
# CONTEXT PROCESSOR
# ======================
@app.context_processor
def inject_categories():
    return {
        "all_categories": load_categories()
    }

# ======================
# ADMIN: CATEGORÍAS (web)
# ======================
@app.route("/admin/categories", methods=["GET", "POST"])
@login_required
def admin_categories():
    categories = load_categories()

    if request.method == "POST":
        action = request.form.get("action", "")
        name = (request.form.get("name") or "").strip()
        new_name = (request.form.get("new_name") or "").strip()

        if action == "add":
            if not name:
                flash("Escribí un nombre de categoría.", "warning")
            else:
                categories.append(name)
                save_categories(categories)
                flash("Categoría agregada.", "success")

        elif action == "delete":
            if not name or name == "General":
                flash("No podés borrar 'General'.", "warning")
            else:
                categories = [c for c in categories if c != name]
                save_categories(categories)
                flash("Categoría eliminada.", "success")

        elif action == "rename":
            if not name or name == "General":
                flash("No podés renombrar 'General'.", "warning")
            elif not new_name:
                flash("Escribí el nuevo nombre.", "warning")
            else:
                categories = [new_name if c == name else c for c in categories]
                save_categories(categories)
                flash("Categoría actualizada.", "success")

        return redirect(url_for("admin_categories"))

    return render_template("admin/categories.html", categories=categories)
# 1) Cargar .env (antes de leer variables)
load_dotenv()



# 3) Configuración
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "pochi")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(app.instance_path, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static", "uploads")
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8MB
os.makedirs(app.instance_path, exist_ok=True)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# 4) Upload helpers
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# 5) Mercado Pago env
MP_ACCESS_TOKEN = os.getenv("MP_ACCESS_TOKEN")
MP_PUBLIC_KEY = os.getenv("MP_PUBLIC_KEY")
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")

if not MP_ACCESS_TOKEN:
    raise RuntimeError("Falta MP_ACCESS_TOKEN en el .env")

mp = mercadopago.SDK(MP_ACCESS_TOKEN)

# 6) Extensiones
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"

class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password_hash = db.Column(db.String(255), nullable=False)
        is_admin = db.Column(db.Boolean, default=False, nullable=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

        def set_password(self, password: str) -> None:
            self.password_hash = generate_password_hash(password)

        def check_password(self, password: str) -> bool:
            return check_password_hash(self.password_hash, password)


class Product(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(140), nullable=False)
        price = db.Column(db.Integer, nullable=False)  # ARS (demo)
        category = db.Column(db.String(80), nullable=False, default="General")
        stock = db.Column(db.Integer, nullable=False, default=10)
        image_url = db.Column(db.String(400), nullable=False)
        description = db.Column(db.Text, nullable=False, default="")
        created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Order(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
        customer_name = db.Column(db.String(120), nullable=False)
        customer_email = db.Column(db.String(120), nullable=False)
        total = db.Column(db.Integer, nullable=False, default=0)
        user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
        user = db.relationship("User", backref="orders")


class OrderItem(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)
        product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
        qty = db.Column(db.Integer, nullable=False)
        unit_price = db.Column(db.Integer, nullable=False)

        order = db.relationship("Order", backref="items")
        product = db.relationship("Product")


@login_manager.user_loader
def load_user(user_id: str):
        return db.session.get(User, int(user_id))


def admin_required():
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)


def money_ars(value: int) -> str:
        # Simple ARS formatting
        s = f"{value:,}".replace(",", ".")
        return f"$ {s}"


@app.context_processor
def inject_helpers():
        return {"money_ars": money_ars, "cart_count": cart_count}


def cart_get() -> dict[str, int]:
        return session.get("cart", {})


def cart_set(cart: dict[str, int]) -> None:
        session["cart"] = cart
        session.modified = True

def cart_count() -> int:
        cart = cart_get()
        return sum(cart.values()) if cart else 0


def cart_items():
        cart = cart_get()
        if not cart:
            return []
        ids = [int(pid) for pid in cart.keys()]
        products = Product.query.filter(Product.id.in_(ids)).all()
        by_id = {p.id: p for p in products}
        items = []
        for pid_str, qty in cart.items():
            pid = int(pid_str)
            p = by_id.get(pid)
            if not p:
                continue
            items.append({
                "product": p,
                "qty": qty,
                "subtotal": qty * p.price
            })
        items.sort(key=lambda x: x["product"].name.lower())
        return items


def cart_total() -> int:
        return sum(i["subtotal"] for i in cart_items())

def get_categories() -> list[str]:
    return [
        c[0]
        for c in db.session
            .query(Product.category)
            .distinct()
            .order_by(Product.category)
            .all()
    ]

def seed_data():
        if User.query.first() is not None:
            return

        admin = User(username="admin", email="admin@local", is_admin=True)
        admin.set_password("admin123!")

        demo = User(username="demo", email="demo@local", is_admin=False)
        demo.set_password("demo123!")

        db.session.add_all([admin, demo])

        demo_products = [
            ("Consola Portátil X", 380000, "Gaming", 12, "https://picsum.photos/seed/console/900/600",
             "Consola portátil con pantalla grande y buena batería. Ideal para viajes."),
            ("Auriculares Pro", 99000, "Audio", 30, "https://picsum.photos/seed/headphones/900/600",
             "Cancelación de ruido (demo), micrófono y estuche de carga."),
            ("Smartwatch W70 Style", 85000, "Wearables", 25, "https://picsum.photos/seed/watch/900/600",
             "Notificaciones, deportes, y esfera personalizable (demo)."),
            ("Router WiFi 6 Turbo", 120000, "Redes", 18, "https://picsum.photos/seed/router/900/600",
             "Wi‑Fi 6 para casa/oficina. Modo mesh (demo) y QoS básico."),
            ("Tablet 10.1” Study", 140000, "Tablets", 20, "https://picsum.photos/seed/tablet/900/600",
             "Para clases, YouTube y laburo liviano. Buen audio y batería (demo)."),
            ("Cámara Action Mini", 110000, "Cámaras", 10, "https://picsum.photos/seed/cam/900/600",
             "Compacta, ideal para bici y viajes. Montura incluida (demo)."),
            ("Teclado Mecánico 60%", 70000, "Periféricos", 15, "https://picsum.photos/seed/keyboard/900/600",
             "Formato 60% con switches táctiles (demo). RGB para presumir."),
            ("Mouse Ultraliviano", 45000, "Periféricos", 22, "https://picsum.photos/seed/mouse/900/600",
             "Sensor rápido, agarre cómodo. Te hace apuntar mejor (no garantiza)."),
        ]

        for name, price, cat, stock, img, desc in demo_products:
            db.session.add(Product(
                name=name,
                price=price,
                category=cat,
                stock=stock,
                image_url=img,
                description=desc
            ))

        db.session.commit()


@app.before_request
def ensure_db():
        # Create tables on first run
        db.create_all()
        seed_data()


    # ------------------ Public ------------------

@app.get("/")
def home():
        q = request.args.get("q", "").strip()
        cat = request.args.get("cat", "").strip()

        query = Product.query
        if q:
            like = f"%{q}%"
            query = query.filter((Product.name.ilike(like)) | (Product.description.ilike(like)))
        if cat:
            query = query.filter(Product.category == cat)

        products = query.order_by(Product.created_at.desc()).all()
        categories = [c[0] for c in db.session.query(Product.category).distinct().order_by(Product.category).all()]
        return render_template("home.html", products=products, q=q, cat=cat, categories=categories)


@app.get("/product/<int:product_id>")
def product_detail(product_id: int):
        product = db.session.get(Product, product_id)
        if not product:
            abort(404)
        return render_template("product_detail.html", product=product)


@app.get("/cart")
def cart_view():
        return render_template("cart.html", items=cart_items(), total=cart_total())


@app.post("/cart/add/<int:product_id>")
def cart_add(product_id: int):
        product = db.session.get(Product, product_id)
        if not product:
            abort(404)
        qty = int(request.form.get("qty", 1))
        qty = max(1, min(qty, 50))

        cart = cart_get()
        cart[str(product_id)] = min(cart.get(str(product_id), 0) + qty, 50)
        cart_set(cart)
        flash(f"Agregado: {product.name} (x{qty})", "success")
        return redirect(request.referrer or url_for("home"))


@app.post("/cart/remove/<int:product_id>")
def cart_remove(product_id: int):
        cart = cart_get()
        cart.pop(str(product_id), None)
        cart_set(cart)
        flash("Producto eliminado del carrito.", "info")
        return redirect(url_for("cart_view"))


@app.post("/cart/update")
def cart_update():
        cart = cart_get()
        for key, val in request.form.items():
            if not key.startswith("qty_"):
                continue
            pid = key.replace("qty_", "")
            try:
                qty = int(val)
            except ValueError:
                qty = 1
            qty = max(0, min(qty, 50))
            if qty == 0:
                cart.pop(pid, None)
            else:
                cart[pid] = qty
        cart_set(cart)
        flash("Carrito actualizado.", "success")
        return redirect(url_for("cart_view"))

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        flash("No file part", "danger")
        return redirect(request.url)
    file = request.files["file"]
    if file.filename == "":
        flash("No selected file", "danger")
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        flash(f"Archivo cargado: {filename}", "success")
        return redirect(url_for("product_edit", filename=filename))
    else:
        flash("Archivo no permitido", "danger")
        return redirect(request.url)

@app.route("/checkout", methods=["GET", "POST"])
def checkout():
        items = cart_items()
        if not items:
            flash("Tu carrito está vacío.", "warning")
            return redirect(url_for("home"))

        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip()
            if not name or not email:
                flash("Completá nombre y email.", "danger")
                return redirect(url_for("checkout"))

            total = cart_total()
            order = Order(
                customer_name=name,
                customer_email=email,
                total=total,
                user_id=current_user.id if current_user.is_authenticated else None
            )
            db.session.add(order)
            db.session.flush()  # to get order.id

            # Create items
            for it in items:
                p: Product = it["product"]
                qty = it["qty"]
                db.session.add(OrderItem(
                    order_id=order.id,
                    product_id=p.id,
                    qty=qty,
                    unit_price=p.price
                ))
                # simple stock decrease (demo)
                p.stock = max(0, p.stock - qty)

            db.session.commit()
            cart_set({})
            flash(f"Orden creada (#{order.id}). Esto es demo: no cobra nada 🙂", "success")
            return redirect(url_for("order_detail", order_id=order.id))

        # Prefill
        default_name = current_user.username if current_user.is_authenticated else ""
        default_email = current_user.email if current_user.is_authenticated else ""
        return render_template("checkout.html", items=items, total=cart_total(), default_name=default_name, default_email=default_email)


@app.get("/order/<int:order_id>")
def order_detail(order_id: int):
        order = db.session.get(Order, order_id)
        if not order:
            abort(404)
        return render_template("order_detail.html", order=order)
@app.get("/pago/exitoso")
def pago_exitoso():
    cart_set({})
    flash("Pago aprobado ✔️", "success")
    return redirect(url_for("home"))

@app.get("/pago/error")
def pago_error():
    flash("El pago fue rechazado.", "danger")
    return redirect(url_for("cart_view"))

@app.get("/pago/pendiente")
def pago_pendiente():
    flash("Pago pendiente.", "warning")
    return redirect(url_for("cart_view"))

# ===== CHECKOUT MERCADO PAGO =====
@app.post("/checkout/mp")
def checkout_mp():
    items = cart_items()
    if not items:
        flash("Tu carrito está vacío.", "warning")
        return redirect(url_for("home"))

    total = cart_total()

    order = Order(
        customer_name=(current_user.username if current_user.is_authenticated else "Cliente"),
        customer_email=(current_user.email if current_user.is_authenticated else "sin-email@local"),
        total=total,
        user_id=current_user.id if current_user.is_authenticated else None
    )
    db.session.add(order)
    db.session.flush()

    for it in items:
        p = it["product"]
        qty = int(it["qty"])
        db.session.add(OrderItem(
            order_id=order.id,
            product_id=p.id,
            qty=qty,
            unit_price=p.price
        ))

    db.session.commit()

    preference_items = []
    for it in items:
        p = it["product"]
        preference_items.append({
            "title": p.name,
            "quantity": int(it["qty"]),
            "unit_price": float(p.price),
            "currency_id": "ARS"
        })

    base_url = (BASE_URL or "http://127.0.0.1:5000").rstrip("/")
    success_url = f"{base_url}/pago/exitoso"
    failure_url = f"{base_url}/pago/error"
    pending_url = f"{base_url}/pago/pendiente"

    preference_data = {
        "items": preference_items,
        "external_reference": str(order.id),
        "back_urls": {
            "success": success_url,
            "failure": failure_url,
            "pending": pending_url
        },
        "back_url": {  # compat
            "success": success_url,
            "failure": failure_url,
            "pending": pending_url
        },
        "auto_return": "approved"
    }

    preference = mp.preference().create(preference_data)
    print("MP preference:", preference)

    resp = preference.get("response") or {}
    init_point = resp.get("init_point")
    sandbox_init_point = resp.get("sandbox_init_point")

    if not init_point and not sandbox_init_point:
        print("MP error:", {
            "status": preference.get("status"),
            "error": preference.get("error"),
            "message": preference.get("message"),
            "response": resp
        })
        flash("Mercado Pago no devolvió init_point. Mirá la consola para ver el error.", "danger")
        return redirect(url_for("cart_view"))

    return redirect(init_point or sandbox_init_point)



    # ------------------ Auth ------------------

@app.route("/login", methods=["GET", "POST"])
def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = User.query.filter_by(username=username).first()
            if not user or not user.check_password(password):
                flash("Credenciales inválidas.", "danger")
                return redirect(url_for("login"))
            login_user(user)
            flash("Login OK.", "success")
            return redirect(url_for("admin_dashboard") if user.is_admin else url_for("home"))
        return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
        logout_user()
        flash("Sesión cerrada.", "info")
        return redirect(url_for("home"))


@app.route("/register", methods=["GET", "POST"])
def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")

            if not username or not email or not password:
                flash("Completá usuario, email y contraseña.", "danger")
                return redirect(url_for("register"))
            if User.query.filter((User.username == username) | (User.email == email)).first():
                flash("Usuario o email ya existe.", "warning")
                return redirect(url_for("register"))

            user = User(username=username, email=email, is_admin=False)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("Cuenta creada. Ya podés iniciar sesión.", "success")
            return redirect(url_for("login"))

        return render_template("register.html")


    # ------------------ Admin ------------------

@app.get("/admin")
@login_required
def admin_dashboard():
        admin_required()
        product_count = Product.query.count()
        user_count = User.query.count()
        order_count = Order.query.count()
        latest_orders = Order.query.order_by(Order.created_at.desc()).limit(8).all()
        return render_template(
            "admin/dashboard.html",
            product_count=product_count,
            user_count=user_count,
            order_count=order_count,
            latest_orders=latest_orders
        )
@app.get("/perfil")
@login_required
def profile():
    return render_template("profile.html")


    # Products CRUD
@app.get("/admin/products")
@login_required
def admin_products():
        admin_required()
        q = request.args.get("q", "").strip()
        query = Product.query
        if q:
            like = f"%{q}%"
            query = query.filter(Product.name.ilike(like))
        products = query.order_by(Product.created_at.desc()).all()
        return render_template("admin/products.html", products=products, q=q)


@app.route("/admin/products/new", methods=["GET", "POST"])
@login_required
def admin_product_new():
    admin_required()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price = int(request.form.get("price", 0) or 0)
        category = request.form.get("category", "General").strip()
        stock = int(request.form.get("stock", 0) or 0)
        description = request.form.get("description", "").strip()

        # 👉 ACA VA EL BLOQUE DE IMAGEN 👇
        image_file = request.files.get("image")

        image_url = None

        if image_file and image_file.filename != "":
            if allowed_file(image_file.filename):
                ext = image_file.filename.rsplit(".", 1)[1].lower()
                filename = f"{uuid4().hex}.{ext}"
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                image_file.save(filepath)
                image_url = f"/static/uploads/{filename}"

        if not image_url:
            image_url = "/static/img/no-image.png"

        # 👉 ACA SE CREA EL PRODUCTO
        p = Product(
            name=name,
            price=price,
            category=category,
            stock=max(stock, 0),
            image_url=image_url,
            description=description
        )

        db.session.add(p)
        db.session.commit()

        flash("Producto creado.", "success")
        return redirect(url_for("admin_products"))

    # GET
    return render_template(
        "admin/product_form.html",
        mode="new",
        product=None,
        categories=get_categories()
    )


@app.route("/admin/products/<int:product_id>/edit", methods=["GET", "POST"])
@login_required
def admin_product_edit(product_id: int):
    admin_required()

    product = db.session.get(Product, product_id)
    if not product:
        abort(404)

    if request.method == "POST":
        product.name = request.form.get("name", "").strip()
        product.price = int(request.form.get("price", 0) or 0)
        product.category = request.form.get("category", "General").strip() or "General"
        product.stock = max(0, int(request.form.get("stock", 0) or 0))
        product.description = request.form.get("description", "").strip()

        # 🔥 IMAGEN (igual que NEW)
        image_file = request.files.get("image")

        if image_file and image_file.filename != "":
            if allowed_file(image_file.filename):
                ext = image_file.filename.rsplit(".", 1)[1].lower()
                filename = f"{uuid4().hex}.{ext}"
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                image_file.save(filepath)
                product.image_url = f"/static/uploads/{filename}"

        if not product.name or product.price <= 0:
            flash("Nombre y precio válido son obligatorios.", "danger")
            return redirect(url_for("admin_product_edit", product_id=product_id))

        db.session.commit()
        flash("Producto actualizado.", "success")
        return redirect(url_for("admin_products"))

    return render_template(
        "admin/product_form.html",
        mode="edit",
        product=product,
        categories=get_categories()
    )


@app.post("/admin/products/<int:product_id>/delete")
@login_required
def admin_product_delete(product_id: int):
        admin_required()
        product = db.session.get(Product, product_id)
        if not product:
            abort(404)
        db.session.delete(product)
        db.session.commit()
        flash("Producto eliminado.", "info")
        return redirect(url_for("admin_products"))


    # Users CRUD
@app.get("/admin/users")
@login_required
def admin_users():
        admin_required()
        q = request.args.get("q", "").strip()
        query = User.query
        if q:
            like = f"%{q}%"
            query = query.filter((User.username.ilike(like)) | (User.email.ilike(like)))
        users = query.order_by(User.created_at.desc()).all()
        return render_template("admin/users.html", users=users, q=q)


@app.route("/admin/users/new", methods=["GET", "POST"])
@login_required
def admin_user_new():
        admin_required()
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            is_admin = request.form.get("is_admin") == "on"

            if not username or not email or not password:
                flash("Completá usuario, email y contraseña.", "danger")
                return redirect(url_for("admin_user_new"))

            if User.query.filter((User.username == username) | (User.email == email)).first():
                flash("Usuario o email ya existe.", "warning")
                return redirect(url_for("admin_user_new"))

            u = User(username=username, email=email, is_admin=is_admin)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            flash("Usuario creado.", "success")
            return redirect(url_for("admin_users"))

        return render_template("admin/user_form.html", mode="new", user=None)


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
def admin_user_edit(user_id: int):
        admin_required()
        u = db.session.get(User, user_id)
        if not u:
            abort(404)
        if request.method == "POST":
            u.username = request.form.get("username", "").strip()
            u.email = request.form.get("email", "").strip()
            u.is_admin = request.form.get("is_admin") == "on"
            new_password = request.form.get("password", "")
            if new_password:
                u.set_password(new_password)

            if not u.username or not u.email:
                flash("Usuario y email son obligatorios.", "danger")
                return redirect(url_for("admin_user_edit", user_id=user_id))

            db.session.commit()
            flash("Usuario actualizado.", "success")
            return redirect(url_for("admin_users"))

        return render_template("admin/user_form.html", mode="edit", user=u)


@app.post("/admin/users/<int:user_id>/delete")
@login_required
def admin_user_delete(user_id: int):
        admin_required()
        if current_user.id == user_id:
            flash("No podés borrar tu propio usuario mientras estás logueado.", "warning")
            return redirect(url_for("admin_users"))
        u = db.session.get(User, user_id)
        if not u:
            abort(404)
        db.session.delete(u)
        db.session.commit()
        flash("Usuario eliminado.", "info")
        return redirect(url_for("admin_users"))


    # Orders list
@app.get("/admin/orders")
@login_required
def admin_orders():
        admin_required()
        orders = Order.query.order_by(Order.created_at.desc()).limit(200).all()
        return render_template("admin/orders.html", orders=orders)


@app.get("/admin/orders/<int:order_id>")
@login_required
def admin_order_detail(order_id: int):
        admin_required()
        order = db.session.get(Order, order_id)
        if not order:
            abort(404)
        return render_template("admin/order_detail.html", order=order)


    # ------------------ Errors ------------------

@app.errorhandler(403)
def forbidden(_):
        return render_template("errors/403.html"), 403


@app.errorhandler(404)
def not_found(_):
        return render_template("errors/404.html"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
