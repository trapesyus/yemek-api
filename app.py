# app.py
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import sqlite3
import bcrypt
import jwt
from functools import wraps

app = Flask(__name__)
DB_NAME = "orders.db"
SECRET_KEY = "çok_gizli_bir_anahtar"  # PROD: environment variable ile sakla
JWT_ALGORITHM = "HS256"
TOKEN_EXP_HOURS = 8

# ---------- Helper: DB connection ----------
def get_conn():
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash BLOB,
        role TEXT,
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS couriers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        first_name TEXT,
        last_name TEXT,
        email TEXT UNIQUE,
        phone TEXT,
        status TEXT DEFAULT 'boşta',
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_uuid TEXT UNIQUE,
        external_id TEXT,
        vendor_id TEXT,
        customer_name TEXT,
        items TEXT,
        total_amount REAL,
        address TEXT,
        status TEXT DEFAULT 'yeni',
        courier_id INTEGER,
        payload TEXT,
        created_at TEXT
    )
    """)
    conn.commit()
    conn.close()

# ---------- Password & JWT ----------
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

def _normalize_hash(h):
    if isinstance(h, memoryview):
        return bytes(h)
    if isinstance(h, str):
        return h.encode("utf-8")
    return h

def check_password(password: str, hashed) -> bool:
    if not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), _normalize_hash(hashed))
    except Exception:
        return False

def generate_token(user_id: int, role: str) -> str:
    payload = {"user_id": user_id, "role": role, "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXP_HOURS)}
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    if isinstance(token, bytes):
        return token.decode("utf-8")
    return token

def decode_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])

# ---------- Auth decorators ----------
def token_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = None
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1].strip()
        if not token:
            return jsonify({"message": "Token gerekli"}), 401
        try:
            data = decode_token(token)
            request.user_id = data.get("user_id")
            request.user_role = data.get("role")
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token süresi doldu"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token geçersiz"}), 401
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    @token_required
    def wrapped(*args, **kwargs):
        if getattr(request, "user_role", None) != "admin":
            return jsonify({"message": "Admin yetkisi gerekli"}), 403
        return f(*args, **kwargs)
    return wrapped

# ---------- Auth: register/login ----------
@app.route("/auth/register", methods=["POST"])
def auth_register():
    """
    Kurye kendi kendine kaydolabilir (role=courier).
    role=admin ise:
      - Eğer henüz admin yoksa bootstrap (ilk admin) oluşturulur.
      - Eğer admin mevcutsa, sadece admin token ile yeni admin oluşturulabilir.
    Body: { username, password, role, first_name, last_name, email, phone }
    """
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    role = (data.get("role") or "courier").lower()

    if not username or not password:
        return jsonify({"message": "username ve password gerekli"}), 400
    if role not in ("admin", "courier"):
        return jsonify({"message": "role sadece 'admin' veya 'courier' olabilir"}), 400

    conn = get_conn()
    cur = conn.cursor()
    # Eğer role admin isteniyorsa güvenlik: ilk admin yoksa izin ver, yoksa admin token şartı koy
    if role == "admin":
        cur.execute("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1")
        has_admin = cur.fetchone() is not None
        if has_admin:
            # require admin token
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                conn.close()
                return jsonify({"message": "Mevcut admin var. Yeni admin oluşturmak için admin token gerekli."}), 403
            token = auth.split(" ", 1)[1].strip()
            try:
                data_token = decode_token(token)
                if data_token.get("role") != "admin":
                    conn.close()
                    return jsonify({"message": "Yalnızca admin yeni admin oluşturabilir."}), 403
            except Exception:
                conn.close()
                return jsonify({"message": "Token geçersiz"}), 401

    hashed = hash_password(password)
    try:
        cur.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                    (username, hashed, role, datetime.utcnow().isoformat()))
        user_id = cur.lastrowid
        # if courier, create courier record as well
        if role == "courier":
            first_name = data.get("first_name") or ""
            last_name = data.get("last_name") or ""
            email = data.get("email")
            phone = data.get("phone")
            cur.execute("""INSERT INTO couriers (user_id, first_name, last_name, email, phone, created_at)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (user_id, first_name, last_name, email, phone, datetime.utcnow().isoformat()))
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        return jsonify({"message": "Kullanıcı adı veya e-posta zaten var", "error": str(e)}), 400
    conn.close()
    return jsonify({"message": f"{role} oluşturuldu", "username": username}), 201

@app.route("/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"message": "username ve password gerekli"}), 400
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()
    if not user:
        return jsonify({"message": "Kullanıcı bulunamadı"}), 404
    if not check_password(password, user["password_hash"]):
        return jsonify({"message": "Parola yanlış"}), 401
    token = generate_token(user["id"], user["role"])
    return jsonify({"token": token, "role": user["role"]})

# ---------- Admin creates courier (explicit) ----------
@app.route("/admin/couriers", methods=["POST"])
@admin_required
def admin_create_courier():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"message": "username ve password gerekli"}), 400
    email = data.get("email")

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        conn.close()
        return jsonify({"message": "Kullanıcı adı kullanılıyor"}), 400
    if email:
        cur.execute("SELECT 1 FROM couriers WHERE email = ?", (email,))
        if cur.fetchone():
            conn.close()
            return jsonify({"message": "E-posta zaten kullanılıyor"}), 400
    hashed = hash_password(password)
    try:
        cur.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'courier', ?)",
                    (username, hashed, datetime.utcnow().isoformat()))
        user_id = cur.lastrowid
        first_name = data.get("first_name") or ""
        last_name = data.get("last_name") or ""
        phone = data.get("phone") or ""
        cur.execute("""INSERT INTO couriers (user_id, first_name, last_name, email, phone, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (user_id, first_name, last_name, email, phone, datetime.utcnow().isoformat()))
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        return jsonify({"message": "IntegrityError", "error": str(e)}), 400
    conn.close()
    return jsonify({"message": "Kurye oluşturuldu", "username": username}), 201

# ---------- Current user info ----------
@app.route("/me", methods=["GET"])
@token_required
def me():
    uid = request.user_id
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id, username, role, created_at FROM users WHERE id = ?", (uid,))
    u = cur.fetchone()
    user = dict(u) if u else None
    # if courier, attach courier details
    if user and user["role"] == "courier":
        cur.execute("SELECT id, first_name, last_name, email, phone, status FROM couriers WHERE user_id = ?", (uid,))
        c = cur.fetchone()
        user["courier"] = dict(c) if c else None
    conn.close()
    return jsonify(user)

# ---------- Users management (admin) ----------
@app.route("/users", methods=["GET"])
@admin_required
def list_users():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id, username, role, created_at FROM users")
    rows = cur.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/users/<int:user_id>", methods=["PATCH"])
@admin_required
def update_user(user_id):
    data = request.get_json() or {}
    fields = []
    values = []
    if "role" in data:
        if data["role"] not in ("admin", "courier"):
            return jsonify({"message": "role admin veya courier olmalı"}), 400
        fields.append("role = ?"); values.append(data["role"])
    if "password" in data:
        fields.append("password_hash = ?"); values.append(hash_password(data["password"]))
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400
    values.append(user_id)
    conn = get_conn(); cur = conn.cursor()
    cur.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", values)
    conn.commit(); conn.close()
    return jsonify({"message": "Kullanıcı güncellendi"})

@app.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    conn = get_conn(); cur = conn.cursor()
    # delete courier row if exists
    cur.execute("DELETE FROM couriers WHERE user_id = ?", (user_id,))
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit(); conn.close()
    return jsonify({"message": "Kullanıcı silindi (ve bağlı kurye kaydı kaldırıldı)"})

# ---------- Couriers listing & CRUD ----------
@app.route("/couriers", methods=["GET"])
@admin_required
def admin_list_couriers():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id, user_id, first_name, last_name, email, phone, status, created_at FROM couriers")
    rows = cur.fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/couriers/<int:courier_id>", methods=["PATCH"])
@admin_required
def admin_update_courier(courier_id):
    data = request.get_json() or {}
    allowed = ("first_name", "last_name", "email", "phone", "status")
    fields = []; values = []
    for k in allowed:
        if k in data:
            fields.append(f"{k} = ?"); values.append(data[k])
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400
    values.append(courier_id)
    conn = get_conn(); cur = conn.cursor()
    try:
        cur.execute(f"UPDATE couriers SET {', '.join(fields)} WHERE id = ?", values)
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close(); return jsonify({"message": "Integrity error", "error": str(e)}), 400
    conn.close()
    return jsonify({"message": "Kurye güncellendi"})

@app.route("/couriers/<int:courier_id>", methods=["DELETE"])
@admin_required
def admin_delete_courier(courier_id):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM couriers WHERE id = ?", (courier_id,))
    conn.commit(); conn.close()
    return jsonify({"message": f"Kurye {courier_id} silindi"})

# ---------- Courier actions (self) ----------
@app.route("/couriers/<int:courier_id>/status", methods=["PATCH"])
@token_required
def courier_update_status(courier_id):
    # courier can update own status; admin can update any
    if request.user_role != "admin":
        # ensure courier.user_id == request.user_id
        conn = get_conn(); cur = conn.cursor()
        cur.execute("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        row = cur.fetchone(); conn.close()
        if not row or row["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403
    data = request.get_json() or {}
    status = data.get("status")
    if status not in ("boşta", "molada", "teslimatta"):
        return jsonify({"message": "Geçersiz status"}), 400
    conn = get_conn(); cur = conn.cursor()
    cur.execute("UPDATE couriers SET status = ? WHERE id = ?", (status, courier_id))
    conn.commit(); conn.close()
    return jsonify({"message": "Kurye durumu güncellendi", "status": status})

@app.route("/couriers/<int:courier_id>/orders", methods=["GET"])
@token_required
def courier_get_orders(courier_id):
    # courier can view own assigned orders or admin
    if request.user_role != "admin":
        conn = get_conn(); cur = conn.cursor()
        cur.execute("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        row = cur.fetchone(); conn.close()
        if not row or row["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE courier_id = ? AND status IN ('yeni','teslim alındı')", (courier_id,))
    rows = cur.fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/couriers/<int:courier_id>/orders/<int:order_id>/pickup", methods=["POST"])
@token_required
def courier_pickup_order(courier_id, order_id):
    if request.user_role != "admin":
        conn = get_conn(); cur = conn.cursor()
        cur.execute("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        row = cur.fetchone(); conn.close()
        if not row or row["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE id = ? AND courier_id = ?", (order_id, courier_id))
    order = cur.fetchone()
    if not order:
        conn.close(); return jsonify({"message": "Sipariş bulunamadı veya atanmadı"}), 404
    if order["status"] != "yeni":
        conn.close(); return jsonify({"message": "Sipariş zaten alınmış veya teslim edilmiş"}), 400
    cur.execute("UPDATE orders SET status = 'teslim alındı' WHERE id = ?", (order_id,))
    cur.execute("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", (courier_id,))
    conn.commit(); conn.close()
    return jsonify({"message": "Sipariş teslim alındı"})

@app.route("/couriers/<int:courier_id>/orders/<int:order_id>/deliver", methods=["POST"])
@token_required
def courier_deliver_order(courier_id, order_id):
    if request.user_role != "admin":
        conn = get_conn(); cur = conn.cursor()
        cur.execute("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        row = cur.fetchone(); conn.close()
        if not row or row["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE id = ? AND courier_id = ?", (order_id, courier_id))
    order = cur.fetchone()
    if not order:
        conn.close(); return jsonify({"message": "Sipariş bulunamadı veya atanmadı"}), 404
    if order["status"] != "teslim alındı":
        conn.close(); return jsonify({"message": "Sipariş teslim alınmamış"}), 400
    cur.execute("UPDATE orders SET status = 'teslim edildi' WHERE id = ?", (order_id,))
    cur.execute("UPDATE couriers SET status = 'boşta' WHERE id = ?", (courier_id,))
    conn.commit(); conn.close()
    return jsonify({"message": "Sipariş teslim edildi"})

# ---------- Orders (webhook + admin) ----------
@app.route("/webhooks/yemeksepeti", methods=["POST"])
def webhook_yemeksepeti():
    """
    Public webhook for Yemeksepeti or tests.
    Accepts many shapes; stores payload and minimal fields.
    """
    data = request.get_json() or {}
    external_id = data.get("external_id") or data.get("order_id") or data.get("id")
    vendor_id = data.get("vendor_id")
    customer_name = data.get("customer_name") or data.get("customer")
    items = data.get("items")
    total = data.get("total") or data.get("total_amount") or 0
    address = data.get("address") or data.get("customer_address")
    payload = str(data)
    created = datetime.utcnow().isoformat()
    order_uuid = f"o-{int(datetime.utcnow().timestamp()*1000)}"

    conn = get_conn(); cur = conn.cursor()
    try:
        cur.execute("""INSERT INTO orders
                       (order_uuid, external_id, vendor_id, customer_name, items, total_amount, address, payload, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (order_uuid, external_id, vendor_id, customer_name, str(items), total, address, payload, created))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"message": "Sipariş kaydedilirken hata (duplicate veya integrity)"}), 400
    conn.close()
    return jsonify({"message": "Sipariş alındı", "order_uuid": order_uuid}), 201

@app.route("/orders", methods=["GET"])
@admin_required
def admin_list_orders():
    status_filter = request.args.get("status")
    conn = get_conn(); cur = conn.cursor()
    if status_filter:
        cur.execute("SELECT * FROM orders WHERE status = ? ORDER BY created_at DESC", (status_filter,))
    else:
        cur.execute("SELECT * FROM orders ORDER BY created_at DESC")
    rows = cur.fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/orders/<int:order_id>", methods=["PATCH"])
@admin_required
def admin_patch_order(order_id):
    data = request.get_json() or {}
    allowed = ("status", "courier_id", "customer_name", "items", "total_amount", "address")
    fields = []; values = []
    for k in allowed:
        if k in data:
            fields.append(f"{k} = ?"); values.append(data[k])
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400
    values.append(order_id)
    conn = get_conn(); cur = conn.cursor()
    cur.execute(f"UPDATE orders SET {', '.join(fields)} WHERE id = ?", values)
    conn.commit(); conn.close()
    return jsonify({"message": "Sipariş güncellendi"})

@app.route("/orders/<int:order_id>", methods=["DELETE"])
@admin_required
def admin_delete_order(order_id):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit(); conn.close()
    return jsonify({"message": "Sipariş silindi"})

# ---------- Admin reports ----------
@app.route("/admin/reports/orders", methods=["GET"])
@admin_required
def admin_reports_orders():
    start = request.args.get("start_date")
    end = request.args.get("end_date")
    if not start or not end:
        return jsonify({"message": "start_date ve end_date parametreleri gerekli (YYYY-MM-DD)"}), 400
    try:
        start_dt = datetime.strptime(start, "%Y-%m-%d")
        end_dt = datetime.strptime(end, "%Y-%m-%d") + timedelta(days=1)
    except Exception:
        return jsonify({"message": "Tarih formatı YYYY-MM-DD olmalı"}), 400

    conn = get_conn(); cur = conn.cursor()
    cur.execute("""SELECT status, COUNT(*) as cnt FROM orders
                   WHERE created_at >= ? AND created_at < ? GROUP BY status""",
                (start_dt.isoformat(), end_dt.isoformat()))
    status_counts = {row[0]: row[1] for row in cur.fetchall()}

    cur.execute("""SELECT courier_id, COUNT(*) as delivered_count FROM orders
                   WHERE created_at >= ? AND created_at < ? AND status = 'teslim edildi' GROUP BY courier_id""",
                (start_dt.isoformat(), end_dt.isoformat()))
    perf = []
    for row in cur.fetchall():
        courier_id = row[0]
        cnt = row[1]
        if not courier_id:
            name = "Unassigned"
        else:
            # fetch courier name
            r = conn.execute("SELECT first_name, last_name FROM couriers WHERE id = ?", (courier_id,)).fetchone()
            name = f"{r['first_name']} {r['last_name']}" if r else "Bilinmeyen Kurye"
        perf.append({"courier_id": courier_id, "courier_name": name, "delivered_orders": cnt})
    conn.close()
    return jsonify({"status_counts": status_counts, "courier_performance": perf, "period": {"start": start, "end": end}})

# ---------- Health ----------
@app.route("/")
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
