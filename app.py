# app.py
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import sqlite3
import bcrypt
import jwt
from functools import wraps

app = Flask(__name__)
DB_NAME = "orders.db"
SECRET_KEY = "çok_gizli_bir_anahtar"  # PROD: env variable ile sakla
JWT_ALGORITHM = "HS256"
TOKEN_EXP_HOURS = 8

# ---------------- DB ----------------
def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
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
        user_id INTEGER, -- optional link to users.id
        first_name TEXT,
        last_name TEXT,
        email TEXT UNIQUE,
        phone TEXT,
        status TEXT DEFAULT 'boşta', -- boşta, molada, teslimatta
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_uuid TEXT UNIQUE,
        external_id TEXT,
        customer_name TEXT,
        items TEXT,
        total_amount REAL,
        address TEXT,
        status TEXT DEFAULT 'yeni', -- yeni, teslim alındı, teslim edildi, iptal
        courier_id INTEGER,
        payload TEXT,
        created_at TEXT
    )
    """)

    conn.commit()
    conn.close()

# ---------------- Password & JWT ----------------
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

def normalize_hash_for_check(hashed):
    # sqlite may return memoryview, bytes, or str
    if isinstance(hashed, memoryview):
        return bytes(hashed)
    if isinstance(hashed, str):
        return hashed.encode("utf-8")
    return hashed

def check_password(password: str, hashed) -> bool:
    if hashed is None:
        return False
    hashed_norm = normalize_hash_for_check(hashed)
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed_norm)
    except Exception:
        return False

def generate_token(user_id: int, role: str) -> str:
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXP_HOURS)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    # PyJWT >=2 returns str, older returns bytes
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def decode_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])

def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
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
    return wrapper

# ---------------- Auth / Register / Login ----------------
@app.route("/auth/register", methods=["POST"])
def register_user():
    """
    Body: { username, password, role } where role in ["admin","courier"]
    If role == "courier" also create entry in couriers table (optional fields allowed)
    """
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    role = (data.get("role") or "courier").lower()

    if not username or not password:
        return jsonify({"message": "username ve password gerekli"}), 400
    if role not in ("admin", "courier"):
        return jsonify({"message": "role yalnızca 'admin' veya 'courier' olabilir"}), 400

    hashed = hash_password(password)
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hashed, role, datetime.utcnow().isoformat())
        )
        user_id = cur.lastrowid
        # if courier role, create couriers row (email/phone optional)
        if role == "courier":
            first_name = data.get("first_name") or ""
            last_name = data.get("last_name") or ""
            email = data.get("email")
            phone = data.get("phone")
            cur.execute(
                "INSERT INTO couriers (user_id, first_name, last_name, email, phone, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, first_name, last_name, email, phone, datetime.utcnow().isoformat())
            )
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        return jsonify({"message": "Kullanıcı adı veya e-posta zaten var", "error": str(e)}), 400
    conn.close()
    return jsonify({"message": f"{role} oluşturuldu", "username": username}), 201

@app.route("/auth/login", methods=["POST"])
def login_user():
    """
    Body: { username, password }
    Returns: { token }
    """
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"message": "username ve password gerekli"}), 400

    conn = get_db_connection()
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

# ---------------- User (admin) management ----------------
@app.route("/users", methods=["GET"])
@token_required
def list_users():
    # admin-only
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    role_filter = request.args.get("role")  # optional filter
    conn = get_db_connection()
    cur = conn.cursor()
    if role_filter:
        cur.execute("SELECT id, username, role, created_at FROM users WHERE role = ?", (role_filter,))
    else:
        cur.execute("SELECT id, username, role, created_at FROM users")
    rows = cur.fetchall()
    conn.close()
    users = [dict(r) for r in rows]
    return jsonify(users)

@app.route("/users/<int:user_id>", methods=["PATCH"])
@token_required
def update_user(user_id):
    # admin-only
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    data = request.get_json() or {}
    fields = []
    values = []
    if "role" in data:
        if data["role"] not in ("admin", "courier"):
            return jsonify({"message": "role yalnızca admin veya courier olabilir"}), 400
        fields.append("role = ?"); values.append(data["role"])
    if "password" in data:
        fields.append("password_hash = ?"); values.append(hash_password(data["password"]))
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400
    values.append(user_id)
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", values)
    conn.commit(); conn.close()
    return jsonify({"message": "Kullanıcı güncellendi"})

@app.route("/users/<int:user_id>", methods=["DELETE"])
@token_required
def delete_user(user_id):
    # admin-only
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    conn = get_db_connection(); cur = conn.cursor()
    # also delete linked courier row if exists
    cur.execute("DELETE FROM couriers WHERE user_id = ?", (user_id,))
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit(); conn.close()
    return jsonify({"message": "Kullanıcı ve bağlı kurye (varsa) silindi"})

# ---------------- Couriers CRUD & listing ----------------
@app.route("/couriers", methods=["GET"])
@token_required
def list_couriers():
    # admin-only
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT id, user_id, first_name, last_name, email, phone, status, created_at FROM couriers")
    rows = cur.fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/couriers/<int:courier_id>", methods=["PATCH"])
@token_required
def update_courier(courier_id):
    # admin-only
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    data = request.get_json() or {}
    allowed = ("first_name", "last_name", "email", "phone", "status")
    fields = []; values = []
    for k in allowed:
        if k in data:
            fields.append(f"{k} = ?"); values.append(data[k])
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400
    values.append(courier_id)
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute(f"UPDATE couriers SET {', '.join(fields)} WHERE id = ?", values)
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close(); return jsonify({"message": "Integrity error", "error": str(e)}), 400
    conn.close()
    return jsonify({"message": "Kurye güncellendi"})

@app.route("/couriers/<int:courier_id>", methods=["DELETE"])
@token_required
def remove_courier(courier_id):
    # admin-only
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("DELETE FROM couriers WHERE id = ?", (courier_id,))
    conn.commit(); conn.close()
    return jsonify({"message": f"Kurye {courier_id} silindi"})

# ---------------- Courier actions ----------------
@app.route("/couriers/<int:courier_id>/status", methods=["PATCH"])
@token_required
def courier_update_status(courier_id):
    # courier can update their own status OR admin can update any
    if request.user_role != "admin" and request.user_id is not None:
        # need to ensure courier_id corresponds to user's courier row when not admin
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        row = cur.fetchone(); conn.close()
        if not row or row["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403
    data = request.get_json() or {}
    status = data.get("status")
    if status not in ("boşta", "molada", "teslimatta"):
        return jsonify({"message": "Geçersiz status"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("UPDATE couriers SET status = ? WHERE id = ?", (status, courier_id))
    conn.commit(); conn.close()
    return jsonify({"message": "Kurye durumu güncellendi", "status": status})

@app.route("/couriers/<int:courier_id>/orders", methods=["GET"])
@token_required
def courier_assigned_orders(courier_id):
    # courier can view own orders OR admin
    if request.user_role != "admin":
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        row = cur.fetchone(); conn.close()
        if not row or row["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE courier_id = ? AND status IN ('yeni','teslim alındı')", (courier_id,))
    rows = cur.fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/couriers/<int:courier_id>/orders/<int:order_id>/pickup", methods=["POST"])
@token_required
def courier_pickup(courier_id, order_id):
    # courier or admin
    if request.user_role != "admin":
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        row = cur.fetchone(); conn.close()
        if not row or row["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE id = ? AND courier_id = ?", (order_id, courier_id))
    order = cur.fetchone()
    if not order:
        conn.close()
        return jsonify({"message": "Sipariş bulunamadı veya bu kurye için atanmadı"}), 404
    if order["status"] != "yeni":
        conn.close(); return jsonify({"message": "Sipariş zaten teslim alınmış veya teslim edilmiş"}), 400
    cur.execute("UPDATE orders SET status = 'teslim alındı' WHERE id = ?", (order_id,))
    cur.execute("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", (courier_id,))
    conn.commit(); conn.close()
    return jsonify({"message": "Sipariş teslim alındı"})

@app.route("/couriers/<int:courier_id>/orders/<int:order_id>/deliver", methods=["POST"])
@token_required
def courier_deliver(courier_id, order_id):
    # courier or admin
    if request.user_role != "admin":
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        row = cur.fetchone(); conn.close()
        if not row or row["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE id = ? AND courier_id = ?", (order_id, courier_id))
    order = cur.fetchone()
    if not order:
        conn.close(); return jsonify({"message": "Sipariş bulunamadı veya bu kurye için atanmadı"}), 404
    if order["status"] != "teslim alındı":
        conn.close(); return jsonify({"message": "Sipariş teslim alınmamış"}), 400
    cur.execute("UPDATE orders SET status = 'teslim edildi' WHERE id = ?", (order_id,))
    cur.execute("UPDATE couriers SET status = 'boşta' WHERE id = ?", (courier_id,))
    conn.commit(); conn.close()
    return jsonify({"message": "Sipariş teslim edildi"})

# ---------------- Orders (webhook + admin) ----------------
@app.route("/webhooks/yemeksepeti", methods=["POST"])
def webhook_yemeksepeti():
    # Public endpoint intended for Yemeksepeti webhook (no auth)
    data = request.get_json() or {}
    external_id = data.get("external_id") or data.get("order_id") or data.get("id")
    customer_name = data.get("customer_name") or data.get("customer")
    items = data.get("items")
    total = data.get("total") or data.get("total_amount") or 0
    address = data.get("address") or data.get("customer_address")
    payload = str(data)
    created = datetime.utcnow().isoformat()

    conn = get_db_connection(); cur = conn.cursor()
    # allow duplicate external_id check
    cur.execute("INSERT INTO orders (order_uuid, external_id, customer_name, items, total_amount, address, payload, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (f"o-{int(datetime.utcnow().timestamp()*1000)}", external_id, customer_name, str(items), total, address, payload, created))
    conn.commit(); conn.close()
    return jsonify({"message": "Order received"}), 201

@app.route("/orders", methods=["GET"])
@token_required
def admin_list_orders():
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT * FROM orders ORDER BY created_at DESC")
    rows = cur.fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/orders/<order_uuid>", methods=["PATCH"])
@token_required
def admin_update_order(order_uuid):
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    data = request.get_json() or {}
    fields = []; values = []
    allowed = ("status", "courier_id")
    for k in allowed:
        if k in data:
            fields.append(f"{k} = ?"); values.append(data[k])
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400
    values.append(order_uuid)
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(f"UPDATE orders SET {', '.join(fields)} WHERE order_uuid = ?", values)
    conn.commit(); conn.close()
    return jsonify({"message": "Order güncellendi"})

# ---------------- Admin Reports ----------------
@app.route("/admin/reports/orders", methods=["GET"])
@token_required
def order_report():
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    if not start_date or not end_date:
        return jsonify({"message": "start_date ve end_date gerekli (YYYY-MM-DD)"}), 400
    try:
        start_dt = datetime.strptime(start_date, "%Y-%m-%d")
        end_dt = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
    except Exception:
        return jsonify({"message": "Tarih formatı YYYY-MM-DD olmalı"}), 400

    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT status, COUNT(*) as cnt
        FROM orders
        WHERE created_at >= ? AND created_at < ?
        GROUP BY status
    """, (start_dt.isoformat(), end_dt.isoformat()))
    status_counts = {row[0]: row[1] for row in cur.fetchall()}

    cur.execute("""
        SELECT courier_id, COUNT(*) as delivered_count
        FROM orders
        WHERE created_at >= ? AND created_at < ? AND status = 'teslim edildi'
        GROUP BY courier_id
    """, (start_dt.isoformat(), end_dt.isoformat()))
    cp = []
    for courier_id, cnt in cur.fetchall():
        if courier_id is None:
            name = "Unassigned"
        else:
            r = conn.execute("SELECT first_name, last_name FROM couriers WHERE id = ?", (courier_id,)).fetchone()
            name = f"{r['first_name']} {r['last_name']}" if r else "Bilinmeyen Kurye"
        cp.append({"courier_id": courier_id, "courier_name": name, "delivered_orders": cnt})
    conn.close()

    return jsonify({"order_status_counts": status_counts, "courier_performance": cp, "period": {"start": start_date, "end": end_date}})

# ---------------- Health ----------------
@app.route("/")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
