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
    conn = sqlite3.connect(DB_NAME, timeout=10)
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

# ---------------- Password & JWT ----------------
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

def normalize_hash_for_check(hashed):
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

# ---------------- Admin-only Courier creation ----------------
@app.route("/admin/couriers", methods=["POST"])
@token_required
def admin_create_courier():
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403

    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "username ve password gerekli"}), 400

    email = data.get("email")

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        conn.close()
        return jsonify({"message": "Kullanıcı adı zaten kullanılıyor"}), 400

    if email:
        cur.execute("SELECT 1 FROM couriers WHERE email = ?", (email,))
        if cur.fetchone():
            conn.close()
            return jsonify({"message": "Email zaten kullanılıyor"}), 400

    hashed = hash_password(password)

    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hashed, "courier", datetime.utcnow().isoformat())
        )
        user_id = cur.lastrowid
        first_name = data.get("first_name") or ""
        last_name = data.get("last_name") or ""
        phone = data.get("phone") or ""

        cur.execute(
            "INSERT INTO couriers (user_id, first_name, last_name, email, phone, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, first_name, last_name, email, phone, datetime.utcnow().isoformat())
        )
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        return jsonify({"message": "IntegrityError", "error": str(e)}), 400

    conn.close()
    return jsonify({"message": "Kurye başarıyla oluşturuldu", "username": username}), 201

# ---------------- User (admin) management ----------------
@app.route("/users", methods=["GET"])
@token_required
def list_users():
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    role_filter = request.args.get("role")
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
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    data = request.get_json() or {}
    fields = []
    values = []
    if "role" in data:
        if data["role"] not in ("admin", "courier"):
            return jsonify({"message": "role yalnızca admin veya courier olabilir"}), 400
        fields.append("role = ?")
        values.append(data["role"])
    if "password" in data:
        fields.append("password_hash = ?")
        values.append(hash_password(data["password"]))
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400
    values.append(user_id)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", values)
    conn.commit()
    conn.close()
    return jsonify({"message": "Kullanıcı güncellendi"})

@app.route("/users/<int:user_id>", methods=["DELETE"])
@token_required
def delete_user(user_id):
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM couriers WHERE user_id = ?", (user_id,))
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Kullanıcı ve bağlı kurye (varsa) silindi"})

# ---------------- Couriers CRUD & listing ----------------
@app.route("/couriers", methods=["GET"])
@token_required
def list_couriers():
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, user_id, first_name, last_name, email, phone, status, created_at FROM couriers")
    rows = cur.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/couriers/<int:courier_id>", methods=["PATCH"])
@token_required
def update_courier(courier_id):
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    data = request.get_json() or {}
    allowed = ("first_name", "last_name", "email", "phone", "status")
    fields = []
    values = []
    for k in allowed:
        if k in data:
            fields.append(f"{k} = ?")
            values.append(data[k])
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400
    values.append(courier_id)
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(f"UPDATE couriers SET {', '.join(fields)} WHERE id = ?", values)
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        return jsonify({"message": "Integrity error", "error": str(e)}), 400
    conn.close()
    return jsonify({"message": "Kurye güncellendi"})

@app.route("/couriers/<int:courier_id>", methods=["DELETE"])
@token_required
def remove_courier(courier_id):
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM couriers WHERE id = ?", (courier_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Kurye {courier_id} silindi"})

# ---------------- Courier actions ----------------
@app.route("/couriers/<int:courier_id>/status", methods=["PATCH"])
@token_required
def courier_update_status(courier_id):
    if request.user_role != "admin" and request.user_id is not None:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        row = cur.fetchone()
        conn.close()
        if not row or row["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403
    data = request.get_json() or {}
    status = data.get("status")
    if status not in ("boşta", "molada", "teslimatta"):
        return jsonify({"message": "Geçersiz status"}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE couriers SET status = ? WHERE id = ?", (status, courier_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Kurye durumu güncellendi", "status": status})

@app.route("/couriers/<int:courier_id>/orders", methods=["GET"])
@token_required
def courier_assigned_orders(courier_id):
    if request.user_role != "admin":
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        row = cur.fetchone()
        conn.close()
        if not row or row["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE courier_id = ? AND status IN ('yeni','teslim alındı')", (courier_id,))
    rows = cur.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/couriers/<int:courier_id>/orders/<int:order_id>/pickup", methods=["POST"])
@token_required
def courier_pickup(courier_id, order_id):
    if request.user_role != "admin":
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        row = cur.fetchone()
        conn.close()
        if not row or row["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE id = ? AND courier_id = ?", (order_id, courier_id))
    order = cur.fetchone()
    if not order:
        conn.close()
        return jsonify({"message": "Sipariş bulunamadı veya bu kurye için atanmadı"}), 404
    if order["status"] != "yeni":
        conn.close()
        return jsonify({"message": "Sipariş zaten teslim alınmış veya teslim edilmiş"}), 400
    cur.execute("UPDATE orders SET status = 'teslim alındı' WHERE id = ?", (order_id,))
    cur.execute("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", (courier_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Sipariş teslim alındı"})

@app.route("/couriers/<int:courier_id>/orders/<int:order_id>/deliver", methods=["POST"])
@token_required
def courier_deliver(courier_id, order_id):
    if request.user_role != "admin":
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        row = cur.fetchone()
        conn.close()
        if not row or row["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE id = ? AND courier_id = ?", (order_id, courier_id))
    order = cur.fetchone()
    if not order:
        conn.close()
        return jsonify({"message": "Sipariş bulunamadı veya bu kurye için atanmadı"}), 404
    if order["status"] != "teslim alındı":
        conn.close()
        return jsonify({"message": "Sipariş teslim alınmamış"}), 400
    cur.execute("UPDATE orders SET status = 'teslim edildi' WHERE id = ?", (order_id,))
    cur.execute("UPDATE couriers SET status = 'boşta' WHERE id = ?", (courier_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Sipariş teslim edildi"})

# ---------------- Orders (webhook + admin) ----------------
@app.route("/webhooks/yemeksepeti", methods=["POST"])
def webhook_yemeksepeti():
    data = request.get_json() or {}
    external_id = data.get("external_id") or data.get("order_id") or data.get("id")
    customer_name = data.get("customer_name") or data.get("customer")
    items = data.get("items")
    total = data.get("total") or data.get("total_amount") or 0
    address = data.get("address") or data.get("customer_address")
    payload = str(data)
    created = datetime.utcnow().isoformat()

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO orders (order_uuid, external_id, customer_name, items, total_amount, address, payload, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (f"o-{int(datetime.utcnow().timestamp()*1000)}", external_id, customer_name, str(items), total, address, payload, created)
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "Sipariş alındı"}), 201

@app.route("/orders", methods=["GET"])
@token_required
def list_orders():
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    status_filter = request.args.get("status")
    conn = get_db_connection()
    cur = conn.cursor()
    if status_filter:
        cur.execute("SELECT * FROM orders WHERE status = ?", (status_filter,))
    else:
        cur.execute("SELECT * FROM orders")
    rows = cur.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/orders/<int:order_id>", methods=["PATCH"])
@token_required
def update_order(order_id):
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    data = request.get_json() or {}
    allowed = ("status", "courier_id", "customer_name", "items", "total_amount", "address")
    fields = []
    values = []
    for k in allowed:
        if k in data:
            fields.append(f"{k} = ?")
            values.append(data[k])
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400
    values.append(order_id)
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(f"UPDATE orders SET {', '.join(fields)} WHERE id = ?", values)
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        return jsonify({"message": "Integrity error", "error": str(e)}), 400
    conn.close()
    return jsonify({"message": "Sipariş güncellendi"})

@app.route("/orders/<int:order_id>", methods=["DELETE"])
@token_required
def delete_order(order_id):
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Sipariş silindi"})

# ---------------- Ana Sayfa ----------------
@app.route("/")
def index():
    return jsonify({"message": "Order API çalışıyor"})


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
