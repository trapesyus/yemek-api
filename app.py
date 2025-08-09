from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import sqlite3
import bcrypt
import jwt
from functools import wraps

app = Flask(__name__)
DB_NAME = "orders.db"
SECRET_KEY = "çok_gizli_bir_anahtar"  # Prod’da env variable ile sakla!

# --------- DB Bağlantı ---------
def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id TEXT,
            customer_name TEXT,
            items TEXT,
            status TEXT,
            courier_id INTEGER,
            created_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS couriers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT,
            last_name TEXT,
            email TEXT UNIQUE,
            phone TEXT,
            status TEXT DEFAULT 'boşta',
            created_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash BLOB,
            role TEXT,
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()

# --------- Auth Fonksiyonları ---------
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def generate_token(user_id, role):
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=8)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
        if not token:
            return jsonify({"message": "Token gerekli"}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_id = data["user_id"]
            request.user_role = data["role"]
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token süresi doldu"}), 401
        except Exception:
            return jsonify({"message": "Token geçersiz"}), 401
        return f(*args, **kwargs)
    return decorated

# --------- Auth Routes ---------
@app.route("/auth/register", methods=["POST"])
def register_user():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    # Rol opsiyonel, default courier
    role = data.get("role", "courier")
    if not username or not password:
        return jsonify({"message": "Kullanıcı adı ve parola gerekli"}), 400

    # Sadece admin rolü için kontrol yapabiliriz, ama burada herkes courier olabiliyor
    if role != "courier":
        # Kendi kayıtlarında sadece courier rolü verilsin, admin kayıtları manuel
        return jsonify({"message": "Sadece kurye kendini kaydedebilir"}), 403

    hashed = hash_password(password)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hashed, role, datetime.utcnow().isoformat())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"message": "Kullanıcı adı zaten var"}), 400
    conn.close()
    return jsonify({"message": "Kurye kaydı başarılı"}), 201

@app.route("/auth/login", methods=["POST"])
def login_user():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"message": "Kullanıcı adı ve parola gerekli"}), 400
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not user:
        return jsonify({"message": "Kullanıcı bulunamadı"}), 404
    if not check_password(password, user["password_hash"]):
        return jsonify({"message": "Parola yanlış"}), 401
    token = generate_token(user["id"], user["role"])
    return jsonify({"token": token})

# --------- Kurye Durum Güncelleme ---------
@app.route("/couriers/<int:courier_id>/status", methods=["PATCH"])
@token_required
def update_courier_status(courier_id):
    # Sadece kendi durumu güncellenebilir
    if request.user_role != "admin" and request.user_id != courier_id:
        return jsonify({"message": "Yetkisiz"}), 403

    data = request.get_json()
    new_status = data.get("status")
    if new_status not in ["boşta", "molada", "teslimatta"]:
        return jsonify({"error": "Geçersiz durum"}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE couriers SET status=? WHERE id=?", (new_status, courier_id))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Kurye durumu {new_status} olarak güncellendi"})

# --------- Kurye Siparişleri ---------
@app.route("/couriers/<int:courier_id>/orders", methods=["GET"])
@token_required
def get_courier_orders(courier_id):
    if request.user_role != "admin" and request.user_id != courier_id:
        return jsonify({"message": "Yetkisiz"}), 403

    conn = get_db_connection()
    orders = conn.execute(
        "SELECT * FROM orders WHERE courier_id=? AND status IN ('yeni', 'teslim alındı')", (courier_id,)
    ).fetchall()
    conn.close()
    result = []
    for o in orders:
        result.append({
            "id": o["id"],
            "order_id": o["order_id"],
            "customer_name": o["customer_name"],
            "items": o["items"],
            "status": o["status"],
            "created_at": o["created_at"]
        })
    return jsonify(result)

# --------- Kurye Sipariş Teslim Alma ---------
@app.route("/couriers/<int:courier_id>/orders/<int:order_id>/pickup", methods=["POST"])
@token_required
def courier_pickup_order(courier_id, order_id):
    if request.user_role != "admin" and request.user_id != courier_id:
        return jsonify({"message": "Yetkisiz"}), 403

    conn = get_db_connection()
    cursor = conn.cursor()
    order = cursor.execute("SELECT * FROM orders WHERE id=? AND courier_id=?", (order_id, courier_id)).fetchone()
    if not order:
        conn.close()
        return jsonify({"error": "Sipariş bulunamadı veya size ait değil"}), 404
    if order["status"] != "yeni":
        conn.close()
        return jsonify({"error": "Sipariş zaten teslim alınmış veya teslim edilmiş"}), 400

    cursor.execute("UPDATE orders SET status='teslim alındı' WHERE id=?", (order_id,))
    cursor.execute("UPDATE couriers SET status='teslimatta' WHERE id=?", (courier_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Sipariş teslim alındı"})

# --------- Kurye Sipariş Teslim Etme ---------
@app.route("/couriers/<int:courier_id>/orders/<int:order_id>/deliver", methods=["POST"])
@token_required
def courier_deliver_order(courier_id, order_id):
    if request.user_role != "admin" and request.user_id != courier_id:
        return jsonify({"message": "Yetkisiz"}), 403

    conn = get_db_connection()
    cursor = conn.cursor()
    order = cursor.execute("SELECT * FROM orders WHERE id=? AND courier_id=?", (order_id, courier_id)).fetchone()
    if not order:
        conn.close()
        return jsonify({"error": "Sipariş bulunamadı veya size ait değil"}), 404
    if order["status"] != "teslim alındı":
        conn.close()
        return jsonify({"error": "Sipariş teslim alınmamış"}), 400

    cursor.execute("UPDATE orders SET status='teslim edildi' WHERE id=?", (order_id,))
    cursor.execute("UPDATE couriers SET status='boşta' WHERE id=?", (courier_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Sipariş teslim edildi"})

# --------- Sipariş API ---------
@app.route("/orders", methods=["POST"])
@token_required
def create_order():
    # Admin dışında sipariş oluşturamaz
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403

    data = request.get_json()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO orders (order_id, customer_name, items, status, courier_id, created_at)
        VALUES (?, ?, ?, 'yeni', NULL, ?)
    """, (
        data.get("order_id"),
        data.get("customer_name"),
        str(data.get("items")),
        datetime.utcnow().isoformat()
    ))
    conn.commit()
    conn.close()
    return jsonify({"message": "Order created successfully"}), 201

@app.route("/orders", methods=["GET"])
@token_required
def list_orders():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders")
    rows = cursor.fetchall()
    conn.close()
    orders = []
    for r in rows:
        orders.append({
            "id": r[0],
            "order_id": r[1],
            "customer_name": r[2],
            "items": r[3],
            "status": r[4],
            "courier_id": r[5],
            "created_at": r[6]
        })
    return jsonify(orders)

@app.route("/orders/<order_id>", methods=["PATCH"])
@token_required
def update_order_status(order_id):
    # Admin dışında güncelleme yok
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403

    data = request.get_json()
    new_status = data.get("status")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE orders SET status=? WHERE order_id=?", (new_status, order_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Order status updated"}), 200

# --------- Admin Raporlama ---------
@app.route("/admin/reports/orders", methods=["GET"])
@token_required
def order_report():
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    if not start_date or not end_date:
        return jsonify({"error": "start_date ve end_date parametreleri gerekli"}), 400

    try:
        start_dt = datetime.strptime(start_date, "%Y-%m-%d")
        end_dt = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
    except ValueError:
        return jsonify({"error": "Tarih formatı YYYY-MM-DD olmalı"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            status, COUNT(*) as count
        FROM orders
        WHERE created_at >= ? AND created_at < ?
        GROUP BY status
    """, (start_dt.isoformat(), end_dt.isoformat()))

    status_counts = {row[0]: row[1] for row in cursor.fetchall()}

    cursor.execute("""
        SELECT courier_id, COUNT(*) as delivered_count
        FROM orders
        WHERE created_at >= ? AND created_at < ? AND status = 'teslim edildi'
        GROUP BY courier_id
    """, (start_dt.isoformat(), end_dt.isoformat()))

    courier_performance = []
    for courier_id, count in cursor.fetchall():
        courier = conn.execute("SELECT first_name, last_name FROM couriers WHERE id=?", (courier_id,)).fetchone()
        courier_name = f"{courier['first_name']} {courier['last_name']}" if courier else "Bilinmeyen Kurye"
        courier_performance.append({
            "courier_id": courier_id,
            "courier_name": courier_name,
            "delivered_orders": count
        })

    conn.close()

    return jsonify({
        "order_status_counts": status_counts,
        "courier_performance": courier_performance,
        "report_period": {"start_date": start_date, "end_date": end_date}
    })

# --------- Kurye Silme (Admin) ---------
@app.route("/couriers/<int:courier_id>", methods=["DELETE"])
@token_required
def delete_courier(courier_id):
    if request.user_role != "admin":
        return jsonify({"message": "Yetkisiz"}), 403

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM couriers WHERE id=?", (courier_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Kurye {courier_id} silindi"})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
