# app.py
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room
from datetime import datetime, timedelta
import sqlite3
import bcrypt
import jwt
import re
import time
import json
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'çok_gizli_bir_anahtar_socket_io_icin'
DB_NAME = "orders.db"
SECRET_KEY = "çok_gizli_bir_anahtar"  # PROD: environment variable ile sakla
JWT_ALGORITHM = "HS256"
TOKEN_EXP_HOURS = 8

# SocketIO inicializasyonu
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Kurye WebSocket bağlantıları için sözlük
courier_connections = {}


# ---------------- DB ----------------
def get_conn():
    conn = sqlite3.connect(DB_NAME, timeout=30)  # Timeout süresini artırdık
    conn.execute("PRAGMA busy_timeout = 30000")  # 30 saniye busy timeout
    conn.row_factory = sqlite3.Row
    return conn


def row_to_dict(row):
    if not row:
        return None
    return {k: row[k] for k in row.keys()}


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # Users table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash BLOB,
        role TEXT,
        created_at TEXT
    )
    """)

    # Couriers table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS couriers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        first_name TEXT,
        last_name TEXT,
        email TEXT UNIQUE,
        phone TEXT,
        status TEXT DEFAULT 'boşta',
        created_at TEXT,
        fcm_token TEXT
    )
    """)

    # Orders table
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
        delivery_failed_reason TEXT,
        created_at TEXT,
        updated_at TEXT,
        neighborhood_id INTEGER
    )
    """)

    # Restaurants table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS restaurants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        fee_per_package REAL DEFAULT 5.0,
        address TEXT,
        phone TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TEXT
    )
    """)

    # Delivery history table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS delivery_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER,
        courier_id INTEGER,
        status TEXT,
        notes TEXT,
        created_at TEXT
    )
    """)

    # Neighborhoods table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS neighborhoods (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        created_at TEXT
    )
    """)

    # Courier performance table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS courier_performance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        courier_id INTEGER UNIQUE,
        total_orders INTEGER DEFAULT 0,
        last_assigned TEXT,
        FOREIGN KEY (courier_id) REFERENCES couriers (id)
    )
    """)

    conn.commit()
    conn.close()


# ---------------- WebSocket Event Handlers ----------------
@socketio.on('connect')
def handle_connect():
    print('Client connected: ' + request.sid)
    emit('connection_response', {'data': 'Bağlantı başarılı'})


@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected: ' + request.sid)
    # Bağlantı koptuğunda sözlükten kaldır
    for courier_id, sid in list(courier_connections.items()):
        if sid == request.sid:
            del courier_connections[courier_id]
            print(f'Courier {courier_id} bağlantısı kesildi')
            break


@socketio.on('courier_register')
def handle_courier_register(data):
    try:
        courier_id = data.get('courier_id')
        if courier_id:
            courier_connections[courier_id] = request.sid
            join_room(f'courier_{courier_id}')
            print(f'Courier {courier_id} registered with SID: {request.sid}')
            emit('registration_success', {'message': 'Kurye kaydı başarılı'})
        else:
            emit('registration_error', {'message': 'Kurye ID gerekli'})
    except Exception as e:
        print(f'Kurye kayıt hatası: {e}')
        emit('registration_error', {'message': 'Kayıt sırasında hata oluştu'})


# Sipariş atandığında bildirim gönderme fonksiyonu
def notify_courier_new_order(courier_id, order_data):
    try:
        if courier_id in courier_connections:
            socketio.emit('new_order', order_data, room=f'courier_{courier_id}')
            print(f"Notification sent to courier {courier_id}: {order_data}")
            return True
        else:
            print(f"Courier {courier_id} is not connected")
            return False
    except Exception as e:
        print(f"Bildirim gönderme hatası: {e}")
        return False


# ---------------- Veritabanı İşlemleri İçin Yardımcı Fonksiyonlar ----------------
def execute_with_retry(query, params=None, max_retries=5):
    """Veritabanı işlemlerini belirli sayıda deneme yapar"""
    for attempt in range(max_retries):
        try:
            conn = get_conn()
            cur = conn.cursor()
            if params:
                cur.execute(query, params)
            else:
                cur.execute(query)
            conn.commit()
            result = cur.fetchall()
            conn.close()
            return result
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                time.sleep(0.1 * (attempt + 1))  # Üssel backoff
            else:
                raise e
    return None


def execute_write_with_retry(query, params=None, max_retries=5):
    """Yazma işlemleri için belirli sayıda deneme yapar"""
    for attempt in range(max_retries):
        try:
            conn = get_conn()
            cur = conn.cursor()
            if params:
                cur.execute(query, params)
            else:
                cur.execute(query)
            conn.commit()
            conn.close()
            return True
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                time.sleep(0.1 * (attempt + 1))  # Üssel backoff
            else:
                raise e
    return False


# ---------------- Password & JWT ----------------
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
        token = token.decode("utf-8")
    return token


def decode_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])


# ---------------- Auth decorators ----------------
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
            return jsonify({"message": "Token süresi dolmuş"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Geçersiz token"}), 401
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


def courier_required(f):
    @wraps(f)
    @token_required
    def wrapped(*args, **kwargs):
        if getattr(request, "user_role", None) != "courier":
            return jsonify({"message": "Kurye yetkisi gerekli"}), 403
        return f(*args, **kwargs)

    return wrapped


# ---------------- Mahalle ve Dağıtım İşlemleri ----------------
def extract_neighborhood(address):
    if not address:
        return None

    address_lower = address.lower()

    # Mahalle desenleri
    patterns = [
        r'(\w+)\s*mah\.',
        r'(\w+)\s*mahallesi',
        r'(\w+)\s*mahalle',
        r'mah\.\s*(\w+)',
        r'mahallesi\s*(\w+)'
    ]

    for pattern in patterns:
        match = re.search(pattern, address_lower)
        if match:
            neighborhood_name = match.group(1).strip().title()
            return neighborhood_name

    return None


def get_or_create_neighborhood(neighborhood_name):
    if not neighborhood_name:
        return None

    # Önce mahalleyi bulmaya çalış
    result = execute_with_retry("SELECT id FROM neighborhoods WHERE name = ?", (neighborhood_name,))
    if result and len(result) > 0:
        return result[0]["id"]

    # Mahalle yoksa oluştur
    success = execute_write_with_retry(
        "INSERT INTO neighborhoods (name, created_at) VALUES (?, ?)",
        (neighborhood_name, datetime.utcnow().isoformat())
    )

    if success:
        # Yeni oluşturulan mahallenin ID'sini al
        result = execute_with_retry("SELECT id FROM neighborhoods WHERE name = ?", (neighborhood_name,))
        if result and len(result) > 0:
            return result[0]["id"]

    return None


def ensure_courier_performance(courier_id):
    # Kurye performans kaydı var mı kontrol et
    result = execute_with_retry("SELECT 1 FROM courier_performance WHERE courier_id = ?", (courier_id,))
    if not result or len(result) == 0:
        # Kurye performans kaydı yoksa oluştur
        execute_write_with_retry(
            "INSERT INTO courier_performance (courier_id, last_assigned) VALUES (?, ?)",
            (courier_id, datetime.utcnow().isoformat())
        )


def assign_order_to_courier(order_id):
    # Sipariş bilgilerini al
    result = execute_with_retry("SELECT * FROM orders WHERE id = ?", (order_id,))
    if not result or len(result) == 0:
        return False

    order = result[0]

    # Adresten mahalle bilgisini çıkar
    address = order["address"]
    neighborhood_name = extract_neighborhood(address)
    neighborhood_id = None

    if neighborhood_name:
        # Mahalleyi kaydet veya getir
        neighborhood_id = get_or_create_neighborhood(neighborhood_name)

        # Siparişin mahalle bilgisini güncelle
        execute_write_with_retry(
            "UPDATE orders SET neighborhood_id = ? WHERE id = ?",
            (neighborhood_id, order_id)
        )

    # Aynı mahalledeki son 5 dakika içindeki siparişleri bul
    five_min_ago = (datetime.utcnow() - timedelta(minutes=5)).isoformat()

    if neighborhood_id:
        # Aynı mahalledeki son siparişleri ve kuryelerini bul
        result = execute_with_retry("""
        SELECT courier_id, COUNT(*) as order_count 
        FROM orders 
        WHERE neighborhood_id = ? 
          AND created_at >= ? 
          AND status IN ('yeni', 'teslim alındı')
          AND courier_id IS NOT NULL
        GROUP BY courier_id
        ORDER BY order_count ASC
        """, (neighborhood_id, five_min_ago))

        # Bu mahallede aktif siparişi olan kuryeleri önceliklendir
        for courier in result:
            courier_id = courier["courier_id"]

            # Kuryenin durumunu kontrol et
            status_result = execute_with_retry("SELECT status FROM couriers WHERE id = ?", (courier_id,))
            if status_result and status_result[0]["status"] in ("boşta", "teslimatta"):
                # Bu kuryeye siparişi ata
                execute_write_with_retry("UPDATE orders SET courier_id = ? WHERE id = ?", (courier_id, order_id))
                execute_write_with_retry("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", (courier_id,))

                # Kurye performansını güncelle
                ensure_courier_performance(courier_id)
                execute_write_with_retry("""
                UPDATE courier_performance 
                SET total_orders = total_orders + 1, 
                    last_assigned = ?
                WHERE courier_id = ?
                """, (datetime.utcnow().isoformat(), courier_id))

                # Kuryeye bildirim gönder
                order_result = execute_with_retry("SELECT * FROM orders WHERE id = ?", (order_id,))
                if order_result and len(order_result) > 0:
                    order = row_to_dict(order_result[0])
                    order_data = {
                        'order_id': order['id'],
                        'order_uuid': order['order_uuid'],
                        'customer_name': order['customer_name'],
                        'address': order['address'],
                        'total_amount': order['total_amount'],
                        'items': order['items']
                    }
                    notify_courier_new_order(courier_id, order_data)

                return True

    # Eğer aynı mahallede aktif kurye yoksa, en az siparişi olan kuryeyi bul
    result = execute_with_retry("""
    SELECT c.id, COALESCE(cp.total_orders, 0) as total_orders, 
           COALESCE(cp.last_assigned, '2000-01-01T00:00:00.000000') as last_assigned
    FROM couriers c
    LEFT JOIN courier_performance cp ON c.id = cp.courier_id
    WHERE c.status IN ('boşta', 'teslimatta')
    ORDER BY total_orders ASC, last_assigned ASC
    LIMIT 1
    """)

    if result and len(result) > 0:
        courier_id = result[0]["id"]

        # Siparişi kuryeye ata
        execute_write_with_retry("UPDATE orders SET courier_id = ? WHERE id = ?", (courier_id, order_id))
        execute_write_with_retry("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", (courier_id,))

        # Kurye performansını güncelle
        ensure_courier_performance(courier_id)
        execute_write_with_retry("""
        UPDATE courier_performance 
        SET total_orders = COALESCE(total_orders, 0) + 1, 
            last_assigned = ?
        WHERE courier_id = ?
        """, (datetime.utcnow().isoformat(), courier_id))

        # Kuryeye bildirim gönder
        order_result = execute_with_retry("SELECT * FROM orders WHERE id = ?", (order_id,))
        if order_result and len(order_result) > 0:
            order = row_to_dict(order_result[0])
            order_data = {
                'order_id': order['id'],
                'order_uuid': order['order_uuid'],
                'customer_name': order['customer_name'],
                'address': order['address'],
                'total_amount': order['total_amount'],
                'items': order['items']
            }
            notify_courier_new_order(courier_id, order_data)

        return True

    return False


# ---------------- Auth: register/login ----------------
@app.route("/auth/register", methods=["POST"])
def auth_register():
    """
    Body: { username, password, role (admin|courier), first_name, last_name, email, phone }
    - courier: anyone can self-register
    - admin: if no admin exists, allowed; if admin exists, only existing admin (via Bearer token) can create new admin
    Returns created user summary (not including password hash)
    """
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    role = (data.get("role") or "courier").lower()

    if not username or not password:
        return jsonify({"message": "username ve password gerekli"}), 400
    if role not in ("admin", "courier"):
        return jsonify({"message": "role sadece 'admin' veya 'courier' olabilir"}), 400

    # If admin asked and admin exists, require admin token
    if role == "admin":
        result = execute_with_retry("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1")
        has_admin = result is not None and len(result) > 0
        if has_admin:
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"message": "Mevcut admin var. Yeni admin oluşturmak için admin token gerekli."}), 403
            token = auth.split(" ", 1)[1].strip()
            try:
                data_token = decode_token(token)
                if data_token.get("role") != "admin":
                    return jsonify({"message": "Yalnızca admin yeni admin oluşturabilir."}), 403
            except Exception:
                return jsonify({"message": "Token geçersiz"}), 401

    hashed = hash_password(password)
    try:
        # Kullanıcıyı oluştur
        execute_write_with_retry(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hashed, role, datetime.utcnow().isoformat())
        )

        # Yeni kullanıcının ID'sini al
        result = execute_with_retry("SELECT id FROM users WHERE username = ?", (username,))
        if not result or len(result) == 0:
            return jsonify({"message": "Kullanıcı oluşturulamadı"}), 500

        user_id = result[0]["id"]

        courier_obj = None
        if role == "courier":
            first_name = data.get("first_name") or ""
            last_name = data.get("last_name") or ""
            email = data.get("email")
            phone = data.get("phone")

            # Kurye kaydını oluştur
            execute_write_with_retry(
                """INSERT INTO couriers (user_id, first_name, last_name, email, phone, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (user_id, first_name, last_name, email, phone, datetime.utcnow().isoformat())
            )

            # Kurye bilgilerini al
            result = execute_with_retry("SELECT * FROM couriers WHERE user_id = ?", (user_id,))
            if result and len(result) > 0:
                courier_obj = row_to_dict(result[0])

    except sqlite3.IntegrityError as e:
        return jsonify({"message": "Kullanıcı adı veya e-posta zaten var", "error": str(e)}), 400

    # prepare response object (no password hash)
    user_resp = {"id": user_id, "username": username, "role": role, "created_at": datetime.utcnow().isoformat()}
    if role == "courier":
        user_resp["courier"] = courier_obj

    return jsonify({"message": f"{role} oluşturuldu", "user": user_resp}), 201


@app.route("/auth/login", methods=["POST"])
def auth_login():
    """
    Body: { username, password }
    Returns: { token, user: { id, username, role, created_at, courier: { ... } (optional) } }
    """
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"message": "username ve password gerekli"}), 400

    result = execute_with_retry("SELECT * FROM users WHERE username = ?", (username,))
    if not result or len(result) == 0:
        return jsonify({"message": "Kullanıcı bulunamadı"}), 404

    user_row = result[0]
    if not check_password(password, user_row["password_hash"]):
        return jsonify({"message": "Parola yanlış"}), 401

    user_id = user_row["id"]
    role = user_row["role"]
    token = generate_token(user_id, role)

    user_out = {
        "id": user_id,
        "username": user_row["username"],
        "role": role,
        "created_at": user_row["created_at"]
    }

    # attach courier profile if applicable
    if role == "courier":
        result = execute_with_retry(
            "SELECT id, first_name, last_name, email, phone, status, created_at FROM couriers WHERE user_id = ?",
            (user_id,))
        if result and len(result) > 0:
            user_out["courier"] = row_to_dict(result[0])

    return jsonify({"token": token, "user": user_out})


# ---------------- FCM Token Güncelleme ----------------
@app.route("/couriers/<int:courier_id>/fcm-token", methods=["POST"])
@token_required
def update_fcm_token(courier_id):
    if request.user_role != "admin":
        result = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not result or len(result) == 0 or result[0]["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    data = request.get_json() or {}
    fcm_token = data.get("fcm_token")

    if not fcm_token:
        return jsonify({"message": "FCM token gerekli"}), 400

    execute_write_with_retry(
        "UPDATE couriers SET fcm_token = ? WHERE id = ?",
        (fcm_token, courier_id)
    )

    return jsonify({"message": "FCM token güncellendi"})


# ---------------- Admin creates courier (explicit) ----------------
@app.route("/admin/couriers", methods=["POST"])
@admin_required
def admin_create_courier():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"message": "username ve password gerekli"}), 400
    email = data.get("email")

    # Check if username already exists
    result = execute_with_retry("SELECT 1 FROM users WHERE username = ?", (username,))
    if result and len(result) > 0:
        return jsonify({"message": "Kullanıcı adı kullanılıyor"}), 400

    if email:
        result = execute_with_retry("SELECT 1 FROM couriers WHERE email = ?", (email,))
        if result and len(result) > 0:
            return jsonify({"message": "E-posta zaten kullanılıyor"}), 400

    hashed = hash_password(password)
    try:
        # Create user
        execute_write_with_retry(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'courier', ?)",
            (username, hashed, datetime.utcnow().isoformat())
        )

        # Get user ID
        result = execute_with_retry("SELECT id FROM users WHERE username = ?", (username,))
        if not result or len(result) == 0:
            return jsonify({"message": "Kullanıcı oluşturulamadı"}), 500

        user_id = result[0]["id"]

        # Create courier
        first_name = data.get("first_name") or ""
        last_name = data.get("last_name") or ""
        phone = data.get("phone") or ""

        execute_write_with_retry(
            """INSERT INTO couriers (user_id, first_name, last_name, email, phone, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, first_name, last_name, email, phone, datetime.utcnow().isoformat())
        )

        # Get created courier
        result = execute_with_retry(
            "SELECT id, user_id, first_name, last_name, email, phone, status, created_at FROM couriers WHERE user_id = ?",
            (user_id,))
        if result and len(result) > 0:
            courier_obj = row_to_dict(result[0])
        else:
            courier_obj = None

        return jsonify({
            "message": "Kurye oluşturuldu",
            "user": {"id": user_id, "username": username, "role": "courier"},
            "courier": courier_obj
        }), 201

    except sqlite3.IntegrityError as e:
        return jsonify({"message": "IntegrityError", "error": str(e)}), 400


# ---------------- Current user info ----------------
@app.route("/me", methods=["GET"])
@token_required
def me():
    uid = request.user_id
    result = execute_with_retry("SELECT id, username, role, created_at FROM users WHERE id = ?", (uid,))
    if not result or len(result) == 0:
        return jsonify({"message": "Kullanıcı bulunamadı"}), 404

    user = row_to_dict(result[0])
    if user["role"] == "courier":
        result = execute_with_retry(
            "SELECT id, first_name, last_name, email, phone, status, created_at FROM couriers WHERE user_id = ?",
            (uid,))
        if result and len(result) > 0:
            user["courier"] = row_to_dict(result[0])

    return jsonify(user)


# ---------------- Users management (admin) ----------------
@app.route("/users", methods=["GET"])
@admin_required
def list_users():
    result = execute_with_retry("SELECT id, username, role, created_at FROM users")
    return jsonify([row_to_dict(r) for r in result]) if result else jsonify([])


@app.route("/users/<int:user_id>", methods=["PATCH"])
@admin_required
def update_user(user_id):
    data = request.get_json() or {}
    fields = []
    values = []
    if "role" in data:
        if data["role"] not in ("admin", "courier"):
            return jsonify({"message": "role admin veya courier olmalı"}), 400
        fields.append("role = ?");
        values.append(data["role"])
    if "password" in data:
        fields.append("password_hash = ?");
        values.append(hash_password(data["password"]))
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400

    values.append(user_id)
    query = f"UPDATE users SET {', '.join(fields)} WHERE id = ?"

    success = execute_write_with_retry(query, values)
    if not success:
        return jsonify({"message": "Kullanıcı güncellenirken hata oluştu"}), 500

    return jsonify({"message": "Kullanıcı güncellendi"})


@app.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    # delete courier row if exists, then user
    execute_write_with_retry("DELETE FROM couriers WHERE user_id = ?", (user_id,))
    execute_write_with_retry("DELETE FROM users WHERE id = ?", (user_id,))
    return jsonify({"message": "Kullanıcı silindi (ve bağlı kurye kaydı kaldırıldı)"})


# ---------------- Couriers listing & CRUD ----------------
@app.route("/couriers", methods=["GET"])
@admin_required
def admin_list_couriers():
    result = execute_with_retry(
        "SELECT id, user_id, first_name, last_name, email, phone, status, created_at, fcm_token FROM couriers")
    return jsonify([row_to_dict(r) for r in result]) if result else jsonify([])


@app.route("/couriers/<int:courier_id>", methods=["PATCH"])
@admin_required
def admin_update_courier(courier_id):
    data = request.get_json() or {}
    allowed = ("first_name", "last_name", "email", "phone", "status", "fcm_token")
    fields = [];
    values = []
    for k in allowed:
        if k in data:
            fields.append(f"{k} = ?");
            values.append(data[k])
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400

    values.append(courier_id)
    query = f"UPDATE couriers SET {', '.join(fields)} WHERE id = ?"

    try:
        success = execute_write_with_retry(query, values)
        if not success:
            return jsonify({"message": "Kurye güncellenirken hata oluştu"}), 500

        return jsonify({"message": "Kurye güncellendi"})
    except sqlite3.IntegrityError as e:
        return jsonify({"message": "Integrity error", "error": str(e)}), 400


@app.route("/couriers/<int:courier_id>", methods=["DELETE"])
@admin_required
def admin_delete_courier(courier_id):
    execute_write_with_retry("DELETE FROM couriers WHERE id = ?", (courier_id,))
    return jsonify({"message": f"Kurye {courier_id} silindi"})


# ---------------- Courier actions (self) ----------------
@app.route("/couriers/<int:courier_id>/status", methods=["PATCH"])
@token_required
def courier_update_status(courier_id):
    # courier can update own status; admin can update any
    if request.user_role != "admin":
        result = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not result or len(result) == 0 or result[0]["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    data = request.get_json() or {}
    status = data.get("status")
    if status not in ("boşta", "molada", "teslimatta"):
        return jsonify({"message": "Geçersiz status"}), 400

    execute_write_with_retry("UPDATE couriers SET status = ? WHERE id = ?", (status, courier_id))
    return jsonify({"message": "Kurye durumu güncellendi", "status": status})


@app.route("/couriers/<int:courier_id>/orders", methods=["GET"])
@token_required
def courier_get_orders(courier_id):
    # courier can view own assigned orders or admin
    if request.user_role != "admin":
        result = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not result or len(result) == 0 or result[0]["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    result = execute_with_retry("SELECT * FROM orders WHERE courier_id = ? AND status IN ('yeni','teslim alındı')",
                                (courier_id,))
    return jsonify([row_to_dict(r) for r in result]) if result else jsonify([])


@app.route("/couriers/<int:courier_id>/orders/<int:order_id>/pickup", methods=["POST"])
@token_required
def courier_pickup_order(courier_id, order_id):
    if request.user_role != "admin":
        result = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not result or len(result) == 0 or result[0]["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    result = execute_with_retry("SELECT * FROM orders WHERE id = ? AND courier_id = ?", (order_id, courier_id))
    if not result or len(result) == 0:
        return jsonify({"message": "Sipariş bulunamadı veya atanmadı"}), 404

    order = result[0]
    if order["status"] != "yeni":
        return jsonify({"message": "Sipariş zaten alınmış veya teslim edilmiş"}), 400

    now = datetime.utcnow().isoformat()
    execute_write_with_retry("UPDATE orders SET status = 'teslim alındı', updated_at = ? WHERE id = ?", (now, order_id))
    execute_write_with_retry("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", (courier_id,))

    # Add to delivery history
    execute_write_with_retry(
        "INSERT INTO delivery_history (order_id, courier_id, status, notes, created_at) VALUES (?, ?, ?, ?, ?)",
        (order_id, courier_id, 'teslim alındı', 'Kurye siparişi teslim aldı', now)
    )

    return jsonify({"message": "Sipariş teslim alındı"})


@app.route("/couriers/<int:courier_id>/orders/<int:order_id>/deliver", methods=["POST"])
@token_required
def courier_deliver_order(courier_id, order_id):
    if request.user_role != "admin":
        result = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not result or len(result) == 0 or result[0]["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    result = execute_with_retry("SELECT * FROM orders WHERE id = ? AND courier_id = ?", (order_id, courier_id))
    if not result or len(result) == 0:
        return jsonify({"message": "Sipariş bulunamadı veya atanmadı"}), 404

    order = result[0]
    if order["status"] != "teslim alındı":
        return jsonify({"message": "Sipariş teslim alınmamış"}), 400

    now = datetime.utcnow().isoformat()
    execute_write_with_retry("UPDATE orders SET status = 'teslim edildi', updated_at = ? WHERE id = ?", (now, order_id))
    execute_write_with_retry("UPDATE couriers SET status = 'boşta' WHERE id = ?", (courier_id,))

    # Add to delivery history
    execute_write_with_retry(
        "INSERT INTO delivery_history (order_id, courier_id, status, notes, created_at) VALUES (?, ?, ?, ?, ?)",
        (order_id, courier_id, 'teslim edildi', 'Sipariş başarıyla teslim edildi', now)
    )

    return jsonify({"message": "Sipariş teslim edildi"})


@app.route("/couriers/<int:courier_id>/orders/<int:order_id>/fail", methods=["POST"])
@token_required
def courier_fail_order(courier_id, order_id):
    if request.user_role != "admin":
        result = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not result or len(result) == 0 or result[0]["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    data = request.get_json() or {}
    reason = data.get("reason", "")
    if not reason:
        return jsonify({"message": "Teslimat başarısızlığı nedeni gereklidir"}), 400

    result = execute_with_retry("SELECT * FROM orders WHERE id = ? AND courier_id = ?", (order_id, courier_id))
    if not result or len(result) == 0:
        return jsonify({"message": "Sipariş bulunamadı veya atanmadı"}), 404

    now = datetime.utcnow().isoformat()
    execute_write_with_retry(
        "UPDATE orders SET status = 'teslim edilemedi', delivery_failed_reason = ?, updated_at = ? WHERE id = ?",
        (reason, now, order_id)
    )
    execute_write_with_retry("UPDATE couriers SET status = 'boşta' WHERE id = ?", (courier_id,))

    # Add to delivery history
    execute_write_with_retry(
        "INSERT INTO delivery_history (order_id, courier_id, status, notes, created_at) VALUES (?, ?, ?, ?, ?)",
        (order_id, courier_id, 'teslim edilemedi', f'Teslimat başarısız: {reason}', now)
    )

    return jsonify({"message": "Teslimat başarısız olarak işaretlendi"})


@app.route("/couriers/<int:courier_id>/delivery-history", methods=["GET"])
@token_required
def courier_delivery_history(courier_id):
    # courier can view own delivery history
    if request.user_role != "admin":
        result = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not result or len(result) == 0 or result[0]["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    result = execute_with_retry("""
        SELECT dh.*, o.customer_name, o.address, o.total_amount 
        FROM delivery_history dh 
        JOIN orders o ON dh.order_id = o.id 
        WHERE dh.courier_id = ? 
        ORDER BY dh.created_at DESC
    """, (courier_id,))

    return jsonify([row_to_dict(r) for r in result]) if result else jsonify([])


# ---------------- Orders (webhook + admin) ----------------
@app.route("/webhooks/yemeksepeti", methods=["POST"])
def webhook_yemeksepeti():
    data = request.get_json() or {}
    external_id = data.get("external_id") or data.get("order_id") or data.get("id")
    vendor_id = data.get("vendor_id")
    customer_name = data.get("customer_name") or data.get("customer")
    items = data.get("items")
    total = data.get("total") or data.get("total_amount") or 0
    address = data.get("address") or data.get("customer_address")
    payload = str(data)
    created = datetime.utcnow().isoformat()
    order_uuid = f"o-{int(datetime.utcnow().timestamp() * 1000)}"

    try:
        # Siparişi kaydet
        execute_write_with_retry(
            """INSERT INTO orders
               (order_uuid, external_id, vendor_id, customer_name, items, total_amount, address, payload, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (order_uuid, external_id, vendor_id, customer_name, str(items), total, address, payload, created, created)
        )

        # Yeni siparişin ID'sini al
        result = execute_with_retry("SELECT id FROM orders WHERE order_uuid = ?", (order_uuid,))
        if result and len(result) > 0:
            order_id = result[0]["id"]

            # Siparişi kuryeye ata (async olarak çalıştırılabilir)
            try:
                assign_order_to_courier(order_id)
            except Exception as e:
                # Atama hatası ana işlemi etkilemesin, sadece loglayalım
                print(f"Sipariş atama hatası: {e}")

        return jsonify({"message": "Sipariş alındı", "order_uuid": order_uuid}), 201

    except sqlite3.IntegrityError:
        return jsonify({"message": "Sipariş kaydedilirken hata (duplicate veya integrity)"}), 400


@app.route("/orders", methods=["GET"])
@admin_required
def admin_list_orders():
    status_filter = request.args.get("status")
    if status_filter:
        result = execute_with_retry("SELECT * FROM orders WHERE status = ? ORDER BY created_at DESC", (status_filter,))
    else:
        result = execute_with_retry("SELECT * FROM orders ORDER BY created_at DESC")

    return jsonify([row_to_dict(r) for r in result]) if result else jsonify([])


@app.route("/orders/<int:order_id>", methods=["PATCH"])
@admin_required
def admin_patch_order(order_id):
    data = request.get_json() or {}
    allowed = ("status", "courier_id", "customer_name", "items", "total_amount", "address")
    fields = [];
    values = []
    for k in allowed:
        if k in data:
            fields.append(f"{k} = ?");
            values.append(data[k])
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400

    # Add updated_at timestamp
    fields.append("updated_at = ?")
    values.append(datetime.utcnow().isoformat())

    values.append(order_id)
    query = f"UPDATE orders SET {', '.join(fields)} WHERE id = ?"

    execute_write_with_retry(query, values)
    return jsonify({"message": "Sipariş güncellendi"})


@app.route("/orders/<int:order_id>", methods=["DELETE"])
@admin_required
def admin_delete_order(order_id):
    execute_write_with_retry("DELETE FROM orders WHERE id = ?", (order_id,))
    return jsonify({"message": "Sipariş silindi"})


# ---------------- Restaurant Management (admin) ----------------
@app.route("/restaurants", methods=["GET"])
@admin_required
def list_restaurants():
    result = execute_with_retry("SELECT * FROM restaurants ORDER BY name")
    return jsonify([row_to_dict(r) for r in result]) if result else jsonify([])


@app.route("/restaurants", methods=["POST"])
@admin_required
def create_restaurant():
    data = request.get_json() or {}
    name = data.get("name")
    fee_per_package = data.get("fee_per_package", 5.0)
    address = data.get("address", "")
    phone = data.get("phone", "")

    if not name:
        return jsonify({"message": "Restoran adı gereklidir"}), 400

    try:
        execute_write_with_retry(
            """INSERT INTO restaurants 
               (name, fee_per_package, address, phone, created_at) 
               VALUES (?, ?, ?, ?, ?)""",
            (name, fee_per_package, address, phone, datetime.utcnow().isoformat())
        )

        # Get created restaurant
        result = execute_with_retry("SELECT * FROM restaurants WHERE name = ?", (name,))
        if result and len(result) > 0:
            restaurant = row_to_dict(result[0])
        else:
            restaurant = None

        return jsonify({"message": "Restoran oluşturuldu", "restaurant": restaurant}), 201

    except sqlite3.IntegrityError:
        return jsonify({"message": "Bu isimde bir restoran zaten var"}), 400


@app.route("/restaurants/<int:restaurant_id>", methods=["PATCH"])
@admin_required
def update_restaurant(restaurant_id):
    data = request.get_json() or {}
    allowed = ("name", "fee_per_package", "address", "phone", "is_active")
    fields = [];
    values = []
    for k in allowed:
        if k in data:
            fields.append(f"{k} = ?");
            values.append(data[k])
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400

    values.append(restaurant_id)
    query = f"UPDATE restaurants SET {', '.join(fields)} WHERE id = ?"

    try:
        execute_write_with_retry(query, values)
        return jsonify({"message": "Restoran güncellendi"})
    except sqlite3.IntegrityError:
        return jsonify({"message": "Bu isimde bir restoran zaten var"}), 400


@app.route("/restaurants/<int:restaurant_id>", methods=["DELETE"])
@admin_required
def delete_restaurant(restaurant_id):
    execute_write_with_retry("DELETE FROM restaurants WHERE id = ?", (restaurant_id,))
    return jsonify({"message": "Restoran silindi"})


# ---------------- Neighborhood Management (admin) ----------------
@app.route("/neighborhoods", methods=["GET"])
@admin_required
def list_neighborhoods():
    result = execute_with_retry("SELECT * FROM neighborhoods ORDER BY name")
    return jsonify([row_to_dict(r) for r in result]) if result else jsonify([])


@app.route("/neighborhoods", methods=["POST"])
@admin_required
def create_neighborhood():
    data = request.get_json() or {}
    name = data.get("name")

    if not name:
        return jsonify({"message": "Mahalle adı gereklidir"}), 400

    try:
        execute_write_with_retry(
            "INSERT INTO neighborhoods (name, created_at) VALUES (?, ?)",
            (name, datetime.utcnow().isoformat())
        )

        # Get created neighborhood
        result = execute_with_retry("SELECT * FROM neighborhoods WHERE name = ?", (name,))
        if result and len(result) > 0:
            neighborhood = row_to_dict(result[0])
        else:
            neighborhood = None

        return jsonify({"message": "Mahalle oluşturuldu", "neighborhood": neighborhood}), 201

    except sqlite3.IntegrityError:
        return jsonify({"message": "Bu isimde mahalle zaten var"}), 400


@app.route("/neighborhoods/<int:neighborhood_id>", methods=["DELETE"])
@admin_required
def delete_neighborhood(neighborhood_id):
    execute_write_with_retry("DELETE FROM neighborhoods WHERE id = ?", (neighborhood_id,))
    return jsonify({"message": "Mahalle silindi"})


# ---------------- Manual Order Assignment ----------------
@app.route("/admin/assign-orders", methods=["POST"])
@admin_required
def manual_assign_orders():
    # Atanmamış siparişleri bul
    result = execute_with_retry("SELECT id FROM orders WHERE courier_id IS NULL AND status = 'yeni'")
    if not result:
        return jsonify({"message": "Atanmamış sipariş bulunamadı"})

    assigned_count = 0
    for order in result:
        if assign_order_to_courier(order["id"]):
            assigned_count += 1

    return jsonify({"message": f"{assigned_count} sipariş kuryelere atandı"})


# ---------------- Courier Performance Reset ----------------
@app.route("/admin/couriers/<int:courier_id>/reset-performance", methods=["POST"])
@admin_required
def reset_courier_performance(courier_id):
    execute_write_with_retry("UPDATE courier_performance SET total_orders = 0 WHERE courier_id = ?", (courier_id,))
    return jsonify({"message": "Kurye performansı sıfırlandı"})


# ---------------- Admin reports ----------------
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

    # Status counts
    result = execute_with_retry("""
        SELECT status, COUNT(*) as cnt FROM orders
        WHERE created_at >= ? AND created_at < ? GROUP BY status
    """, (start_dt.isoformat(), end_dt.isoformat()))

    status_counts = {row[0]: row[1] for row in result} if result else {}

    # Courier performance
    result = execute_with_retry("""
        SELECT courier_id, COUNT(*) as delivered_count FROM orders
        WHERE created_at >= ? AND created_at < ? AND status = 'teslim edildi' GROUP BY courier_id
    """, (start_dt.isoformat(), end_dt.isoformat()))

    perf = []
    if result:
        for row in result:
            courier_id = row[0]
            cnt = row[1]
            if not courier_id:
                name = "Atanmamış"
            else:
                r = execute_with_retry("SELECT first_name, last_name FROM couriers WHERE id = ?", (courier_id,))
                if r and len(r) > 0:
                    name = f"{r[0]['first_name']} {r[0]['last_name']}"
                else:
                    name = "Bilinmeyen Kurye"
            perf.append({"courier_id": courier_id, "courier_name": name, "delivered_orders": cnt})

    # Restaurant performance
    result = execute_with_retry("""
        SELECT vendor_id, COUNT(*) as order_count FROM orders
        WHERE created_at >= ? AND created_at < ? GROUP BY vendor_id
    """, (start_dt.isoformat(), end_dt.isoformat()))

    rest_perf = []
    if result:
        for row in result:
            vendor_id = row[0]
            cnt = row[1]
            if vendor_id:
                r = execute_with_retry("SELECT name FROM restaurants WHERE id = ?", (vendor_id,))
                if r and len(r) > 0:
                    name = r[0]['name']
                else:
                    name = "Bilinmeyen Restoran"
            else:
                name = "Bilinmeyen Restoran"
            rest_perf.append({"vendor_id": vendor_id, "restaurant_name": name, "order_count": cnt})

    # Courier distribution
    result = execute_with_retry("""
        SELECT c.id, c.first_name, c.last_name, COALESCE(cp.total_orders, 0) as total_orders
        FROM couriers c
        LEFT JOIN courier_performance cp ON c.id = cp.courier_id
        ORDER BY total_orders DESC
    """)

    courier_dist = []
    if result:
        for row in result:
            courier_dist.append({
                "courier_id": row["id"],
                "courier_name": f"{row['first_name']} {row['last_name']}",
                "total_orders": row["total_orders"]
            })

    # Neighborhood distribution
    result = execute_with_retry("""
        SELECT n.name, COUNT(o.id) as order_count
        FROM neighborhoods n
        LEFT JOIN orders o ON n.id = o.neighborhood_id
        GROUP BY n.id
        ORDER BY order_count DESC
    """)

    neighborhood_dist = []
    if result:
        for row in result:
            neighborhood_dist.append({
                "neighborhood_name": row["name"],
                "order_count": row["order_count"]
            })

    return jsonify({
        "status_counts": status_counts,
        "courier_performance": perf,
        "restaurant_performance": rest_perf,
        "courier_distribution": courier_dist,
        "neighborhood_distribution": neighborhood_dist,
        "period": {"start": start, "end": end}
    })


# ---------------- Health ----------------
@app.route("/")
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})


if __name__ == "__main__":
    init_db()
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
