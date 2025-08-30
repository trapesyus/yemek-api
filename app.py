# app.py
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import sqlite3
import bcrypt
import jwt
import re
from functools import wraps

app = Flask(__name__)
DB_NAME = "orders.db"
SECRET_KEY = "çok_gizli_bir_anahtar"  # PROD: environment variable ile sakla
JWT_ALGORITHM = "HS256"
TOKEN_EXP_HOURS = 8

# ---------------- DB ----------------
def get_conn():
    conn = sqlite3.connect(DB_NAME, timeout=10)
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
        created_at TEXT
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
        courier_id INTEGER,
        total_orders INTEGER DEFAULT 0,
        last_assigned TEXT,
        FOREIGN KEY (courier_id) REFERENCES couriers (id)
    )
    """)

    conn.commit()
    conn.close()

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
        
    conn = get_conn()
    cur = conn.cursor()
    
    # Mahalleyi bul veya oluştur
    cur.execute("SELECT id FROM neighborhoods WHERE name = ?", (neighborhood_name,))
    neighborhood = cur.fetchone()
    
    if neighborhood:
        neighborhood_id = neighborhood["id"]
    else:
        cur.execute("INSERT INTO neighborhoods (name, created_at) VALUES (?, ?)",
                   (neighborhood_name, datetime.utcnow().isoformat()))
        neighborhood_id = cur.lastrowid
        conn.commit()
    
    conn.close()
    return neighborhood_id

def ensure_courier_performance(courier_id):
    conn = get_conn()
    cur = conn.cursor()
    
    cur.execute("SELECT 1 FROM courier_performance WHERE courier_id = ?", (courier_id,))
    if not cur.fetchone():
        cur.execute("INSERT INTO courier_performance (courier_id, last_assigned) VALUES (?, ?)",
                   (courier_id, datetime.utcnow().isoformat()))
        conn.commit()
    
    conn.close()

def assign_order_to_courier(order_id):
    conn = get_conn()
    cur = conn.cursor()
    
    # Sipariş bilgilerini al
    cur.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    order = cur.fetchone()
    if not order:
        conn.close()
        return False
    
    # Adresten mahalle bilgisini çıkar
    address = order["address"]
    neighborhood_name = extract_neighborhood(address)
    
    if neighborhood_name:
        # Mahalleyi kaydet veya getir
        neighborhood_id = get_or_create_neighborhood(neighborhood_name)
        
        # Siparişin mahalle bilgisini güncelle
        cur.execute("UPDATE orders SET neighborhood_id = ? WHERE id = ?", 
                   (neighborhood_id, order_id))
        conn.commit()
    else:
        neighborhood_id = None
    
    # Aynı mahalledeki son 5 dakika içindeki siparişleri bul
    five_min_ago = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
    
    if neighborhood_id:
        # Aynı mahalledeki son siparişleri ve kuryelerini bul
        cur.execute("""
        SELECT courier_id, COUNT(*) as order_count 
        FROM orders 
        WHERE neighborhood_id = ? 
          AND created_at >= ? 
          AND status IN ('yeni', 'teslim alındı')
          AND courier_id IS NOT NULL
        GROUP BY courier_id
        ORDER BY order_count ASC
        """, (neighborhood_id, five_min_ago))
        
        neighborhood_orders = cur.fetchall()
        
        # Bu mahallede aktif siparişi olan kuryeleri önceliklendir
        for courier in neighborhood_orders:
            courier_id = courier["courier_id"]
            
            # Kuryenin durumunu kontrol et
            cur.execute("SELECT status FROM couriers WHERE id = ?", (courier_id,))
            courier_status = cur.fetchone()
            
            if courier_status and courier_status["status"] in ("boşta", "teslimatta"):
                # Bu kuryeye siparişi ata
                cur.execute("UPDATE orders SET courier_id = ? WHERE id = ?", 
                           (courier_id, order_id))
                cur.execute("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", 
                           (courier_id,))
                
                # Kurye performansını güncelle
                ensure_courier_performance(courier_id)
                cur.execute("""
                UPDATE courier_performance 
                SET total_orders = total_orders + 1, 
                    last_assigned = ?
                WHERE courier_id = ?
                """, (datetime.utcnow().isoformat(), courier_id))
                
                conn.commit()
                conn.close()
                return True
    
    # Eğer aynı mahallede aktif kurye yoksa, en az siparişi olan kuryeyi bul
    cur.execute("""
    SELECT c.id, cp.total_orders, cp.last_assigned
    FROM couriers c
    LEFT JOIN courier_performance cp ON c.id = cp.courier_id
    WHERE c.status IN ('boşta', 'teslimatta')
    ORDER BY cp.total_orders ASC, cp.last_assigned ASC
    LIMIT 1
    """)
    
    best_courier = cur.fetchone()
    
    if best_courier:
        courier_id = best_courier["id"]
        
        # Siparişi kuryeye ata
        cur.execute("UPDATE orders SET courier_id = ? WHERE id = ?", 
                   (courier_id, order_id))
        cur.execute("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", 
                   (courier_id,))
        
        # Kurye performansını güncelle
        ensure_courier_performance(courier_id)
        cur.execute("""
        UPDATE courier_performance 
        SET total_orders = total_orders + 1, 
            last_assigned = ?
        WHERE courier_id = ?
        """, (datetime.utcnow().isoformat(), courier_id))
        
        conn.commit()
        conn.close()
        return True
    
    conn.close()
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

    conn = get_conn()
    cur = conn.cursor()

    # If admin asked and admin exists, require admin token
    if role == "admin":
        cur.execute("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1")
        has_admin = cur.fetchone() is not None
        if has_admin:
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                conn.close()
                return jsonify({"message": "Mevcut admin var. Yeni admin oluşturmak için admin token gerekli."}), 403
            token = auth.split(" ", 1)[1].strip()
            try:
                data_token = decode_token(token)
                if data_token.get("role") != "admin":
                    conn.close()
                    return jsonify({"message": "Yalnızca admin yeni admin oluşturabilir."), 403
            except Exception:
                conn.close()
                return jsonify({"message": "Token geçersiz"}), 401

    hashed = hash_password(password)
    try:
        cur.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                    (username, hashed, role, datetime.utcnow().isoformat()))
        user_id = cur.lastrowid

        courier_obj = None
        if role == "courier":
            first_name = data.get("first_name") or ""
            last_name = data.get("last_name") or ""
            email = data.get("email")
            phone = data.get("phone")
            cur.execute("""INSERT INTO couriers (user_id, first_name, last_name, email, phone, created_at)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (user_id, first_name, last_name, email, phone, datetime.utcnow().isoformat()))
            conn.commit()
            cur.execute("SELECT * FROM couriers WHERE user_id = ?", (user_id,))
            courier_row = cur.fetchone()
            courier_obj = row_to_dict(courier_row)
        else:
            conn.commit()

    except sqlite3.IntegrityError as e:
        conn.close()
        return jsonify({"message": "Kullanıcı adı veya e-posta zaten var", "error": str(e)}), 400

    # prepare response object (no password hash)
    user_resp = {"id": user_id, "username": username, "role": role, "created_at": datetime.utcnow().isoformat()}
    if role == "courier":
        user_resp["courier"] = courier_obj

    conn.close()
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

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return jsonify({"message": "Kullanıcı bulunamadı"}), 404

    if not check_password(password, user_row["password_hash"]):
        conn.close()
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
        cur.execute("SELECT id, first_name, last_name, email, phone, status, created_at FROM couriers WHERE user_id = ?", (user_id,))
        courier_row = cur.fetchone()
        user_out["courier"] = row_to_dict(courier_row) if courier_row else None

    conn.close()
    return jsonify({"token": token, "user": user_out})

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
        # return created object
        cur.execute("SELECT id, user_id, first_name, last_name, email, phone, status, created_at FROM couriers WHERE user_id = ?", (user_id,))
        courier_row = cur.fetchone()
        courier_obj = row_to_dict(courier_row)
    except sqlite3.IntegrityError as e:
        conn.close()
        return jsonify({"message": "IntegrityError", "error": str(e)}), 400
    conn.close()
    return jsonify({"message": "Kurye oluşturuldu", "user": {"id": user_id, "username": username, "role": "courier"}, "courier": courier_obj}), 201

# ---------------- Current user info ----------------
@app.route("/me", methods=["GET"])
@token_required
def me():
    uid = request.user_id
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id, username, role, created_at FROM users WHERE id = ?", (uid,))
    u = cur.fetchone()
    if not u:
        conn.close()
        return jsonify({"message": "Kullanıcı bulunamadı"}), 404
    user = row_to_dict(u)
    if user["role"] == "courier":
        cur.execute("SELECT id, first_name, last_name, email, phone, status, created_at FROM couriers WHERE user_id = ?", (uid,))
        c = cur.fetchone()
        user["courier"] = row_to_dict(c) if c else None
    conn.close()
    return jsonify(user)

# ---------------- Users management (admin) ----------------
@app.route("/users", methods=["GET"])
@admin_required
def list_users():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id, username, role, created_at FROM users")
    rows = cur.fetchall()
    conn.close()
    return jsonify([row_to_dict(r) for r in rows])

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
    # delete courier row if exists, then user
    cur.execute("DELETE FROM couriers WHERE user_id = ?", (user_id,))
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit(); conn.close()
    return jsonify({"message": "Kullanıcı silindi (ve bağlı kurye kaydı kaldırıldı)"})

# ---------------- Couriers listing & CRUD ----------------
@app.route("/couriers", methods=["GET"])
@admin_required
def admin_list_couriers():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id, user_id, first_name, last_name, email, phone, status, created_at FROM couriers")
    rows = cur.fetchall(); conn.close()
    return jsonify([row_to_dict(r) for r in rows])

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

# ---------------- Courier actions (self) ----------------
@app.route("/couriers/<int:courier_id>/status", methods=["PATCH"])
@token_required
def courier_update_status(courier_id):
    # courier can update own status; admin can update any
    if request.user_role != "admin":
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
    return jsonify([row_to_dict(r) for r in rows])

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
    now = datetime.utcnow().isoformat()
    cur.execute("UPDATE orders SET status = 'teslim alındı', updated_at = ? WHERE id = ?", (now, order_id))
    cur.execute("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", (courier_id,))
    
    # Add to delivery history
    cur.execute("INSERT INTO delivery_history (order_id, courier_id, status, notes, created_at) VALUES (?, ?, ?, ?, ?)",
                (order_id, courier_id, 'teslim alındı', 'Kurye siparişi teslim aldı', now))
    
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
    now = datetime.utcnow().isoformat()
    cur.execute("UPDATE orders SET status = 'teslim edildi', updated_at = ? WHERE id = ?", (now, order_id))
    cur.execute("UPDATE couriers SET status = 'boşta' WHERE id = ?", (courier_id,))
    
    # Add to delivery history
    cur.execute("INSERT INTO delivery_history (order_id, courier_id, status, notes, created_at) VALUES (?, ?, ?, ?, ?)",
                (order_id, courier_id, 'teslim edildi', 'Sipariş başarıyla teslim edildi', now))
    
    conn.commit(); conn.close()
    return jsonify({"message": "Sipariş teslim edildi"})

@app.route("/couriers/<int:courier_id>/orders/<int:order_id>/fail", methods=["POST"])
@token_required
def courier_fail_order(courier_id, order_id):
    if request.user_role != "admin":
        conn = get_conn(); cur = conn.cursor()
        cur.execute("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        row = cur.fetchone(); conn.close()
        if not row or row["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403
    
    data = request.get_json() or {}
    reason = data.get("reason", "")
    if not reason:
        return jsonify({"message": "Teslimat başarısızlığı nedeni gereklidir"}), 400
    
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE id = ? AND courier_id = ?", (order_id, courier_id))
    order = cur.fetchone()
    if not order:
        conn.close(); return jsonify({"message": "Sipariş bulunamadı veya atanmadı"}), 404
    
    now = datetime.utcnow().isoformat()
    cur.execute("UPDATE orders SET status = 'teslim edilemedi', delivery_failed_reason = ?, updated_at = ? WHERE id = ?", 
                (reason, now, order_id))
    cur.execute("UPDATE couriers SET status = 'boşta' WHERE id = ?", (courier_id,))
    
    # Add to delivery history
    cur.execute("INSERT INTO delivery_history (order_id, courier_id, status, notes, created_at) VALUES (?, ?, ?, ?, ?)",
                (order_id, courier_id, 'teslim edilemedi', f'Teslimat başarısız: {reason}', now))
    
    conn.commit(); conn.close()
    return jsonify({"message": "Teslimat başarısız olarak işaretlendi"})

@app.route("/couriers/<int:courier_id>/delivery-history", methods=["GET"])
@token_required
def courier_delivery_history(courier_id):
    # courier can view own delivery history
    if request.user_role != "admin":
        conn = get_conn(); cur = conn.cursor()
        cur.execute("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        row = cur.fetchone(); conn.close()
        if not row or row["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403
    
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""
        SELECT dh.*, o.customer_name, o.address, o.total_amount 
        FROM delivery_history dh 
        JOIN orders o ON dh.order_id = o.id 
        WHERE dh.courier_id = ? 
        ORDER BY dh.created_at DESC
    """, (courier_id,))
    rows = cur.fetchall(); conn.close()
    return jsonify([row_to_dict(r) for r in rows])

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
    order_uuid = f"o-{int(datetime.utcnow().timestamp()*1000)}"

    conn = get_conn(); cur = conn.cursor()
    try:
        cur.execute("""INSERT INTO orders
                       (order_uuid, external_id, vendor_id, customer_name, items, total_amount, address, payload, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (order_uuid, external_id, vendor_id, customer_name, str(items), total, address, payload, created, created))
        order_id = cur.lastrowid
        conn.commit()
        
        # Siparişi kuryeye ata
        assign_order_to_courier(order_id)
        
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
    return jsonify([row_to_dict(r) for r in rows])

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
    
    # Add updated_at timestamp
    fields.append("updated_at = ?")
    values.append(datetime.utcnow().isoformat())
    
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

# ---------------- Restaurant Management (admin) ----------------
@app.route("/restaurants", methods=["GET"])
@admin_required
def list_restaurants():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT * FROM restaurants ORDER BY name")
    rows = cur.fetchall(); conn.close()
    return jsonify([row_to_dict(r) for r in rows])

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
    
    conn = get_conn(); cur = conn.cursor()
    try:
        cur.execute("""INSERT INTO restaurants 
                      (name, fee_per_package, address, phone, created_at) 
                      VALUES (?, ?, ?, ?, ?)""",
                    (name, fee_per_package, address, phone, datetime.utcnow().isoformat()))
        conn.commit()
        restaurant_id = cur.lastrowid
        cur.execute("SELECT * FROM restaurants WHERE id = ?", (restaurant_id,))
        restaurant = row_to_dict(cur.fetchone())
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"message": "Bu isimde bir restoran zaten var"}), 400
    
    conn.close()
    return jsonify({"message": "Restoran oluşturuldu", "restaurant": restaurant}), 201

@app.route("/restaurants/<int:restaurant_id>", methods=["PATCH"])
@admin_required
def update_restaurant(restaurant_id):
    data = request.get_json() or {}
    allowed = ("name", "fee_per_package", "address", "phone", "is_active")
    fields = []; values = []
    for k in allowed:
        if k in data:
            fields.append(f"{k} = ?"); values.append(data[k])
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400
    values.append(restaurant_id)
    conn = get_conn(); cur = conn.cursor()
    try:
        cur.execute(f"UPDATE restaurants SET {', '.join(fields)} WHERE id = ?", values)
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); return jsonify({"message": "Bu isimde bir restoran zaten var"}), 400
    conn.close()
    return jsonify({"message": "Restoran güncellendi"})

@app.route("/restaurants/<int:restaurant_id>", methods=["DELETE"])
@admin_required
def delete_restaurant(restaurant_id):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM restaurants WHERE id = ?", (restaurant_id,))
    conn.commit(); conn.close()
    return jsonify({"message": "Restoran silindi"})

# ---------------- Neighborhood Management (admin) ----------------
@app.route("/neighborhoods", methods=["GET"])
@admin_required
def list_neighborhoods():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT * FROM neighborhoods ORDER BY name")
    rows = cur.fetchall(); conn.close()
    return jsonify([row_to_dict(r) for r in rows])

@app.route("/neighborhoods", methods=["POST"])
@admin_required
def create_neighborhood():
    data = request.get_json() or {}
    name = data.get("name")
    
    if not name:
        return jsonify({"message": "Mahalle adı gereklidir"}), 400
    
    conn = get_conn(); cur = conn.cursor()
    try:
        cur.execute("INSERT INTO neighborhoods (name, created_at) VALUES (?, ?)",
                   (name, datetime.utcnow().isoformat()))
        conn.commit()
        neighborhood_id = cur.lastrowid
        cur.execute("SELECT * FROM neighborhoods WHERE id = ?", (neighborhood_id,))
        neighborhood = row_to_dict(cur.fetchone())
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"message": "Bu isimde mahalle zaten var"}), 400
    
    conn.close()
    return jsonify({"message": "Mahalle oluşturuldu", "neighborhood": neighborhood}), 201

@app.route("/neighborhoods/<int:neighborhood_id>", methods=["DELETE"])
@admin_required
def delete_neighborhood(neighborhood_id):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM neighborhoods WHERE id = ?", (neighborhood_id,))
    conn.commit(); conn.close()
    return jsonify({"message": "Mahalle silindi"})

# ---------------- Manual Order Assignment ----------------
@app.route("/admin/assign-orders", methods=["POST"])
@admin_required
def manual_assign_orders():
    conn = get_conn()
    cur = conn.cursor()
    
    # Atanmamış siparişleri bul
    cur.execute("SELECT id FROM orders WHERE courier_id IS NULL AND status = 'yeni'")
    unassigned_orders = cur.fetchall()
    
    assigned_count = 0
    for order in unassigned_orders:
        if assign_order_to_courier(order["id"]):
            assigned_count += 1
    
    conn.close()
    return jsonify({"message": f"{assigned_count} sipariş kuryelere atandı"})

# ---------------- Courier Performance Reset ----------------
@app.route("/admin/couriers/<int:courier_id>/reset-performance", methods=["POST"])
@admin_required
def reset_courier_performance(courier_id):
    conn = get_conn()
    cur = conn.cursor()
    
    cur.execute("UPDATE courier_performance SET total_orders = 0 WHERE courier_id = ?", (courier_id,))
    conn.commit()
    conn.close()
    
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
            name = "Atanmamış"
        else:
            r = conn.execute("SELECT first_name, last_name FROM couriers WHERE id = ?", (courier_id,)).fetchone()
            name = f"{r['first_name']} {r['last_name']}" if r else "Bilinmeyen Kurye"
        perf.append({"courier_id": courier_id, "courier_name": name, "delivered_orders": cnt})
    
    # Restaurant performance
    cur.execute("""SELECT vendor_id, COUNT(*) as order_count FROM orders
                   WHERE created_at >= ? AND created_at < ? GROUP BY vendor_id""",
                (start_dt.isoformat(), end_dt.isoformat()))
    rest_perf = []
    for row in cur.fetchall():
        vendor_id = row[0]
        cnt = row[1]
        if vendor_id:
            r = conn.execute("SELECT name FROM restaurants WHERE id = ?", (vendor_id,)).fetchone()
            name = r['name'] if r else "Bilinmeyen Restoran"
        else:
            name = "Bilinmeyen Restoran"
        rest_perf.append({"vendor_id": vendor_id, "restaurant_name": name, "order_count": cnt})
    
    # Courier distribution
    cur.execute("""
    SELECT c.id, c.first_name, c.last_name, cp.total_orders
    FROM couriers c
    LEFT JOIN courier_performance cp ON c.id = cp.courier_id
    ORDER BY cp.total_orders DESC
    """)
    
    courier_dist = []
    for row in cur.fetchall():
        courier_dist.append({
            "courier_id": row["id"],
            "courier_name": f"{row['first_name']} {row['last_name']}",
            "total_orders": row["total_orders"] or 0
        })
    
    # Neighborhood distribution
    cur.execute("""
    SELECT n.name, COUNT(o.id) as order_count
    FROM neighborhoods n
    LEFT JOIN orders o ON n.id = o.neighborhood_id
    GROUP BY n.id
    ORDER BY order_count DESC
    """)
    
    neighborhood_dist = []
    for row in cur.fetchall():
        neighborhood_dist.append({
            "neighborhood_name": row["name"],
            "order_count": row["order_count"]
        })
    
    conn.close()
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
    app.run(host="0.0.0.0", port=5000, debug=True)
