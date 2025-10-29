# app.py - İSTANBUL SAATİ DESTEKLİ TAM VERSİYON
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room
from datetime import datetime, timedelta
import sqlite3
import bcrypt
import jwt
import re
import time
import json
import traceback
import smtplib
import os
import logging
from logging.handlers import RotatingFileHandler
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from apscheduler.schedulers.background import BackgroundScheduler

# Firebase Admin SDK imports
try:
    import firebase_admin
    from firebase_admin import credentials, messaging
    from firebase_admin.exceptions import FirebaseError
    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False
    print("⚠️ Firebase Admin SDK kurulu değil. FCM özellikleri devre dışı.")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'çok_gizli_bir_anahtar_socket_io_icin'
DB_NAME = "orders.db"
SECRET_KEY = "çok_gizli_bir_anahtar"
JWT_ALGORITHM = "HS256"
TOKEN_EXP_HOURS = 8

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# İstanbul saat dilimi için fonksiyon
def get_istanbul_time():
    """UTC'yi İstanbul saatine çevir (+3 saat)"""
    utc_now = datetime.utcnow()
    istanbul_offset = timedelta(hours=3)
    return utc_now + istanbul_offset

def format_datetime_for_display(dt_string):
    """UTC datetime string'ini İstanbul zamanına çevir ve formatla"""
    if not dt_string:
        return None
    try:
        # UTC datetime'ını parse et
        if 'Z' in dt_string:
            dt_string = dt_string.replace('Z', '+00:00')
        utc_dt = datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
        
        # UTC'den İstanbul'a çevir (+3 saat)
        istanbul_dt = utc_dt + timedelta(hours=3)
        
        # Okunabilir formata çevir
        return istanbul_dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, AttributeError) as e:
        app.logger.error(f"❌ Tarih dönüşüm hatası: {e}, orijinal: {dt_string}")
        return dt_string

def format_datetime_for_storage():
    """Veritabanına kaydetmek için UTC zamanı döndür"""
    return datetime.utcnow().isoformat()

# Loglama sistemini kur
def setup_logging():
    if not os.path.exists('logs'):
        os.makedirs('logs')

    file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)

setup_logging()

# Firebase Admin SDK initialization
firebase_app = None
if FIREBASE_AVAILABLE:
    try:
        service_account_files = [
            "service-account.json",
            "service-account-key.json",
            "firebase-service-account.json"
        ]

        cred = None
        used_file = None

        for service_file in service_account_files:
            if not os.path.exists(service_file):
                continue

            try:
                with open(service_file, 'r') as f:
                    key_data = json.load(f)

                required_fields = ['type', 'project_id', 'private_key_id', 'private_key', 'client_email']
                missing = [f for f in required_fields if f not in key_data]

                if missing:
                    app.logger.error(f"❌ {service_file} eksik alanlar: {missing}")
                    continue

                if key_data.get('type') != 'service_account':
                    app.logger.error(f"❌ {service_file} service account değil")
                    continue

                if not key_data.get('private_key', '').startswith('-----BEGIN PRIVATE KEY-----'):
                    app.logger.error(f"❌ {service_file} private key formatı geçersiz")
                    continue

                cred = credentials.Certificate(service_file)
                used_file = service_file
                break

            except json.JSONDecodeError as e:
                app.logger.error(f"❌ {service_file} JSON hatası: {e}")
                continue
            except Exception as e:
                app.logger.error(f"❌ {service_file} okuma hatası: {e}")
                continue

        if cred:
            try:
                firebase_app = firebase_admin.initialize_app(cred)
                app.logger.info(f"✅ Firebase başlatıldı: {used_file}")
            except Exception as e:
                app.logger.error(f"❌ Firebase init: {e}")
                firebase_app = None
        else:
            app.logger.warning("❌ Geçerli service account dosyası yok")

    except Exception as e:
        app.logger.error(f"❌ Firebase başlatma: {e}")
        firebase_app = None

def check_firebase_setup():
    if not firebase_app:
        app.logger.warning("\n" + "=" * 60)
        app.logger.warning("🚨 FIREBASE KURULUMU GEREKLİ")
        app.logger.warning("=" * 60)
        app.logger.warning("1. Firebase Console → Service Accounts → YENİ KEY İNDİR")
        app.logger.warning("2. 'service-account.json' olarak kaydet")
        app.logger.warning("3. Sunucu saati UTC olmalı: date (UTC göstermeli)")
        app.logger.warning("=" * 60 + "\n")

courier_connections = {}
scheduler = BackgroundScheduler()

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USERNAME = "your_email@gmail.com"
EMAIL_PASSWORD = "your_app_password"
REPORT_RECIPIENTS = {"email": ["admin@firma.com"]}

# FCM Fonksiyonları
def validate_fcm_token(fcm_token):
    if not fcm_token:
        return False

    if not firebase_app:
        return True  # Firebase yoksa kabul et

    try:
        if len(fcm_token) < 20:
            return False

        message = messaging.Message(token=fcm_token, data={'validation': 'test'})
        messaging.send(message, dry_run=True)
        app.logger.info(f"✅ Token geçerli: {fcm_token[:15]}...")
        return True

    except FirebaseError as e:
        error_str = str(e).lower()
        if 'unregistered' in error_str or 'not-found' in error_str:
            app.logger.warning(f"⚠️ Token kayıtsız: {fcm_token[:15]}...")
            return False
        if 'invalid-argument' in error_str or 'invalid' in error_str:
            app.logger.error(f"❌ Token geçersiz: {fcm_token[:15]}...")
            return False
        app.logger.error(f"❌ Firebase error: {e}")
        return False

    except Exception as e:
        app.logger.error(f"❌ Validation error: {e}")
        return False

def send_fcm_notification(fcm_token, title, body, data=None):
    if not fcm_token or not firebase_app:
        return False

    try:
        message = messaging.Message(
            token=fcm_token,
            notification=messaging.Notification(title=title, body=body),
            data=data or {},
            android=messaging.AndroidConfig(
                priority='high',
                notification=messaging.AndroidNotification(
                    sound='default',
                    click_action='FLUTTER_NOTIFICATION_CLICK'
                )
            ),
            apns=messaging.APNSConfig(
                payload=messaging.APNSPayload(
                    aps=messaging.Aps(sound='default', badge=1)
                )
            )
        )

        response = messaging.send(message)
        app.logger.info(f"✅ Bildirim gönderildi: {response}")
        return True

    except FirebaseError as e:
        error_str = str(e).lower()
        if any(x in error_str for x in ['unregistered', 'not-found', 'invalid-argument']):
            cleanup_invalid_fcm_token(fcm_token)
        app.logger.error(f"❌ FCM error: {e}")
        return False

    except Exception as e:
        app.logger.error(f"❌ Send error: {e}")
        return False

def cleanup_invalid_fcm_token(token):
    try:
        execute_write_with_retry("UPDATE couriers SET fcm_token = NULL WHERE fcm_token = ?", (token,))
        app.logger.info(f"🧹 Token temizlendi: {token[:15]}...")
    except Exception as e:
        app.logger.error(f"❌ Cleanup error: {e}")

# Database
def get_conn():
    conn = sqlite3.connect(DB_NAME, timeout=30)
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.row_factory = sqlite3.Row
    return conn

def row_to_dict(row):
    if not row:
        return None
    
    result = {k: row[k] for k in row.keys()}
    
    # Tarih alanlarını İstanbul saatine çevir
    datetime_fields = ['created_at', 'updated_at', 'last_assigned', 'cooldown_until']
    for field in datetime_fields:
        if field in result and result[field]:
            result[field] = format_datetime_for_display(result[field])
    
    return result

def column_exists(conn, table, column):
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    return column in [r[1] for r in cur.fetchall()]

def execute_with_retry(query, params=None, max_retries=5):
    for attempt in range(max_retries):
        try:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(query, params) if params else cur.execute(query)
            conn.commit()
            result = cur.fetchall()
            conn.close()
            return result
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                time.sleep(0.1 * (attempt + 1))
            else:
                raise
    return None

def execute_write_with_retry(query, params=None, max_retries=5):
    for attempt in range(max_retries):
        try:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute(query, params) if params else cur.execute(query)
            conn.commit()
            conn.close()
            return True
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                time.sleep(0.1 * (attempt + 1))
            else:
                raise
    return False

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash BLOB,
        role TEXT,
        created_at TEXT,
        restaurant_id TEXT
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS couriers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        first_name TEXT,
        last_name TEXT,
        email TEXT UNIQUE,
        phone TEXT,
        status TEXT DEFAULT 'boşta',
        created_at TEXT,
        fcm_token TEXT
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS orders (
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
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS restaurants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        restaurant_id TEXT UNIQUE,
        name TEXT UNIQUE,
        fee_per_package REAL DEFAULT 5.0,
        address TEXT,
        phone TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TEXT
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS delivery_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER,
        courier_id INTEGER,
        status TEXT,
        notes TEXT,
        created_at TEXT
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS neighborhoods (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        created_at TEXT
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS courier_performance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        courier_id INTEGER UNIQUE,
        daily_orders INTEGER DEFAULT 0,
        total_orders INTEGER DEFAULT 0,
        last_assigned TEXT,
        cooldown_until TEXT,
        current_neighborhood_id INTEGER,
        FOREIGN KEY (courier_id) REFERENCES couriers (id)
    )""")

    conn.commit()

    # Migrations
    migrations = [
        ('users', 'restaurant_id', 'TEXT'),
        ('orders', 'vendor_id', 'TEXT'),
        ('restaurants', 'restaurant_id', 'TEXT'),
        ('courier_performance', 'cooldown_until', 'TEXT'),
        ('courier_performance', 'current_neighborhood_id', 'INTEGER')
    ]

    for table, column, col_type in migrations:
        try:
            if not column_exists(conn, table, column):
                cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
                conn.commit()
        except:
            pass

    conn.close()

# Scheduler functions
def reset_daily_orders():
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("UPDATE courier_performance SET daily_orders = 0")
        conn.commit()
        conn.close()
        app.logger.info("✅ Günlük sipariş sayıları sıfırlandı")
    except Exception as e:
        app.logger.error(f"❌ Günlük sıfırlama hatası: {e}")

def reset_monthly_orders():
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("UPDATE courier_performance SET daily_orders = 0, total_orders = 0")
        conn.commit()
        conn.close()
        app.logger.info("✅ Aylık sipariş sayıları sıfırlandı")
    except Exception as e:
        app.logger.error(f"❌ Aylık sıfırlama hatası: {e}")

def send_email(to_email, subject, html_content):
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = EMAIL_USERNAME
        msg['To'] = to_email
        msg.attach(MIMEText(html_content, 'html'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()

        app.logger.info(f"✅ Email gönderildi: {to_email}")
        return True
    except Exception as e:
        app.logger.error(f"❌ Email hatası: {e}")
        return False

def generate_monthly_report():
    try:
        today = datetime.utcnow()
        first_day = today.replace(day=1)
        last_day = first_day - timedelta(days=1)
        first_prev = last_day.replace(day=1)

        start = first_prev.strftime("%Y-%m-%d")
        end = last_day.strftime("%Y-%m-%d")

        result = execute_with_retry(
            "SELECT status, COUNT(*) as cnt FROM orders WHERE created_at >= ? AND created_at < ? GROUP BY status",
            (start, f"{end} 23:59:59")
        )

        status_counts = {row["status"]: row["cnt"] for row in result} if result else {}

        return {
            'success': True,
            'period': {'start': start, 'end': end},
            'status_counts': status_counts
        }
    except Exception as e:
        app.logger.error(f"❌ Rapor hatası: {e}")
        return {'success': False, 'error': str(e)}

def format_report_for_email(report_data):
    if not report_data.get('success'):
        return f"Rapor hatası: {report_data.get('error')}", "Hata"

    period = report_data['period']
    istanbul_time = get_istanbul_time().strftime("%Y-%m-%d %H:%M:%S")
    subject = f"Aylık Rapor - {period['start']} - {period['end']}"

    html = f"""<html><body>
    <h1>Aylık Rapor</h1>
    <p>Dönem: {period['start']} - {period['end']}</p>
    <p>Oluşturulma: {istanbul_time} (İstanbul)</p>
    </body></html>"""

    return html, subject

def distribute_monthly_report():
    try:
        report_data = generate_monthly_report()
        html, subject = format_report_for_email(report_data)

        count = 0
        for email in REPORT_RECIPIENTS.get('email', []):
            if send_email(email, subject, html):
                count += 1

        if count > 0:
            reset_monthly_orders()

        return {'success': True, 'email_sent': count}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def schedule_monthly_report():
    try:
        scheduler.add_job(distribute_monthly_report, 'cron', day='last', hour=23, minute=0, id='monthly_report',
                          replace_existing=True)
        app.logger.info("✅ Aylık rapor zamanlayıcısı eklendi")
    except Exception as e:
        app.logger.error(f"❌ Zamanlayıcı hatası: {e}")

scheduler.add_job(reset_daily_orders, 'cron', hour=0, minute=0)
schedule_monthly_report()
scheduler.start()

# WebSocket
@socketio.on('connect')
def handle_connect():
    app.logger.info(f'✅ Client connected: {request.sid}')
    emit('connection_response', {'data': 'Bağlantı başarılı'})

@socketio.on('disconnect')
def handle_disconnect():
    app.logger.info(f'❌ Client disconnected: {request.sid}')
    for cid, sid in list(courier_connections.items()):
        if sid == request.sid:
            del courier_connections[cid]
            break

@socketio.on('courier_register')
def handle_courier_register(data):
    try:
        cid = str(data.get('courier_id'))
        if cid:
            courier_connections[cid] = request.sid
            join_room(f'courier_{cid}')
            emit('registration_success', {'message': 'Kayıt başarılı'})
    except Exception as e:
        emit('registration_error', {'message': str(e)})

def notify_courier_new_order(courier_id, order_data):
    try:
        cid = str(courier_id)

        if cid in courier_connections:
            socketio.emit('new_order', order_data, room=f'courier_{cid}')

        result = execute_with_retry("SELECT fcm_token FROM couriers WHERE id = ?", (courier_id,))
        if result and len(result) > 0:
            token = row_to_dict(result[0]).get('fcm_token')
            if token:
                title = "Yeni Sipariş 🚴"
                body = f"{order_data.get('customer_name')} - {order_data.get('address')}"
                fcm_data = {
                    'type': 'new_order',
                    'order_id': str(order_data.get('order_id')),
                    'click_action': 'FLUTTER_NOTIFICATION_CLICK'
                }
                send_fcm_notification(token, title, body, fcm_data)

        return True
    except Exception as e:
        app.logger.error(f"❌ Notify error: {e}")
        return False

def notify_courier_reassignment(courier_id, order_id, action):
    try:
        cid = str(courier_id)

        if cid in courier_connections:
            socketio.emit('order_reassigned', {
                'order_id': order_id,
                'action': action
            }, room=f'courier_{cid}')

        return True
    except Exception as e:
        app.logger.error(f"❌ Reassign notify error: {e}")
        return False

# Password & JWT
def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

def _normalize_hash(h):
    if isinstance(h, memoryview):
        return bytes(h)
    if isinstance(h, str):
        return h.encode("utf-8")
    return h

def check_password(password, hashed):
    if not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), _normalize_hash(hashed))
    except:
        return False

def generate_token(user_id, role):
    payload = {"user_id": user_id, "role": role, "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXP_HOURS)}
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token.decode("utf-8") if isinstance(token, bytes) else token

def decode_token(token):
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])

# Decorators
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

def restaurant_required(f):
    @wraps(f)
    @token_required
    def wrapped(*args, **kwargs):
        if getattr(request, "user_role", None) != "restaurant":
            return jsonify({"message": "Restoran yetkisi gerekli"}), 403
        return f(*args, **kwargs)

    return wrapped

# Neighborhood & Assignment
def extract_neighborhood(address):
    if not address:
        return None
    patterns = [
        r'(\w+)\s*mah\.',
        r'(\w+)\s*mahallesi',
        r'(\w+)\s*mahalle'
    ]
    for pattern in patterns:
        match = re.search(pattern, address.lower())
        if match:
            return match.group(1).strip().title()
    return None

def get_or_create_neighborhood(name):
    if not name:
        return None
    result = execute_with_retry("SELECT id FROM neighborhoods WHERE name = ?", (name,))
    if result and len(result) > 0:
        return result[0]["id"]
    execute_write_with_retry("INSERT INTO neighborhoods (name, created_at) VALUES (?, ?)",
                             (name, format_datetime_for_storage()))
    result = execute_with_retry("SELECT id FROM neighborhoods WHERE name = ?", (name,))
    return result[0]["id"] if result and len(result) > 0 else None

def ensure_courier_performance(courier_id):
    result = execute_with_retry("SELECT 1 FROM courier_performance WHERE courier_id = ?", (courier_id,))
    if not result or len(result) == 0:
        execute_write_with_retry("INSERT INTO courier_performance (courier_id, last_assigned) VALUES (?, ?)",
                                 (courier_id, format_datetime_for_storage()))

def set_courier_cooldown(courier_id, neighborhood_id):
    cooldown = (datetime.utcnow() + timedelta(minutes=3)).isoformat()
    execute_write_with_retry(
        "UPDATE courier_performance SET cooldown_until = ?, current_neighborhood_id = ? WHERE courier_id = ?",
        (cooldown, neighborhood_id, courier_id))

def assign_order_to_courier(order_id):
    result = execute_with_retry("SELECT * FROM orders WHERE id = ?", (order_id,))
    if not result or len(result) == 0:
        return False

    order = row_to_dict(result[0])
    neighborhood_id = None
    neighborhood_name = extract_neighborhood(order["address"])

    if neighborhood_name:
        neighborhood_id = get_or_create_neighborhood(neighborhood_name)
        execute_write_with_retry("UPDATE orders SET neighborhood_id = ? WHERE id = ?", (neighborhood_id, order_id))

    result = execute_with_retry("""
        SELECT c.id, COALESCE(cp.daily_orders, 0) as daily_orders
        FROM couriers c
        LEFT JOIN courier_performance cp ON c.id = cp.courier_id
        WHERE c.status IN ('boşta', 'teslimatta')
        ORDER BY daily_orders ASC, c.id ASC
        LIMIT 1
    """)

    if result and len(result) > 0:
        courier = row_to_dict(result[0])
        courier_id = courier["id"]

        execute_write_with_retry("UPDATE orders SET courier_id = ? WHERE id = ?", (courier_id, order_id))
        execute_write_with_retry("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", (courier_id,))

        ensure_courier_performance(courier_id)
        execute_write_with_retry(
            "UPDATE courier_performance SET daily_orders = daily_orders + 1, total_orders = total_orders + 1, last_assigned = ? WHERE courier_id = ?",
            (format_datetime_for_storage(), courier_id))

        if neighborhood_id:
            set_courier_cooldown(courier_id, neighborhood_id)

        order_result = execute_with_retry("SELECT * FROM orders WHERE id = ?", (order_id,))
        if order_result and len(order_result) > 0:
            order = row_to_dict(order_result[0])
            notify_courier_new_order(courier_id, {
                'order_id': order['id'],
                'order_uuid': order['order_uuid'],
                'customer_name': order['customer_name'],
                'address': order['address'],
                'total_amount': order['total_amount'],
                'items': order['items']
            })

        return True

    return False

# FCM Token Endpoint
@app.route("/couriers/<int:courier_id>/fcm-token", methods=["POST"])
@token_required
def update_fcm_token(courier_id):
    if request.user_role != "admin":
        result = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not result or result[0]["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    data = request.get_json() or {}
    fcm_token = data.get("fcm_token")

    if not fcm_token:
        return jsonify({"message": "FCM token gerekli"}), 400

    try:
        if firebase_app:
            app.logger.warning(f"⚠️ Token kaydediliyor (validation atlandı): {fcm_token[:15]}...")

        success = execute_write_with_retry("UPDATE couriers SET fcm_token = ? WHERE id = ?", (fcm_token, courier_id))

        if success:
            msg = "Token kaydedildi (validation geçici olarak devre dışı)"
            return jsonify({"message": msg})
        else:
            return jsonify({"message": "Token güncellenemedi"}), 500

    except Exception as e:
        app.logger.error(f"❌ Token update error: {e}")
        return jsonify({"message": "Sunucu hatası", "error": str(e)}), 500

@app.route("/admin/fcm/validate-all-tokens", methods=["POST"])
@admin_required
def validate_all_fcm_tokens():
    try:
        result = execute_with_retry("SELECT id, fcm_token FROM couriers WHERE fcm_token IS NOT NULL")
        if not result:
            return jsonify({"message": "Token bulunamadı"})

        invalid_tokens = []
        valid_count = 0

        for row in result:
            courier = row_to_dict(row)
            token = courier.get('fcm_token')

            if token and firebase_app and validate_fcm_token(token):
                valid_count += 1
            else:
                invalid_tokens.append(token)
                cleanup_invalid_fcm_token(token)

        return jsonify({
            "message": "Validasyon tamamlandı",
            "valid_tokens": valid_count,
            "invalid_tokens_cleaned": len(invalid_tokens)
        })

    except Exception as e:
        app.logger.error(f"❌ Toplu validasyon hatası: {e}")
        return jsonify({"message": "Validasyon hatası"}), 500

# Auth Endpoints
@app.route("/auth/register", methods=["POST"])
def auth_register():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    role = (data.get("role") or "courier").lower()

    if not username or not password:
        return jsonify({"message": "username ve password gerekli"}), 400
    if role not in ("admin", "courier", "restaurant"):
        return jsonify({"message": "role: admin, courier veya restaurant"}), 400

    if role == "admin":
        result = execute_with_retry("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1")
        has_admin = result is not None and len(result) > 0
        if has_admin:
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"message": "Admin oluşturmak için admin token gerekli"}), 403
            token = auth.split(" ", 1)[1].strip()
            try:
                token_data = decode_token(token)
                if token_data.get("role") != "admin":
                    return jsonify({"message": "Sadece admin, admin oluşturabilir"}), 403
            except:
                return jsonify({"message": "Token geçersiz"}), 401

    restaurant_id = None
    if role == "restaurant":
        restaurant_id = data.get("restaurant_id")
        if not restaurant_id:
            return jsonify({"message": "restaurant_id gerekli"}), 400
        phone = data.get("phone")
        if not phone:
            return jsonify({"message": "phone gerekli"}), 400
        restaurant_id = str(restaurant_id)

        r = execute_with_retry("SELECT id FROM restaurants WHERE restaurant_id = ?", (restaurant_id,))
        if not r or len(r) == 0:
            name = data.get("restaurant_name") or f"Restaurant {restaurant_id}"
            execute_write_with_retry(
                "INSERT INTO restaurants (restaurant_id, name, fee_per_package, address, phone, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (restaurant_id, name, data.get("fee_per_package", 5.0), data.get("address", ""), phone,
                 format_datetime_for_storage())
            )

    if role == "courier":
        phone = data.get("phone")
        if not phone:
            return jsonify({"message": "phone gerekli"}), 400

    existing = execute_with_retry("SELECT id FROM users WHERE username = ?", (username,))
    if existing and len(existing) > 0:
        return jsonify({"message": "Kullanıcı adı kullanılıyor"}), 400

    hashed = hash_password(password)
    try:
        if role == "restaurant":
            execute_write_with_retry(
                "INSERT INTO users (username, password_hash, role, created_at, restaurant_id) VALUES (?, ?, ?, ?, ?)",
                (username, hashed, role, format_datetime_for_storage(), restaurant_id)
            )
        else:
            execute_write_with_retry(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username, hashed, role, format_datetime_for_storage())
            )

        result = execute_with_retry("SELECT id FROM users WHERE username = ?", (username,))
        if not result or len(result) == 0:
            return jsonify({"message": "Kullanıcı oluşturulamadı"}), 500

        user_id = result[0]["id"]
        courier_obj = None

        if role == "courier":
            execute_write_with_retry(
                "INSERT INTO couriers (user_id, first_name, last_name, email, phone, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, data.get("first_name", ""), data.get("last_name", ""), data.get("email"), data.get("phone"),
                 format_datetime_for_storage())
            )
            result = execute_with_retry("SELECT * FROM couriers WHERE user_id = ?", (user_id,))
            if result and len(result) > 0:
                courier_obj = row_to_dict(result[0])

    except sqlite3.IntegrityError as e:
        return jsonify({"message": "Kullanıcı adı veya email/phone zaten var", "error": str(e)}), 400

    user_resp = {"id": user_id, "username": username, "role": role, "created_at": format_datetime_for_display(format_datetime_for_storage())}
    if role == "courier":
        user_resp["courier"] = courier_obj
    elif role == "restaurant":
        user_resp["restaurant_id"] = restaurant_id

    return jsonify({"message": f"{role} oluşturuldu", "user": user_resp}), 201

@app.route("/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"message": "username ve password gerekli"}), 400

    result = execute_with_retry("SELECT * FROM users WHERE username = ?", (username,))
    if not result or len(result) == 0:
        return jsonify({"message": "Kullanıcı bulunamadı"}), 404

    user_row = row_to_dict(result[0])
    if not check_password(password, user_row["password_hash"]):
        return jsonify({"message": "Parola yanlış"}), 401

    user_id = user_row["id"]
    role = user_row["role"]
    token = generate_token(user_id, role)

    user_out = {
        "id": user_id,
        "username": user_row["username"],
        "role": role,
        "created_at": format_datetime_for_display(user_row["created_at"])
    }

    if role == "courier":
        result = execute_with_retry(
            "SELECT id, first_name, last_name, email, phone, status, created_at FROM couriers WHERE user_id = ?",
            (user_id,))
        if result and len(result) > 0:
            user_out["courier"] = row_to_dict(result[0])

    if role == "restaurant":
        user_out["restaurant_id"] = user_row["restaurant_id"]

    return jsonify({"token": token, "user": user_out})

@app.route("/me", methods=["GET"])
@token_required
def me():
    uid = request.user_id
    result = execute_with_retry("SELECT id, username, role, created_at, restaurant_id FROM users WHERE id = ?", (uid,))
    if not result or len(result) == 0:
        return jsonify({"message": "Kullanıcı bulunamadı"}), 404

    user = row_to_dict(result[0])
    if user["role"] == "courier":
        result = execute_with_retry(
            "SELECT id, first_name, last_name, email, phone, status, created_at FROM couriers WHERE user_id = ?",
            (uid,))
        if result and len(result) > 0:
            user["courier"] = row_to_dict(result[0])
    elif user["role"] == "restaurant":
        rid = user.get("restaurant_id")
        if rid:
            result = execute_with_retry("SELECT * FROM restaurants WHERE restaurant_id = ?", (rid,))
            if result and len(result) > 0:
                user["restaurant"] = row_to_dict(result[0])

    return jsonify(user)

# Admin Endpoints
@app.route("/admin/couriers", methods=["POST"])
@admin_required
def admin_create_courier():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    phone = data.get("phone")
    if not username or not password or not phone:
        return jsonify({"message": "username, password, phone gerekli"}), 400

    result = execute_with_retry("SELECT 1 FROM users WHERE username = ?", (username,))
    if result and len(result) > 0:
        return jsonify({"message": "Kullanıcı adı kullanılıyor"}), 400

    hashed = hash_password(password)
    try:
        execute_write_with_retry(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'courier', ?)",
            (username, hashed, format_datetime_for_storage())
        )

        result = execute_with_retry("SELECT id FROM users WHERE username = ?", (username,))
        user_id = result[0]["id"]

        execute_write_with_retry(
            "INSERT INTO couriers (user_id, first_name, last_name, email, phone, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, data.get("first_name", ""), data.get("last_name", ""), data.get("email"), phone,
             format_datetime_for_storage())
        )

        result = execute_with_retry("SELECT * FROM couriers WHERE user_id = ?", (user_id,))
        courier_obj = row_to_dict(result[0]) if result and len(result) > 0 else None

        return jsonify({
            "message": "Kurye oluşturuldu",
            "user": {"id": user_id, "username": username, "role": "courier", "created_at": format_datetime_for_display(format_datetime_for_storage())},
            "courier": courier_obj
        }), 201

    except sqlite3.IntegrityError as e:
        return jsonify({"message": "IntegrityError", "error": str(e)}), 400

@app.route("/admin/orders/<int:order_id>/reassign", methods=["POST"])
@admin_required
def admin_reassign_order(order_id):
    data = request.get_json() or {}
    new_courier_id = data.get("new_courier_id")

    if not new_courier_id:
        return jsonify({"message": "new_courier_id gerekli"}), 400

    result = execute_with_retry(
        "SELECT o.*, c.id as current_courier_id FROM orders o LEFT JOIN couriers c ON o.courier_id = c.id WHERE o.id = ?",
        (order_id,))
    if not result or len(result) == 0:
        return jsonify({"message": "Sipariş bulunamadı"}), 404

    order = row_to_dict(result[0])
    current_courier_id = order["current_courier_id"]

    result = execute_with_retry(
        "SELECT id, first_name, last_name FROM couriers WHERE id = ? AND status IN ('boşta', 'teslimatta')",
        (new_courier_id,))
    if not result or len(result) == 0:
        return jsonify({"message": "Yeni kurye bulunamadı"}), 404

    new_courier = row_to_dict(result[0])

    if order["status"] not in ["yeni", "teslim alındı"]:
        return jsonify({"message": "Sadece yeni/teslim alındı siparişler yeniden atanabilir"}), 400

    if current_courier_id == new_courier_id:
        return jsonify({"message": "Sipariş zaten bu kuryede"}), 400

    now = format_datetime_for_storage()

    try:
        if current_courier_id:
            result = execute_with_retry(
                "SELECT COUNT(*) as cnt FROM orders WHERE courier_id = ? AND status IN ('yeni', 'teslim alındı') AND id != ?",
                (current_courier_id, order_id))
            if result and result[0]["cnt"] == 0:
                execute_write_with_retry("UPDATE couriers SET status = 'boşta' WHERE id = ?", (current_courier_id,))
            execute_write_with_retry(
                "UPDATE courier_performance SET cooldown_until = NULL, current_neighborhood_id = NULL WHERE courier_id = ?",
                (current_courier_id,))
            notify_courier_reassignment(current_courier_id, order_id, "removed")

        execute_write_with_retry(
            "UPDATE orders SET courier_id = ?, status = 'teslim alındı', updated_at = ? WHERE id = ?",
            (new_courier_id, now, order_id))
        execute_write_with_retry("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", (new_courier_id,))
        ensure_courier_performance(new_courier_id)

        if order.get("neighborhood_id"):
            set_courier_cooldown(new_courier_id, order["neighborhood_id"])

        execute_write_with_retry(
            "INSERT INTO delivery_history (order_id, courier_id, status, notes, created_at) VALUES (?, ?, ?, ?, ?)",
            (order_id, new_courier_id, 'reassigned', f'Yeniden atandı', now))

        result = execute_with_retry("SELECT * FROM orders WHERE id = ?", (order_id,))
        if result and len(result) > 0:
            order_data = row_to_dict(result[0])
            notify_courier_new_order(new_courier_id, {
                'order_id': order_data['id'],
                'order_uuid': order_data['order_uuid'],
                'customer_name': order_data['customer_name'],
                'address': order_data['address'],
                'total_amount': order_data['total_amount'],
                'items': order_data['items'],
                'reassigned': True
            })

        return jsonify({
            "message": f"Sipariş {new_courier['first_name']} {new_courier['last_name']} kuryesine atandı",
            "new_courier_id": new_courier_id
        })

    except Exception as e:
        app.logger.error(f"❌ Reassign error: {e}")
        return jsonify({"message": "Hata oluştu", "error": str(e)}), 500

@app.route("/users", methods=["GET"])
@admin_required
def list_users():
    result = execute_with_retry("SELECT id, username, role, created_at, restaurant_id FROM users")
    users = [row_to_dict(r) for r in result] if result else []
    return jsonify(users)

@app.route("/users/<int:user_id>", methods=["PATCH"])
@admin_required
def update_user(user_id):
    data = request.get_json() or {}
    fields, values = [], []
    if "role" in data:
        if data["role"] not in ("admin", "courier", "restaurant"):
            return jsonify({"message": "Geçersiz role"}), 400
        fields.append("role = ?")
        values.append(data["role"])
    if "password" in data:
        fields.append("password_hash = ?")
        values.append(hash_password(data["password"]))
    if "restaurant_id" in data:
        fields.append("restaurant_id = ?")
        values.append(data["restaurant_id"])
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400

    values.append(user_id)
    execute_write_with_retry(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", values)
    return jsonify({"message": "Kullanıcı güncellendi"})

@app.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    execute_write_with_retry("DELETE FROM couriers WHERE user_id = ?", (user_id,))
    execute_write_with_retry("DELETE FROM users WHERE id = ?", (user_id,))
    return jsonify({"message": "Kullanıcı silindi"})

@app.route("/couriers", methods=["GET"])
@admin_required
def admin_list_couriers():
    result = execute_with_retry(
        "SELECT id, user_id, first_name, last_name, email, phone, status, created_at, fcm_token FROM couriers")
    couriers = [row_to_dict(r) for r in result] if result else []
    return jsonify(couriers)

@app.route("/couriers/<int:courier_id>", methods=["PATCH"])
@admin_required
def admin_update_courier(courier_id):
    data = request.get_json() or {}
    allowed = ("first_name", "last_name", "email", "phone", "status", "fcm_token")
    fields, values = [], []
    for k in allowed:
        if k in data:
            fields.append(f"{k} = ?")
            values.append(data[k])
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400

    values.append(courier_id)
    try:
        execute_write_with_retry(f"UPDATE couriers SET {', '.join(fields)} WHERE id = ?", values)
        return jsonify({"message": "Kurye güncellendi"})
    except sqlite3.IntegrityError as e:
        return jsonify({"message": "Integrity error", "error": str(e)}), 400

@app.route("/couriers/<int:courier_id>", methods=["DELETE"])
@admin_required
def admin_delete_courier(courier_id):
    execute_write_with_retry("DELETE FROM couriers WHERE id = ?", (courier_id,))
    return jsonify({"message": "Kurye silindi"})

@app.route("/couriers/<int:courier_id>/reset-performance", methods=["POST"])
@admin_required
def reset_courier_performance(courier_id):
    execute_write_with_retry("UPDATE courier_performance SET daily_orders = 0, total_orders = 0 WHERE courier_id = ?",
                             (courier_id,))
    return jsonify({"message": "Performans sıfırlandı"})

@app.route("/admin/assign-orders", methods=["POST"])
@admin_required
def manual_assign_orders():
    result = execute_with_retry("SELECT id FROM orders WHERE courier_id IS NULL AND status = 'yeni'")
    if not result:
        return jsonify({"message": "Atanmamış sipariş yok"})

    count = sum(1 for row in result if assign_order_to_courier(row_to_dict(row)["id"]))
    return jsonify({"message": f"{count} sipariş atandı"})

@app.route("/admin/trigger-monthly-report", methods=["POST"])
@admin_required
def trigger_monthly_report():
    result = distribute_monthly_report()
    if result['success']:
        return jsonify({"message": "Rapor gönderildi", "email_sent": result.get('email_sent', 0)})
    else:
        return jsonify({"message": "Rapor hatası", "error": result.get('error')}), 500

@app.route("/admin/reports/orders", methods=["GET"])
@admin_required
def admin_reports_orders():
    start = request.args.get("start_date")
    end = request.args.get("end_date")
    if not start or not end:
        return jsonify({"message": "start_date ve end_date gerekli (YYYY-MM-DD)"}), 400

    try:
        start_dt = datetime.strptime(start, "%Y-%m-%d")
        end_dt = datetime.strptime(end, "%Y-%m-%d") + timedelta(days=1)
    except:
        return jsonify({"message": "Tarih formatı YYYY-MM-DD"}), 400

    result = execute_with_retry(
        "SELECT status, COUNT(*) as cnt FROM orders WHERE created_at >= ? AND created_at < ? GROUP BY status",
        (start_dt.isoformat(), end_dt.isoformat()))
    status_counts = {row["status"]: row["cnt"] for row in result} if result else {}

    return jsonify({"status_counts": status_counts, "period": {"start": start, "end": end}})

# Courier Endpoints
@app.route("/couriers/<int:courier_id>/status", methods=["PATCH"])
@token_required
def courier_update_status(courier_id):
    if request.user_role != "admin":
        result = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not result or row_to_dict(result[0])["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    data = request.get_json() or {}
    status = data.get("status")
    if status not in ("boşta", "molada", "teslimatta"):
        return jsonify({"message": "Geçersiz status"}), 400

    execute_write_with_retry("UPDATE couriers SET status = ? WHERE id = ?", (status, courier_id))
    return jsonify({"message": "Durum güncellendi", "status": status})

@app.route("/couriers/<int:courier_id>/orders", methods=["GET"])
@token_required
def courier_get_orders(courier_id):
    if request.user_role != "admin":
        result = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not result or row_to_dict(result[0])["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    result = execute_with_retry("SELECT * FROM orders WHERE courier_id = ? AND status IN ('yeni','teslim alındı')",
                                (courier_id,))
    orders = [row_to_dict(r) for r in result] if result else []
    return jsonify(orders)

@app.route("/couriers/<int:courier_id>/orders/<int:order_id>/pickup", methods=["POST"])
@token_required
def courier_pickup_order(courier_id, order_id):
    if request.user_role != "admin":
        result = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not result or row_to_dict(result[0])["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    result = execute_with_retry("SELECT * FROM orders WHERE id = ? AND courier_id = ?", (order_id, courier_id))
    if not result or len(result) == 0:
        return jsonify({"message": "Sipariş bulunamadı"}), 404

    order = row_to_dict(result[0])
    if order["status"] != "yeni":
        return jsonify({"message": "Sipariş zaten alınmış"}), 400

    now = format_datetime_for_storage()
    execute_write_with_retry("UPDATE orders SET status = 'teslim alındı', updated_at = ? WHERE id = ?", (now, order_id))
    execute_write_with_retry("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", (courier_id,))
    execute_write_with_retry(
        "INSERT INTO delivery_history (order_id, courier_id, status, notes, created_at) VALUES (?, ?, ?, ?, ?)",
        (order_id, courier_id, 'teslim alındı', 'Teslim alındı', now))

    return jsonify({"message": "Sipariş teslim alındı"})

@app.route("/couriers/<int:courier_id>/orders/<int:order_id>/deliver", methods=["POST"])
@token_required
def courier_deliver_order(courier_id, order_id):
    if request.user_role != "admin":
        result = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not result or row_to_dict(result[0])["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    result = execute_with_retry("SELECT * FROM orders WHERE id = ? AND courier_id = ?", (order_id, courier_id))
    if not result or len(result) == 0:
        return jsonify({"message": "Sipariş bulunamadı"}), 404

    order = row_to_dict(result[0])
    if order["status"] != "teslim alındı":
        return jsonify({"message": "Sipariş teslim alınmamış"}), 400

    now = format_datetime_for_storage()
    execute_write_with_retry("UPDATE orders SET status = 'teslim edildi', updated_at = ? WHERE id = ?", (now, order_id))
    execute_write_with_retry("UPDATE couriers SET status = 'boşta' WHERE id = ?", (courier_id,))
    execute_write_with_retry(
        "UPDATE courier_performance SET cooldown_until = NULL, current_neighborhood_id = NULL WHERE courier_id = ?",
        (courier_id,))
    execute_write_with_retry(
        "INSERT INTO delivery_history (order_id, courier_id, status, notes, created_at) VALUES (?, ?, ?, ?, ?)",
        (order_id, courier_id, 'teslim edildi', 'Teslim edildi', now))

    return jsonify({"message": "Sipariş teslim edildi"})

@app.route("/couriers/<int:courier_id>/orders/<int:order_id>/fail", methods=["POST"])
@token_required
def courier_fail_order(courier_id, order_id):
    if request.user_role != "admin":
        result = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not result or row_to_dict(result[0])["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    data = request.get_json() or {}
    reason = data.get("reason", "")
    if not reason:
        return jsonify({"message": "Neden gerekli"}), 400

    result = execute_with_retry("SELECT * FROM orders WHERE id = ? AND courier_id = ?", (order_id, courier_id))
    if not result or len(result) == 0:
        return jsonify({"message": "Sipariş bulunamadı"}), 404

    now = format_datetime_for_storage()
    execute_write_with_retry(
        "UPDATE orders SET status = 'teslim edilemedi', delivery_failed_reason = ?, updated_at = ? WHERE id = ?",
        (reason, now, order_id))
    execute_write_with_retry("UPDATE couriers SET status = 'boşta' WHERE id = ?", (courier_id,))
    execute_write_with_retry(
        "UPDATE courier_performance SET cooldown_until = NULL, current_neighborhood_id = NULL WHERE courier_id = ?",
        (courier_id,))
    execute_write_with_retry(
        "INSERT INTO delivery_history (order_id, courier_id, status, notes, created_at) VALUES (?, ?, ?, ?, ?)",
        (order_id, courier_id, 'teslim edilemedi', f'Başarısız: {reason}', now))

    return jsonify({"message": "Başarısız işaretlendi"})

@app.route("/couriers/<int:courier_id>/delivery-history", methods=["GET"])
@token_required
def courier_delivery_history(courier_id):
    if request.user_role != "admin":
        result = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not result or row_to_dict(result[0])["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    result = execute_with_retry(
        "SELECT dh.*, o.customer_name, o.address FROM delivery_history dh JOIN orders o ON dh.order_id = o.id WHERE dh.courier_id = ? ORDER BY dh.created_at DESC",
        (courier_id,))
    history = [row_to_dict(r) for r in result] if result else []
    return jsonify(history)

# Restaurant Endpoints
@app.route("/restaurants/orders", methods=["GET"])
@restaurant_required
def restaurant_get_orders():
    result = execute_with_retry("SELECT restaurant_id FROM users WHERE id = ?", (request.user_id,))
    if not result or len(result) == 0:
        return jsonify({"message": "Restaurant ID yok"}), 404

    rid = row_to_dict(result[0])["restaurant_id"]
    result = execute_with_retry("SELECT * FROM orders WHERE vendor_id = ? ORDER BY created_at DESC", (rid,))
    orders = [row_to_dict(r) for r in result] if result else []
    return jsonify(orders)

@app.route("/restaurants/orders/<int:order_id>", methods=["GET"])
@restaurant_required
def restaurant_get_order(order_id):
    result = execute_with_retry("SELECT restaurant_id FROM users WHERE id = ?", (request.user_id,))
    if not result or len(result) == 0:
        return jsonify({"message": "Restaurant ID yok"}), 404

    rid = row_to_dict(result[0])["restaurant_id"]
    result = execute_with_retry("SELECT * FROM orders WHERE id = ? AND vendor_id = ?", (order_id, rid))
    if not result or len(result) == 0:
        return jsonify({"message": "Sipariş bulunamadı"}), 404

    return jsonify(row_to_dict(result[0]))

# Order Endpoints
@app.route("/webhooks/yemeksepeti", methods=["POST"])
def webhook_yemeksepeti():
    data = request.get_json() or {}
    external_id = data.get("external_id") or data.get("order_id") or data.get("id")
    vendor_id = str(data.get("vendor_id")) if data.get("vendor_id") else None
    customer_name = data.get("customer_name") or data.get("customer")
    items = data.get("items")
    total = data.get("total") or data.get("total_amount") or 0
    address = data.get("address") or data.get("customer_address")
    payload = json.dumps(data, ensure_ascii=False)
    created = format_datetime_for_storage()
    order_uuid = f"o-{int(datetime.utcnow().timestamp() * 1000)}"

    try:
        ok = execute_write_with_retry(
            "INSERT INTO orders (order_uuid, external_id, vendor_id, customer_name, items, total_amount, address, payload, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (order_uuid, external_id, vendor_id, customer_name, str(items), total, address, payload, created, created)
        )
    except sqlite3.IntegrityError as e:
        app.logger.error(f"❌ Webhook IntegrityError: {e}")
        return jsonify({"message": "Duplicate sipariş", "error": str(e)}), 400
    except Exception as e:
        app.logger.error(f"❌ Webhook error: {e}")
        return jsonify({"message": "Sunucu hatası", "error": str(e)}), 500

    if not ok:
        return jsonify({"message": "Sipariş kaydedilemedi"}), 500

    try:
        result = execute_with_retry("SELECT id FROM orders WHERE order_uuid = ?", (order_uuid,))
    except Exception as e:
        app.logger.error(f"❌ Webhook SELECT: {e}")
        return jsonify({"message": "Doğrulama hatası", "error": str(e)}), 500

    if not result or len(result) == 0:
        app.logger.error(f"❌ Order not found: {order_uuid}")
        return jsonify({"message": "Sipariş kaydedilemedi"}), 500

    order_id = result[0]["id"]

    try:
        assign_order_to_courier(order_id)
    except Exception as e:
        app.logger.error(f"❌ Assignment error: {e}")

    return jsonify({"message": "Sipariş alındı", "order_uuid": order_uuid}), 201

@app.route("/orders", methods=["GET"])
@admin_required
def admin_list_orders():
    status_filter = request.args.get("status")
    if status_filter:
        result = execute_with_retry("SELECT * FROM orders WHERE status = ? ORDER BY created_at DESC", (status_filter,))
    else:
        result = execute_with_retry("SELECT * FROM orders ORDER BY created_at DESC")

    orders = [row_to_dict(r) for r in result] if result else []
    return jsonify(orders)

@app.route("/orders/<int:order_id>", methods=["PATCH"])
@admin_required
def admin_patch_order(order_id):
    data = request.get_json() or {}
    allowed = ("status", "courier_id", "customer_name", "items", "total_amount", "address", "vendor_id")
    fields, values = [], []
    for k in allowed:
        if k in data:
            fields.append(f"{k} = ?")
            values.append(data[k])
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400

    fields.append("updated_at = ?")
    values.append(format_datetime_for_storage())
    values.append(order_id)

    execute_write_with_retry(f"UPDATE orders SET {', '.join(fields)} WHERE id = ?", values)
    return jsonify({"message": "Sipariş güncellendi"})

@app.route("/orders/<int:order_id>", methods=["DELETE"])
@admin_required
def admin_delete_order(order_id):
    execute_write_with_retry("DELETE FROM orders WHERE id = ?", (order_id,))
    return jsonify({"message": "Sipariş silindi"})

# Restaurant Management
@app.route("/restaurants", methods=["GET"])
@admin_required
def list_restaurants():
    result = execute_with_retry("SELECT * FROM restaurants ORDER BY name")
    restaurants = [row_to_dict(r) for r in result] if result else []
    return jsonify(restaurants)

@app.route("/restaurants", methods=["POST"])
@admin_required
def create_restaurant():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    restaurant_id = data.get("restaurant_id")
    name = data.get("name")
    phone = data.get("phone")

    if not username or not password or not restaurant_id or not name or not phone:
        return jsonify({"message": "username, password, restaurant_id, name, phone gerekli"}), 400

    restaurant_id = str(restaurant_id)

    result = execute_with_retry("SELECT 1 FROM users WHERE username = ?", (username,))
    if result and len(result) > 0:
        return jsonify({"message": "Kullanıcı adı kullanılıyor"}), 400

    result = execute_with_retry("SELECT 1 FROM restaurants WHERE restaurant_id = ? OR name = ?", (restaurant_id, name))
    if result and len(result) > 0:
        return jsonify({"message": "Restaurant ID veya isim kullanılıyor"}), 400

    hashed = hash_password(password)
    try:
        execute_write_with_retry(
            "INSERT INTO users (username, password_hash, role, created_at, restaurant_id) VALUES (?, ?, 'restaurant', ?, ?)",
            (username, hashed, format_datetime_for_storage(), restaurant_id)
        )

        execute_write_with_retry(
            "INSERT INTO restaurants (restaurant_id, name, fee_per_package, address, phone, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (restaurant_id, name, data.get("fee_per_package", 5.0), data.get("address", ""), phone,
             data.get("is_active", 1), format_datetime_for_storage())
        )

        user_row = execute_with_retry(
            "SELECT id, username, role, created_at, restaurant_id FROM users WHERE username = ?", (username,))
        rest_row = execute_with_retry("SELECT * FROM restaurants WHERE restaurant_id = ?", (restaurant_id,))

        return jsonify({
            "message": "Restoran oluşturuldu",
            "user": row_to_dict(user_row[0]) if user_row else None,
            "restaurant": row_to_dict(rest_row[0]) if rest_row else None
        }), 201

    except sqlite3.IntegrityError as e:
        try:
            execute_write_with_retry("DELETE FROM users WHERE username = ?", (username,))
        except:
            pass
        return jsonify({"message": "Integrity error", "error": str(e)}), 400
    except Exception as e:
        try:
            execute_write_with_retry("DELETE FROM users WHERE username = ?", (username,))
            execute_write_with_retry("DELETE FROM restaurants WHERE restaurant_id = ?", (restaurant_id,))
        except:
            pass
        return jsonify({"message": "Sunucu hatası", "error": str(e)}), 500

@app.route("/restaurants/<restaurant_id>", methods=["PATCH"])
@admin_required
def update_restaurant(restaurant_id):
    data = request.get_json() or {}
    allowed = ("restaurant_id", "name", "fee_per_package", "address", "phone", "is_active")
    fields, values = [], []
    for k in allowed:
        if k in data:
            fields.append(f"{k} = ?")
            values.append(data[k])
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400

    values.append(restaurant_id)
    try:
        execute_write_with_retry(f"UPDATE restaurants SET {', '.join(fields)} WHERE restaurant_id = ?", values)
        return jsonify({"message": "Restoran güncellendi"})
    except sqlite3.IntegrityError as e:
        return jsonify({"message": "Integrity error", "error": str(e)}), 400

@app.route("/restaurants/<restaurant_id>", methods=["DELETE"])
@admin_required
def delete_restaurant(restaurant_id):
    execute_write_with_retry("DELETE FROM restaurants WHERE restaurant_id = ?", (restaurant_id,))
    execute_write_with_retry("DELETE FROM users WHERE restaurant_id = ?", (restaurant_id,))
    return jsonify({"message": "Restoran silindi"})

# Neighborhood Management
@app.route("/neighborhoods", methods=["GET"])
@token_required
def list_neighborhoods():
    result = execute_with_retry("SELECT * FROM neighborhoods ORDER BY name")
    neighborhoods = [row_to_dict(r) for r in result] if result else []
    return jsonify(neighborhoods)

@app.route("/neighborhoods", methods=["POST"])
@admin_required
def create_neighborhood():
    data = request.get_json() or {}
    name = data.get("name")

    if not name:
        return jsonify({"message": "Mahalle adı gerekli"}), 400

    try:
        execute_write_with_retry("INSERT INTO neighborhoods (name, created_at) VALUES (?, ?)",
                                 (name, format_datetime_for_storage()))
        result = execute_with_retry("SELECT * FROM neighborhoods WHERE name = ?", (name,))
        neighborhood = row_to_dict(result[0]) if result and len(result) > 0 else None
        return jsonify({"message": "Mahalle oluşturuldu", "neighborhood": neighborhood}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "Bu mahalle zaten var"}), 400

@app.route("/neighborhoods/<int:neighborhood_id>", methods=["DELETE"])
@admin_required
def delete_neighborhood(neighborhood_id):
    execute_write_with_retry("DELETE FROM neighborhoods WHERE id = ?", (neighborhood_id,))
    return jsonify({"message": "Mahalle silindi"})

# Health Check
@app.route("/")
def health():
    istanbul_time = get_istanbul_time().strftime("%Y-%m-%d %H:%M:%S")
    return jsonify({
        "status": "ok", 
        "server_time_utc": datetime.utcnow().isoformat(),
        "server_time_istanbul": istanbul_time
    })

if __name__ == "__main__":
    init_db()
    app.logger.info("🚀 Flask başlatılıyor...")
    check_firebase_setup()

    # SUNUCU SAATİ KONTROLÜ
    now_utc = datetime.utcnow()
    now_istanbul = get_istanbul_time()
    app.logger.info(f"⏰ UTC zamanı: {now_utc.isoformat()}")
    app.logger.info(f"⏰ İstanbul zamanı: {now_istanbul.strftime('%Y-%m-%d %H:%M:%S')}")

    import time
    offset = time.timezone if not time.daylight else time.altzone
    offset_hours = -offset / 3600
    app.logger.info(f"⏰ UTC offset: {offset_hours:+.1f} saat")

    if abs(offset_hours) > 0.5:
        app.logger.warning("⚠️ UYARI: Sunucu UTC değil! Firebase için sorun olabilir.")
        app.logger.warning("   Çözüm: sudo timedatectl set-timezone UTC")

    app.logger.info("✅ Veritabanı hazır")
    app.logger.info("✅ WebSocket aktif")
    app.logger.info("✅ Zamanlayıcı aktif")
    app.logger.info("✅ İstanbul saat dilimi aktif")

    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
