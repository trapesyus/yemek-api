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
        sa_path = "/root/perem-sa-new.json"
        if not os.path.exists(sa_path):
            app.logger.error(f"❌ Service account dosyası bulunamadı: {sa_path}")
        else:
            try:
                with open(sa_path, 'r', encoding='utf-8') as f:
                    key_data = json.load(f)
                
                required_fields = ['type', 'project_id', 'private_key_id', 'private_key', 'client_email']
                missing = [f for f in required_fields if f not in key_data]
                if missing:
                    app.logger.error(f"❌ Service account dosyası eksik alanlar: {missing}")
                elif key_data.get('type') != 'service_account':
                    app.logger.error(f"❌ service account tipi beklenmiyor: {key_data.get('type')}")
                else:
                    pk = key_data.get('private_key','')
                    if '\\n' in pk:
                        app.logger.warning("⚠️ private_key içinde kaçışlı '\\n' bulundu; düzeltiliyor.")
                        key_data['private_key'] = pk.replace('\\n', '\n')
                    
                    if not key_data['private_key'].strip().startswith('-----BEGIN PRIVATE KEY-----'):
                        app.logger.error("❌ private_key PEM formatı beklenmiyor.")
                    else:
                        try:
                            cred = credentials.Certificate(key_data)
                            firebase_app = firebase_admin.initialize_app(cred)
                            app.logger.info(f"✅ Firebase başlatıldı: {sa_path}")
                        except Exception as e:
                            app.logger.exception(f"❌ Firebase initialize hatası: {e}")
                            firebase_app = None
            except Exception as e:
                app.logger.exception(f"❌ Service account okunurken hata: {e}")
    except Exception as e:
        app.logger.exception(f"❌ Genel firebase init hatası: {e}")
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
EMAIL_USERNAME = "hediyecennetti@gmail.com"
EMAIL_PASSWORD = "brvl ucry jgml qnsn"
REPORT_RECIPIENTS = {"email": ["emrulllahtoprak009@gmail.com"]}

# Decorators
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Token formatı hatalı'}), 401
        
        if not token:
            return jsonify({'message': 'Token gerekli'}), 401
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
            request.user_id = data['user_id']
            request.user_role = data['role']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token süresi dolmuş'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Geçersiz token'}), 401
        
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Token formatı hatalı'}), 401
        
        if not token:
            return jsonify({'message': 'Token gerekli'}), 401
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
            if data['role'] != 'admin':
                return jsonify({'message': 'Admin yetkisi gerekli'}), 403
            request.user_id = data['user_id']
            request.user_role = data['role']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token süresi dolmuş'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Geçersiz token'}), 401
        
        return f(*args, **kwargs)
    return decorated

def restaurant_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Token formatı hatalı'}), 401
        
        if not token:
            return jsonify({'message': 'Token gerekli'}), 401
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
            if data['role'] != 'restaurant':
                return jsonify({'message': 'Restoran yetkisi gerekli'}), 403
            request.user_id = data['user_id']
            request.user_role = data['role']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token süresi dolmuş'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Geçersiz token'}), 401
        
        return f(*args, **kwargs)
    return decorated

# Auth Utilities
def generate_token(user_id, role):
    expiration = datetime.utcnow() + timedelta(hours=TOKEN_EXP_HOURS)
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': expiration
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)

def decode_token(token):
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed):
    if isinstance(hashed, str):
        hashed = hashed.encode('utf-8')
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# FCM Fonksiyonları
def validate_fcm_token(fcm_token):
    if not fcm_token:
        return False
    if not firebase_app:
        return True
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
        if 'invalid_grant' in error_str:
            app.logger.error("❌ SUNUCU SAATİ YANLIŞ!")
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
        if 'invalid_grant' in error_str:
            app.logger.error("❌ SUNUCU SAATİ HATASI!")
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
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn

def row_to_dict(row):
    return {k: row[k] for k in row.keys()} if row else None

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

# Total Amount Helper Function
def parse_total_amount(amount):
    """
    Total amount değerini double'a çevirir
    String gelirse temizler ve float'a çevirir
    """
    if amount is None:
        return 0.0
    
    try:
        if isinstance(amount, str):
            # TL, ₺, virgül, boşluk gibi karakterleri temizle
            cleaned = re.sub(r'[^\d.,]', '', str(amount).strip())
            # Virgülü noktaya çevir
            cleaned = cleaned.replace(',', '.')
            # Birden fazla nokta varsa son noktayı kullan
            if cleaned.count('.') > 1:
                parts = cleaned.split('.')
                cleaned = '.'.join(parts[:-1]) + '.' + parts[-1]
            return float(cleaned)
        else:
            return float(amount)
    except (ValueError, TypeError):
        return 0.0

# Courier Assignment Logic
def ensure_courier_performance(courier_id):
    result = execute_with_retry("SELECT 1 FROM courier_performance WHERE courier_id = ?", (courier_id,))
    if not result or len(result) == 0:
        execute_write_with_retry(
            "INSERT INTO courier_performance (courier_id, daily_orders, total_orders, last_assigned) VALUES (?, 0, 0, ?)",
            (courier_id, datetime.utcnow().isoformat())
        )

def set_courier_cooldown(courier_id, neighborhood_id):
    cooldown_until = (datetime.utcnow() + timedelta(minutes=30)).isoformat()
    execute_write_with_retry(
        "UPDATE courier_performance SET cooldown_until = ?, current_neighborhood_id = ? WHERE courier_id = ?",
        (cooldown_until, neighborhood_id, courier_id)
    )

def get_available_couriers(neighborhood_id=None):
    query = """
        SELECT c.*, cp.daily_orders, cp.total_orders, cp.cooldown_until, cp.current_neighborhood_id
        FROM couriers c
        LEFT JOIN courier_performance cp ON c.id = cp.courier_id
        WHERE c.status = 'boşta' 
        AND (cp.cooldown_until IS NULL OR cp.cooldown_until < ?)
    """
    now = datetime.utcnow().isoformat()
    params = [now]
    
    if neighborhood_id:
        query += " AND (cp.current_neighborhood_id IS NULL OR cp.current_neighborhood_id = ?)"
        params.append(neighborhood_id)
    
    query += " ORDER BY cp.daily_orders ASC, cp.total_orders ASC LIMIT 10"
    
    return execute_with_retry(query, params)

def assign_order_to_courier(order_id):
    try:
        result = execute_with_retry("SELECT * FROM orders WHERE id = ?", (order_id,))
        if not result or len(result) == 0:
            return False
        
        order = row_to_dict(result[0])
        if order["courier_id"] is not None:
            return True
        
        couriers = get_available_couriers(order.get("neighborhood_id"))
        if not couriers or len(couriers) == 0:
            couriers = get_available_couriers()
        
        if not couriers or len(couriers) == 0:
            app.logger.warning(f"⚠️ Uygun kurye yok: Order {order_id}")
            return False
        
        courier = row_to_dict(couriers[0])
        courier_id = courier["id"]
        
        now = datetime.utcnow().isoformat()
        
        execute_write_with_retry(
            "UPDATE orders SET courier_id = ?, status = 'teslim alındı', updated_at = ? WHERE id = ?",
            (courier_id, now, order_id)
        )
        
        execute_write_with_retry("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", (courier_id,))
        
        ensure_courier_performance(courier_id)
        execute_write_with_retry(
            "UPDATE courier_performance SET daily_orders = daily_orders + 1, total_orders = total_orders + 1, last_assigned = ? WHERE courier_id = ?",
            (now, courier_id)
        )
        
        if order.get("neighborhood_id"):
            set_courier_cooldown(courier_id, order["neighborhood_id"])
        
        execute_write_with_retry(
            "INSERT INTO delivery_history (order_id, courier_id, status, notes, created_at) VALUES (?, ?, ?, ?, ?)",
            (order_id, courier_id, 'assigned', 'Sistemsel atama', now)
        )
        
        order_data = {
            'order_id': order['id'],
            'order_uuid': order['order_uuid'],
            'customer_name': order['customer_name'],
            'customer_phone': order.get('customer_phone', ''),
            'address': order['address'],
            'total_amount': order['total_amount'],
            'items': order['items']
        }
        
        notify_courier_new_order(courier_id, order_data)
        app.logger.info(f"✅ Sipariş {order_id} -> Kurye {courier_id}")
        return True
        
    except Exception as e:
        app.logger.error(f"❌ Assignment error: {e}")
        return False

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # Tabloları oluştur
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL,
        role TEXT NOT NULL,
        created_at TEXT NOT NULL,
        restaurant_id TEXT
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS couriers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE,
        first_name TEXT,
        last_name TEXT,
        email TEXT UNIQUE,
        phone TEXT UNIQUE,
        status TEXT DEFAULT 'boşta',
        created_at TEXT,
        fcm_token TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_uuid TEXT UNIQUE,
        external_id TEXT,
        vendor_id TEXT,
        customer_name TEXT,
        customer_phone TEXT,
        items TEXT,
        total_amount REAL,
        address TEXT,
        status TEXT DEFAULT 'yeni',
        courier_id INTEGER,
        payload TEXT,
        delivery_failed_reason TEXT,
        created_at TEXT,
        updated_at TEXT,
        neighborhood_id INTEGER,
        FOREIGN KEY (courier_id) REFERENCES couriers(id) ON DELETE SET NULL
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS restaurants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        restaurant_id TEXT UNIQUE,
        name TEXT UNIQUE,
        fee_per_package REAL DEFAULT 5.0,
        address TEXT,
        phone TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TEXT,
        monthly_order_count INTEGER DEFAULT 0,
        total_order_count INTEGER DEFAULT 0
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS delivery_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER,
        courier_id INTEGER,
        status TEXT,
        notes TEXT,
        created_at TEXT,
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
        FOREIGN KEY (courier_id) REFERENCES couriers(id) ON DELETE SET NULL
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
        monthly_orders INTEGER DEFAULT 0,
        total_orders INTEGER DEFAULT 0,
        last_assigned TEXT,
        cooldown_until TEXT,
        current_neighborhood_id INTEGER,
        FOREIGN KEY (courier_id) REFERENCES couriers(id) ON DELETE CASCADE
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS monthly_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_month TEXT UNIQUE,
        courier_stats TEXT,
        restaurant_stats TEXT,
        order_stats TEXT,
        created_at TEXT
    )""")

    conn.commit()

    # Migrations
    migrations = [
        ('users', 'restaurant_id', 'TEXT'),
        ('orders', 'vendor_id', 'TEXT'),
        ('restaurants', 'restaurant_id', 'TEXT'),
        ('courier_performance', 'cooldown_until', 'TEXT'),
        ('courier_performance', 'current_neighborhood_id', 'INTEGER'),
        ('orders', 'customer_phone', 'TEXT'),
        ('restaurants', 'monthly_order_count', 'INTEGER'),
        ('restaurants', 'total_order_count', 'INTEGER'),
        ('courier_performance', 'monthly_orders', 'INTEGER')
    ]

    for table, column, col_type in migrations:
        try:
            if not column_exists(conn, table, column):
                cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
                conn.commit()
        except:
            pass

    # Eğer monthly_orders yoksa ve daily_orders varsa, değerleri kopyala
    try:
        cur.execute("UPDATE courier_performance SET monthly_orders = daily_orders WHERE monthly_orders IS NULL")
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

def reset_monthly_counts():
    """Aylık istatistikleri sıfırla ve rapor oluştur"""
    try:
        # Önce mevcut aylık istatistikleri rapora kaydet
        generate_monthly_report()
        
        # Sıfırlama işlemleri
        conn = get_conn()
        cur = conn.cursor()
        
        # Kurye aylık siparişleri sıfırla
        cur.execute("UPDATE courier_performance SET monthly_orders = 0")
        
        # Restoran aylık siparişleri sıfırla
        cur.execute("UPDATE restaurants SET monthly_order_count = 0")
        
        conn.commit()
        conn.close()
        
        app.logger.info("✅ Aylık istatistikler sıfırlandı ve rapor oluşturuldu")
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
    """Aylık rapor verilerini oluştur ve kaydet"""
    try:
        today = datetime.utcnow()
        first_day = today.replace(day=1)
        last_month = first_day - timedelta(days=1)
        report_month = last_month.strftime("%Y-%m")
        
        start_date = last_month.replace(day=1)
        end_date = first_day
        
        # Kurye istatistikleri
        courier_stats = execute_with_retry("""
            SELECT c.id, c.first_name, c.last_name, cp.monthly_orders, cp.total_orders
            FROM couriers c
            JOIN courier_performance cp ON c.id = cp.courier_id
            WHERE cp.monthly_orders > 0
            ORDER BY cp.monthly_orders DESC
        """)
        
        # Restoran istatistikleri
        restaurant_stats = execute_with_retry("""
            SELECT restaurant_id, name, monthly_order_count, total_order_count
            FROM restaurants 
            WHERE monthly_order_count > 0
            ORDER BY monthly_order_count DESC
        """)
        
        # Sipariş istatistikleri
        order_stats = execute_with_retry("""
            SELECT status, COUNT(*) as count 
            FROM orders 
            WHERE created_at >= ? AND created_at < ?
            GROUP BY status
        """, (start_date.isoformat(), end_date.isoformat()))
        
        # Raporu veritabanına kaydet
        report_data = {
            'courier_stats': [row_to_dict(row) for row in courier_stats] if courier_stats else [],
            'restaurant_stats': [row_to_dict(row) for row in restaurant_stats] if restaurant_stats else [],
            'order_stats': {row['status']: row['count'] for row in order_stats} if order_stats else {},
            'report_month': report_month,
            'generated_at': datetime.utcnow().isoformat()
        }
        
        execute_write_with_retry("""
            INSERT OR REPLACE INTO monthly_reports (report_month, courier_stats, restaurant_stats, order_stats, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            report_month,
            json.dumps(report_data['courier_stats'], ensure_ascii=False),
            json.dumps(report_data['restaurant_stats'], ensure_ascii=False),
            json.dumps(report_data['order_stats'], ensure_ascii=False),
            report_data['generated_at']
        ))
        
        return report_data
        
    except Exception as e:
        app.logger.error(f"❌ Rapor oluşturma hatası: {e}")
        return None

def format_report_for_email(report_data):
    """Rapor verilerini email formatına dönüştür"""
    if not report_data:
        return "Rapor oluşturulamadı", "Hata"
    
    month = report_data.get('report_month', 'Bilinmeyen Ay')
    subject = f"Aylık Teslimat Raporu - {month}"
    
    # Kurye istatistikleri tablosu
    courier_table = ""
    if report_data.get('courier_stats'):
        courier_table = "<h3>Kurye Performansları</h3><table border='1' style='border-collapse: collapse; width: 100%;'><tr><th>Kurye</th><th>Aylık Teslimat</th><th>Toplam Teslimat</th></tr>"
        for courier in report_data['courier_stats']:
            courier_table += f"<tr><td>{courier.get('first_name', '')} {courier.get('last_name', '')}</td><td style='text-align: center;'>{courier.get('monthly_orders', 0)}</td><td style='text-align: center;'>{courier.get('total_orders', 0)}</td></tr>"
        courier_table += "</table>"
    
    # Restoran istatistikleri tablosu
    restaurant_table = ""
    if report_data.get('restaurant_stats'):
        restaurant_table = "<h3>Restoran Siparişleri</h3><table border='1' style='border-collapse: collapse; width: 100%;'><tr><th>Restoran</th><th>Aylık Sipariş</th><th>Toplam Sipariş</th></tr>"
        for restaurant in report_data['restaurant_stats']:
            restaurant_table += f"<tr><td>{restaurant.get('name', '')}</td><td style='text-align: center;'>{restaurant.get('monthly_order_count', 0)}</td><td style='text-align: center;'>{restaurant.get('total_order_count', 0)}</td></tr>"
        restaurant_table += "</table>"
    
    # Sipariş durumları
    order_stats = ""
    if report_data.get('order_stats'):
        order_stats = "<h3>Sipariş Durumları</h3><table border='1' style='border-collapse: collapse; width: 100%;'><tr><th>Durum</th><th>Sayı</th></tr>"
        for status, count in report_data['order_stats'].items():
            order_stats += f"<tr><td>{status}</td><td style='text-align: center;'>{count}</td></tr>"
        order_stats += "</table>"
    
    html = f"""
    <html>
        <body>
            <h2>Aylık Teslimat Raporu - {month}</h2>
            <p>Rapor oluşturulma tarihi: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
            {courier_table}
            <br>
            {restaurant_table}
            <br>
            {order_stats}
            <br>
            <p>Bu rapor otomatik olarak oluşturulmuştur.</p>
        </body>
    </html>
    """
    
    return html, subject

def distribute_monthly_report():
    """Aylık raporu oluştur ve email olarak gönder"""
    try:
        report_data = generate_monthly_report()
        if not report_data:
            return {'success': False, 'error': 'Rapor oluşturulamadı'}
        
        html, subject = format_report_for_email(report_data)
        
        count = 0
        for email in REPORT_RECIPIENTS.get('email', []):
            if send_email(email, subject, html):
                count += 1
        
        # İstatistikleri sıfırla
        reset_monthly_counts()
        
        return {'success': True, 'email_sent': count, 'report_month': report_data.get('report_month')}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def schedule_monthly_report():
    """Aylık rapor için zamanlayıcı kur"""
    try:
        # Her ayın 1'inde saat 00:05'te çalıştır
        scheduler.add_job(
            distribute_monthly_report, 
            'cron', 
            day=1, 
            hour=0, 
            minute=5,
            id='monthly_report',
            replace_existing=True
        )
        app.logger.info("✅ Aylık rapor zamanlayıcısı eklendi")
    except Exception as e:
        app.logger.error(f"❌ Zamanlayıcı hatası: {e}")

# Zamanlayıcıları başlat
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
        # GEÇİCİ FIX: Validation'ı atla, sadece kaydet
        if firebase_app:
            app.logger.warning(f"⚠️ Token kaydediliyor (validation atlandı): {fcm_token[:15]}...")

        # Token'ı kaydet
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
                 datetime.utcnow().isoformat())
            )

    if role == "courier":
        phone = data.get("phone")
        if not phone:
            return jsonify({"message": "phone gerekli"}), 400

    # ÖNEMLİ DÜZELTME: Silinmiş kullanıcıları kontrol et
    existing = execute_with_retry("SELECT id FROM users WHERE username = ?", (username,))
    if existing and len(existing) > 0:
        return jsonify({"message": "Kullanıcı adı kullanılıyor"}), 400

    # ÖNEMLİ DÜZELTME: Email ve phone kontrolü - sadece aktif kullanıcılar için
    if role == "courier":
        email = data.get("email")
        if email:
            existing_email = execute_with_retry("SELECT 1 FROM couriers WHERE email = ?", (email,))
            if existing_email and len(existing_email) > 0:
                return jsonify({"message": "Email adresi kullanılıyor"}), 400
        
        existing_phone = execute_with_retry("SELECT 1 FROM couriers WHERE phone = ?", (phone,))
        if existing_phone and len(existing_phone) > 0:
            return jsonify({"message": "Telefon numarası kullanılıyor"}), 400

    hashed = hash_password(password)
    try:
        if role == "restaurant":
            execute_write_with_retry(
                "INSERT INTO users (username, password_hash, role, created_at, restaurant_id) VALUES (?, ?, ?, ?, ?)",
                (username, hashed, role, datetime.utcnow().isoformat(), restaurant_id)
            )
        else:
            execute_write_with_retry(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username, hashed, role, datetime.utcnow().isoformat())
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
                 datetime.utcnow().isoformat())
            )
            result = execute_with_retry("SELECT * FROM couriers WHERE user_id = ?", (user_id,))
            if result and len(result) > 0:
                courier_obj = row_to_dict(result[0])

    except sqlite3.IntegrityError as e:
        # ÖNEMLİ DÜZELTME: Hata durumunda oluşan kullanıcıyı temizle
        execute_write_with_retry("DELETE FROM users WHERE username = ?", (username,))
        return jsonify({"message": "Kullanıcı adı, email veya telefon zaten var", "error": str(e)}), 400

    user_resp = {"id": user_id, "username": username, "role": role, "created_at": datetime.utcnow().isoformat()}
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
        "created_at": user_row["created_at"]
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

# Yeni Raporlama Endpoint'leri
@app.route("/admin/reports/monthly", methods=["GET"])
@admin_required
def get_monthly_reports():
    """Kayıtlı aylık raporları getir"""
    try:
        result = execute_with_retry(
            "SELECT report_month, courier_stats, restaurant_stats, order_stats, created_at FROM monthly_reports ORDER BY created_at DESC"
        )
        
        reports = []
        for row in result:
            report = row_to_dict(row)
            # JSON string'lerini dict'e çevir
            report['courier_stats'] = json.loads(report['courier_stats']) if report['courier_stats'] else []
            report['restaurant_stats'] = json.loads(report['restaurant_stats']) if report['restaurant_stats'] else []
            report['order_stats'] = json.loads(report['order_stats']) if report['order_stats'] else {}
            reports.append(report)
            
        return jsonify(reports)
    except Exception as e:
        app.logger.error(f"❌ Rapor getirme hatası: {e}")
        return jsonify({"message": "Raporlar getirilemedi", "error": str(e)}), 500

@app.route("/admin/reports/current-stats", methods=["GET"])
@admin_required
def get_current_stats():
    """Mevcut ayın istatistiklerini getir"""
    try:
        # Kurye istatistikleri
        courier_stats = execute_with_retry("""
            SELECT c.id, c.first_name, c.last_name, cp.monthly_orders, cp.total_orders, cp.daily_orders
            FROM couriers c
            JOIN courier_performance cp ON c.id = cp.courier_id
            ORDER BY cp.monthly_orders DESC
        """)
        
        # Restoran istatistikleri
        restaurant_stats = execute_with_retry("""
            SELECT restaurant_id, name, monthly_order_count, total_order_count
            FROM restaurants 
            ORDER BY monthly_order_count DESC
        """)
        
        # Mevcut ayın sipariş istatistikleri
        current_month = datetime.utcnow().strftime("%Y-%m")
        first_day = datetime.utcnow().replace(day=1)
        next_month = (first_day + timedelta(days=32)).replace(day=1)
        
        order_stats = execute_with_retry("""
            SELECT status, COUNT(*) as count 
            FROM orders 
            WHERE created_at >= ? AND created_at < ?
            GROUP BY status
        """, (first_day.isoformat(), next_month.isoformat()))
        
        return jsonify({
            'courier_stats': [row_to_dict(row) for row in courier_stats] if courier_stats else [],
            'restaurant_stats': [row_to_dict(row) for row in restaurant_stats] if restaurant_stats else [],
            'order_stats': {row['status']: row['count'] for row in order_stats} if order_stats else {},
            'current_month': current_month
        })
        
    except Exception as e:
        app.logger.error(f"❌ İstatistik getirme hatası: {e}")
        return jsonify({"message": "İstatistikler getirilemedi", "error": str(e)}), 500

@app.route("/admin/reports/generate-test", methods=["POST"])
@admin_required
def generate_test_report():
    """Test amaçlı rapor oluştur"""
    try:
        report_data = generate_monthly_report()
        if report_data:
            return jsonify({
                "message": "Test raporu oluşturuldu",
                "report": report_data
            })
        else:
            return jsonify({"message": "Rapor oluşturulamadı"}), 500
    except Exception as e:
        return jsonify({"message": "Test raporu hatası", "error": str(e)}), 500

# Restoran sipariş sayacı güncelleme
def update_restaurant_order_count(vendor_id):
    """Restoranın sipariş sayacını güncelle"""
    try:
        if vendor_id:
            execute_write_with_retry("""
                UPDATE restaurants 
                SET monthly_order_count = monthly_order_count + 1, 
                    total_order_count = total_order_count + 1 
                WHERE restaurant_id = ?
            """, (vendor_id,))
    except Exception as e:
        app.logger.error(f"❌ Restoran sayac güncelleme hatası: {e}")

# Admin Endpoints (mevcut endpoint'ler aynı kalacak, sadece gerekli güncellemeler yapıldı)
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

    # ÖNEMLİ DÜZELTME: Telefon kontrolü
    existing_phone = execute_with_retry("SELECT 1 FROM couriers WHERE phone = ?", (phone,))
    if existing_phone and len(existing_phone) > 0:
        return jsonify({"message": "Telefon numarası kullanılıyor"}), 400

    hashed = hash_password(password)
    try:
        execute_write_with_retry(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'courier', ?)",
            (username, hashed, datetime.utcnow().isoformat())
        )

        result = execute_with_retry("SELECT id FROM users WHERE username = ?", (username,))
        user_id = result[0]["id"]

        execute_write_with_retry(
            "INSERT INTO couriers (user_id, first_name, last_name, email, phone, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, data.get("first_name", ""), data.get("last_name", ""), data.get("email"), phone,
             datetime.utcnow().isoformat())
        )

        result = execute_with_retry("SELECT * FROM couriers WHERE user_id = ?", (user_id,))
        courier_obj = row_to_dict(result[0]) if result and len(result) > 0 else None

        return jsonify({
            "message": "Kurye oluşturuldu",
            "user": {"id": user_id, "username": username, "role": "courier"},
            "courier": courier_obj
        }), 201

    except sqlite3.IntegrityError as e:
        # Hata durumunda temizlik
        execute_write_with_retry("DELETE FROM users WHERE username = ?", (username,))
        return jsonify({"message": "IntegrityError", "error": str(e)}), 400

# Order webhook endpoint'inde restoran sayacı güncelleme
@app.route("/webhooks/yemeksepeti", methods=["POST"])
def webhook_yemeksepeti():
    data = request.get_json() or {}
    external_id = data.get("external_id") or data.get("order_id") or data.get("id")
    vendor_id = str(data.get("vendor_id")) if data.get("vendor_id") else None
    customer_name = data.get("customer_name") or data.get("customer")
    customer_phone = data.get("customer_phone") or data.get("phone") or data.get("customer_phone_number")
    items = data.get("items")
    
    # TOTAL AMOUNT DÜZENLEMESİ - STRING'DEN DOUBLE'A ÇEVİR
    total = parse_total_amount(data.get("total") or data.get("total_amount") or 0)
    
    address = data.get("address") or data.get("customer_address")
    payload = json.dumps(data, ensure_ascii=False)
    created = datetime.utcnow().isoformat()
    order_uuid = f"o-{int(datetime.utcnow().timestamp() * 1000)}"

    try:
        ok = execute_write_with_retry(
            "INSERT INTO orders (order_uuid, external_id, vendor_id, customer_name, customer_phone, items, total_amount, address, payload, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (order_uuid, external_id, vendor_id, customer_name, customer_phone, str(items), total, address, payload, created, created)
        )
        
        # Restoran sipariş sayacını güncelle
        if vendor_id:
            update_restaurant_order_count(vendor_id)
            
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

# Diğer endpoint'ler aynı kalacak, sadece raporlama endpoint'leri eklendi
@app.route("/admin/trigger-monthly-report", methods=["POST"])
@admin_required
def trigger_monthly_report():
    result = distribute_monthly_report()
    if result['success']:
        return jsonify({"message": "Rapor gönderildi", "email_sent": result.get('email_sent', 0), "report_month": result.get('report_month')})
    else:
        return jsonify({"message": "Rapor hatası", "error": result.get('error')}), 500

# Health Check
@app.route("/")
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})

if __name__ == "__main__":
    init_db()
    app.logger.info("🚀 Flask başlatılıyor...")
    check_firebase_setup()

    # SUNUCU SAATİ KONTROLÜ
    now_utc = datetime.utcnow()
    now_local = datetime.now()
    app.logger.info(f"⏰ UTC zamanı: {now_utc.isoformat()}")
    app.logger.info(f"⏰ Local zamanı: {now_local.isoformat()}")

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
    app.logger.info("✅ Raporlama sistemi aktif")

    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
