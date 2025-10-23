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
import traceback
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from apscheduler.schedulers.background import BackgroundScheduler

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

# Günlük kurye performans sıfırlama için zamanlayıcı
scheduler = BackgroundScheduler()

# Email konfigürasyonu (environment variables'dan alınması önerilir)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USERNAME = "your_email@gmail.com"  # Gerçek email adresinizle değiştirin
EMAIL_PASSWORD = "your_app_password"     # Gmail App Password ile değiştirin

# FCM Server Key (Firebase Console'dan alınacak)
FCM_SERVER_KEY = "94a98412778ae9aa36e3428362c797963f4189b4"  # Environment variable olarak saklayın

# Rapor alıcıları
REPORT_RECIPIENTS = {
    "email": ["admin@firma.com", "rapor@firma.com"]  # Email adreslerinizle değiştirin
}

# ---------------- FCM Bildirim Fonksiyonları ----------------
def send_fcm_notification(fcm_token, title, body, data=None):
    """FCM ile push bildirim gönderir"""
    if not fcm_token:
        print("FCM token bulunamadı")
        return False
        
    try:
        url = 'https://fcm.googleapis.com/fcm/send'
        headers = {
            'Authorization': f'key={FCM_SERVER_KEY}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'to': fcm_token,
            'notification': {
                'title': title,
                'body': body,
                'sound': 'default',
                'click_action': 'FLUTTER_NOTIFICATION_CLICK'
            },
            'data': data or {}
        }
        
        response = requests.post(url, json=payload, headers=headers)
        
        if response.status_code == 200:
            print(f"FCM bildirimi gönderildi: {fcm_token}")
            return True
        else:
            print(f"FCM hatası: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"FCM gönderme hatası: {e}")
        return False

# ---------------- DB ----------------
def get_conn():
    conn = sqlite3.connect(DB_NAME, timeout=30)
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.row_factory = sqlite3.Row
    return conn

def row_to_dict(row):
    if not row:
        return None
    return {k: row[k] for k in row.keys()}

def column_exists(conn, table, column):
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in cur.fetchall()]
    return column in cols

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # Users table (restaurant_id as TEXT)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash BLOB,
        role TEXT,
        created_at TEXT,
        restaurant_id TEXT
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

    # Orders table (vendor_id stored as TEXT to match restaurant_id string)
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

    # Restaurants table: integer internal id + external string restaurant_id
    cur.execute("""
    CREATE TABLE IF NOT EXISTS restaurants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        restaurant_id TEXT UNIQUE,
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
        daily_orders INTEGER DEFAULT 0,
        total_orders INTEGER DEFAULT 0,
        last_assigned TEXT,
        cooldown_until TEXT,
        current_neighborhood_id INTEGER,
        FOREIGN KEY (courier_id) REFERENCES couriers (id)
    )
    """)

    conn.commit()

    # Backfill / migration for older DBs: ensure columns exist (best-effort)
    try:
        if not column_exists(conn, 'users', 'restaurant_id'):
            cur.execute("ALTER TABLE users ADD COLUMN restaurant_id TEXT")
            conn.commit()
    except Exception:
        pass

    try:
        if not column_exists(conn, 'orders', 'vendor_id'):
            cur.execute("ALTER TABLE orders ADD COLUMN vendor_id TEXT")
            conn.commit()
    except Exception:
        pass

    try:
        if not column_exists(conn, 'restaurants', 'restaurant_id'):
            cur.execute("ALTER TABLE restaurants ADD COLUMN restaurant_id TEXT")
            conn.commit()
    except Exception:
        pass

    try:
        if not column_exists(conn, 'courier_performance', 'cooldown_until'):
            cur.execute("ALTER TABLE courier_performance ADD COLUMN cooldown_until TEXT")
            conn.commit()
    except Exception:
        pass

    try:
        if not column_exists(conn, 'courier_performance', 'current_neighborhood_id'):
            cur.execute("ALTER TABLE courier_performance ADD COLUMN current_neighborhood_id INTEGER")
            conn.commit()
    except Exception:
        pass

    conn.close()

# ---------------- Günlük Kurye Performans Sıfırlama ----------------
def reset_daily_orders():
    """Her gün gece yarısı kuryelerin günlük sipariş sayılarını sıfırla"""
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("UPDATE courier_performance SET daily_orders = 0")
        conn.commit()
        conn.close()
        print("Günlük kurye sipariş sayıları sıfırlandı")
    except Exception as e:
        print(f"Günlük sıfırlama hatası: {e}")

# ---------------- Aylık Kurye Performans Sıfırlama ----------------
def reset_monthly_orders():
    """Her ayın başında kuryelerin aylık sipariş sayılarını sıfırla"""
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("UPDATE courier_performance SET daily_orders = 0, total_orders = 0")
        conn.commit()
        conn.close()
        print("Aylık kurye sipariş sayıları sıfırlandı")
    except Exception as e:
        print(f"Aylık sıfırlama hatası: {e}")

# ---------------- Email Gönderme Fonksiyonu ----------------
def send_email(to_email, subject, html_content):
    """Email gönderir"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = EMAIL_USERNAME
        msg['To'] = to_email
        
        # HTML içeriği ekle
        html_part = MIMEText(html_content, 'html')
        msg.attach(html_part)
        
        # SMTP bağlantısı
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        print(f"Email gönderildi: {to_email}")
        return True
        
    except Exception as e:
        print(f"Email gönderme hatası ({to_email}): {e}")
        return False

# ---------------- Aylık Rapor Fonksiyonları ----------------
def generate_monthly_report():
    """Aylık rapor verilerini oluşturur"""
    try:
        # Önceki ayın başlangıç ve bitiş tarihleri
        today = datetime.utcnow()
        first_day_of_month = today.replace(day=1)
        last_day_of_previous_month = first_day_of_month - timedelta(days=1)
        first_day_of_previous_month = last_day_of_previous_month.replace(day=1)
        
        start_date = first_day_of_previous_month.strftime("%Y-%m-%d")
        end_date = last_day_of_previous_month.strftime("%Y-%m-%d")
        
        print(f"Aylık rapor oluşturuluyor: {start_date} - {end_date}")
        
        # Status counts
        result = execute_with_retry("""
            SELECT status, COUNT(*) as cnt FROM orders
            WHERE created_at >= ? AND created_at < ? GROUP BY status
        """, (start_date, f"{end_date} 23:59:59"))

        status_counts = {row["status"]: row["cnt"] for row in result} if result else {}

        # Courier performance
        result = execute_with_retry("""
            SELECT courier_id, COUNT(*) as delivered_count FROM orders
            WHERE created_at >= ? AND created_at < ? AND status = 'teslim edildi' GROUP BY courier_id
        """, (start_date, f"{end_date} 23:59:59"))

        perf = []
        if result:
            for row in result:
                courier_id = row["courier_id"]
                cnt = row["delivered_count"]
                if not courier_id:
                    name = "Atanmamış"
                else:
                    r = execute_with_retry("SELECT first_name, last_name FROM couriers WHERE id = ?", (courier_id,))
                    if r and len(r) > 0:
                        r_dict = row_to_dict(r[0])
                        name = f"{r_dict['first_name']} {r_dict['last_name']}"
                    else:
                        name = "Bilinmeyen Kurye"
                perf.append({"courier_id": courier_id, "courier_name": name, "delivered_orders": cnt})

        # Restaurant performance (vendor_id is string -> match restaurants.restaurant_id)
        result = execute_with_retry("""
            SELECT vendor_id, COUNT(*) as order_count FROM orders
            WHERE created_at >= ? AND created_at < ? GROUP BY vendor_id
        """, (start_date, f"{end_date} 23:59:59"))

        rest_perf = []
        if result:
            for row in result:
                vendor_id = row["vendor_id"]
                cnt = row["order_count"]
                if vendor_id:
                    r = execute_with_retry("SELECT name FROM restaurants WHERE restaurant_id = ?", (vendor_id,))
                    if r and len(r) > 0:
                        name = row_to_dict(r[0])['name']
                    else:
                        name = "Bilinmeyen Restoran"
                else:
                    name = "Bilinmeyen Restoran"
                rest_perf.append({"vendor_id": vendor_id, "restaurant_name": name, "order_count": cnt})

        # Courier distribution
        result = execute_with_retry("""
            SELECT c.id, c.first_name, c.last_name, COALESCE(cp.daily_orders, 0) as daily_orders
            FROM couriers c
            LEFT JOIN courier_performance cp ON c.id = cp.courier_id
            ORDER BY daily_orders DESC
        """)

        courier_dist = []
        if result:
            for row in result:
                row_dict = row_to_dict(row)
                courier_dist.append({
                    "courier_id": row_dict["id"],
                    "courier_name": f"{row_dict['first_name']} {row_dict['last_name']}",
                    "daily_orders": row_dict["daily_orders"]
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
                row_dict = row_to_dict(row)
                neighborhood_dist.append({
                    "neighborhood_name": row_dict["name"],
                    "order_count": row_dict["order_count"]
                })

        return {
            'success': True,
            'period': {'start': start_date, 'end': end_date},
            'status_counts': status_counts,
            'courier_performance': perf,
            'restaurant_performance': rest_perf,
            'courier_distribution': courier_dist,
            'neighborhood_distribution': neighborhood_dist
        }
        
    except Exception as e:
        print(f"Rapor oluşturma hatası: {e}")
        return {
            'success': False,
            'error': str(e)
        }

def format_report_for_email(report_data):
    """Raporu email formatında formatlar"""
    try:
        if not report_data.get('success'):
            return f"Rapor oluşturulamadı: {report_data.get('error', 'Bilinmeyen hata')}", "Hata"
        
        data = report_data
        period = data['period']
        start_date = period['start']
        end_date = period['end']
        
        subject = f"Aylık Rapor - {start_date} - {end_date}"
        
        # HTML içerik oluştur
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; }}
                .section-title {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
                .success {{ color: green; }}
                .warning {{ color: orange; }}
                .error {{ color: red; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📊 Aylık Rapor</h1>
                <p><strong>Dönem:</strong> {start_date} - {end_date}</p>
                <p><strong>Oluşturulma Tarihi:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
            </div>
        """
        
        # Sipariş durumları
        status_counts = data.get('status_counts', {})
        total_orders = sum(status_counts.values())
        
        html_content += f"""
            <div class="section">
                <h2 class="section-title">📦 Sipariş Durumları</h2>
                <p><strong>Toplam Sipariş:</strong> {total_orders}</p>
                <table>
                    <tr><th>Durum</th><th>Sayı</th><th>Yüzde</th></tr>
        """
        
        for status, count in status_counts.items():
            percentage = (count / total_orders * 100) if total_orders > 0 else 0
            html_content += f"<tr><td>{status}</td><td>{count}</td><td>{percentage:.1f}%</td></tr>"
        
        html_content += "</table></div>"
        
        # Kurye performansı
        html_content += """
            <div class="section">
                <h2 class="section-title">🚴 Kurye Performansı</h2>
                <table>
                    <tr><th>Kurye</th><th>Teslim Edilen Sipariş</th></tr>
        """
        
        courier_perf = data.get('courier_performance', [])
        for courier in courier_perf:
            html_content += f"<tr><td>{courier.get('courier_name', 'Bilinmeyen')}</td><td>{courier.get('delivered_orders', 0)}</td></tr>"
        
        html_content += "</table></div>"
        
        # Restoran performansı
        html_content += """
            <div class="section">
                <h2 class="section-title">🏪 Restoran Performansı</h2>
                <table>
                    <tr><th>Restoran</th><th>Sipariş Sayısı</th></tr>
        """
        
        restaurant_perf = data.get('restaurant_performance', [])
        for restaurant in restaurant_perf:
            html_content += f"<tr><td>{restaurant.get('restaurant_name', 'Bilinmeyen')}</td><td>{restaurant.get('order_count', 0)}</td></tr>"
        
        html_content += """
                </table>
            </div>
            <div class="section">
                <p><em>Bu rapor otomatik olarak oluşturulmuştur. Rapor gönderildikten sonra kurye performans verileri sıfırlanmıştır.</em></p>
            </div>
        </body>
        </html>
        """
        
        return html_content, subject
        
    except Exception as e:
        print(f"Email formatlama hatası: {e}")
        return f"<p>Rapor formatlama hatası: {str(e)}</p>", "Rapor Hatası"

def distribute_monthly_report():
    """Aylık raporu Email ile dağıtır ve verileri sıfırlar"""
    try:
        print("Aylık rapor dağıtımı başlatılıyor...")
        
        # Raporu oluştur
        report_data = generate_monthly_report()
        
        # Email gönder
        email_html, email_subject = format_report_for_email(report_data)
        email_success_count = 0
        
        for email_address in REPORT_RECIPIENTS.get('email', []):
            try:
                if send_email(email_address, email_subject, email_html):
                    email_success_count += 1
                else:
                    print(f"Email gönderilemedi: {email_address}")
            except Exception as e:
                print(f"Email gönderme hatası ({email_address}): {e}")
                # Hata yakalandı, işleme devam et
        
        # Rapor başarıyla gönderildiyse verileri sıfırla
        if email_success_count > 0:
            try:
                reset_monthly_orders()
                print("Aylık kurye performans verileri sıfırlandı")
            except Exception as e:
                print(f"Veri sıfırlama hatası: {e}")
        
        # Sonuçları logla
        print(f"Rapor dağıtımı tamamlandı:")
        print(f"- Email: {email_success_count}/{len(REPORT_RECIPIENTS.get('email', []))} başarılı")
        
        return {
            'success': True,
            'email_sent': email_success_count,
            'total_recipients': len(REPORT_RECIPIENTS.get('email', [])),
            'data_reset': email_success_count > 0
        }
        
    except Exception as e:
        print(f"Rapor dağıtım hatası: {e}")
        return {
            'success': False,
            'error': str(e)
        }

# ---------------- Aylık Rapor Zamanlayıcı ----------------
def schedule_monthly_report():
    """Her ayın son günü saat 23:00'te rapor gönderimini planlar"""
    try:
        scheduler.add_job(
            distribute_monthly_report,
            'cron',
            day='last',  # Ayın son günü
            hour=23,     # Saat 23:00
            minute=0,
            id='monthly_report',
            replace_existing=True
        )
        print("Aylık rapor zamanlayıcısı eklendi: Her ayın son günü saat 23:00")
    except Exception as e:
        print(f"Zamanlayıcı ekleme hatası: {e}")

# Zamanlayıcıyı başlat
scheduler.add_job(reset_daily_orders, 'cron', hour=0, minute=0)  # Her gün gece yarısı
scheduler.start()

# Uygulama başlatılırken zamanlayıcıyı başlat
schedule_monthly_report()

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
        courier_id = str(data.get('courier_id'))
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

# ---------------- Bildirim Fonksiyonları ----------------
def notify_courier_new_order(courier_id, order_data):
    """Kuryeye hem WebSocket hem FCM bildirimi gönderir"""
    try:
        courier_id = str(courier_id)
        websocket_sent = False
        fcm_sent = False
        
        # 1. Önce WebSocket bildirimi dene
        if courier_id in courier_connections:
            socketio.emit('new_order', order_data, room=f'courier_{courier_id}')
            print(f"WebSocket bildirimi gönderildi: courier {courier_id}")
            websocket_sent = True
        
        # 2. FCM bildirimi gönder (WebSocket başarısız olsa da)
        result = execute_with_retry("SELECT fcm_token FROM couriers WHERE id = ?", (courier_id,))
        if result and len(result) > 0:
            courier = row_to_dict(result[0])
            fcm_token = courier.get('fcm_token')
            
            if fcm_token:
                title = "Yeni Sipariş 🚴"
                body = f"{order_data.get('customer_name', 'Müşteri')} - {order_data.get('address', 'Adres')}"
                
                # FCM data payload
                fcm_data = {
                    'type': 'new_order',
                    'order_id': str(order_data.get('order_id')),
                    'order_uuid': order_data.get('order_uuid', ''),
                    'customer_name': order_data.get('customer_name', ''),
                    'address': order_data.get('address', ''),
                    'total_amount': str(order_data.get('total_amount', 0)),
                    'items': order_data.get('items', ''),
                    'click_action': 'FLUTTER_NOTIFICATION_CLICK'
                }
                
                fcm_sent = send_fcm_notification(fcm_token, title, body, fcm_data)
        
        return websocket_sent or fcm_sent
        
    except Exception as e:
        print(f"Bildirim gönderme hatası: {e}")
        return False

def notify_courier_reassignment(courier_id, order_id, action):
    """Kuryeye yeniden atama bildirimi gönderir"""
    try:
        courier_id = str(courier_id)
        
        # WebSocket bildirimi
        if courier_id in courier_connections:
            notification_data = {
                'order_id': order_id,
                'action': action,
                'message': 'Bir sipariş size yeniden atandı' if action == 'removed' else 'Yeni sipariş atandı'
            }
            socketio.emit('order_reassigned', notification_data, room=f'courier_{courier_id}')
            print(f"Reassignment WebSocket bildirimi: courier {courier_id}")
        
        # FCM bildirimi
        result = execute_with_retry("SELECT fcm_token FROM couriers WHERE id = ?", (courier_id,))
        if result and len(result) > 0:
            courier = row_to_dict(result[0])
            fcm_token = courier.get('fcm_token')
            
            if fcm_token:
                if action == 'removed':
                    title = "Sipariş Yeniden Atandı"
                    body = "Bir sipariş başka kuryeye atandı"
                else:
                    title = "Yeni Sipariş Atandı"
                    body = "Size yeni bir sipariş atandı"
                
                fcm_data = {
                    'type': 'reassignment',
                    'order_id': str(order_id),
                    'action': action,
                    'click_action': 'FLUTTER_NOTIFICATION_CLICK'
                }
                
                send_fcm_notification(fcm_token, title, body, fcm_data)
        
        return True
        
    except Exception as e:
        print(f"Yeniden atama bildirimi hatası: {e}")
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
                time.sleep(0.1 * (attempt + 1))
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
                time.sleep(0.1 * (attempt + 1))
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

def restaurant_required(f):
    @wraps(f)
    @token_required
    def wrapped(*args, **kwargs):
        if getattr(request, "user_role", None) != "restaurant":
            return jsonify({"message": "Restoran yetkisi gerekli"}), 403
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

def is_courier_in_cooldown(courier_id, neighborhood_id):
    """Kuryenin aynı mahallede cooldown süresinde olup olmadığını kontrol et"""
    result = execute_with_retry(
        "SELECT cooldown_until FROM courier_performance WHERE courier_id = ? AND current_neighborhood_id = ?",
        (courier_id, neighborhood_id)
    )
    
    if result and len(result) > 0:
        cooldown_until = result[0]["cooldown_until"]
        if cooldown_until:
            cooldown_time = datetime.fromisoformat(cooldown_until)
            if cooldown_time > datetime.utcnow():
                return True  # Hala cooldown süresinde
    return False

def set_courier_cooldown(courier_id, neighborhood_id):
    """Kuryeyi 3 dakika cooldown'a al"""
    cooldown_until = (datetime.utcnow() + timedelta(minutes=3)).isoformat()
    execute_write_with_retry(
        "UPDATE courier_performance SET cooldown_until = ?, current_neighborhood_id = ? WHERE courier_id = ?",
        (cooldown_until, neighborhood_id, courier_id)
    )

def assign_order_to_courier(order_id):
    # Sipariş bilgilerini al
    result = execute_with_retry("SELECT * FROM orders WHERE id = ?", (order_id,))
    if not result or len(result) == 0:
        return False

    order = row_to_dict(result[0])

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

    # Öncelikle: Aynı mahallede cooldown süresindeki kuryeleri kontrol et
    if neighborhood_id:
        result = execute_with_retry("""
            SELECT cp.courier_id, c.status
            FROM courier_performance cp
            JOIN couriers c ON cp.courier_id = c.id
            WHERE cp.current_neighborhood_id = ? 
            AND cp.cooldown_until > ?
            AND c.status IN ('boşta', 'teslimatta')
        """, (neighborhood_id, datetime.utcnow().isoformat()))
        
        if result and len(result) > 0:
            # Cooldown'daki kuryelerden en az siparişi olanı seç
            for courier_row in result:
                courier = row_to_dict(courier_row)
                courier_id = courier["courier_id"]
                
                # Kuryenin günlük sipariş sayısını al
                order_count_result = execute_with_retry(
                    "SELECT daily_orders FROM courier_performance WHERE courier_id = ?",
                    (courier_id,)
                )
                
                if order_count_result and len(order_count_result) > 0:
                    # Bu kuryeye siparişi ata
                    execute_write_with_retry("UPDATE orders SET courier_id = ? WHERE id = ?", (courier_id, order_id))
                    execute_write_with_retry("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", (courier_id,))

                    # Kurye performansını güncelle
                    ensure_courier_performance(courier_id)
                    execute_write_with_retry("""
                    UPDATE courier_performance 
                    SET daily_orders = daily_orders + 1, 
                        total_orders = total_orders + 1, 
                        last_assigned = ?
                    WHERE courier_id = ?
                    """, (datetime.utcnow().isoformat(), courier_id))

                    # Kuryeyi cooldown'a al
                    set_courier_cooldown(courier_id, neighborhood_id)

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

    # İkinci öncelik: Aynı mahallede son 5 dakika içindeki siparişleri bul
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
        for courier_row in result:
            courier = row_to_dict(courier_row)
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
                SET daily_orders = daily_orders + 1, 
                    total_orders = total_orders + 1, 
                    last_assigned = ?
                WHERE courier_id = ?
                """, (datetime.utcnow().isoformat(), courier_id))

                # Kuryeyi cooldown'a al
                set_courier_cooldown(courier_id, neighborhood_id)

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

    # Eğer aynı mahallede aktif kurye yoksa, en az günlük siparişi olan kuryeyi bul
    result = execute_with_retry("""
    SELECT c.id, COALESCE(cp.daily_orders, 0) as daily_orders, 
           COALESCE(cp.last_assigned, '2000-01-01T00:00:00.000000') as last_assigned
    FROM couriers c
    LEFT JOIN courier_performance cp ON c.id = cp.courier_id
    WHERE c.status IN ('boşta', 'teslimatta')
    ORDER BY daily_orders ASC, last_assigned ASC
    LIMIT 1
    """)

    if result and len(result) > 0:
        courier = row_to_dict(result[0])
        courier_id = courier["id"]

        # Siparişi kuryeye ata
        execute_write_with_retry("UPDATE orders SET courier_id = ? WHERE id = ?", (courier_id, order_id))
        execute_write_with_retry("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", (courier_id,))

        # Kurye performansını güncelle
        ensure_courier_performance(courier_id)
        execute_write_with_retry("""
        UPDATE courier_performance 
        SET daily_orders = COALESCE(daily_orders, 0) + 1, 
            total_orders = COALESCE(total_orders, 0) + 1, 
            last_assigned = ?
        WHERE courier_id = ?
        """, (datetime.utcnow().isoformat(), courier_id))

        # Kuryeyi cooldown'a al
        if neighborhood_id:
            set_courier_cooldown(courier_id, neighborhood_id)

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
# ---------------- Manuel Rapor Tetikleme Endpoint'i ----------------
@app.route("/admin/trigger-monthly-report", methods=["POST"])
@admin_required
def trigger_monthly_report():
    """Manuel olarak aylık rapor tetikleme endpoint'i"""
    try:
        result = distribute_monthly_report()
        
        if result['success']:
            response_data = {
                "message": "Rapor dağıtımı başlatıldı",
                "email_sent": result.get('email_sent', 0),
                "total_recipients": result.get('total_recipients', 0)
            }
            if result.get('data_reset'):
                response_data["message"] += " ve veriler sıfırlandı"
            
            return jsonify(response_data)
        else:
            return jsonify({
                "message": "Rapor dağıtımı başarısız",
                "error": result.get('error', 'Bilinmeyen hata')
            }), 500
            
    except Exception as e:
        print(f"Rapor tetikleme hatası: {e}")
        return jsonify({
            "message": "Rapor tetikleme sırasında hata oluştu",
            "error": str(e)
        }), 500



# ---------------- Auth: register/login ----------------
@app.route("/auth/register", methods=["POST"])
def auth_register():
    """
    Body: { username, password, role (admin|courier|restaurant), first_name, last_name, email, phone, restaurant_id (for restaurant role), restaurant_name/address/phone optional for self-creating restaurant }
    - courier: anyone can self-register (phone required)
    - admin: if no admin exists, allowed; if admin exists, only existing admin (via Bearer token) can create new admin
    - restaurant: restaurant user can register even if admin hasn't created that restaurant_id; in that case system will create restaurants row automatically using provided restaurant_name/address/phone (phone required)
    Returns created user summary (not including password hash)
    """
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    role = (data.get("role") or "courier").lower()

    if not username or not password:
        return jsonify({"message": "username ve password gerekli"}), 400
    if role not in ("admin", "courier", "restaurant"):
        return jsonify({"message": "role sadece 'admin', 'courier' veya 'restaurant' olabilir"}), 400

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

    # If restaurant role, process restaurant_id (string) and require phone (for restaurant)
    restaurant_id = None
    if role == "restaurant":
        restaurant_id = data.get("restaurant_id")
        if not restaurant_id:
            return jsonify({"message": "Restoran kullanıcısı için restaurant_id gerekli"}), 400
        # require phone for restaurant registration
        rest_phone = data.get("phone")
        if not rest_phone:
            return jsonify({"message": "Restoran kaydı için telefon numarası (phone) gerekli"}), 400
        restaurant_id = str(restaurant_id)

        # Check if restaurant exists; if not, create it (self-service flow)
        r = execute_with_retry("SELECT id FROM restaurants WHERE restaurant_id = ?", (restaurant_id,))
        if not r or len(r) == 0:
            # create restaurant record using optional supplied fields (name/address/phone) or fallback name
            restaurant_name = data.get("restaurant_name") or f"Unnamed {restaurant_id}"
            address = data.get("address") or ""
            phone = rest_phone
            fee = data.get("fee_per_package", 5.0)
            try:
                execute_write_with_retry(
                    "INSERT INTO restaurants (restaurant_id, name, fee_per_package, address, phone, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (restaurant_id, restaurant_name, fee, address, phone, datetime.utcnow().isoformat())
                )
            except sqlite3.IntegrityError as e:
                return jsonify({"message": "Restaurant oluşturulurken hata (muhtemel duplicate)", "error": str(e)}), 400

    # If courier role: require phone for courier registration
    if role == "courier":
        phone = data.get("phone")
        if not phone:
            return jsonify({"message": "Kurye kaydı için telefon numarası (phone) gerekli"}), 400

    # username uniqueness check
    existing = execute_with_retry("SELECT id FROM users WHERE username = ?", (username,))
    if existing and len(existing) > 0:
        return jsonify({"message": "Kullanıcı adı zaten kullanılıyor"}), 400

    hashed = hash_password(password)
    try:
        # Kullanıcıyı oluştur
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
        return jsonify({"message": "Kullanıcı adı veya e-posta/telefon zaten var", "error": str(e)}), 400

    # prepare response object (no password hash)
    user_resp = {"id": user_id, "username": username, "role": role, "created_at": datetime.utcnow().isoformat()}
    if role == "courier":
        user_resp["courier"] = courier_obj
    elif role == "restaurant":
        user_resp["restaurant_id"] = restaurant_id

    return jsonify({"message": f"{role} oluşturuldu", "user": user_resp}), 201

@app.route("/auth/login", methods=["POST"])
def auth_login():
    """
    Body: { username, password }
    Returns: { token, user: { id, username, role, created_at, courier: { ... } (optional), restaurant_id (optional) } }
    """
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

    # attach courier profile if applicable
    if role == "courier":
        result = execute_with_retry(
            "SELECT id, first_name, last_name, email, phone, status, created_at FROM couriers WHERE user_id = ?",
            (user_id,))
        if result and len(result) > 0:
            user_out["courier"] = row_to_dict(result[0])
    
    # attach restaurant_id if applicable
    if role == "restaurant":
        user_out["restaurant_id"] = user_row["restaurant_id"]

    return jsonify({"token": token, "user": user_out})

# ---------------- FCM Token Güncelleme ----------------
@app.route("/couriers/<int:courier_id>/fcm-token", methods=["POST"])
@token_required
def update_fcm_token(courier_id):
    """Kuryenin FCM token'ını günceller"""
    if request.user_role != "admin":
        result = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not result or len(result) == 0 or result[0]["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    data = request.get_json() or {}
    fcm_token = data.get("fcm_token")

    if not fcm_token:
        return jsonify({"message": "FCM token gerekli"}), 400

    try:
        success = execute_write_with_retry(
            "UPDATE couriers SET fcm_token = ? WHERE id = ?",
            (fcm_token, courier_id)
        )
        
        if success:
            return jsonify({"message": "FCM token güncellendi"})
        else:
            return jsonify({"message": "FCM token güncellenemedi"}), 500
            
    except Exception as e:
        print(f"FCM token güncelleme hatası: {e}")
        return jsonify({"message": "Sunucu hatası"}), 500

# ---------------- Admin creates courier (explicit) ----------------
@app.route("/admin/couriers", methods=["POST"])
@admin_required
def admin_create_courier():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    phone = data.get("phone")
    if not username or not password or not phone:
        return jsonify({"message": "username, password ve phone (telefon) gerekli"}), 400
    email = data.get("email")

    # Check if username already exists
    result = execute_with_retry("SELECT 1 FROM users WHERE username = ?", (username,))
    if result and len(result) > 0:
        return jsonify({"message": "Kullanıcı adı kullanılıyor"}), 400

    if email:
        result = execute_with_retry("SELECT 1 FROM couriers WHERE email = ?", (email,))
        if result and len(result) > 0:
            return jsonify({"message": "E-posta zaten kullanılıyor"}), 400

    # Check phone uniqueness
    result = execute_with_retry("SELECT 1 FROM couriers WHERE phone = ?", (phone,))
    if result and len(result) > 0:
        return jsonify({"message": "Telefon numarası zaten kullanılıyor"}), 400

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
        restaurant_id = user.get("restaurant_id")
        if restaurant_id:
            result = execute_with_retry("SELECT * FROM restaurants WHERE restaurant_id = ?", (restaurant_id,))
            if result and len(result) > 0:
                user["restaurant"] = row_to_dict(result[0])

    return jsonify(user)

# ---------------- Admin Courier Reassignment ----------------
@app.route("/admin/orders/<int:order_id>/reassign", methods=["POST"])
@admin_required
def admin_reassign_order(order_id):
    """
    Admin endpoint to reassign an order to a different courier
    Body: { "new_courier_id": int }
    """
    data = request.get_json() or {}
    new_courier_id = data.get("new_courier_id")
    
    if not new_courier_id:
        return jsonify({"message": "new_courier_id gereklidir"}), 400

    # Get the current order details - row_to_dict kullan
    result = execute_with_retry("""
        SELECT o.*, c.id as current_courier_id, c.status as courier_status 
        FROM orders o 
        LEFT JOIN couriers c ON o.courier_id = c.id 
        WHERE o.id = ?
    """, (order_id,))
    
    if not result or len(result) == 0:
        return jsonify({"message": "Sipariş bulunamadı"}), 404

    # row_to_dict kullanarak sqlite3.Row'u dictionary'ye çevir
    order = row_to_dict(result[0])
    current_courier_id = order["current_courier_id"]

    # Check if new courier exists and is available - row_to_dict kullan
    new_courier_result = execute_with_retry("""
        SELECT id, status, first_name, last_name 
        FROM couriers 
        WHERE id = ? AND status IN ('boşta', 'teslimatta')
    """, (new_courier_id,))
    
    if not new_courier_result or len(new_courier_result) == 0:
        return jsonify({"message": "Yeni kurye bulunamadı veya müsait değil"}), 404

    # row_to_dict kullanarak sqlite3.Row'u dictionary'ye çevir
    new_courier = row_to_dict(new_courier_result[0])

    # Validate order can be reassigned
    if order["status"] not in ["yeni", "teslim alındı"]:
        return jsonify({"message": "Sadece 'yeni' veya 'teslim alındı' durumundaki siparişler yeniden atanabilir"}), 400

    if current_courier_id == new_courier_id:
        return jsonify({"message": "Sipariş zaten bu kuryede"}), 400

    now = datetime.utcnow().isoformat()
    
    try:
        # 1. Update the previous courier's status if needed
        if current_courier_id:
            # Check if previous courier has other active orders
            other_orders_result = execute_with_retry("""
                SELECT COUNT(*) as active_count 
                FROM orders 
                WHERE courier_id = ? AND status IN ('yeni', 'teslim alındı') AND id != ?
            """, (current_courier_id, order_id))
            
            if other_orders_result and other_orders_result[0]["active_count"] == 0:
                # No other active orders, set status to 'boşta'
                execute_write_with_retry(
                    "UPDATE couriers SET status = 'boşta' WHERE id = ?",
                    (current_courier_id,)
                )
            
            # Clear cooldown for previous courier
            execute_write_with_retry(
                "UPDATE courier_performance SET cooldown_until = NULL, current_neighborhood_id = NULL WHERE courier_id = ?",
                (current_courier_id,)
            )

            # Notify previous courier about reassignment
            notify_courier_reassignment(current_courier_id, order_id, "removed")

        # 2. Assign to new courier
        execute_write_with_retry(
            "UPDATE orders SET courier_id = ?, status = 'teslim alındı', updated_at = ? WHERE id = ?",
            (new_courier_id, now, order_id)
        )

        # 3. Update new courier status
        execute_write_with_retry(
            "UPDATE couriers SET status = 'teslimatta' WHERE id = ?",
            (new_courier_id,)
        )

        # 4. Ensure performance record exists and update
        ensure_courier_performance(new_courier_id)
        
        # 5. Set cooldown for new courier if neighborhood exists
        # DÜZELTME: order artık dictionary, bu yüzden .get() kullanabiliriz
        if order.get("neighborhood_id"):
            set_courier_cooldown(new_courier_id, order["neighborhood_id"])

        # 6. Add to delivery history
        execute_write_with_retry(
            "INSERT INTO delivery_history (order_id, courier_id, status, notes, created_at) VALUES (?, ?, ?, ?, ?)",
            (order_id, new_courier_id, 'reassigned', 
             f'Sipariş {current_courier_id} numaralı kuryeden {new_courier_id} numaralı kuryeye yeniden atandı', 
             now)
        )

        # 7. Notify new courier - row_to_dict kullan
        order_result = execute_with_retry("SELECT * FROM orders WHERE id = ?", (order_id,))
        if order_result and len(order_result) > 0:
            order_data = row_to_dict(order_result[0])
            notification_data = {
                'order_id': order_data['id'],
                'order_uuid': order_data['order_uuid'],
                'customer_name': order_data['customer_name'],
                'address': order_data['address'],
                'total_amount': order_data['total_amount'],
                'items': order_data['items'],
                'reassigned': True,
                'previous_courier_id': current_courier_id
            }
            notify_courier_new_order(new_courier_id, notification_data)

        return jsonify({
            "message": f"Sipariş {new_courier['first_name']} {new_courier['last_name']} kuryesine atandı",
            "previous_courier_id": current_courier_id,
            "new_courier_id": new_courier_id,
            "new_courier_name": f"{new_courier['first_name']} {new_courier['last_name']}"
        })

    except Exception as e:
        print(f"Sipariş yeniden atama hatası: {e}")
        traceback.print_exc()
        return jsonify({"message": "Sipariş yeniden atanırken hata oluştu", "error": str(e)}), 500

# ---------------- Users management (admin) ----------------
@app.route("/users", methods=["GET"])
@admin_required
def list_users():
    result = execute_with_retry("SELECT id, username, role, created_at, restaurant_id FROM users")
    return jsonify([row_to_dict(r) for r in result]) if result else jsonify([])

@app.route("/users/<int:user_id>", methods=["PATCH"])
@admin_required
def update_user(user_id):
    data = request.get_json() or {}
    fields = []
    values = []
    if "role" in data:
        if data["role"] not in ("admin", "courier", "restaurant"):
            return jsonify({"message": "role admin, courier veya restaurant olmalı"}), 400
        fields.append("role = ?");
        values.append(data["role"])
    if "password" in data:
        fields.append("password_hash = ?");
        values.append(hash_password(data["password"]))
    if "restaurant_id" in data:
        fields.append("restaurant_id = ?");
        values.append(data["restaurant_id"])
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
            return jsonify({"message": "Kurye güncellenirwhile hata oluştu"}), 500

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
        if not result or len(result) == 0 or row_to_dict(result[0])["user_id"] != request.user_id:
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
        if not result or len(result) == 0 or row_to_dict(result[0])["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    result = execute_with_retry("SELECT * FROM orders WHERE courier_id = ? AND status IN ('yeni','teslim alındı')",
                                (courier_id,))
    return jsonify([row_to_dict(r) for r in result]) if result else jsonify([])

@app.route("/couriers/<int:courier_id>/orders/<int:order_id>/pickup", methods=["POST"])
@token_required
def courier_pickup_order(courier_id, order_id):
    if request.user_role != "admin":
        result = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not result or len(result) == 0 or row_to_dict(result[0])["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    result = execute_with_retry("SELECT * FROM orders WHERE id = ? AND courier_id = ?", (order_id, courier_id))
    if not result or len(result) == 0:
        return jsonify({"message": "Sipariş bulunamadı veya atanmadı"}), 404

    order = row_to_dict(result[0])
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
        if not result or len(result) == 0 or row_to_dict(result[0])["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    result = execute_with_retry("SELECT * FROM orders WHERE id = ? AND courier_id = ?", (order_id, courier_id))
    if not result or len(result) == 0:
        return jsonify({"message": "Sipariş bulunamadı veya atanmadı"}), 404

    order = row_to_dict(result[0])
    if order["status"] != "teslim alındı":
        return jsonify({"message": "Sipariş teslim alınmamış"}), 400

    now = datetime.utcnow().isoformat()
    execute_write_with_retry("UPDATE orders SET status = 'teslim edildi', updated_at = ? WHERE id = ?", (now, order_id))
    execute_write_with_retry("UPDATE couriers SET status = 'boşta' WHERE id = ?", (courier_id,))

    # Cooldown'u temizle
    execute_write_with_retry(
        "UPDATE courier_performance SET cooldown_until = NULL, current_neighborhood_id = NULL WHERE courier_id = ?",
        (courier_id,)
    )

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
        if not result or len(result) == 0 or row_to_dict(result[0])["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    data = request.get_json() or {}
    reason = data.get("reason", "")
    if not reason:
        return jsonify({"message": "Teslimat başarısızlığı nedeni gereklidir"}), 400

    result = execute_with_retry("SELECT * FROM orders WHERE id = ? AND courier_id = ?", (order_id, courier_id))
    if not result or len(result) == 0:
        return jsonify({"message": "Sipariş bulunamadı veya atanmadı"}), 404

    order = row_to_dict(result[0])
    now = datetime.utcnow().isoformat()
    execute_write_with_retry(
        "UPDATE orders SET status = 'teslim edilemedi', delivery_failed_reason = ?, updated_at = ? WHERE id = ?",
        (reason, now, order_id)
    )
    execute_write_with_retry("UPDATE couriers SET status = 'boşta' WHERE id = ?", (courier_id,))

    # Cooldown'u temizle
    execute_write_with_retry(
        "UPDATE courier_performance SET cooldown_until = NULL, current_neighborhood_id = NULL WHERE courier_id = ?",
        (courier_id,)
    )

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
        if not result or len(result) == 0 or row_to_dict(result[0])["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403

    result = execute_with_retry("""
        SELECT dh.*, o.customer_name, o.address, o.total_amount 
        FROM delivery_history dh 
        JOIN orders o ON dh.order_id = o.id 
        WHERE dh.courier_id = ? 
        ORDER BY dh.created_at DESC
    """, (courier_id,))

    return jsonify([row_to_dict(r) for r in result]) if result else jsonify([])

# ---------------- Restaurant actions ----------------
@app.route("/restaurants/orders", methods=["GET"])
@restaurant_required
def restaurant_get_orders():
    """Restoranın siparişlerini getir (restaurant_id string ile eşleşir)"""
    restaurant_id = None
    result = execute_with_retry("SELECT restaurant_id FROM users WHERE id = ?", (request.user_id,))
    if result and len(result) > 0:
        restaurant_id = row_to_dict(result[0])["restaurant_id"]
    
    if not restaurant_id:
        return jsonify({"message": "Restoran ID bulunamadı"}), 404
    
    # Restoran bilgilerini al (restaurant_id ile)
    result = execute_with_retry("SELECT name FROM restaurants WHERE restaurant_id = ?", (restaurant_id,))
    if not result or len(result) == 0:
        return jsonify({"message": "Restoran bulunamadı"}), 404
    
    restaurant_name = row_to_dict(result[0])["name"]
    
    # Restoranın siparişlerini getir (orders.vendor_id eşleşmesi string restaurant_id ile yapılır)
    result = execute_with_retry("""
        SELECT * FROM orders 
        WHERE vendor_id = ? OR customer_name LIKE ? 
        ORDER BY created_at DESC
    """, (restaurant_id, f"%{restaurant_name}%"))
    
    return jsonify([row_to_dict(r) for r in result]) if result else jsonify([])

@app.route("/restaurants/orders/<int:order_id>", methods=["GET"])
@restaurant_required
def restaurant_get_order(order_id):
    """Belirli bir siparişin detaylarını getir (restaurant_id string ile kontrol yapılır)"""
    restaurant_id = None
    result = execute_with_retry("SELECT restaurant_id FROM users WHERE id = ?", (request.user_id,))
    if result and len(result) > 0:
        restaurant_id = row_to_dict(result[0])["restaurant_id"]
    
    if not restaurant_id:
        return jsonify({"message": "Restoran ID bulunamadı"}), 404
    
    # Restoran bilgilerini al
    result = execute_with_retry("SELECT name FROM restaurants WHERE restaurant_id = ?", (restaurant_id,))
    if not result or len(result) == 0:
        return jsonify({"message": "Restoran bulunamadı"}), 404
    
    restaurant_name = row_to_dict(result[0])["name"]
    
    # Siparişi getir (vendor_id ile eşleşme)
    result = execute_with_retry("""
        SELECT * FROM orders 
        WHERE id = ? AND (vendor_id = ? OR customer_name LIKE ?)
    """, (order_id, restaurant_id, f"%{restaurant_name}%"))
    
    if not result or len(result) == 0:
        return jsonify({"message": "Sipariş bulunamadı"}), 404
    
    return jsonify(row_to_dict(result[0]))

# ---------------- Orders (webhook + admin) ----------------
@app.route("/webhooks/yemeksepeti", methods=["POST"])
def webhook_yemeksepeti():
    data = request.get_json() or {}
    external_id = data.get("external_id") or data.get("order_id") or data.get("id")
    vendor_id = data.get("vendor_id")
    # normalize vendor_id to string for consistency
    vendor_id = None if vendor_id is None else str(vendor_id)
    # vendor/restaurant name field(s)
    vendor_name = data.get("vendor_name") or data.get("restaurant_name") or data.get("vendor") or data.get("merchant_name")
    customer_name = data.get("customer_name") or data.get("customer")
    items = data.get("items")
    total = data.get("total") or data.get("total_amount") or 0
    address = data.get("address") or data.get("customer_address")
    # use json.dumps to keep valid json string (and preserve unicode)
    payload = json.dumps(data, ensure_ascii=False)
    created = datetime.utcnow().isoformat()
    order_uuid = f"o-{int(datetime.utcnow().timestamp() * 1000)}"

    # 1) INSERT işlemi (hataları yakala)
    try:
        ok = execute_write_with_retry(
            """INSERT INTO orders
               (order_uuid, external_id, vendor_id, customer_name, items, total_amount, address, payload, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (order_uuid, external_id, vendor_id, customer_name, str(items), total, address, payload, created, created)
        )
    except sqlite3.IntegrityError as ie:
        # duplicate veya constraint hatası
        print("WEBHOOK INSERT IntegrityError:", ie)
        traceback.print_exc()
        return jsonify({"message": "Sipariş kaydedilirken hata (duplicate veya integrity)", "error": str(ie)}), 400
    except Exception as e:
        print("WEBHOOK INSERT HATA:", e)
        traceback.print_exc()
        return jsonify({"message": "Sunucu hatası (insert sırasında)", "error": str(e)}), 500

    if not ok:
        # execute_write_with_retry başarısız oldu (örn. OperationalError yakalandı ve False döndü)
        print("WEBHOOK: INSERT başarısız (ok == False)")
        return jsonify({"message": "Sunucu hatası (insert başarısız)"}), 500

    # 2) INSERT sonrası kesin kontrol: satırı oku
    try:
        result = execute_with_retry("SELECT id FROM orders WHERE order_uuid = ?", (order_uuid,))
    except Exception as e:
        print("WEBHOOK SELECT HATASI:", e)
        traceback.print_exc()
        return jsonify({"message": "Sunucu hatası (insert doğrulama sırasında)", "error": str(e)}), 500

    if not result or len(result) == 0:
        print("WEBHOOK: INSERT sonrası order bulunamadı, order_uuid:", order_uuid)
        return jsonify({"message": "Sunucu hatası (kaydedilemedi)"}), 500

    order_id = result[0]["id"]

    # 3) Siparişi kuryeye ata - burada çıkabilecek hataları yakala ama client'a 201 dön
    try:
        assign_order_to_courier(order_id)
    except Exception as e:
        print(f"Sipariş atama hatası (order_id={order_id}): {e}")
        traceback.print_exc()
        # isteğe bağlı: burada delivery_history'ye hata kaydı yazılabilir

    # 4) Başarılı cevap gönder
    return jsonify({"message": "Sipariş alındı", "order_uuid": order_uuid}), 201

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
    allowed = ("status", "courier_id", "customer_name", "items", "total_amount", "address", "vendor_id")
    fields = [];
    values = []
    for k in allowed:
        if k in data:
            # vendor_id may be string
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
    """
    Admin -> yeni restoran + restoran kullanıcısı oluşturur.
    Body (JSON) required: username, password, restaurant_id (string), name, phone
    Optional: fee_per_package, address, is_active
    """
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    restaurant_id = data.get("restaurant_id")
    name = data.get("name")
    phone = data.get("phone")
    fee_per_package = data.get("fee_per_package", 5.0)
    address = data.get("address", "")
    is_active = data.get("is_active", 1)

    if not username or not password or not restaurant_id or not name or not phone:
        return jsonify({"message": "username, password, restaurant_id, name ve phone (telefon) gereklidir"}), 400

    restaurant_id = str(restaurant_id)

    # Check username uniqueness
    existing_user = execute_with_retry("SELECT 1 FROM users WHERE username = ?", (username,))
    if existing_user and len(existing_user) > 0:
        return jsonify({"message": "Kullanıcı adı zaten kullanılıyor"}), 400

    # check uniqueness: restaurant_id or name must not exist
    r = execute_with_retry("SELECT 1 FROM restaurants WHERE restaurant_id = ? OR name = ?", (restaurant_id, name))
    if r and len(r) > 0:
        return jsonify({"message": "Bu restaurant_id veya isim zaten kullanılıyor"}), 400

    # create user (role restaurant) then restaurant row
    hashed = hash_password(password)
    try:
        # create user
        ok_user = execute_write_with_retry(
            "INSERT INTO users (username, password_hash, role, created_at, restaurant_id) VALUES (?, ?, 'restaurant', ?, ?)",
            (username, hashed, datetime.utcnow().isoformat(), restaurant_id)
        )
        if not ok_user:
            return jsonify({"message": "Kullanıcı oluşturulamadı (db error)"}), 500

        # Create restaurant row
        ok_rest = execute_write_with_retry(
            """INSERT INTO restaurants 
               (restaurant_id, name, fee_per_package, address, phone, is_active, created_at) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (restaurant_id, name, fee_per_package, address, phone, is_active, datetime.utcnow().isoformat())
        )

        if not ok_rest:
            # rollback: delete created user
            execute_write_with_retry("DELETE FROM users WHERE username = ?", (username,))
            return jsonify({"message": "Restoran oluşturulamadı (db error)"}), 500

        # fetch created objects
        user_row = execute_with_retry("SELECT id, username, role, created_at, restaurant_id FROM users WHERE username = ?", (username,))
        rest_row = execute_with_retry("SELECT * FROM restaurants WHERE restaurant_id = ?", (restaurant_id,))

        user_out = row_to_dict(user_row[0]) if user_row and len(user_row) > 0 else None
        rest_out = row_to_dict(rest_row[0]) if rest_row and len(rest_row) > 0 else None

        return jsonify({"message": "Restoran ve restoran kullanıcısı oluşturuldu", "user": user_out, "restaurant": rest_out}), 201

    except sqlite3.IntegrityError as e:
        # Possible race duplicate - try to cleanup if needed
        try:
            execute_write_with_retry("DELETE FROM users WHERE username = ?", (username,))
        except Exception:
            pass
        return jsonify({"message": "Integrity error", "error": str(e)}), 400
    except Exception as e:
        # generic error, try cleanup
        try:
            execute_write_with_retry("DELETE FROM users WHERE username = ?", (username,))
            execute_write_with_retry("DELETE FROM restaurants WHERE restaurant_id = ?", (restaurant_id,))
        except Exception:
            pass
        return jsonify({"message": "Sunucu hatası", "error": str(e)}), 500

@app.route("/restaurants/<restaurant_id>", methods=["PATCH"])
@admin_required
def update_restaurant(restaurant_id):
    data = request.get_json() or {}
    allowed = ("restaurant_id", "name", "fee_per_package", "address", "phone", "is_active")
    fields = [];
    values = []
    for k in allowed:
        if k in data:
            fields.append(f"{k} = ?");
            values.append(data[k])
    if not fields:
        return jsonify({"message": "Güncellenecek alan yok"}), 400

    values.append(restaurant_id)
    query = f"UPDATE restaurants SET {', '.join(fields)} WHERE restaurant_id = ?"

    try:
        execute_write_with_retry(query, values)
        return jsonify({"message": "Restoran güncellendi"})
    except sqlite3.IntegrityError as e:
        return jsonify({"message": "Integrity error", "error": str(e)}), 400

@app.route("/restaurants/<restaurant_id>", methods=["DELETE"])
@admin_required
def delete_restaurant(restaurant_id):
    execute_write_with_retry("DELETE FROM restaurants WHERE restaurant_id = ?", (restaurant_id,))
    # optionally also remove users with that restaurant_id
    execute_write_with_retry("DELETE FROM users WHERE restaurant_id = ?", (restaurant_id,))
    return jsonify({"message": "Restoran silindi"})

# ---------------- Neighborhood Management ----------------
@app.route("/neighborhoods", methods=["GET"])
@token_required  # Sadece genel token gerekiyor - GET için
def list_neighborhoods():
    result = execute_with_retry("SELECT * FROM neighborhoods ORDER BY name")
    return jsonify([row_to_dict(r) for r in result]) if result else jsonify([])

@app.route("/neighborhoods", methods=["POST"])
@admin_required  # Admin token gerekiyor - POST için
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
@admin_required  # Admin token gerekiyor - DELETE için
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
    for order_row in result:
        order = row_to_dict(order_row)
        if assign_order_to_courier(order["id"]):
            assigned_count += 1

    return jsonify({"message": f"{assigned_count} sipariş kuryelere atandı"})

# ---------------- Courier Performance Reset ----------------
@app.route("/admin/couriers/<int:courier_id>/reset-performance", methods=["POST"])
@admin_required
def reset_courier_performance(courier_id):
    execute_write_with_retry("UPDATE courier_performance SET daily_orders = 0, total_orders = 0 WHERE courier_id = ?", (courier_id,))
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

    status_counts = {row["status"]: row["cnt"] for row in result} if result else {}

    # Courier performance
    result = execute_with_retry("""
        SELECT courier_id, COUNT(*) as delivered_count FROM orders
        WHERE created_at >= ? AND created_at < ? AND status = 'teslim edildi' GROUP BY courier_id
    """, (start_dt.isoformat(), end_dt.isoformat()))

    perf = []
    if result:
        for row in result:
            courier_id = row["courier_id"]
            cnt = row["delivered_count"]
            if not courier_id:
                name = "Atanmamış"
            else:
                r = execute_with_retry("SELECT first_name, last_name FROM couriers WHERE id = ?", (courier_id,))
                if r and len(r) > 0:
                    r_dict = row_to_dict(r[0])
                    name = f"{r_dict['first_name']} {r_dict['last_name']}"
                else:
                    name = "Bilinmeyen Kurye"
            perf.append({"courier_id": courier_id, "courier_name": name, "delivered_orders": cnt})

    # Restaurant performance (vendor_id is string -> match restaurants.restaurant_id)
    result = execute_with_retry("""
        SELECT vendor_id, COUNT(*) as order_count FROM orders
        WHERE created_at >= ? AND created_at < ? GROUP BY vendor_id
    """, (start_dt.isoformat(), end_dt.isoformat()))

    rest_perf = []
    if result:
        for row in result:
            vendor_id = row["vendor_id"]
            cnt = row["order_count"]
            if vendor_id:
                r = execute_with_retry("SELECT name FROM restaurants WHERE restaurant_id = ?", (vendor_id,))
                if r and len(r) > 0:
                    name = row_to_dict(r[0])['name']
                else:
                    name = "Bilinmeyen Restoran"
            else:
                name = "Bilinmeyen Restoran"
            rest_perf.append({"vendor_id": vendor_id, "restaurant_name": name, "order_count": cnt})

    # Courier distribution
    result = execute_with_retry("""
        SELECT c.id, c.first_name, c.last_name, COALESCE(cp.daily_orders, 0) as daily_orders
        FROM couriers c
        LEFT JOIN courier_performance cp ON c.id = cp.courier_id
        ORDER BY daily_orders DESC
    """)

    courier_dist = []
    if result:
        for row in result:
            row_dict = row_to_dict(row)
            courier_dist.append({
                "courier_id": row_dict["id"],
                "courier_name": f"{row_dict['first_name']} {row_dict['last_name']}",
                "daily_orders": row_dict["daily_orders"]
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
            row_dict = row_to_dict(row)
            neighborhood_dist.append({
                "neighborhood_name": row_dict["name"],
                "order_count": row_dict["order_count"]
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
