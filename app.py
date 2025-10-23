# app.py
import os
import traceback
import time
import json
import re
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import requests

# Third-party libs
from apscheduler.schedulers.background import BackgroundScheduler
import bcrypt
import jwt
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room

# Optional firebase admin (recommended). If not installed, fallback to legacy FCM key path is used.
try:
    import firebase_admin
    from firebase_admin import credentials, messaging
    FIREBASE_ADMIN_AVAILABLE = True
except Exception:
    FIREBASE_ADMIN_AVAILABLE = False

# ---------------- Config (use environment variables in production) ----------------
app = Flask(__name__)
# Load secrets from env with safe defaults for local dev (override in production)
DB_NAME = os.getenv("DB_NAME", "orders.db")
SECRET_KEY = os.getenv("SECRET_KEY", os.getenv("FLASK_SECRET_KEY", "çok_gizli_bir_anahtar"))
JWT_ALGORITHM = "HS256"
TOKEN_EXP_HOURS = int(os.getenv("TOKEN_EXP_HOURS", "8"))

# Email / SMTP
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
EMAIL_USERNAME = os.getenv("EMAIL_USERNAME", "")  # e.g. your_email@gmail.com
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")  # e.g. app password

# FCM config
FCM_SERVER_KEY = os.getenv("FCM_SERVER_KEY", "")  # legacy key - fallback only
SERVICE_ACCOUNT_FILE = os.getenv("SERVICE_ACCOUNT_FILE", os.getenv("GOOGLE_APPLICATION_CREDENTIALS", ""))

# Report recipients
REPORT_RECIPIENTS = {
    "email": os.getenv("REPORT_RECIPIENTS", "admin@firma.com,rapor@firma.com").split(",")
}

# SocketIO initialization
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Scheduler
scheduler = BackgroundScheduler()
scheduler.start()

# Courier WebSocket connections mapping
courier_connections = {}

# ---------------- Firebase Admin initialization (if service account provided) ----------------
FIREBASE_ADMIN_INITIALIZED = False
if SERVICE_ACCOUNT_FILE and FIREBASE_ADMIN_AVAILABLE:
    try:
        cred = credentials.Certificate(SERVICE_ACCOUNT_FILE)
        # Initialize app only once
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred)
        FIREBASE_ADMIN_INITIALIZED = True
        print("Firebase Admin initialized using SERVICE_ACCOUNT_FILE.")
    except Exception as e:
        print("Failed to initialize Firebase Admin:", e)
        traceback.print_exc()
        FIREBASE_ADMIN_INITIALIZED = False
else:
    if SERVICE_ACCOUNT_FILE and not FIREBASE_ADMIN_AVAILABLE:
        print("SERVICE_ACCOUNT_FILE provided but firebase_admin package is not available. Install firebase-admin for HTTP v1 support.")
    else:
        print("No SERVICE_ACCOUNT_FILE provided; will use legacy FCM key fallback if available.")


# ---------------- Database helpers ----------------
def get_conn():
    conn = sqlite3.connect(DB_NAME, timeout=30, check_same_thread=False)
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
    """Create tables if not exist and run safe migrations."""
    conn = get_conn()
    cur = conn.cursor()

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

    cur.execute("""
    CREATE TABLE IF NOT EXISTS neighborhoods (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        created_at TEXT
    )
    """)

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

    # Ensure optional columns exist (best-effort)
    try:
        if not column_exists(conn, 'users', 'restaurant_id'):
            cur.execute("ALTER TABLE users ADD COLUMN restaurant_id TEXT")
    except Exception:
        pass

    try:
        if not column_exists(conn, 'orders', 'vendor_id'):
            cur.execute("ALTER TABLE orders ADD COLUMN vendor_id TEXT")
    except Exception:
        pass

    try:
        if not column_exists(conn, 'restaurants', 'restaurant_id'):
            cur.execute("ALTER TABLE restaurants ADD COLUMN restaurant_id TEXT")
    except Exception:
        pass

    try:
        if not column_exists(conn, 'courier_performance', 'cooldown_until'):
            cur.execute("ALTER TABLE courier_performance ADD COLUMN cooldown_until TEXT")
    except Exception:
        pass

    try:
        if not column_exists(conn, 'courier_performance', 'current_neighborhood_id'):
            cur.execute("ALTER TABLE courier_performance ADD COLUMN current_neighborhood_id INTEGER")
    except Exception:
        pass

    conn.commit()
    conn.close()


# ---------------- DB execute helpers ----------------
def execute_with_retry(query, params=None, max_retries=5):
    for attempt in range(max_retries):
        conn = None
        try:
            conn = get_conn()
            cur = conn.cursor()
            if params:
                cur.execute(query, params)
            else:
                cur.execute(query)
            result = cur.fetchall()
            conn.commit()
            return result
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() and attempt < max_retries - 1:
                time.sleep(0.1 * (attempt + 1))
                continue
            else:
                print("DB OperationalError:", e)
                raise
        finally:
            if conn:
                conn.close()
    return None


def execute_write_with_retry(query, params=None, max_retries=5):
    for attempt in range(max_retries):
        conn = None
        try:
            conn = get_conn()
            cur = conn.cursor()
            if params:
                cur.execute(query, params)
            else:
                cur.execute(query)
            conn.commit()
            return True
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() and attempt < max_retries - 1:
                time.sleep(0.1 * (attempt + 1))
                continue
            else:
                print("DB write OperationalError:", e)
                raise
        finally:
            if conn:
                conn.close()
    return False


# ---------------- Firebase / FCM sending ----------------
def send_fcm_notification(fcm_token, title, body, data=None):
    """
    Send push notification:
    - If Firebase Admin SDK initialized: use messaging.send (HTTP v1) — recommended.
    - Otherwise fallback to legacy server key endpoint if FCM_SERVER_KEY provided.
    """
    if not fcm_token:
        print("send_fcm_notification: missing fcm_token")
        return False

    # Preferred: firebase_admin.messaging (HTTP v1)
    if FIREBASE_ADMIN_INITIALIZED:
        try:
            message = messaging.Message(
                token=fcm_token,
                notification=messaging.Notification(title=title, body=body),
                data={k: str(v) for k, v in (data or {}).items()}
            )
            response = messaging.send(message)
            print("FCM (admin) sent, response:", response)
            return True
        except Exception as e:
            print("FCM admin send error:", e)
            traceback.print_exc()
            # fallthrough to legacy option if available

    # Legacy fallback (server key)
    if not FCM_SERVER_KEY:
        print("No FCM_SERVER_KEY configured and Firebase Admin not initialized.")
        return False

    try:
        url = "https://fcm.googleapis.com/fcm/send"
        headers = {
            "Authorization": f"key={FCM_SERVER_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "to": fcm_token,
            "notification": {
                "title": title,
                "body": body,
                "sound": "default",
                "click_action": "FLUTTER_NOTIFICATION_CLICK"
            },
            "data": data or {}
        }
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        if r.status_code in (200, 201):
            print("FCM (legacy) sent:", r.text)
            return True
        else:
            print("FCM (legacy) error:", r.status_code, r.text)
            return False
    except Exception as e:
        print("FCM legacy send exception:", e)
        traceback.print_exc()
        return False


# ---------------- Email sending ----------------
def send_email(to_email, subject, html_content):
    if not EMAIL_USERNAME or not EMAIL_PASSWORD:
        print("Email credentials not configured in env.")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = EMAIL_USERNAME
        msg["To"] = to_email
        html_part = MIMEText(html_content, "html")
        msg.attach(html_part)

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20)
        server.starttls()
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print("Email sent to", to_email)
        return True
    except Exception as e:
        print("send_email error:", e)
        traceback.print_exc()
        return False


# ---------------- Scheduler jobs: daily/monthly resets & monthly report ----------------
def reset_daily_orders():
    try:
        execute_write_with_retry("UPDATE courier_performance SET daily_orders = 0")
        print("Daily orders reset.")
    except Exception as e:
        print("reset_daily_orders error:", e)


def reset_monthly_orders():
    try:
        execute_write_with_retry("UPDATE courier_performance SET daily_orders = 0, total_orders = 0")
        print("Monthly orders reset.")
    except Exception as e:
        print("reset_monthly_orders error:", e)


def generate_monthly_report():
    """Return dict with report data. Does not send email itself."""
    try:
        today = datetime.utcnow()
        first_day_of_month = today.replace(day=1)
        last_day_prev = first_day_of_month - timedelta(days=1)
        first_day_prev = last_day_prev.replace(day=1)
        start_date = first_day_prev.strftime("%Y-%m-%d")
        end_date = last_day_prev.strftime("%Y-%m-%d")

        # status counts
        result = execute_with_retry(
            "SELECT status, COUNT(*) as cnt FROM orders WHERE created_at >= ? AND created_at <= ? GROUP BY status",
            (start_date, f"{end_date} 23:59:59")
        )
        status_counts = {r["status"]: r["cnt"] for r in (result or [])}

        # courier perf
        result = execute_with_retry(
            "SELECT courier_id, COUNT(*) as delivered_count FROM orders WHERE created_at >= ? AND created_at <= ? AND status = 'teslim edildi' GROUP BY courier_id",
            (start_date, f"{end_date} 23:59:59")
        )
        perf = []
        for r in (result or []):
            courier_id = r["courier_id"]
            name = "Atanmamış"
            if courier_id:
                cr = execute_with_retry("SELECT first_name, last_name FROM couriers WHERE id = ?", (courier_id,))
                if cr and len(cr) > 0:
                    crd = row_to_dict(cr[0])
                    name = f"{crd.get('first_name','')} {crd.get('last_name','')}".strip()
            perf.append({"courier_id": courier_id, "courier_name": name, "delivered_orders": r["delivered_count"]})

        # restaurants
        result = execute_with_retry(
            "SELECT vendor_id, COUNT(*) as order_count FROM orders WHERE created_at >= ? AND created_at <= ? GROUP BY vendor_id",
            (start_date, f"{end_date} 23:59:59")
        )
        rest_perf = []
        for r in (result or []):
            vendor_id = r["vendor_id"]
            name = "Bilinmeyen Restoran"
            if vendor_id:
                rn = execute_with_retry("SELECT name FROM restaurants WHERE restaurant_id = ?", (vendor_id,))
                if rn and len(rn) > 0:
                    name = row_to_dict(rn[0]).get("name", name)
            rest_perf.append({"vendor_id": vendor_id, "restaurant_name": name, "order_count": r["order_count"]})

        # courier distribution
        result = execute_with_retry("""
            SELECT c.id, c.first_name, c.last_name, COALESCE(cp.daily_orders, 0) as daily_orders
            FROM couriers c
            LEFT JOIN courier_performance cp ON c.id = cp.courier_id
            ORDER BY daily_orders DESC
        """)
        courier_dist = []
        for r in (result or []):
            rd = row_to_dict(r)
            courier_dist.append({
                "courier_id": rd["id"],
                "courier_name": f"{rd.get('first_name','')} {rd.get('last_name','')}".strip(),
                "daily_orders": rd.get("daily_orders", 0)
            })

        # neighborhood distribution
        result = execute_with_retry("""
            SELECT n.name, COUNT(o.id) as order_count
            FROM neighborhoods n
            LEFT JOIN orders o ON n.id = o.neighborhood_id
            GROUP BY n.id
            ORDER BY order_count DESC
        """)
        neighborhood_dist = []
        for r in (result or []):
            rd = row_to_dict(r)
            neighborhood_dist.append({"neighborhood_name": rd["name"], "order_count": rd["order_count"]})

        return {
            "success": True,
            "period": {"start": start_date, "end": end_date},
            "status_counts": status_counts,
            "courier_performance": perf,
            "restaurant_performance": rest_perf,
            "courier_distribution": courier_dist,
            "neighborhood_distribution": neighborhood_dist
        }
    except Exception as e:
        print("generate_monthly_report error:", e)
        traceback.print_exc()
        return {"success": False, "error": str(e)}


def format_report_for_email(report_data):
    if not report_data.get("success"):
        return "<p>Rapor oluşturulamadı</p>", "Rapor Hatası"
    try:
        period = report_data["period"]
        subject = f"Aylık Rapor - {period['start']} - {period['end']}"
        html = f"<h1>Aylık Rapor</h1><p>Dönem: {period['start']} - {period['end']}</p>"
        # Very simple HTML; you can expand
        html += "<h2>Sipariş Durumları</h2><ul>"
        total = sum(report_data.get("status_counts", {}).values())
        for s, c in report_data.get("status_counts", {}).items():
            pc = f"{(c/total*100):.1f}%" if total > 0 else "0.0%"
            html += f"<li>{s}: {c} ({pc})</li>"
        html += "</ul>"
        return html, subject
    except Exception as e:
        print("format_report_for_email error:", e)
        traceback.print_exc()
        return "<p>Formatlama hatası</p>", "Rapor Format Hatası"


def distribute_monthly_report():
    print("Distribute monthly report start...")
    report = generate_monthly_report()
    html, subject = format_report_for_email(report)
    sent = 0
    for em in REPORT_RECIPIENTS.get("email", []):
        em = em.strip()
        if not em:
            continue
        ok = send_email(em, subject, html)
        if ok:
            sent += 1
    if sent > 0:
        reset_monthly_orders()
    return {"success": True, "sent": sent, "total": len(REPORT_RECIPIENTS.get("email", []))}


# Schedule jobs
scheduler.add_job(reset_daily_orders, "cron", hour=0, minute=0, id="daily_reset", replace_existing=True)
scheduler.add_job(lambda: distribute_monthly_report(), "cron", day="last", hour=23, minute=0, id="monthly_report", replace_existing=True)


# ---------------- SocketIO handlers ----------------
@socketio.on("connect")
def handle_connect():
    print("Client connected:", request.sid)
    emit("connection_response", {"data": "Bağlantı başarılı"})


@socketio.on("disconnect")
def handle_disconnect():
    print("Client disconnected:", request.sid)
    for courier_id, sid in list(courier_connections.items()):
        if sid == request.sid:
            del courier_connections[courier_id]
            print("Courier", courier_id, "disconnected")
            break


@socketio.on("courier_register")
def handle_courier_register(data):
    try:
        courier_id = str(data.get("courier_id"))
        if courier_id:
            courier_connections[courier_id] = request.sid
            join_room(f"courier_{courier_id}")
            emit("registration_success", {"message": "Kurye kaydı başarılı"})
            print("Registered courier", courier_id, "sid:", request.sid)
        else:
            emit("registration_error", {"message": "Kurye ID gerekli"})
    except Exception as e:
        print("handle_courier_register error:", e)
        traceback.print_exc()
        emit("registration_error", {"message": "Kayıt sırasında hata oluştu"})


# ---------------- Notifications (websocket + fcm) ----------------
def notify_courier_new_order(courier_id, order_data):
    try:
        cid_str = str(courier_id)
        ws_sent = False
        fcm_sent = False
        if cid_str in courier_connections:
            socketio.emit("new_order", order_data, room=f"courier_{cid_str}")
            ws_sent = True
            print("WebSocket new_order sent for", cid_str)

        res = execute_with_retry("SELECT fcm_token FROM couriers WHERE id = ?", (courier_id,))
        if res and len(res) > 0:
            courier = row_to_dict(res[0])
            fcm_token = courier.get("fcm_token")
            if fcm_token:
                title = "Yeni Sipariş 🚴"
                body = f"{order_data.get('customer_name','Müşteri')} - {order_data.get('address','Adres')}"
                payload = {
                    "type": "new_order",
                    "order_id": str(order_data.get("order_id")),
                    "order_uuid": order_data.get("order_uuid", ""),
                }
                payload.update({k: str(v) for k, v in order_data.items()})
                fcm_sent = send_fcm_notification(fcm_token, title, body, payload)
        return ws_sent or fcm_sent
    except Exception as e:
        print("notify_courier_new_order error:", e)
        traceback.print_exc()
        return False


def notify_courier_reassignment(courier_id, order_id, action):
    try:
        cid_str = str(courier_id)
        if cid_str in courier_connections:
            socketio.emit("order_reassigned", {"order_id": order_id, "action": action}, room=f"courier_{cid_str}")
        res = execute_with_retry("SELECT fcm_token FROM couriers WHERE id = ?", (courier_id,))
        if res and len(res) > 0:
            courier = row_to_dict(res[0])
            fcm_token = courier.get("fcm_token")
            if fcm_token:
                title = "Sipariş Yeniden Atandı" if action == "removed" else "Yeni Sipariş Atandı"
                body = "Bir sipariş yeniden atandı"
                payload = {"type": "reassignment", "order_id": str(order_id), "action": action}
                send_fcm_notification(fcm_token, title, body, payload)
        return True
    except Exception as e:
        print("notify_courier_reassignment error:", e)
        traceback.print_exc()
        return False


# ---------------- Auth helpers ----------------
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
    payload = {"user_id": int(user_id), "role": role, "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXP_HOURS)}
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def decode_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])


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


# ---------------- Utility: neighborhood extraction & assignment logic ----------------
def extract_neighborhood(address):
    if not address:
        return None
    a = address.lower()
    patterns = [r'(\w+)\s*mah\.', r'(\w+)\s*mahallesi', r'(\w+)\s*mahalle', r'mah\.\s*(\w+)', r'mahallesi\s*(\w+)']
    for p in patterns:
        m = re.search(p, a)
        if m:
            return m.group(1).strip().title()
    return None


def get_or_create_neighborhood(name):
    if not name:
        return None
    r = execute_with_retry("SELECT id FROM neighborhoods WHERE name = ?", (name,))
    if r and len(r) > 0:
        return r[0]["id"]
    ok = execute_write_with_retry("INSERT INTO neighborhoods (name, created_at) VALUES (?, ?)", (name, datetime.utcnow().isoformat()))
    if ok:
        r = execute_with_retry("SELECT id FROM neighborhoods WHERE name = ?", (name,))
        if r and len(r) > 0:
            return r[0]["id"]
    return None


def ensure_courier_performance(courier_id):
    r = execute_with_retry("SELECT 1 FROM courier_performance WHERE courier_id = ?", (courier_id,))
    if not r or len(r) == 0:
        execute_write_with_retry("INSERT INTO courier_performance (courier_id, last_assigned) VALUES (?, ?)", (courier_id, datetime.utcnow().isoformat()))


def is_courier_in_cooldown(courier_id, neighborhood_id):
    r = execute_with_retry("SELECT cooldown_until FROM courier_performance WHERE courier_id = ? AND current_neighborhood_id = ?", (courier_id, neighborhood_id))
    if r and len(r) > 0:
        cu = r[0]["cooldown_until"]
        if cu:
            try:
                dt = datetime.fromisoformat(cu)
                return dt > datetime.utcnow()
            except Exception:
                return False
    return False


def set_courier_cooldown(courier_id, neighborhood_id, minutes=3):
    cooldown_until = (datetime.utcnow() + timedelta(minutes=minutes)).isoformat()
    execute_write_with_retry("UPDATE courier_performance SET cooldown_until = ?, current_neighborhood_id = ? WHERE courier_id = ?", (cooldown_until, neighborhood_id, courier_id))


def assign_order_to_courier(order_id):
    try:
        res = execute_with_retry("SELECT * FROM orders WHERE id = ?", (order_id,))
        if not res or len(res) == 0:
            return False
        order = row_to_dict(res[0])
        address = order.get("address")
        neighborhood_name = extract_neighborhood(address)
        neighborhood_id = None
        if neighborhood_name:
            neighborhood_id = get_or_create_neighborhood(neighborhood_name)
            execute_write_with_retry("UPDATE orders SET neighborhood_id = ? WHERE id = ?", (neighborhood_id, order_id))

        # Try cooldowned couriers in same neighborhood
        if neighborhood_id:
            rows = execute_with_retry("""
                SELECT cp.courier_id, c.status
                FROM courier_performance cp
                JOIN couriers c ON cp.courier_id = c.id
                WHERE cp.current_neighborhood_id = ? 
                  AND cp.cooldown_until > ?
                  AND c.status IN ('boşta', 'teslimatta')
            """, (neighborhood_id, datetime.utcnow().isoformat()))
            if rows:
                for r in rows:
                    cr = row_to_dict(r)
                    courier_id = cr["courier_id"]
                    execute_write_with_retry("UPDATE orders SET courier_id = ?, status = 'teslim alındı' WHERE id = ?", (courier_id, order_id))
                    execute_write_with_retry("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", (courier_id,))
                    ensure_courier_performance(courier_id)
                    execute_write_with_retry("UPDATE courier_performance SET daily_orders = COALESCE(daily_orders,0)+1, total_orders = COALESCE(total_orders,0)+1, last_assigned = ? WHERE courier_id = ?", (datetime.utcnow().isoformat(), courier_id))
                    set_courier_cooldown(courier_id, neighborhood_id)
                    # notify
                    order_row = execute_with_retry("SELECT * FROM orders WHERE id = ?", (order_id,))
                    notify_courier_new_order(courier_id, row_to_dict(order_row[0]) if order_row else {})
                    return True

        # Next priority: couriers active in same neighborhood recent orders
        five_min_ago = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
        if neighborhood_id:
            rows = execute_with_retry("""
                SELECT courier_id, COUNT(*) as order_count 
                FROM orders 
                WHERE neighborhood_id = ? 
                  AND created_at >= ? 
                  AND status IN ('yeni','teslim alındı')
                  AND courier_id IS NOT NULL
                GROUP BY courier_id
                ORDER BY order_count ASC
            """, (neighborhood_id, five_min_ago))
            if rows:
                for r in rows:
                    courier_id = r["courier_id"]
                    st = execute_with_retry("SELECT status FROM couriers WHERE id = ?", (courier_id,))
                    if st and st[0]["status"] in ("boşta", "teslimatta"):
                        execute_write_with_retry("UPDATE orders SET courier_id = ? WHERE id = ?", (courier_id, order_id))
                        execute_write_with_retry("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", (courier_id,))
                        ensure_courier_performance(courier_id)
                        execute_write_with_retry("UPDATE courier_performance SET daily_orders = COALESCE(daily_orders,0)+1, total_orders = COALESCE(total_orders,0)+1, last_assigned = ? WHERE courier_id = ?", (datetime.utcnow().isoformat(), courier_id))
                        set_courier_cooldown(courier_id, neighborhood_id)
                        order_row = execute_with_retry("SELECT * FROM orders WHERE id = ?", (order_id,))
                        notify_courier_new_order(courier_id, row_to_dict(order_row[0]) if order_row else {})
                        return True

        # Fallback: choose least busy courier overall
        rows = execute_with_retry("""
            SELECT c.id, COALESCE(cp.daily_orders, 0) as daily_orders, COALESCE(cp.last_assigned, '2000-01-01T00:00:00') as last_assigned
            FROM couriers c
            LEFT JOIN courier_performance cp ON c.id = cp.courier_id
            WHERE c.status IN ('boşta', 'teslimatta')
            ORDER BY daily_orders ASC, last_assigned ASC
            LIMIT 1
        """)
        if rows and len(rows) > 0:
            c = row_to_dict(rows[0])
            courier_id = c["id"]
            execute_write_with_retry("UPDATE orders SET courier_id = ? WHERE id = ?", (courier_id, order_id))
            execute_write_with_retry("UPDATE couriers SET status = 'teslimatta' WHERE id = ?", (courier_id,))
            ensure_courier_performance(courier_id)
            execute_write_with_retry("UPDATE courier_performance SET daily_orders = COALESCE(daily_orders,0)+1, total_orders = COALESCE(total_orders,0)+1, last_assigned = ? WHERE courier_id = ?", (datetime.utcnow().isoformat(), courier_id))
            if neighborhood_id:
                set_courier_cooldown(courier_id, neighborhood_id)
            order_row = execute_with_retry("SELECT * FROM orders WHERE id = ?", (order_id,))
            notify_courier_new_order(courier_id, row_to_dict(order_row[0]) if order_row else {})
            return True
        return False
    except Exception as e:
        print("assign_order_to_courier error:", e)
        traceback.print_exc()
        return False


# ---------------- Routes: Auth, users, couriers, orders, webhooks ----------------
@app.route("/auth/register", methods=["POST"])
def auth_register():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    role = (data.get("role") or "courier").lower()
    if not username or not password:
        return jsonify({"message": "username ve password gerekli"}), 400
    if role not in ("admin", "courier", "restaurant"):
        return jsonify({"message": "role admin|courier|restaurant olmalı"}), 400

    # admin creation rules
    if role == "admin":
        r = execute_with_retry("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1")
        if r is not None and len(r) > 0:
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

    restaurant_id = None
    if role == "restaurant":
        restaurant_id = data.get("restaurant_id")
        if not restaurant_id:
            return jsonify({"message": "Restoran için restaurant_id gerekli"}), 400
        rest_phone = data.get("phone")
        if not rest_phone:
            return jsonify({"message": "Restoran kaydı için telefon gerekli"}), 400
        restaurant_id = str(restaurant_id)
        r = execute_with_retry("SELECT id FROM restaurants WHERE restaurant_id = ?", (restaurant_id,))
        if not r or len(r) == 0:
            restaurant_name = data.get("restaurant_name") or f"Unnamed {restaurant_id}"
            address = data.get("address") or ""
            phone = rest_phone
            fee = data.get("fee_per_package", 5.0)
            try:
                execute_write_with_retry("INSERT INTO restaurants (restaurant_id, name, fee_per_package, address, phone, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                                         (restaurant_id, restaurant_name, fee, address, phone, datetime.utcnow().isoformat()))
            except sqlite3.IntegrityError as e:
                return jsonify({"message": "Restaurant oluşturulurken hata", "error": str(e)}), 400

    if role == "courier":
        phone = data.get("phone")
        if not phone:
            return jsonify({"message": "Kurye kaydı için telefon gerekli"}), 400

    existing = execute_with_retry("SELECT id FROM users WHERE username = ?", (username,))
    if existing and len(existing) > 0:
        return jsonify({"message": "Kullanıcı adı zaten kullanılıyor"}), 400

    hashed = hash_password(password)
    try:
        if role == "restaurant":
            execute_write_with_retry("INSERT INTO users (username, password_hash, role, created_at, restaurant_id) VALUES (?, ?, ?, ?, ?)",
                                     (username, hashed, role, datetime.utcnow().isoformat(), restaurant_id))
        else:
            execute_write_with_retry("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                                     (username, hashed, role, datetime.utcnow().isoformat()))
        # get id
        r = execute_with_retry("SELECT id FROM users WHERE username = ?", (username,))
        if not r or len(r) == 0:
            return jsonify({"message": "Kullanıcı oluşturulamadı"}), 500
        user_id = r[0]["id"]
        courier_obj = None
        if role == "courier":
            first_name = data.get("first_name") or ""
            last_name = data.get("last_name") or ""
            email = data.get("email")
            phone = data.get("phone")
            execute_write_with_retry("INSERT INTO couriers (user_id, first_name, last_name, email, phone, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                                     (user_id, first_name, last_name, email, phone, datetime.utcnow().isoformat()))
            res = execute_with_retry("SELECT * FROM couriers WHERE user_id = ?", (user_id,))
            if res and len(res) > 0:
                courier_obj = row_to_dict(res[0])
    except sqlite3.IntegrityError as e:
        return jsonify({"message": "IntegrityError", "error": str(e)}), 400

    user_resp = {"id": user_id, "username": username, "role": role, "created_at": datetime.utcnow().isoformat()}
    if role == "courier":
        user_resp["courier"] = courier_obj
    if role == "restaurant":
        user_resp["restaurant_id"] = restaurant_id
    return jsonify({"message": f"{role} oluşturuldu", "user": user_resp}), 201


@app.route("/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"message": "username ve password gerekli"}), 400
    res = execute_with_retry("SELECT * FROM users WHERE username = ?", (username,))
    if not res or len(res) == 0:
        return jsonify({"message": "Kullanıcı bulunamadı"}), 404
    user_row = row_to_dict(res[0])
    if not check_password(password, user_row["password_hash"]):
        return jsonify({"message": "Parola yanlış"}), 401
    user_id = user_row["id"]
    role = user_row["role"]
    token = generate_token(user_id, role)
    user_out = {"id": user_id, "username": user_row["username"], "role": role, "created_at": user_row["created_at"]}
    if role == "courier":
        r = execute_with_retry("SELECT id, first_name, last_name, email, phone, status, created_at FROM couriers WHERE user_id = ?", (user_id,))
        if r and len(r) > 0:
            user_out["courier"] = row_to_dict(r[0])
    if role == "restaurant":
        user_out["restaurant_id"] = user_row.get("restaurant_id")
    return jsonify({"token": token, "user": user_out})


# Update FCM token endpoint (used by app)
@app.route("/couriers/<int:courier_id>/fcm-token", methods=["POST"])
@token_required
def update_fcm_token(courier_id):
    # courier can update own token unless admin
    if request.user_role != "admin":
        r = execute_with_retry("SELECT user_id FROM couriers WHERE id = ?", (courier_id,))
        if not r or len(r) == 0 or r[0]["user_id"] != request.user_id:
            return jsonify({"message": "Yetkisiz"}), 403
    data = request.get_json() or {}
    fcm_token = data.get("fcm_token")
    if not fcm_token:
        return jsonify({"message": "FCM token gerekli"}), 400
    try:
        ok = execute_write_with_retry("UPDATE couriers SET fcm_token = ? WHERE id = ?", (fcm_token, courier_id))
        if ok:
            return jsonify({"message": "FCM token güncellendi"})
        return jsonify({"message": "FCM token güncellenemedi"}), 500
    except Exception as e:
        print("update_fcm_token error:", e)
        traceback.print_exc()
        return jsonify({"message": "Sunucu hatası"}), 500


# Example webhook that creates order and triggers assignment
@app.route("/webhooks/yemeksepeti", methods=["POST"])
def webhook_yemeksepeti():
    data = request.get_json() or {}
    external_id = data.get("external_id") or data.get("order_id") or data.get("id")
    vendor_id = data.get("vendor_id")
    vendor_id = None if vendor_id is None else str(vendor_id)
    customer_name = data.get("customer_name") or data.get("customer")
    items = data.get("items")
    total = data.get("total") or data.get("total_amount") or 0
    address = data.get("address") or data.get("customer_address")
    payload = json.dumps(data, ensure_ascii=False)
    created = datetime.utcnow().isoformat()
    order_uuid = f"o-{int(datetime.utcnow().timestamp() * 1000)}"
    try:
        ok = execute_write_with_retry(
            """INSERT INTO orders (order_uuid, external_id, vendor_id, customer_name, items, total_amount, address, payload, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (order_uuid, external_id, vendor_id, customer_name, json.dumps(items, ensure_ascii=False), total, address, payload, created, created)
        )
    except sqlite3.IntegrityError as ie:
        print("WEBHOOK INSERT IntegrityError:", ie)
        traceback.print_exc()
        return jsonify({"message": "Sipariş kaydedilirken hata", "error": str(ie)}), 400
    except Exception as e:
        print("WEBHOOK INSERT error:", e)
        traceback.print_exc()
        return jsonify({"message": "Sunucu hatası (insert)", "error": str(e)}), 500
    if not ok:
        return jsonify({"message": "Sunucu hatası (insert başarısız)"}), 500
    try:
        res = execute_with_retry("SELECT id FROM orders WHERE order_uuid = ?", (order_uuid,))
    except Exception as e:
        print("WEBHOOK SELECT error:", e)
        traceback.print_exc()
        return jsonify({"message": "Sunucu hatası (select)", "error": str(e)}), 500
    if not res or len(res) == 0:
        return jsonify({"message": "Sipariş kaydedilemedi"}), 500
    order_id = res[0]["id"]
    # Try to assign - do not fail webhook if assignment fails
    try:
        assign_order_to_courier(order_id)
    except Exception as e:
        print("assign_order_to_courier failed:", e)
        traceback.print_exc()
    return jsonify({"message": "Sipariş alındı", "order_uuid": order_uuid}), 201


# ---------------- Admin endpoints (examples) ----------------
@app.route("/admin/trigger-monthly-report", methods=["POST"])
@admin_required
def trigger_monthly_report():
    try:
        result = distribute_monthly_report()
        return jsonify({"message": "Rapor dağıtımı başlatıldı", "result": result})
    except Exception as e:
        print("trigger_monthly_report error:", e)
        traceback.print_exc()
        return jsonify({"message": "Rapor tetikleme hatası", "error": str(e)}), 500


@app.route("/admin/couriers", methods=["POST"])
@admin_required
def admin_create_courier():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    phone = data.get("phone")
    email = data.get("email")
    if not username or not password or not phone:
        return jsonify({"message": "username,password,phone gerekli"}), 400
    # uniqueness checks simplified
    if execute_with_retry("SELECT 1 FROM users WHERE username = ?", (username,)):
        return jsonify({"message": "Kullanıcı adı kullanılıyor"}), 400
    if email and execute_with_retry("SELECT 1 FROM couriers WHERE email = ?", (email,)):
        return jsonify({"message": "E-posta zaten kullanılıyor"}), 400
    if execute_with_retry("SELECT 1 FROM couriers WHERE phone = ?", (phone,)):
        return jsonify({"message": "Telefon zaten kullanılıyor"}), 400
    hashed = hash_password(password)
    try:
        execute_write_with_retry("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'courier', ?)", (username, hashed, datetime.utcnow().isoformat()))
        r = execute_with_retry("SELECT id FROM users WHERE username = ?", (username,))
        if not r or len(r) == 0:
            return jsonify({"message": "Kullanıcı oluşturulamadı"}), 500
        user_id = r[0]["id"]
        first_name = data.get("first_name") or ""
        last_name = data.get("last_name") or ""
        execute_write_with_retry("INSERT INTO couriers (user_id, first_name, last_name, email, phone, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                                 (user_id, first_name, last_name, email, phone, datetime.utcnow().isoformat()))
        courier_row = execute_with_retry("SELECT id, user_id, first_name, last_name, email, phone, status, created_at FROM couriers WHERE user_id = ?", (user_id,))
        return jsonify({"message": "Kurye oluşturuldu", "courier": row_to_dict(courier_row[0])}), 201
    except Exception as e:
        print("admin_create_courier error:", e)
        traceback.print_exc()
        return jsonify({"message": "Hata", "error": str(e)}), 500


# ---------------- Misc endpoints: users, couriers list (admin) ----------------
@app.route("/users", methods=["GET"])
@admin_required
def list_users():
    res = execute_with_retry("SELECT id, username, role, created_at, restaurant_id FROM users")
    return jsonify([row_to_dict(r) for r in (res or [])])


@app.route("/couriers", methods=["GET"])
@admin_required
def admin_list_couriers():
    res = execute_with_retry("SELECT id, user_id, first_name, last_name, email, phone, status, created_at, fcm_token FROM couriers")
    return jsonify([row_to_dict(r) for r in (res or [])])


# ---------------- App startup ----------------
if __name__ == "__main__":
    # Ensure DB initialized
    init_db()
    print("Database initialized or checked.")
    # Start SocketIO / Flask app
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "5000"))
    DEBUG = os.getenv("DEBUG", "False").lower() in ("1", "true", "yes")
    socketio.run(app, host=HOST, port=PORT, debug=DEBUG)
