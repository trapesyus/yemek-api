# test_firebase_creds.py
import os, json, traceback
from google.oauth2 import service_account
from google.auth.transport.requests import Request
import firebase_admin
from firebase_admin import credentials, messaging

CRED_PATHS = [
    "service-account.json"
   
]

def find_cred():
    for p in CRED_PATHS:
        if os.path.exists(p):
            return p
    env = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if env and os.path.exists(env):
        return env
    return None

def print_file_info(path):
    st = os.stat(path)
    print("Using credential file:", path)
    print("Size bytes:", st.st_size)
    print("Perms:", oct(st.st_mode & 0o777))
    try:
        with open(path, "r") as f:
            j = json.load(f)
        print("client_email:", j.get("client_email"))
        pk = j.get("private_key", "")
        print("private_key present:", bool(pk))
        print("private_key startswith BEGIN?:", pk.strip().startswith("-----BEGIN"))
        print("private_key endswith END?:", pk.strip().endswith("-----END PRIVATE KEY-----"))
    except Exception as e:
        print("Error reading JSON:", e)
        traceback.print_exc()

def test_google_token(path):
    try:
        creds = service_account.Credentials.from_service_account_file(
            path,
            scopes=["https://www.googleapis.com/auth/firebase.messaging"]
        )
        print("Loaded credentials for:", creds.service_account_email)
        creds.refresh(Request())
        print("access_token (first 40 chars):", (creds.token or "")[:40])
        print("expiry:", creds.expiry)
    except Exception as e:
        print("❌ Token refresh failed:")
        traceback.print_exc()

def test_firebase_admin(path):
    try:
        cred = credentials.Certificate(path)
        try:
            app = firebase_admin.initialize_app(cred)
            print("Firebase Admin initialized, app name:", app.name)
        except ValueError:
            app = firebase_admin.get_app()
            print("Firebase already initialized, using existing app:", app.name)
        print("firebase_admin OK")
    except Exception as e:
        print("❌ Firebase Admin init failed:")
        traceback.print_exc()

if __name__ == "__main__":
    path = find_cred()
    if not path:
        print("No credential file found. Set GOOGLE_APPLICATION_CREDENTIALS or place the JSON in one of:", CRED_PATHS)
        raise SystemExit(1)
    print_file_info(path)
    print("=== testing google token refresh ===")
    test_google_token(path)
    print("=== testing firebase admin init ===")
    test_firebase_admin(path)
