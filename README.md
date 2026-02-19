# OAuth2 Mock Server (HTTPS)

A local OAuth2 mock server supporting:
- ✅ **Grant Type**: Authorization Code
- ✅ **Config Mode**: Auto (skip login) or Manual (login form)
- ✅ **Client Authentication**: Client Secret Basic (HTTP Basic Auth)
- ✅ **Scope Delimiter**: Comma
- ✅ **Transport**: HTTPS (self-signed cert, localhost:8443)

---

## 🚀 Quick Start (Windows)

### 1. Install Node.js
Download from https://nodejs.org (v18+ recommended)

### 2. Install dependencies
```cmd
npm install
```

### 3. Generate SSL certificate
```cmd
node setup-certs.js
```

### 4. (Optional) Trust the cert so browsers don't warn
Run PowerShell **as Administrator**:
```powershell
Import-Certificate -FilePath ".\certs\server.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

### 5. Start the server
```cmd
npm start
```

Server runs at **https://localhost:8443**

---

## 📋 Endpoints

| Endpoint | URL |
|----------|-----|
| Discovery | `GET https://localhost:8443/.well-known/openid-configuration` |
| Authorization | `GET https://localhost:8443/oauth2/authorize` |
| Token | `POST https://localhost:8443/oauth2/token` |
| Userinfo | `GET https://localhost:8443/oauth2/userinfo` |
| Introspect | `POST https://localhost:8443/oauth2/introspect` |
| Revoke | `POST https://localhost:8443/oauth2/revoke` |

---

## 👤 Test Credentials

### Client
| Field | Value |
|-------|-------|
| client_id | `my-client-id` |
| client_secret | `my-client-secret` |
| redirect_uri | `https://localhost:3000/callback` |

### Users (Manual mode only)
| Email | Password |
|-------|----------|
| user@example.com | password |
| admin@example.com | admin |

---

## 🔄 Authorization Code Flow

### Step 1 — Get Authorization Code
```
GET https://localhost:8443/oauth2/authorize
  ?client_id=my-client-id
  &redirect_uri=https://localhost:3000/callback
  &response_type=code
  &scope=openid,profile,email
  &state=random-state
```
- **Auto mode**: Instantly redirects with `?code=...`
- **Manual mode**: Shows a login form

### Step 2 — Exchange Code for Token
```
POST https://localhost:8443/oauth2/token
Authorization: Basic bXktY2xpZW50LWlkOm15LWNsaWVudC1zZWNyZXQ=
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<code from step 1>
&redirect_uri=https://localhost:3000/callback
```
The Basic auth value is Base64 of `my-client-id:my-client-secret`.

### Step 3 — Use Access Token
```
GET https://localhost:8443/oauth2/userinfo
Authorization: Bearer <access_token>
```

### Refresh Token
```
POST https://localhost:8443/oauth2/token
Authorization: Basic bXktY2xpZW50LWlkOm15LWNsaWVudC1zZWNyZXQ=
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=<refresh_token>
```

---

## ⚙️ Configuration

Edit `server.js` to change:

### Switch between Auto and Manual mode
```js
const CONFIG_MODE = 'auto'; // or 'manual'
```

### Add more clients
```js
const CLIENTS = {
  'my-client-id': {
    secret: 'my-client-secret',
    redirectUris: ['https://localhost:3000/callback'],
    allowedScopes: ['openid', 'profile', 'email', 'read', 'write'],
  },
  // Add more here...
};
```

### Add more users
```js
const USERS = {
  'newuser@example.com': { password: 'pass', sub: 'user-002', name: 'New User', email: 'newuser@example.com' },
};
```

### Change port
```js
const PORT = 8443;
```

---

## 🧪 Testing with curl

```bash
# Step 1: Get auth URL, visit it in browser (auto mode redirects immediately)
# The redirect will give you: https://localhost:3000/callback?code=XXXX

# Step 2: Exchange code
curl -k -X POST https://localhost:8443/oauth2/token \
  -H "Authorization: Basic bXktY2xpZW50LWlkOm15LWNsaWVudC1zZWNyZXQ=" \
  -d "grant_type=authorization_code&code=XXXX&redirect_uri=https://localhost:3000/callback"

# Step 3: Get user info
curl -k https://localhost:8443/oauth2/userinfo \
  -H "Authorization: Bearer <access_token>"
```

> `-k` flag skips SSL verification for self-signed certs in curl.

---

## 📝 Notes
- Tokens expire in 1 hour, auth codes expire in 60 seconds
- Everything is in-memory — restarts clear all sessions
- Comma-delimited scopes: `openid,profile,email`
