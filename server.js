const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── CONFIG ────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 8443;
const CONFIG_MODE = process.env.CONFIG_MODE || 'auto'; // 'auto' or 'manual'
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const CLIENTS = {
  'my-client-id': {
    secret: 'my-client-secret',
    redirectUris: [
      // Add your Log360 callback URL here e.g:
      // 'https://your-log360-server/oauth/callback',
      'https://localhost:3000/callback',
      'http://localhost:3000/callback',
    ],
    allowedScopes: ['openid', 'profile', 'email', 'read', 'write'],
  },
};

const USERS = {
  'user@example.com':  { password: 'password', sub: 'user-001',  name: 'Test User',  email: 'user@example.com' },
  'admin@example.com': { password: 'admin',    sub: 'admin-001', name: 'Admin User', email: 'admin@example.com' },
};

const authCodes     = new Map();
const tokens        = new Map();
const refreshTokens = new Map();

function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

function parseBasicAuth(req) {
  const h = req.headers['authorization'] || '';
  if (!h.startsWith('Basic ')) return null;
  const decoded = Buffer.from(h.slice(6), 'base64').toString('utf8');
  const [id, ...rest] = decoded.split(':');
  return { id: decodeURIComponent(id), secret: decodeURIComponent(rest.join(':')) };
}

function authenticateClient(req) {
  const creds = parseBasicAuth(req);
  if (!creds) return { error: 'invalid_client', error_description: 'Missing Basic auth header' };
  const client = CLIENTS[creds.id];
  if (!client || client.secret !== creds.secret)
    return { error: 'invalid_client', error_description: 'Invalid client credentials' };
  return { client, clientId: creds.id };
}

// Health / root
app.get('/', (req, res) => {
  res.json({
    status: 'running', mode: CONFIG_MODE,
    endpoints: {
      discovery:     `${BASE_URL}/.well-known/openid-configuration`,
      authorization: `${BASE_URL}/oauth2/authorize`,
      token:         `${BASE_URL}/oauth2/token`,
      userinfo:      `${BASE_URL}/oauth2/userinfo`,
      introspect:    `${BASE_URL}/oauth2/introspect`,
      revoke:        `${BASE_URL}/oauth2/revoke`,
    },
    test_client: { client_id: 'my-client-id', client_secret: 'my-client-secret', scopes: 'openid,profile,email,read,write' },
  });
});

// Discovery
app.get('/.well-known/openid-configuration', (req, res) => {
  res.json({
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/oauth2/authorize`,
    token_endpoint: `${BASE_URL}/oauth2/token`,
    userinfo_endpoint: `${BASE_URL}/oauth2/userinfo`,
    jwks_uri: `${BASE_URL}/.well-known/jwks.json`,
    revocation_endpoint: `${BASE_URL}/oauth2/revoke`,
    introspection_endpoint: `${BASE_URL}/oauth2/introspect`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['client_secret_basic'],
    scopes_supported: ['openid', 'profile', 'email', 'read', 'write'],
    subject_types_supported: ['public'],
  });
});

app.get('/.well-known/jwks.json', (req, res) => res.json({ keys: [] }));

// Authorization GET
app.get('/oauth2/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method } = req.query;
  if (response_type !== 'code') return res.status(400).json({ error: 'unsupported_response_type' });
  const client = CLIENTS[client_id];
  if (!client) return res.status(400).json({ error: 'invalid_client' });

  if (CONFIG_MODE === 'auto') {
    const code = generateToken(16);
    authCodes.set(code, { clientId: client_id, redirectUri: redirect_uri, scope: scope || '', sub: 'user-001', expiresAt: Date.now() + 60_000, codeChallenge: code_challenge, codeChallengeMethod: code_challenge_method });
    return res.redirect(`${redirect_uri}?code=${code}${state ? `&state=${encodeURIComponent(state)}` : ''}`);
  }

  res.send(`<!DOCTYPE html><html><head><title>OAuth2 Mock Login</title>
<style>body{font-family:Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f0f2f5}.box{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);width:320px}h2{margin-top:0;color:#333}input{width:100%;padding:8px;margin:6px 0 14px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}button{width:100%;padding:10px;background:#4f46e5;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:1rem}.scope{background:#f5f5f5;padding:6px;border-radius:4px;margin-bottom:1rem;font-size:.85rem}</style>
</head><body><div class="box">
<h2>🔐 Mock OAuth2 Login</h2>
<div class="scope">Client: <b>${client_id}</b><br>Scopes: ${scope || '(none)'}</div>
<form method="POST" action="/oauth2/authorize">
<input type="hidden" name="client_id" value="${client_id}">
<input type="hidden" name="redirect_uri" value="${redirect_uri}">
<input type="hidden" name="scope" value="${scope || ''}">
<input type="hidden" name="state" value="${state || ''}">
<input type="hidden" name="code_challenge" value="${code_challenge || ''}">
<input type="hidden" name="code_challenge_method" value="${code_challenge_method || ''}">
<label>Email</label><input type="text" name="username" placeholder="user@example.com" required>
<label>Password</label><input type="password" name="password" placeholder="password" required>
<button type="submit">Sign In & Authorize</button>
</form>
<p style="font-size:.75rem;color:#999;margin-top:1rem">user@example.com / password<br>admin@example.com / admin</p>
</div></body></html>`);
});

// Authorization POST (manual mode)
app.post('/oauth2/authorize', (req, res) => {
  const { client_id, redirect_uri, scope, state, username, password, code_challenge, code_challenge_method } = req.body;
  if (!CLIENTS[client_id]) return res.status(400).send('invalid_client');
  const user = USERS[username];
  if (!user || user.password !== password) return res.status(401).send('Invalid credentials');
  const code = generateToken(16);
  authCodes.set(code, { clientId: client_id, redirectUri: redirect_uri, scope: scope || '', sub: user.sub, expiresAt: Date.now() + 60_000, codeChallenge: code_challenge, codeChallengeMethod: code_challenge_method });
  res.redirect(`${redirect_uri}?code=${code}${state ? `&state=${encodeURIComponent(state)}` : ''}`);
});

// Token
app.post('/oauth2/token', (req, res) => {
  const auth = authenticateClient(req);
  if (auth.error) return res.status(401).json(auth);
  const { grant_type, code, refresh_token } = req.body;

  if (grant_type === 'authorization_code') {
    const entry = authCodes.get(code);
    if (!entry) return res.status(400).json({ error: 'invalid_grant', error_description: 'Code not found' });
    if (Date.now() > entry.expiresAt) { authCodes.delete(code); return res.status(400).json({ error: 'invalid_grant', error_description: 'Code expired' }); }
    if (entry.clientId !== auth.clientId) return res.status(400).json({ error: 'invalid_grant', error_description: 'Client mismatch' });
    authCodes.delete(code);
    const accessToken = generateToken();
    const refreshTok  = generateToken();
    tokens.set(accessToken, { sub: entry.sub, clientId: auth.clientId, scope: entry.scope, expiresAt: Date.now() + 3600_000 });
    refreshTokens.set(refreshTok, { sub: entry.sub, clientId: auth.clientId, scope: entry.scope });
    return res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600, refresh_token: refreshTok, scope: entry.scope });
  }

  if (grant_type === 'refresh_token') {
    const entry = refreshTokens.get(refresh_token);
    if (!entry || entry.clientId !== auth.clientId) return res.status(400).json({ error: 'invalid_grant' });
    const accessToken = generateToken();
    tokens.set(accessToken, { sub: entry.sub, clientId: auth.clientId, scope: entry.scope, expiresAt: Date.now() + 3600_000 });
    return res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600, scope: entry.scope });
  }

  res.status(400).json({ error: 'unsupported_grant_type' });
});

// Userinfo
app.get('/oauth2/userinfo', (req, res) => {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '');
  const entry = tokens.get(token);
  if (!entry || Date.now() > entry.expiresAt) return res.status(401).json({ error: 'invalid_token' });
  const user = Object.values(USERS).find(u => u.sub === entry.sub);
  res.json({ sub: entry.sub, name: user?.name, email: user?.email });
});

// Introspect
app.post('/oauth2/introspect', (req, res) => {
  const auth = authenticateClient(req);
  if (auth.error) return res.status(401).json(auth);
  const entry = tokens.get(req.body.token);
  if (!entry || Date.now() > entry.expiresAt) return res.json({ active: false });
  res.json({ active: true, sub: entry.sub, client_id: entry.clientId, scope: entry.scope, exp: Math.floor(entry.expiresAt / 1000), token_type: 'Bearer' });
});

// Revoke
app.post('/oauth2/revoke', (req, res) => {
  const auth = authenticateClient(req);
  if (auth.error) return res.status(401).json(auth);
  tokens.delete(req.body.token);
  refreshTokens.delete(req.body.token);
  res.json({ revoked: true });
});

app.listen(PORT, () => {
  console.log(`\n🔐 OAuth2 Mock Server running`);
  console.log(`   BASE_URL: ${BASE_URL}`);
  console.log(`   Mode:     ${CONFIG_MODE.toUpperCase()}`);
  console.log(`   Port:     ${PORT}`);
});
