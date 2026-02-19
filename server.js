const https = require('https');
const fs = require('fs');
const express = require('express');
const crypto = require('crypto');
const querystring = require('querystring');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── CONFIG ────────────────────────────────────────────────────────────────
const PORT = 8443;
const CONFIG_MODE = 'auto'; // 'auto' or 'manual'

// Registered clients
const CLIENTS = {
  'my-client-id': {
    secret: 'my-client-secret',
    redirectUris: ['https://shyam-nts0023.csez.zohocorpin.com:443/applicationOauthRedirect','https://oauth.pstmn.io/v1/callback'],
    allowedScopes: ['openid', 'profile', 'email', 'read', 'write'],
  },
};

// Mock users (for auto mode)
const USERS = {
  'user@example.com': { password: 'password', sub: 'user-001', name: 'Test User', email: 'user@example.com' },
  'admin@example.com': { password: 'admin', sub: 'admin-001', name: 'Admin User', email: 'admin@example.com' },
};

// In-memory stores
const authCodes = new Map();   // code -> { clientId, redirectUri, scope, sub, expiresAt, codeChallenge, codeChallengeMethod }
const tokens = new Map();      // access_token -> { sub, clientId, scope, expiresAt }
const refreshTokens = new Map(); // refresh_token -> { sub, clientId, scope }

// ─── HELPERS ───────────────────────────────────────────────────────────────
function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

function parseBasicAuth(req) {
  const authHeader = req.headers['authorization'] || '';
  if (!authHeader.startsWith('Basic ')) return null;
  const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
  const [id, secret] = decoded.split(':');
  return { id: decodeURIComponent(id), secret: decodeURIComponent(secret) };
}

function authenticateClient(req) {
  const creds = parseBasicAuth(req);
  if (!creds) return { error: 'invalid_client', error_description: 'Missing Basic auth header' };
  const client = CLIENTS[creds.id];
  if (!client || client.secret !== creds.secret)
    return { error: 'invalid_client', error_description: 'Invalid client credentials' };
  return { client, clientId: creds.id };
}

// ─── ENDPOINTS ─────────────────────────────────────────────────────────────

// Discovery / well-known
app.get('/.well-known/openid-configuration', (req, res) => {
  const base = `https://localhost:${PORT}`;
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/oauth2/authorize`,
    token_endpoint: `${base}/oauth2/token`,
    userinfo_endpoint: `${base}/oauth2/userinfo`,
    jwks_uri: `${base}/.well-known/jwks.json`,
    revocation_endpoint: `${base}/oauth2/revoke`,
    introspection_endpoint: `${base}/oauth2/introspect`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['client_secret_basic'],
    scopes_supported: ['openid', 'profile', 'email', 'read', 'write'],
    subject_types_supported: ['public'],
  });
});

// JWKS (stub)
app.get('/.well-known/jwks.json', (req, res) => {
  res.json({ keys: [] });
});

// ─── AUTHORIZATION ENDPOINT ───────────────────────────────────────────────
app.get('/oauth2/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method } = req.query;

  // Validate
  if (response_type !== 'code')
    return res.status(400).send('unsupported_response_type');
  const client = CLIENTS[client_id];
  if (!client)
    return res.status(400).send('invalid_client');
  if (!client.redirectUris.includes(redirect_uri))
    return res.status(400).send('invalid_redirect_uri');

  if (CONFIG_MODE === 'auto') {
    // Auto mode: skip login, use first mock user
    const sub = USERS['user@example.com'].sub;
    const code = generateToken(16);
    authCodes.set(code, {
      clientId: client_id,
      redirectUri: redirect_uri,
      scope: scope || '',
      sub,
      expiresAt: Date.now() + 60_000,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method,
    });
    const redirect = `${redirect_uri}?code=${code}${state ? `&state=${state}` : ''}`;
    return res.redirect(redirect);
  }

  // Manual mode: show login form
  res.send(`<!DOCTYPE html>
<html>
<head><title>OAuth2 Mock Login</title>
<style>
  body { font-family: Arial, sans-serif; display:flex; justify-content:center; align-items:center; height:100vh; margin:0; background:#f0f2f5; }
  .box { background:#fff; padding:2rem; border-radius:8px; box-shadow:0 2px 10px rgba(0,0,0,0.1); width:320px; }
  h2 { margin-top:0; color:#333; }
  input { width:100%; padding:8px; margin:6px 0 14px; box-sizing:border-box; border:1px solid #ccc; border-radius:4px; }
  button { width:100%; padding:10px; background:#4f46e5; color:#fff; border:none; border-radius:4px; cursor:pointer; font-size:1rem; }
  .info { font-size:0.8rem; color:#666; margin-bottom:1rem; }
  .scope { background:#f5f5f5; padding:6px; border-radius:4px; margin-bottom:1rem; font-size:0.85rem; }
</style>
</head>
<body>
<div class="box">
  <h2>🔐 Mock OAuth2 Login</h2>
  <div class="info">Client: <strong>${client_id}</strong></div>
  <div class="scope">Scopes: ${scope || '(none)'}</div>
  <form method="POST" action="/oauth2/authorize">
    <input type="hidden" name="client_id" value="${client_id}">
    <input type="hidden" name="redirect_uri" value="${redirect_uri}">
    <input type="hidden" name="scope" value="${scope || ''}">
    <input type="hidden" name="state" value="${state || ''}">
    <input type="hidden" name="code_challenge" value="${code_challenge || ''}">
    <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ''}">
    <label>Email</label>
    <input type="text" name="username" placeholder="user@example.com" required>
    <label>Password</label>
    <input type="password" name="password" placeholder="password" required>
    <button type="submit">Sign In & Authorize</button>
  </form>
  <p style="font-size:0.75rem;color:#999;margin-top:1rem;">Test credentials:<br>user@example.com / password<br>admin@example.com / admin</p>
</div>
</body>
</html>`);
});

app.post('/oauth2/authorize', (req, res) => {
  const { client_id, redirect_uri, scope, state, username, password, code_challenge, code_challenge_method } = req.body;
  const client = CLIENTS[client_id];
  if (!client || !client.redirectUris.includes(redirect_uri))
    return res.status(400).send('invalid_request');

  const user = USERS[username];
  if (!user || user.password !== password) {
    return res.status(401).send('Invalid credentials');
  }

  const code = generateToken(16);
  authCodes.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    scope: scope || '',
    sub: user.sub,
    expiresAt: Date.now() + 60_000,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
  });
  const redirect = `${redirect_uri}?code=${code}${state ? `&state=${state}` : ''}`;
  res.redirect(redirect);
});

// ─── TOKEN ENDPOINT ───────────────────────────────────────────────────────
app.post('/oauth2/token', (req, res) => {
  const auth = authenticateClient(req);
  if (auth.error) return res.status(401).json(auth);

  const { grant_type, code, redirect_uri, refresh_token, scope } = req.body;

  if (grant_type === 'authorization_code') {
    const entry = authCodes.get(code);
    if (!entry) return res.status(400).json({ error: 'invalid_grant', error_description: 'Code not found or expired' });
    if (Date.now() > entry.expiresAt) { authCodes.delete(code); return res.status(400).json({ error: 'invalid_grant', error_description: 'Code expired' }); }
    if (entry.clientId !== auth.clientId) return res.status(400).json({ error: 'invalid_grant', error_description: 'Client mismatch' });
    if (entry.redirectUri !== redirect_uri) return res.status(400).json({ error: 'invalid_grant', error_description: 'Redirect URI mismatch' });
    authCodes.delete(code);

    const accessToken = generateToken();
    const refreshToken = generateToken();
    tokens.set(accessToken, { sub: entry.sub, clientId: auth.clientId, scope: entry.scope, expiresAt: Date.now() + 3600_000 });
    refreshTokens.set(refreshToken, { sub: entry.sub, clientId: auth.clientId, scope: entry.scope });

    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: entry.scope,
    });
  }

  if (grant_type === 'refresh_token') {
    const entry = refreshTokens.get(refresh_token);
    if (!entry || entry.clientId !== auth.clientId)
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid refresh token' });

    const accessToken = generateToken();
    tokens.set(accessToken, { sub: entry.sub, clientId: auth.clientId, scope: entry.scope, expiresAt: Date.now() + 3600_000 });

    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: entry.scope,
    });
  }

  res.status(400).json({ error: 'unsupported_grant_type' });
});

// ─── USERINFO ─────────────────────────────────────────────────────────────
app.get('/oauth2/userinfo', (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '');
  const entry = tokens.get(token);
  if (!entry || Date.now() > entry.expiresAt) return res.status(401).json({ error: 'invalid_token' });

  const user = Object.values(USERS).find(u => u.sub === entry.sub);
  res.json({ sub: entry.sub, name: user?.name, email: user?.email });
});

// ─── INTROSPECT ───────────────────────────────────────────────────────────
app.post('/oauth2/introspect', (req, res) => {
  const auth = authenticateClient(req);
  if (auth.error) return res.status(401).json(auth);

  const entry = tokens.get(req.body.token);
  if (!entry || Date.now() > entry.expiresAt) return res.json({ active: false });

  res.json({
    active: true,
    sub: entry.sub,
    client_id: entry.clientId,
    scope: entry.scope,
    exp: Math.floor(entry.expiresAt / 1000),
    token_type: 'Bearer',
  });
});

// ─── REVOKE ───────────────────────────────────────────────────────────────
app.post('/oauth2/revoke', (req, res) => {
  const auth = authenticateClient(req);
  if (auth.error) return res.status(401).json(auth);
  tokens.delete(req.body.token);
  refreshTokens.delete(req.body.token);
  res.status(200).json({ revoked: true });
});

// ─── START HTTPS ──────────────────────────────────────────────────────────
const sslOptions = {
  key: fs.readFileSync('certs/server.key'),
  cert: fs.readFileSync('certs/server.crt'),
};

https.createServer(sslOptions, app).listen(PORT, () => {
  console.log(`\n🔐 OAuth2 Mock Server running at https://localhost:${PORT}`);
  console.log(`   Mode: ${CONFIG_MODE.toUpperCase()}`);
  console.log(`\n📋 Endpoints:`);
  console.log(`   Discovery:     https://localhost:${PORT}/.well-known/openid-configuration`);
  console.log(`   Authorization: https://localhost:${PORT}/oauth2/authorize`);
  console.log(`   Token:         https://localhost:${PORT}/oauth2/token`);
  console.log(`   Userinfo:      https://localhost:${PORT}/oauth2/userinfo`);
  console.log(`   Introspect:    https://localhost:${PORT}/oauth2/introspect`);
  console.log(`   Revoke:        https://localhost:${PORT}/oauth2/revoke`);
  console.log(`\n👤 Test Client:`);
  console.log(`   client_id:     my-client-id`);
  console.log(`   client_secret: my-client-secret`);
  console.log(`   scope:         openid,profile,email,read,write  (comma-delimited)`);
});
