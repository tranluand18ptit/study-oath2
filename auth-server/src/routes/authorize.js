import crypto from 'crypto';
import { Router } from 'express';
import bcrypt from 'bcrypt';
import db from '../db/db.js';
import { generateAuthCode } from '../utils/pkce.js';

const router = Router();
const pendingAuthorizations = new Map();
const PENDING_AUTH_TTL_MS = Number(process.env.AUTH_CODE_EXPIRY_SECONDS || 300) * 1000;

function cleanupExpiredTransactions() {
  const now = Date.now();

  for (const [transactionId, transaction] of pendingAuthorizations.entries()) {
    if (transaction.expiresAt <= now) {
      pendingAuthorizations.delete(transactionId);
    }
  }
}

function validateAuthorizeRequest(params) {
  const {
    client_id,
    redirect_uri,
    response_type,
    scope,
    code_challenge,
    code_challenge_method,
    state,
  } = params;

  const errors = [];
  if (response_type !== 'code') errors.push('response_type must be "code"');
  if (!client_id) errors.push('client_id is required');
  if (!redirect_uri) errors.push('redirect_uri is required');
  if (!code_challenge) errors.push('code_challenge is required (PKCE)');
  if (code_challenge_method !== 'S256') errors.push('code_challenge_method must be "S256"');
  if (!state) errors.push('state is required');

  if (errors.length) {
    return { ok: false, status: 400, body: { error: 'invalid_request', details: errors } };
  }

  if (client_id !== process.env.CLIENT_ID) {
    return {
      ok: false,
      status: 401,
      body: { error: 'invalid_client', message: 'Unknown client_id' },
    };
  }

  if (redirect_uri !== process.env.REDIRECT_URI) {
    return {
      ok: false,
      status: 400,
      body: { error: 'invalid_redirect_uri', message: 'redirect_uri mismatch' },
    };
  }

  return {
    ok: true,
    value: {
      clientId: client_id,
      redirectUri: redirect_uri,
      responseType: response_type,
      scope: scope || 'openid profile',
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method,
      state,
    },
  };
}

function createPendingAuthorization(request) {
  cleanupExpiredTransactions();

  const transactionId = crypto.randomUUID();
  const csrfToken = crypto.randomBytes(24).toString('base64url');
  const expiresAt = Date.now() + PENDING_AUTH_TTL_MS;

  pendingAuthorizations.set(transactionId, {
    ...request,
    csrfToken,
    expiresAt,
  });

  return { transactionId, csrfToken, expiresAt };
}

function consumePendingAuthorization(transactionId, csrfToken) {
  cleanupExpiredTransactions();

  if (!transactionId || !csrfToken) {
    return {
      ok: false,
      status: 400,
      body: { error: 'invalid_request', message: 'transaction_id and csrf_token are required' },
    };
  }

  const transaction = pendingAuthorizations.get(transactionId);

  if (!transaction) {
    return {
      ok: false,
      status: 400,
      body: { error: 'invalid_transaction', message: 'Authorization transaction not found or expired' },
    };
  }

  if (transaction.csrfToken !== csrfToken) {
    return {
      ok: false,
      status: 403,
      body: { error: 'invalid_csrf', message: 'csrf_token mismatch' },
    };
  }

  pendingAuthorizations.delete(transactionId);
  return { ok: true, value: transaction };
}

function issueAuthorizationCode({ clientId, redirectUri, scope, codeChallenge, codeChallengeMethod, state }, userId) {
  const code = generateAuthCode();
  const expiresAt = Math.floor(Date.now() / 1000) + Number(process.env.AUTH_CODE_EXPIRY_SECONDS || 300);

  db.prepare(`
    INSERT INTO auth_codes (code, client_id, redirect_uri, code_challenge, code_challenge_method, scope, user_id, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(code, clientId, redirectUri, codeChallenge, codeChallengeMethod, scope, userId, expiresAt);

  const redirectUrl = new URL(redirectUri);
  redirectUrl.searchParams.set('code', code);
  redirectUrl.searchParams.set('state', state);

  return {
    code,
    redirectUrl: redirectUrl.toString(),
  };
}

function buildAuthorizeHtml(request, errorMessage = '') {
  const { clientId, redirectUri, scope, codeChallenge, codeChallengeMethod, state } = request;

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>OAuth 2.0 — Sign In</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
    }
    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 2rem;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 25px 50px rgba(0,0,0,0.5);
    }
    h1 { font-size: 1.5rem; text-align: center; margin-bottom: 0.25rem; }
    .subtitle { text-align: center; color: #94a3b8; font-size: 0.85rem; margin-bottom: 1.5rem; }
    .flow-info {
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 0.75rem;
      margin-bottom: 1.5rem;
      font-size: 0.75rem;
      color: #94a3b8;
      line-height: 1.5;
    }
    .flow-info code { color: #38bdf8; }
    label { display: block; font-size: 0.85rem; margin-bottom: 0.25rem; color: #cbd5e1; }
    input[type="text"], input[type="password"] {
      width: 100%;
      padding: 0.6rem 0.75rem;
      margin-bottom: 1rem;
      background: #0f172a;
      border: 1px solid #475569;
      border-radius: 6px;
      color: #e2e8f0;
      font-size: 0.9rem;
      outline: none;
    }
    input:focus { border-color: #3b82f6; }
    button {
      width: 100%;
      padding: 0.65rem;
      background: #3b82f6;
      color: white;
      border: none;
      border-radius: 6px;
      font-size: 0.95rem;
      cursor: pointer;
      font-weight: 500;
    }
    button:hover { background: #2563eb; }
    .hint { text-align: center; margin-top: 1rem; font-size: 0.75rem; color: #64748b; }
    .error { background: #7f1d1d; color: #fca5a5; padding: 0.5rem 0.75rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.85rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🔐 Authorization Server</h1>
    <p class="subtitle">OAuth 2.0 + PKCE Login</p>
    <div class="flow-info">
      <strong>Legacy Step:</strong> Auth Server presents login form<br/>
      <code>client_id</code>: ${clientId}<br/>
      <code>scope</code>: ${scope}<br/>
      <code>code_challenge</code>: ${codeChallenge.substring(0, 20)}...
    </div>
    ${errorMessage ? `<div class="error">${errorMessage}</div>` : ''}
    <form method="POST" action="/authorize/submit">
      <input type="hidden" name="client_id" value="${clientId}" />
      <input type="hidden" name="redirect_uri" value="${redirectUri}" />
      <input type="hidden" name="scope" value="${scope}" />
      <input type="hidden" name="code_challenge" value="${codeChallenge}" />
      <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod}" />
      <input type="hidden" name="state" value="${state}" />
      <label for="username">Username</label>
      <input type="text" id="username" name="username" placeholder="alice" autocomplete="username" required />
      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="password123" autocomplete="current-password" required />
      <button type="submit">Sign In &amp; Authorize</button>
    </form>
    <p class="hint">Test credentials: alice / password123</p>
  </div>
</body>
</html>`;
}

function validateCredentials(username, password) {
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return null;
  }

  return user;
}

/**
 * GET /authorize
 *
 * OAuth 2.0 Authorization Endpoint.
 * Validates client params, then renders a login form.
 *
 * Query params: client_id, redirect_uri, response_type, scope,
 *               code_challenge, code_challenge_method, state
 */
router.get('/authorize', (req, res) => {
  const validation = validateAuthorizeRequest(req.query);

  if (!validation.ok) {
    return res.status(validation.status).json(validation.body);
  }

  res.type('html').send(buildAuthorizeHtml(validation.value, req.query.error || ''));
});

router.post('/authorize/init', (req, res) => {
  const validation = validateAuthorizeRequest(req.body);

  if (!validation.ok) {
    return res.status(validation.status).json(validation.body);
  }

  const transaction = createPendingAuthorization(validation.value);

  return res.json({
    transaction_id: transaction.transactionId,
    csrf_token: transaction.csrfToken,
    expires_in: Math.floor((transaction.expiresAt - Date.now()) / 1000),
  });
});

router.post('/login', (req, res) => {
  const { username, password, transaction_id, csrf_token } = req.body;
  const transactionResult = consumePendingAuthorization(transaction_id, csrf_token);

  if (!transactionResult.ok) {
    return res.status(transactionResult.status).json(transactionResult.body);
  }

  const user = validateCredentials(username, password);

  if (!user) {
    return res.status(401).json({
      error: 'invalid_credentials',
      message: 'Invalid username or password',
    });
  }

  const { code, redirectUrl } = issueAuthorizationCode(transactionResult.value, user.id);

  console.log(`✅ Auth code issued for user "${username}" → ${code.substring(0, 8)}...`);

  return res.json({
    code,
    state: transactionResult.value.state,
    redirect_to: redirectUrl,
  });
});

/**
 * POST /authorize/submit
 *
 * Validate credentials, generate auth code, redirect back to client.
 */
router.post('/authorize/submit', (req, res) => {
  const {
    username,
    password,
    client_id,
    redirect_uri,
    scope,
    code_challenge,
    code_challenge_method,
    state,
  } = req.body;

  const user = validateCredentials(username, password);

  if (!user) {
    const qs = new URLSearchParams({
      client_id,
      redirect_uri,
      response_type: 'code',
      scope,
      code_challenge,
      code_challenge_method,
      state,
      error: 'Invalid username or password',
    }).toString();
    return res.redirect(`/authorize?${qs}`);
  }

  const { code, redirectUrl } = issueAuthorizationCode(
    {
      clientId: client_id,
      redirectUri: redirect_uri,
      scope,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method,
      state,
    },
    user.id,
  );

  console.log(`✅ Auth code issued for user "${username}" → ${code.substring(0, 8)}...`);

  res.redirect(redirectUrl);
});

export default router;
