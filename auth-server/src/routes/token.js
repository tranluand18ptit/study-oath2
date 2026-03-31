import { Router } from 'express';
import db from '../db/db.js';
import { verifyCodeChallenge, generateRefreshToken } from '../utils/pkce.js';
import { signAccessToken } from '../utils/jwt.js';

const router = Router();

/**
 * POST /token
 *
 * OAuth 2.0 Token Endpoint.
 * Exchanges authorization_code + code_verifier for tokens.
 *
 * Body (application/x-www-form-urlencoded or JSON):
 *   grant_type, code, redirect_uri, client_id, code_verifier
 */
router.post('/token', (req, res) => {
  const { grant_type, code, redirect_uri, client_id, code_verifier } = req.body;

  // ── grant_type: authorization_code ────────────────────────
  if (grant_type === 'authorization_code') {
    return handleAuthorizationCode(req, res, { code, redirect_uri, client_id, code_verifier });
  }

  // ── grant_type: refresh_token ─────────────────────────────
  if (grant_type === 'refresh_token') {
    return handleRefreshToken(req, res);
  }

  return res.status(400).json({ error: 'unsupported_grant_type' });
});

function handleAuthorizationCode(req, res, { code, redirect_uri, client_id, code_verifier }) {
  if (!code || !redirect_uri || !client_id || !code_verifier) {
    return res.status(400).json({ error: 'invalid_request', message: 'Missing required parameters' });
  }

  // ── Look up the authorization code ────────────────────────
  const authCode = db.prepare('SELECT * FROM auth_codes WHERE code = ?').get(code);

  if (!authCode) {
    return res.status(400).json({ error: 'invalid_grant', message: 'Unknown authorization code' });
  }

  // ── Check if code was already used ────────────────────────
  if (authCode.used) {
    // Potential replay attack — revoke all tokens for this user/client
    db.prepare('DELETE FROM refresh_tokens WHERE user_id = ? AND client_id = ?')
      .run(authCode.user_id, authCode.client_id);
    db.prepare('DELETE FROM auth_codes WHERE code = ?').run(code);
    return res.status(400).json({ error: 'invalid_grant', message: 'Authorization code already used (possible replay)' });
  }

  // ── Validate expiry ───────────────────────────────────────
  if (Math.floor(Date.now() / 1000) > authCode.expires_at) {
    db.prepare('DELETE FROM auth_codes WHERE code = ?').run(code);
    return res.status(400).json({ error: 'invalid_grant', message: 'Authorization code expired' });
  }

  // ── Validate client_id and redirect_uri ───────────────────
  if (authCode.client_id !== client_id || authCode.redirect_uri !== redirect_uri) {
    return res.status(400).json({ error: 'invalid_grant', message: 'client_id or redirect_uri mismatch' });
  }

  // ── PKCE verification ─────────────────────────────────────
  if (!verifyCodeChallenge(code_verifier, authCode.code_challenge)) {
    console.warn('❌ PKCE verification failed');
    return res.status(400).json({ error: 'invalid_grant', message: 'PKCE code_verifier verification failed' });
  }

  console.log('✅ PKCE verified successfully');

  // ── Mark code as used ─────────────────────────────────────
  db.prepare('UPDATE auth_codes SET used = 1 WHERE code = ?').run(code);

  // ── Get user info ─────────────────────────────────────────
  const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(authCode.user_id);

  // ── Issue tokens ──────────────────────────────────────────
  const accessToken = signAccessToken(
    {
      sub: String(user.id),
      username: user.username,
      scope: authCode.scope || 'openid profile',
    },
    process.env.ACCESS_TOKEN_EXPIRY || '15m'
  );

  const refreshTokenValue = generateRefreshToken();
  const refreshExpiresAt = Math.floor(Date.now() / 1000) + (Number(process.env.REFRESH_TOKEN_EXPIRY_DAYS || 7) * 86400);

  db.prepare(`
    INSERT INTO refresh_tokens (token, user_id, client_id, scope, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(refreshTokenValue, user.id, client_id, authCode.scope, refreshExpiresAt);

  console.log(`🎟️  Tokens issued for user "${user.username}"`);

  return res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 900, // 15 minutes in seconds
    refresh_token: refreshTokenValue,
    scope: authCode.scope || 'openid profile',
  });
}

function handleRefreshToken(req, res) {
  const { refresh_token, client_id } = req.body;

  if (!refresh_token || !client_id) {
    return res.status(400).json({ error: 'invalid_request', message: 'Missing refresh_token or client_id' });
  }

  const stored = db.prepare('SELECT * FROM refresh_tokens WHERE token = ?').get(refresh_token);

  if (!stored || stored.revoked || stored.client_id !== client_id) {
    return res.status(400).json({ error: 'invalid_grant', message: 'Invalid refresh token' });
  }

  if (Math.floor(Date.now() / 1000) > stored.expires_at) {
    db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(refresh_token);
    return res.status(400).json({ error: 'invalid_grant', message: 'Refresh token expired' });
  }

  const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(stored.user_id);

  const accessToken = signAccessToken(
    {
      sub: String(user.id),
      username: user.username,
      scope: stored.scope || 'openid profile',
    },
    process.env.ACCESS_TOKEN_EXPIRY || '15m'
  );

  return res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 900,
    scope: stored.scope || 'openid profile',
  });
}

export default router;
