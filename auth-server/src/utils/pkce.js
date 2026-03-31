import crypto from 'crypto';

/**
 * Verify PKCE: SHA256(code_verifier) should match the stored code_challenge (base64url).
 */
export function verifyCodeChallenge(codeVerifier, codeChallenge) {
  const hash = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  return hash === codeChallenge;
}

/**
 * Generate a cryptographically random authorization code.
 */
export function generateAuthCode() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Generate a cryptographically random refresh token.
 */
export function generateRefreshToken() {
  return crypto.randomBytes(48).toString('hex');
}
