/**
 * PKCE (Proof Key for Code Exchange) utilities.
 * Uses the Web Crypto API — no external dependencies.
 *
 * Flow:
 *  1. Generate random code_verifier (43-128 chars, URL-safe)
 *  2. Hash it with SHA-256 → base64url encode → code_challenge
 *  3. Send code_challenge to /authorize
 *  4. Send code_verifier to /token (Auth Server re-hashes to verify)
 */

/**
 * Generate a cryptographically random code_verifier.
 * RFC 7636: 43-128 characters, [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
 */
export function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

/**
 * Generate code_challenge = BASE64URL(SHA256(code_verifier))
 */
export async function generateCodeChallenge(codeVerifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(digest));
}

/**
 * Generate a random state parameter to prevent CSRF.
 */
export function generateState() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

/**
 * Base64url encode a Uint8Array (no padding).
 */
function base64UrlEncode(buffer) {
  const base64 = btoa(String.fromCharCode(...buffer));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
