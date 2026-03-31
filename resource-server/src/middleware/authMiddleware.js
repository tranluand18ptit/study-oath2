import jwt from 'jsonwebtoken';
import crypto from 'crypto';

let cachedKeys = null;
let cacheTime = 0;
const CACHE_TTL = 60_000; // Re-fetch JWKS every 60 seconds

/**
 * Fetch the JWKS from the Auth Server and cache it.
 */
async function getPublicKey(kid) {
  const now = Date.now();

  if (!cachedKeys || now - cacheTime > CACHE_TTL) {
    const url = process.env.AUTH_SERVER_JWKS_URL || 'http://localhost:4000/jwks.json';
    console.log(`🔑 Fetching JWKS from ${url}`);
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Failed to fetch JWKS: ${response.status}`);
    const jwks = await response.json();
    cachedKeys = jwks.keys;
    cacheTime = now;
  }

  const key = cachedKeys.find((k) => k.kid === kid);
  if (!key) throw new Error(`Key with kid "${kid}" not found in JWKS`);

  // Convert JWK to PEM for jsonwebtoken
  const publicKeyObject = crypto.createPublicKey({ key, format: 'jwk' });
  return publicKeyObject.export({ type: 'spki', format: 'pem' });
}

/**
 * Express middleware: verify Bearer JWT from Authorization header.
 */
export async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_token', message: 'Authorization header with Bearer token required' });
  }

  const token = authHeader.slice(7);

  try {
    // Decode header to get kid
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || !decoded.header.kid) {
      return res.status(401).json({ error: 'invalid_token', message: 'Token missing kid in header' });
    }

    const publicKey = await getPublicKey(decoded.header.kid);

    const payload = jwt.verify(token, publicKey, {
      algorithms: ['RS256'],
      issuer: 'http://localhost:4000',
    });

    // Attach user info to request
    req.user = payload;
    console.log(`✅ Token verified for user "${payload.username}" (sub: ${payload.sub})`);
    next();
  } catch (err) {
    console.warn(`❌ Token verification failed: ${err.message}`);
    return res.status(401).json({ error: 'invalid_token', message: err.message });
  }
}
