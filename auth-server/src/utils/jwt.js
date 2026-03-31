import crypto from 'crypto';
import jwt from 'jsonwebtoken';

// ── Generate RSA key pair on startup ────────────────────────
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding:  { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Key ID for JWKS
const kid = crypto.randomUUID();

/**
 * Sign a JWT access token with RS256.
 */
export function signAccessToken(payload, expiresIn = '15m') {
  return jwt.sign(payload, privateKey, {
    algorithm: 'RS256',
    expiresIn,
    issuer: 'http://localhost:4000',
    keyid: kid,
  });
}

/**
 * Verify a JWT access token.
 */
export function verifyAccessToken(token) {
  return jwt.verify(token, publicKey, {
    algorithms: ['RS256'],
    issuer: 'http://localhost:4000',
  });
}

/**
 * Return JWKS (JSON Web Key Set) with the public key.
 * Resource Server fetches this to verify tokens.
 */
export function getJWKS() {
  // Convert PEM public key to JWK components
  const keyObject = crypto.createPublicKey(publicKey);
  const jwk = keyObject.export({ format: 'jwk' });

  return {
    keys: [
      {
        kty: jwk.kty,
        kid,
        use: 'sig',
        alg: 'RS256',
        n: jwk.n,
        e: jwk.e,
      },
    ],
  };
}

export { publicKey, privateKey };
