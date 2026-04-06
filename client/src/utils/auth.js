const AUTH_SERVER = 'http://localhost:4000';
const RESOURCE_SERVER = 'http://localhost:5000';
const CLIENT_ID = 'oauth-study-client';
// const REDIRECT_URI = 'http://localhost:3000/callback';
const REDIRECT_URI = 'http://localhost:4200';

export const config = {
  AUTH_SERVER,
  RESOURCE_SERVER,
  CLIENT_ID,
  REDIRECT_URI,
};

/**
 * Exchange authorization code + code_verifier for tokens.
 */
export async function exchangeCodeForTokens(code, codeVerifier) {
  const response = await fetch(`${AUTH_SERVER}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: codeVerifier,
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || error.error || 'Token exchange failed');
  }

  return response.json();
}

/**
 * Fetch protected profile from the Resource Server.
 */
export async function fetchProfile(accessToken) {
  const response = await fetch(`${RESOURCE_SERVER}/api/profile`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    if (response.status === 401) throw new Error('Token expired or invalid');
    throw new Error('Failed to fetch profile');
  }

  return response.json();
}

/**
 * Decode a JWT payload (without verification — for display only).
 */
export function decodeJwtPayload(token) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(base64));
  } catch {
    return null;
  }
}
