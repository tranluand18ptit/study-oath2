## OAuth 2.0 Authorization Code Flow with PKCE

### Architecture

| Service                       | Port    | Role                         |
| ----------------------------- | ------- | ---------------------------- |
| **Frontend** (Angular)        | `:3000` | OAuth Client (SPA)           |
| **Auth Server** (Express)     | `:4000` | Authorization Server + Login |
| **Resource Server** (Express) | `:5000` | Protected API                |

---

### Step-by-Step Flow

#### 1. User visits home — Route Guard triggers

The home route is protected by `authGuard` (auth.guard.ts). It calls `auth.initializeAuth()`. If no valid session exists, the user is redirected to `/login?returnUrl=/home`.

#### 2. User submits credentials on the Login Page

login.page.ts calls `auth.login(username, password, returnUrl)`.

#### 3. Frontend generates PKCE pair + state

Inside `AuthService.login()` (auth.service.ts):

```
codeVerifier  = random 64 bytes → base64url
codeChallenge = SHA-256(codeVerifier) → base64url
state         = random 24 bytes → base64url
```

#### 4. Frontend → Auth Server: `POST /authorize/init`

The frontend sends the OAuth parameters to the auth server:

```json
{
  "client_id": "oauth-study-client",
  "redirect_uri": "http://localhost:3000/callback",
  "response_type": "code",
  "scope": "openid profile",
  "code_challenge": "<base64url SHA-256 hash>",
  "code_challenge_method": "S256",
  "state": "<random state>"
}
```

The auth server (authorize.js):

1. Validates `client_id`, `redirect_uri`, `response_type`, PKCE params
2. Creates an in-memory **pending authorization** with a `transaction_id` + `csrf_token`
3. Returns `{ transaction_id, csrf_token, expires_in }`

#### 5. Frontend stores pending transaction

`AuthService` saves `{ state, codeVerifier, returnUrl, transactionId, csrfToken }` to `localStorage` under key `oauth.pending_transaction` — needed later in step 8.

#### 6. Frontend → Auth Server: `POST /login`

```json
{
  "username": "alice",
  "password": "password123",
  "transaction_id": "<from step 4>",
  "csrf_token": "<from step 4>"
}
```

The auth server (authorize.js):

1. **Consumes** the pending authorization (validates + deletes the `transaction_id`/`csrf_token`)
2. **Validates credentials** against the SQLite `users` table (bcrypt hash comparison)
3. **Issues an authorization code** — random 32-byte hex, stored in the `auth_codes` table with: `code_challenge`, `user_id`, `scope`, `expires_at`
4. Returns `{ code, state, redirect_to: "http://localhost:3000/callback?code=...&state=..." }`

#### 7. Frontend redirects to callback URL

`window.location.assign(redirect_to)` navigates the browser to `/callback?code=<code>&state=<state>`.

#### 8. Callback Page triggers token exchange

callback.page.ts calls `auth.initializeAuth()`, which detects `code` in the URL and runs `handleAuthorizationCallback()` (auth.service.ts):

1. Reads `code` and `state` from URL query params
2. Reads the pending transaction from `localStorage`
3. **Verifies `state`** — the returned state must match the stored state (CSRF protection)

#### 9. Frontend → Auth Server: `POST /token`

```json
{
  "grant_type": "authorization_code",
  "code": "<authorization code>",
  "redirect_uri": "http://localhost:3000/callback",
  "client_id": "oauth-study-client",
  "code_verifier": "<the original random verifier>"
}
```

The auth server token endpoint (token.js):

1. Looks up the `code` in the `auth_codes` table
2. Checks it wasn't **already used** (replay detection — if used, revokes all refresh tokens)
3. Checks it hasn't **expired**
4. Validates `client_id` and `redirect_uri` match
5. **PKCE verification**: computes `SHA-256(code_verifier)` and compares with the stored `code_challenge` (pkce.js)
6. Marks the code as **used**
7. Signs a **JWT access token** (RS256, 15 min TTL) containing `{ sub, username, scope }` (jwt.js)
8. Generates a **refresh token** (random 48-byte hex, stored in DB, 7 day TTL)
9. Returns:

```json
{
  "access_token": "<RS256 JWT>",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "<hex string>",
  "scope": "openid profile"
}
```

#### 10. Frontend stores tokens

`storeTokenResponse()` saves `access_token`, `refresh_token`, `expires_at`, and `scope` to `localStorage`. The auth phase becomes `'authenticated'`.

#### 11. Callback redirects to Home

The callback page navigates to `getSafeRedirectTarget()` (the original `returnUrl`, defaulting to home).

#### 12. Home Page → Resource Server: `GET /api/profile`

home.page.ts calls `auth.loadProfile()`, which sends `GET http://localhost:5000/api/profile`.

The `authInterceptor` (auth.interceptor.ts) automatically attaches:

```
Authorization: Bearer <JWT access token>
```

#### 13. Resource Server validates the JWT

authMiddleware.js:

1. Extracts Bearer token from `Authorization` header
2. Decodes the JWT header to get the `kid`
3. Fetches the **JWKS** from `http://localhost:4000/jwks.json` (cached 60s)
4. Converts the matching JWK public key to PEM
5. Verifies the JWT signature (RS256) + issuer
6. Sets `req.user` with the decoded claims

#### 14. Resource Server returns profile

profile.js reads claims from `req.user` and returns:

```json
{
  "sub": "1",
  "username": "alice",
  "scope": "openid profile",
  "issued_at": "...",
  "expires_at": "...",
  "issuer": "http://localhost:4000",
  "message": "Hello alice! This data came from the Resource Server, verified via JWT."
}
```

---

### Token Refresh Flow

When the access token expires (or the resource server returns 401):

1. The `authInterceptor` catches the 401 and calls `handleUnauthorizedResponse()`
2. `AuthService.refreshAccessToken()` sends `POST /token` with `grant_type=refresh_token`
3. Auth server validates the refresh token in the DB, issues a **new access token**
4. If the refresh token itself is expired → user is redirected to `/login`

---

### Visual Summary

```
Frontend (:3000)              Auth Server (:4000)           Resource Server (:5000)
     │                              │                              │
     │ 1. POST /authorize/init      │                              │
     │  (PKCE challenge + params)   │                              │
     │ ────────────────────────────►│                              │
     │  { transaction_id, csrf }   │                              │
     │ ◄────────────────────────────│                              │
     │                              │                              │
     │ 2. POST /login               │                              │
     │  (credentials + txn + csrf)  │                              │
     │ ────────────────────────────►│                              │
     │  { code, state, redirect }  │  ┌─────────────────┐        │
     │ ◄────────────────────────────│  │ SQLite: stores  │        │
     │                              │  │ auth_code with  │        │
     │ 3. Redirect to /callback     │  │ code_challenge  │        │
     │     ?code=...&state=...      │  └─────────────────┘        │
     │                              │                              │
     │ 4. POST /token               │                              │
     │  (code + code_verifier)      │                              │
     │ ────────────────────────────►│                              │
     │  { access_token (JWT),      │  ┌─────────────────┐        │
     │    refresh_token }           │  │ PKCE: SHA-256   │        │
     │ ◄────────────────────────────│  │ verify + sign   │        │
     │                              │  │ RS256 JWT       │        │
     │                              │  └─────────────────┘        │
     │ 5. GET /api/profile          │                              │
     │  Authorization: Bearer JWT   │                              │
     │ ────────────────────────────────────────────────────────────►│
     │                              │  6. GET /jwks.json           │
     │                              │ ◄────────────────────────────│
     │                              │  { keys: [...] }             │
     │                              │ ────────────────────────────►│
     │  { profile data }           │                              │
     │ ◄──────────────────────────────────────────────────────────│
```

### Key Security Features

- **PKCE (S256)**: Prevents authorization code interception — the `code_verifier` never leaves the frontend until the token exchange
- **State parameter**: CSRF protection for the authorization redirect
- **Transaction ID + CSRF token**: Binds the `/authorize/init` → `/login` flow, preventing replay
- **RS256 JWT**: Asymmetric signing — resource server verifies via JWKS without sharing the private key
- **Auth code single-use**: If reused, all refresh tokens for that user/client are revoked
- **Refresh token rotation**: Stored in DB with expiry, can be revoked server-side
