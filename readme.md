# gopasskey

WebAuthn/Passkey authentication service with SSO support.

## Authentication

Supports two login methods:

- **Passkey** (WebAuthn/FIDO2) - passwordless authentication using platform authenticators (Touch ID, Windows Hello) or security keys
- **Email magic link** - one-time login link sent to the user's email

## SSO

gopasskey can act as an SSO server for other projects. Uses opaque tokens stored in Redis with sliding expiry (TTL resets on every validated request).

### SSO Endpoints

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/api/pub/sso/authorize` | GET | cookie | Entry point - redirects to login or issues auth code |
| `/api/pub/sso/token` | POST | - | Exchanges auth code for opaque token |
| `/api/pub/sso/validate` | GET | Bearer | Validates token, returns user info, extends TTL |
| `/api/pub/sso/revoke` | POST | Bearer | Instantly revokes a token |
| `/api/pub/sso/logout` | GET | cookie | Clears SSO session and redirects back to client |
| `/api/sso/sessions` | GET | cookie | Lists active SSO sessions for the logged-in user |
| `/api/sso/sessions` | DELETE | cookie | Revokes a specific SSO session by token |

### Registering SSO Clients

SSO clients are stored in the `sso_client` table in the database.

```sql
INSERT INTO sso_client (id, client_secret, redirect_uri, name) VALUES
  ('demo', 'demosecret', 'http://localhost:9090/sso/callback', 'Demo App');
```

### Login Flow

#### Step 1: Client redirects to SSO

User visits the client app with no valid session. The client generates a random `state` string (for CSRF protection), saves it, and redirects the browser to:

```
GET https://sso.example.com/api/pub/sso/authorize
    ?client_id=myapp
    &redirect_uri=https://myapp.example.com/sso/callback
    &state=random_string
```

#### Step 2: SSO checks for existing session

The SSO server reads the `sso_session` cookie from the browser.

- **If valid session exists**: skip to Step 4 (no login needed).
- **If no session**: redirect to the SSO login page with SSO params preserved in the URL.

#### Step 3: User authenticates

The user authenticates via passkey or email magic link on the SSO login page. On success, the SSO server sets an HttpOnly `sso_session` cookie on the SSO domain. The login page JS then redirects back to `/api/pub/sso/authorize` with the same `client_id`, `redirect_uri`, and `state` params.

#### Step 4: SSO issues auth code

The SSO server validates the `sso_session` cookie, generates a one-time auth code (stored in Redis, 5 min TTL), and redirects the browser to:

```
GET https://myapp.example.com/sso/callback
    ?code=one_time_auth_code
    &state=random_string
```

#### Step 5: Client exchanges code for token

The client's backend verifies the `state` matches what it saved in Step 1, then makes a **server-to-server** call:

```
POST https://sso.example.com/api/pub/sso/token
Content-Type: application/json

{"code": "one_time_auth_code", "client_id": "myapp", "client_secret": "mysecret"}
```

Response:

```json
{"access_token": "opaque_token_string", "token_type": "Bearer", "expires_in": 3600}
```

The `client_secret` never leaves the client's backend, and the auth code is single-use.

#### Step 6: Client stores token and serves user

How the client stores the token is up to the client:

- **Server-rendered app**: store in an HttpOnly cookie. Browser sends it automatically.
- **SPA with same-domain API**: same as above, cookie works.
- **SPA with cross-domain API**: store in cookie or memory, send as `Authorization: Bearer <token>` header.

#### Step 7: Client validates token on each request

On every request that needs authentication, the client's backend calls:

```
GET https://sso.example.com/api/pub/sso/validate
Authorization: Bearer <token>
```

Response (200 OK):

```json
{"sub": "user-uuid", "email": "user@example.com", "name": "...", "display_name": "..."}
```

Every successful validation **resets the token TTL to 1 hour**, so active users stay logged in indefinitely. If the token is invalid or expired, the SSO returns 401.

### Logout Flow

Logout requires two steps: revoking the SSO token and clearing the SSO session.

#### Step 1: Client revokes its token

The client's backend calls:

```
POST https://sso.example.com/api/pub/sso/revoke
Authorization: Bearer <token>
```

This deletes the token from Redis immediately. The client also clears its own session (cookie, etc.).

#### Step 2: Client redirects to SSO logout

The client redirects the browser to:

```
GET https://sso.example.com/api/pub/sso/logout
    ?redirect_uri=https://myapp.example.com/logged-out
```

The SSO server clears the `sso_session` cookie and the Redis session, then redirects the browser to the `redirect_uri`.

**Why both steps?** Step 1 revokes the client's token (so it can't be used again). Step 2 clears the SSO session (so the user isn't auto-logged-in next time they visit any client). Skipping Step 2 means the user appears logged out of the client, but the SSO session is still alive and any client will silently get a new token on the next visit.

### Token Behavior

- Opaque tokens are stored in Redis with a 1-hour TTL
- Every successful `/validate` call resets the TTL, so active users stay logged in
- Inactive users are logged out after 1 hour
- Tokens can be revoked instantly via `/revoke` or from the SSO dashboard (Sessions page)

### Session Management

Users can view and manage all their active client sessions from the SSO dashboard under the **Sessions** page. Each session shows the client name, URL (clickable to impersonate that session), and creation time. The **Kick Out** button instantly revokes a session.

### Client Integration Summary

A client app needs to:

1. Redirect unauthenticated users to `/api/pub/sso/authorize?client_id=X&redirect_uri=URI&state=RANDOM`
2. Handle the callback: verify `state`, exchange `code` for token via `POST /api/pub/sso/token`
3. Store the token and send it on each request to `GET /api/pub/sso/validate`
4. On logout: revoke via `POST /api/pub/sso/revoke`, then redirect to `GET /api/pub/sso/logout?redirect_uri=...`

A minimal Go client example is in the `gopasskey_client` directory.

## Cookies

| Cookie | Domain | HttpOnly | Purpose |
|---|---|---|---|
| `sso_session` | SSO server | Yes | Authenticated user session ID |
| `sso_logged_in` | SSO server | No | JS-readable flag for UI state (not sensitive) |

The `sso_session` cookie is HttpOnly so JavaScript cannot access it — this protects against XSS. The `sso_logged_in` cookie is a non-sensitive flag that the frontend reads to decide whether to show the login page or dashboard.

## Redis Keys

| Key Pattern | Type | TTL | Value | Purpose |
|---|---|---|---|---|
| `passkey_session:{id}` | String | 5 min / 1 hour | JSON `webauthn.SessionData` | WebAuthn handshake (5 min) or authenticated user session (1 hour) |
| `passkey_confirm:{token}` | String | 5 min | `userID\|userAgent\|credentialJSON` | Pending credential replacement confirmation |
| `sso_code:{code}` | String | 5 min | `userID` | One-time auth code during SSO code exchange |
| `sso_token:{token}` | String | 1 hour (sliding) | JSON `{"user_id", "client_id", "user_agent", "created"}` | Opaque SSO token for client apps |
| `sso_user_tokens:{userID}` | Set | none | Set of token strings | Tracks all active SSO tokens per user |

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ENV` | | Set to `dev` for hot reload from `web/build/` |
| `HOST` | `localhost` | Server bind host |
| `PORT` | `8080` | Server bind port |
| `RP_NAME` | `Webauthn` | WebAuthn relying party display name |
| `RP_ID` | `$HOST` | WebAuthn relying party ID (domain) |
| `ORIGINS` | | Comma-separated allowed WebAuthn origins |
| `REDIS_URL` | `localhost:6379` | Redis address |
| `DB_USER` | `root` | MySQL user |
| `DB_PASSWORD` | `password` | MySQL password |
| `DB_HOST` | `localhost` | MySQL host |
| `DB_PORT` | `3306` | MySQL port |
| `DB_NAME` | `appdb` | MySQL database name |
| `SMTP_USER` | | SMTP sender email |
| `SMTP_PASS` | | SMTP password |
| `SMTP_HOST` | | SMTP host |
| `SMTP_PORT` | | SMTP port |
