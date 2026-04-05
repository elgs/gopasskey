# gopasskey

A WebAuthn/Passkey authentication service that doubles as an SSO server. Built with Go, MySQL, and Redis.

Users log in with passkeys (Touch ID, Windows Hello, security keys) or email magic links. Other projects can rely on gopasskey for authentication instead of building their own.

## How It Works

There are two roles:

- **SSO server** (this project) — handles user accounts, passkey registration, login, and token management.
- **Client apps** (your other projects) — redirect users to the SSO server for login, then validate tokens on each request.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         SSO Server (gopasskey)                   │
│                                                                  │
│  ┌──────────┐   ┌───────────┐   ┌──────────┐   ┌─────────────┐  │
│  │  MySQL   │   │   Redis   │   │  Go API  │   │  Frontend   │  │
│  │          │   │           │   │          │   │  (leanweb)  │  │
│  │ - user   │   │ - sessions│   │ - auth   │   │             │  │
│  │ - creds  │   │ - tokens  │   │ - sso    │   │ - login     │  │
│  │ - logins │   │ - codes   │   │ - profile│   │ - dashboard │  │
│  │ - clients│   │           │   │          │   │ - sessions  │  │
│  └──────────┘   └───────────┘   └──────────┘   └─────────────┘  │
└──────────────────────────────────────────────────────────────────┘
         ▲                              ▲
         │ server-to-server             │ browser redirects
         │ (code exchange,              │ (authorize, login,
         │  validate, revoke)           │  logout, callback)
         │                              │
┌────────┴──────────────────────────────┴──────────────────────────┐
│                        Client App                                │
│                                                                  │
│  ┌──────────────────┐        ┌───────────────────────────────┐   │
│  │  Backend         │        │  Frontend                     │   │
│  │                  │        │                               │   │
│  │  - /login        │        │  Shows user data or           │   │
│  │  - /sso/callback │        │  "Login with SSO" link        │   │
│  │  - /logout       │        │                               │   │
│  │  - validates     │        │                               │   │
│  │    every request │        │                               │   │
│  └──────────────────┘        └───────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

## Database Tables

### `user`

User accounts. Created on first login.

| Column | Type | Description |
|---|---|---|
| `id` | UUID (PK) | User ID |
| `email` | varchar (unique) | User email |
| `name` | varchar | User name |
| `display_name` | varchar | Display name |
| `balance` | decimal | Account balance |
| `created` | datetime | Creation time |
| `status` | varchar | Account status |
| `is_active` | bool | Active flag |
| `is_deleted` | bool | Soft delete flag |

### `user_credential`

WebAuthn credentials (passkeys) registered by users.

| Column | Type | Description |
|---|---|---|
| `id` | varchar (PK) | Credential ID (hex) |
| `user_id` | UUID (FK) | Owner |
| `aaguid` | varchar | Authenticator type (e.g. "Touch ID") |
| `label` | varchar | User agent at registration time |
| `credential` | JSON | Serialized WebAuthn credential |
| `created` | datetime | Registration time |
| `updated` | datetime | Last used |

### `user_login`

Magic link tokens for email login.

| Column | Type | Description |
|---|---|---|
| `id` | UUID (PK) | Token record ID |
| `email` | varchar | Email address |
| `token` | varchar (unique) | Magic link token |
| `expires` | datetime | Expiry time (10 min) |
| `used` | bool | Whether token has been used |
| `created` | datetime | Creation time |

### `sso_client`

Registered SSO client applications.

| Column | Type | Description |
|---|---|---|
| `id` | varchar (PK) | Client ID (e.g. "myapp") |
| `client_secret` | varchar | Secret for code exchange |
| `redirect_uri` | varchar | Allowed callback URL |
| `name` | varchar | Display name |
| `created` | datetime | Registration time |

To register a client:

```sql
INSERT INTO sso_client (id, client_secret, redirect_uri, name) VALUES
  ('myapp', 'a-strong-random-secret', 'https://myapp.example.com/sso/callback', 'My App');
```

## Redis Keys

| Key | Type | TTL | Value | Used For |
|---|---|---|---|---|
| `passkey_session:{id}` | String | 5 min or 1 hour | JSON session data | WebAuthn handshake (5 min) or logged-in session (1 hour) |
| `passkey_confirm:{token}` | String | 5 min | userID\|userAgent\|credential | Confirming passkey replacement |
| `sso_code:{code}` | String | 5 min | userID\|sessionID | One-time auth code for SSO |
| `sso_token:{token}` | String | 1 hour (sliding) | JSON token metadata | Opaque SSO token for client apps |
| `sso_user_tokens:{userID}` | Set | none | Set of token strings | Index of all SSO tokens per user |

## Cookies

The SSO server sets two cookies on its own domain:

| Cookie | HttpOnly | Purpose |
|---|---|---|
| `sso_session` | Yes | Session ID. JS cannot read this. |
| `sso_logged_in` | No | Flag for the frontend to know whether to show login or dashboard. Not sensitive. |

## API Endpoints

### Public (no auth required)

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/pub/login_start` | Start email magic link login |
| GET | `/api/pub/verify_login` | Verify magic link token |
| POST | `/api/pub/passkey_login_start` | Start passkey login |
| POST | `/api/pub/passkey_login_finish` | Complete passkey login |
| POST | `/api/pub/register_start` | Start passkey registration |
| POST | `/api/pub/register_finish` | Complete passkey registration |
| POST | `/api/pub/register_confirm` | Confirm passkey replacement |

### SSO (called by client apps)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/pub/sso/authorize` | cookie | Entry point. Redirects to login or issues auth code. |
| POST | `/api/pub/sso/token` | body | Exchanges auth code for opaque token. |
| GET | `/api/pub/sso/validate` | Bearer | Validates token, returns user info, extends TTL. |
| POST | `/api/pub/sso/revoke` | Bearer | Revokes a token instantly. |
| GET | `/api/pub/sso/logout` | cookie | Clears SSO session and redirects to client. |

### Protected (requires `sso_session` cookie)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/me` | Get current user info |
| PUT | `/api/profile` | Update name and display name |
| GET | `/api/credentials` | List registered passkeys |
| DELETE | `/api/credentials` | Delete a passkey |
| POST | `/api/logout` | Log out (clear session) |
| GET | `/api/sso/sessions` | List active client sessions |
| DELETE | `/api/sso/sessions` | Kick out a client session |

## SSO Login Flow

This is what happens when a user visits a client app and needs to log in.

```
Browser                     Client App                   SSO Server
  │                            │                            │
  │  1. Visit /               │                            │
  │ ─────────────────────────> │                            │
  │                            │                            │
  │  2. No token. Show         │                            │
  │     "Login with SSO" page  │                            │
  │ <───────────────────────── │                            │
  │                            │                            │
  │  3. Click "Login with SSO" │                            │
  │ ─────────────────────────> │                            │
  │                            │                            │
  │  4. Redirect to SSO /authorize                          │
  │ ──────────────────────────────────────────────────────> │
  │    ?client_id=X&redirect_uri=Y&state=Z                  │
  │                            │                            │
  │  5. No valid sso_session cookie                         │
  │     Redirect to login page                              │
  │ <────────────────────────────────────────────────────── │
  │    /?sso_client_id=X&sso_redirect_uri=Y&sso_state=Z    │
  │                            │                            │
  │  6. User authenticates (passkey or email)                │
  │ ──────────────────────────────────────────────────────> │
  │                            │                            │
  │  7. SSO sets sso_session cookie                         │
  │     JS redirects to /authorize again                    │
  │ ──────────────────────────────────────────────────────> │
  │                            │                            │
  │  8. Valid session. Generate one-time code.               │
  │     Redirect to client callback                         │
  │ <────────────────────────────────────────────────────── │
  │    ?code=CODE&state=Z      │                            │
  │                            │                            │
  │  9. Follow redirect to client callback                  │
  │ ─────────────────────────> │                            │
  │                            │                            │
  │                            │  10. Verify state matches.  │
  │                            │      Exchange code for      │
  │                            │      token (server-to-      │
  │                            │      server).               │
  │                            │ ─────────────────────────> │
  │                            │   POST /sso/token           │
  │                            │   {code, client_id,         │
  │                            │    client_secret}           │
  │                            │                            │
  │                            │  11. Return opaque token    │
  │                            │ <───────────────────────── │
  │                            │   {access_token: "..."}     │
  │                            │                            │
  │  12. Set token cookie.     │                            │
  │      Redirect to /         │                            │
  │ <───────────────────────── │                            │
  │                            │                            │
  │  13. Visit / (has token)   │                            │
  │ ─────────────────────────> │                            │
  │                            │  14. Validate token         │
  │                            │ ─────────────────────────> │
  │                            │   GET /sso/validate         │
  │                            │   Authorization: Bearer T   │
  │                            │                            │
  │                            │  15. Return user info.      │
  │                            │      Extend token TTL.      │
  │                            │ <───────────────────────── │
  │                            │   {sub, email, name, ...}   │
  │                            │                            │
  │  16. Show page with user   │                            │
  │      data.                 │                            │
  │ <───────────────────────── │                            │
```

**If the user already has a valid `sso_session` cookie** (logged in previously), steps 5-7 are skipped. The SSO server issues the auth code immediately at step 8. This is the "single sign-on" experience — the user is not asked to log in again.

**On subsequent requests**, only steps 13-16 happen. The client validates the token with the SSO server on every request. Each successful validation extends the token TTL by 1 hour, so active users stay logged in indefinitely.

## SSO Logout Flow

When a user logs out from a client app:

```
Browser                     Client App                   SSO Server
  │                            │                            │
  │  1. Click "Logout"         │                            │
  │ ─────────────────────────> │                            │
  │                            │                            │
  │                            │  2. Revoke token            │
  │                            │     (server-to-server)      │
  │                            │ ─────────────────────────> │
  │                            │   POST /sso/revoke          │
  │                            │   Authorization: Bearer T   │
  │                            │                            │
  │                            │  3. Token deleted from      │
  │                            │     Redis immediately.      │
  │                            │ <───────────────────────── │
  │                            │                            │
  │  4. Clear client cookie.   │                            │
  │     Redirect to SSO        │                            │
  │     /sso/logout            │                            │
  │ <───────────────────────── │                            │
  │                            │                            │
  │  5. Browser hits SSO       │                            │
  │     /sso/logout            │                            │
  │ ──────────────────────────────────────────────────────> │
  │    ?redirect_uri=https://client.com/logged-out          │
  │                            │                            │
  │  6. SSO deletes session    │                            │
  │     from Redis. Clears     │                            │
  │     sso_session and        │                            │
  │     sso_logged_in cookies. │                            │
  │     Redirects to client.   │                            │
  │ <────────────────────────────────────────────────────── │
  │                            │                            │
  │  7. Show "Logged out"      │                            │
  │     page.                  │                            │
  │ ─────────────────────────> │                            │
  │ <───────────────────────── │                            │
```

**Why two steps?** Step 2 revokes the client's token so it can't be reused. Step 5 clears the SSO session so the user isn't silently re-logged-in next time they visit any client. Both are necessary for a complete logout.

## Session Management (Kick Out)

From the SSO dashboard, users can see all active client sessions and kick them out.

When a session is kicked out:
1. The opaque token is deleted from Redis (client can no longer validate it).
2. The SSO session that created the token is also deleted (prevents silent re-login).

This means the kicked-out browser will need to re-authenticate with passkey or email on the next visit.

If two browsers are logged into the same client, kicking one out does not affect the other — each has its own token and SSO session.

## Token Behavior

- Tokens are random opaque strings (not JWTs). All state lives in Redis.
- Default TTL: 1 hour. Every successful `/validate` call resets the TTL.
- Active users stay logged in indefinitely. Inactive users are logged out after 1 hour.
- Tokens can be revoked instantly via `/revoke` or the dashboard "Kick Out" button.
- Token metadata stored in Redis: `user_id`, `client_id`, `session_id`, `user_agent`, `created`.

## Client Integration

A client app needs to implement four things:

### 1. Login redirect

When the user is not authenticated, redirect to:

```
GET https://sso.example.com/api/pub/sso/authorize
    ?client_id=myapp
    &redirect_uri=https://myapp.example.com/sso/callback
    &state=<random CSRF nonce>
```

Save the `state` value (e.g. in a cookie) to verify it later.

### 2. Callback handler

Handle `GET /sso/callback?code=X&state=Y`:

1. Verify `state` matches what was saved.
2. Exchange the code for a token (server-to-server):

```
POST https://sso.example.com/api/pub/sso/token
Content-Type: application/json

{"code": "X", "client_id": "myapp", "client_secret": "mysecret"}
```

Response: `{"access_token": "...", "token_type": "Bearer", "expires_in": 3600}`

3. Store the `access_token` (e.g. in an HttpOnly cookie).

### 3. Token validation

On each authenticated request, call:

```
GET https://sso.example.com/api/pub/sso/validate
Authorization: Bearer <token>
```

Response (200): `{"sub": "user-uuid", "email": "...", "name": "...", "display_name": "..."}`

If 401: token is invalid or expired. Clear the client session and redirect to login.

### 4. Logout

1. Revoke the token: `POST /api/pub/sso/revoke` with `Authorization: Bearer <token>`
2. Clear the client's own session (cookie, etc.)
3. Redirect browser to: `GET /api/pub/sso/logout?redirect_uri=https://myapp.example.com/logged-out`

A complete working example is in the `gopasskey_client` directory.

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

## Running Locally

1. Start MySQL and Redis.
2. Create the database and tables: `mysql < appdb.sql`
3. Register a client:
   ```sql
   INSERT INTO sso_client (id, client_secret, redirect_uri, name) VALUES
     ('demo', 'demosecret', 'http://localhost:9090/sso/callback', 'Demo App');
   ```
4. Set environment variables (see `.envrc`).
5. Run the SSO server: `go run .`
6. Run the demo client: `cd gopasskey_client && go run .`
7. Visit `http://localhost:9090`.
