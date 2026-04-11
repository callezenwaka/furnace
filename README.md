# Authpilot

A local-first authentication development platform. Build and test OIDC flows against a real protocol implementation before connecting to a production SSO provider.

## Ports

| Port | Purpose |
|------|---------|
| `:8025` | Web UI, admin SPA, management API |
| `:8026` | OIDC and SAML protocol endpoints |

## Quick Start

```bash
go run ./server/cmd/authpilot
```

With a config file:

```bash
go run ./server/cmd/authpilot -config ./configs/authpilot.yaml
```

With Docker Compose:

```bash
docker compose up --build
```

## Make Targets

| Target | Description |
|--------|-------------|
| `make run` | Start on dev-safe ports (`:18025` / `:18026`) |
| `make run-default` | Start on default ports (`:8025` / `:8026`) |
| `make run-auto` | Try default ports, fall back to dev-safe ports |
| `make run-bg` | Start in background, logs to `.tmp/authpilot.log` |
| `make health` | Check health endpoint |
| `make stop` | Stop the tracked process |
| `make stop ALL=1` | Broader cleanup including default ports |
| `make admin-build` | Build the Vue admin SPA |
| `make notify-build` | Build the Vue notification hub SPA |

Override ports at invocation time:

```bash
make run RUN_HTTP_ADDR=:19025 RUN_PROTOCOL_ADDR=:19026
```

Rebuild the admin SPA before starting:

```bash
make run BUILD=1
```

Watch for client-side changes while running:

```bash
make run WATCH=1
```

## Configuration

Config precedence: runtime flags > environment variables > YAML file > defaults.

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTHPILOT_HTTP_ADDR` | `:8025` | Web UI and API address |
| `AUTHPILOT_PROTOCOL_ADDR` | `:8026` | OIDC protocol address |
| `AUTHPILOT_OIDC_ISSUER_URL` | `http://localhost:8026` | Issuer URL in tokens and discovery |
| `AUTHPILOT_PERSISTENCE_ENABLED` | `false` | Enable SQLite persistence for users/groups |
| `AUTHPILOT_SQLITE_PATH` | `./data/authpilot.db` | SQLite database path |
| `AUTHPILOT_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |
| `AUTHPILOT_API_KEY` | _(unset)_ | Protect `/api/v1` with a static key (see below) |
| `AUTHPILOT_SAML_ENTITY_ID` | `http://localhost:8026` | SAML IdP entity ID in metadata and assertions |
| `AUTHPILOT_SAML_CERT_DIR` | _(unset)_ | Directory to persist the SAML signing key and certificate across restarts |
| `AUTHPILOT_RATE_LIMIT` | `0` (disabled) | Requests per minute per IP on `/api/v1`; `0` disables rate limiting |

Enable persistence:

```bash
go run ./server/cmd/authpilot -persistence-enabled=true -sqlite-path ./data/authpilot.db
```

## OIDC Endpoints

Served on `:8026`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | Discovery document |
| `/.well-known/jwks.json` | GET | Public signing keys |
| `/authorize` | GET | Start authorization (redirects to `/login`) |
| `/authorize/complete` | GET | Issue auth code after login completes |
| `/token` | POST | Exchange code for tokens |
| `/userinfo` | GET | User profile (Bearer token required) |
| `/revoke` | POST | Token revocation |

PKCE is required on every authorization request (`S256` or `plain`).

## SAML Endpoints

Served on `:8026` alongside OIDC.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/saml/metadata` | GET | IdP metadata XML — includes SSO and SLO endpoints |
| `/saml/sso` | GET, POST | SP-initiated SSO — HTTP-Redirect and HTTP-POST bindings |
| `/saml/slo` | GET, POST | Single Logout — SP-initiated (SAMLRequest) and IdP-initiated (`?user_id=`) |
| `/saml/cert` | GET | Download the IdP signing certificate (PEM) |
| `/saml/flows` | GET | Debug list of active SAML flows |

Configure your SP with:
- **IdP Entity ID:** `http://localhost:8026`
- **SSO URL:** `http://localhost:8026/saml/sso`
- **SLO URL:** `http://localhost:8026/saml/slo`
- **Metadata URL:** `http://localhost:8026/saml/metadata`
- **Signing Certificate:** `http://localhost:8026/saml/cert`

Assertions are signed with RSA-SHA256 using Exclusive XML Canonicalization (exc-c14n), the standard used by most SPs. A self-signed certificate is generated at startup and is ephemeral by default — set `AUTHPILOT_SAML_CERT_DIR` to persist the key and certificate across restarts. Override the entity ID with `AUTHPILOT_SAML_ENTITY_ID` if your SP requires a specific value.

To trigger IdP-initiated logout for a user:

```bash
curl http://localhost:8026/saml/slo?user_id=<user-id>
```

## Management API

Served on `:8025` under `/api/v1`. Every response includes an `X-Request-ID` header for log correlation.

| Resource | Endpoints |
|----------|-----------|
| Users | `GET/POST /api/v1/users`, `GET/PUT/DELETE /api/v1/users/{id}` |
| Groups | `GET/POST /api/v1/groups`, `GET/PUT/DELETE /api/v1/groups/{id}` |
| Flows | `GET/POST /api/v1/flows`, `GET /api/v1/flows/{id}` |
| Flow actions | `POST /api/v1/flows/{id}/select-user` · `verify-mfa` · `approve` · `deny` |
| Sessions | `GET /api/v1/sessions` |
| Notifications | `GET /api/v1/notifications?flow_id=<id>`, `GET /api/v1/notifications/all` |
| Export | `GET /api/v1/export?format=<fmt>` |
| API contract | `GET /api/v1/openapi.json`, `GET /api/v1/docs` |

### Export

Export all users and groups to a format suitable for bulk import into an identity provider:

```bash
# SCIM 2.0 JSON (generic IdP)
curl http://localhost:8025/api/v1/export?format=scim -o users.json

# Okta CSV bulk import
curl http://localhost:8025/api/v1/export?format=okta -o users.csv

# Azure AD JSON bulk import
curl http://localhost:8025/api/v1/export?format=azure -o azure-users.json

# Google Workspace CSV bulk upload
curl http://localhost:8025/api/v1/export?format=google -o google-users.csv
```

Supported formats: `scim`, `okta`, `azure`, `google`. The response includes a `Content-Disposition` header with a timestamped filename.

### OpenAPI

The full API contract is available as an OpenAPI 3.1 document:

```bash
curl http://localhost:8025/api/v1/openapi.json
```

An interactive Swagger UI is served at `http://localhost:8025/api/v1/docs`.

### Idempotency

All `POST` endpoints on `/api/v1` support idempotency keys to make retries safe:

```bash
curl -X POST http://localhost:8025/api/v1/users \
  -H "Idempotency-Key: my-unique-key-123" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","display_name":"Alice"}'
```

Repeat the same request within 5 minutes with the same key — the handler runs once and subsequent calls return the cached response with an `Idempotent-Replayed: true` header.

### Rate limiting

Set `AUTHPILOT_RATE_LIMIT` to cap requests per minute per IP on the management API:

```bash
AUTHPILOT_RATE_LIMIT=60 go run ./server/cmd/authpilot
```

Requests over the limit receive `429 Too Many Requests` with a `RATE_LIMITED` error code. Rate limiting is disabled when the value is `0` (default).

Errors follow a standard envelope:

```json
{
  "error": {
    "code": "FLOW_NOT_FOUND",
    "message": "flow not found",
    "retryable": false
  },
  "request_id": "req_01abc..."
}
```

### Protected mode

By default the management API is open (local dev). To require authentication, set `AUTHPILOT_API_KEY`:

```bash
AUTHPILOT_API_KEY=mysecret go run ./server/cmd/authpilot
```

Then pass the key on every request:

```bash
curl -H "X-Authpilot-Api-Key: mysecret" http://localhost:8025/api/v1/users
# or
curl -H "Authorization: Bearer mysecret" http://localhost:8025/api/v1/users
```

## Login Simulation

The login UI at `/login` lets you pick any seeded user and walk through a flow without a real password. Set `next_flow` on a user to inject a scenario:

| Scenario | Behaviour |
|----------|-----------|
| `normal` | Straight-through login |
| `mfa_fail` | First MFA attempt fails |
| `account_locked` | Flow errors immediately |
| `slow_mfa` | Push approval delayed 10 seconds |
| `expired_token` | Tokens issued with negative TTL |

MFA methods available (set on user):

| Method | Behaviour |
|--------|-----------|
| `totp` | 6-digit time-based code; visible in Notification Hub |
| `push` | Approve/deny push notification; visible in Notification Hub |
| `sms` | 6-digit code sent to phone; visible in Notification Hub |
| `magic_link` | One-click sign-in link; visible in Notification Hub |

## Admin UI

```bash
make admin-build
```

Then visit `http://localhost:8025/admin`. Re-run after code changes if the page is stale.

**Views available:**
- **Dashboard** — user/group/flow/session counts and recent sessions
- **Users** — list, search, create, edit, delete
- **Groups** — list, create, edit (including member IDs), delete
- **Sessions** — list with expandable detail rows

## Notification Hub

The notification hub intercepts outbound MFA messages (TOTP codes, push requests, SMS codes, magic links) during local testing — no real delivery provider needed.

```bash
make notify-build
```

Then visit `http://localhost:8025/notify`. Re-run after code changes if the page is stale.

**Tabs:**
- **TOTP** — 6-digit codes with countdown timer; copy or navigate directly to the MFA page
- **Push** — pending push approvals; approve or deny
- **SMS** — outbound SMS codes; copy to paste into the MFA page
- **Magic Links** — one-click sign-in links; click to complete login

The hub polls `/api/v1/notifications/all` every 3 seconds.

## Folder Structure

```text
.
├── client/
│   ├── admin-spa/        # Vue 3 admin SPA
│   └── notify-spa/       # Vue 3 notification hub SPA
├── server/
│   ├── cmd/authpilot/    # Binary entrypoint
│   ├── internal/
│   │   ├── app/          # Startup wiring
│   │   ├── config/       # Config loading
│   │   ├── domain/       # Core models
│   │   ├── flow/         # Flow state machine
│   │   ├── httpapi/      # Web UI and management API handlers
│   │   ├── notify/       # MFA notification payload generation
│   │   ├── oidc/         # OIDC engine
│   │   ├── saml/         # SAML 2.0 engine
│   │   └── store/        # Memory and SQLite stores
│   └── web/
│       ├── static/       # Built SPA assets
│       └── templates/    # Server-rendered login pages
├── configs/              # Example YAML configs
├── deploy/               # Deployment files
└── scripts/              # Helper scripts
```
