# Authpilot

A local-first authentication development platform. Build and test OIDC flows against a real protocol implementation before connecting to a production SSO provider.

## Ports

| Port | Purpose |
|------|---------|
| `:8025` | Web UI, admin SPA, management API |
| `:8026` | OIDC protocol endpoints |

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

Key environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTHPILOT_HTTP_ADDR` | `:8025` | Web UI and API address |
| `AUTHPILOT_PROTOCOL_ADDR` | `:8026` | OIDC protocol address |
| `AUTHPILOT_OIDC_ISSUER_URL` | `http://localhost:8026` | Issuer URL in tokens and discovery |
| `AUTHPILOT_PERSISTENCE_ENABLED` | `false` | Enable SQLite persistence for users/groups |
| `AUTHPILOT_SQLITE_PATH` | `./data/authpilot.db` | SQLite database path |
| `AUTHPILOT_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |

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

## Management API

Served on `:8025` under `/api/v1`.

| Resource | Endpoints |
|----------|-----------|
| Users | `GET/POST /api/v1/users`, `GET/PUT/DELETE /api/v1/users/{id}` |
| Groups | `GET/POST /api/v1/groups`, `GET/PUT/DELETE /api/v1/groups/{id}` |
| Flows | `GET/POST /api/v1/flows`, `GET /api/v1/flows/{id}` |
| Flow actions | `POST /api/v1/flows/{id}/select-user` · `verify-mfa` · `approve` · `deny` |

## Login Simulation

The login UI at `/login` lets you pick any seeded user and walk through a flow without a real password. Set `next_flow` on a user to inject a scenario:

| Scenario | Behaviour |
|----------|-----------|
| `normal` | Straight-through login |
| `mfa_fail` | First MFA attempt fails |
| `account_locked` | Flow errors immediately |
| `slow_mfa` | Push approval delayed 10 seconds |
| `expired_token` | Tokens issued with negative TTL |

## Admin UI

```bash
make admin-build
```

Then visit `http://localhost:8025/admin`. Re-run after code changes if the page is stale.

## Folder Structure

```text
.
├── client/
│   └── admin-spa/        # Vue 3 admin SPA
├── server/
│   ├── cmd/authpilot/    # Binary entrypoint
│   ├── internal/
│   │   ├── app/          # Startup wiring
│   │   ├── config/       # Config loading
│   │   ├── domain/       # Core models
│   │   ├── flow/         # Flow state machine
│   │   ├── httpapi/      # Web UI and management API handlers
│   │   ├── oidc/         # OIDC engine
│   │   └── store/        # Memory and SQLite stores
│   └── web/
│       ├── static/       # Built SPA assets
│       └── templates/    # Server-rendered login pages
├── configs/              # Example YAML configs
├── deploy/               # Deployment files
└── scripts/              # Helper scripts
```
