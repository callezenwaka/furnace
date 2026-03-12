# Authpilot

M0/M1 baseline scaffold for the local-first auth development platform.

## What's Included

- Go service scaffold with structured startup logging
- Config loading with precedence:
	runtime flags > environment > YAML > defaults
- Health endpoint: `GET /health`
- Baseline management APIs:
	- `GET/POST /api/v1/users`
	- `GET/PUT/DELETE /api/v1/users/{id}`
	- `GET/POST /api/v1/groups`
	- `GET/PUT/DELETE /api/v1/groups/{id}`
- Store implementations:
	- In-memory users/groups/flows/sessions
	- Optional SQLite persistence for users/groups
- Flow/session cleanup scheduler
- Dockerfile + docker compose setup
- CI workflow with vet, test, lint, and container build

## Quick Start

### Run locally

```bash
go run ./server/cmd/authpilot
```

### Run with config file

```bash
go run ./server/cmd/authpilot -config ./configs/authpilot.yaml
```

### Enable persistence

```bash
go run ./server/cmd/authpilot -persistence-enabled=true -sqlite-path ./data/authpilot.db
```

### Use Docker Compose

```bash
docker compose up --build
```

## Local Run Modes

Use the Makefile for predictable local ports:

- `make run` starts with development-safe defaults:
	- HTTP: `:18025`
	- Protocol: `:18026`
- `make run-auto` prefers default app ports and falls back automatically:
	- Tries HTTP `:8025` / Protocol `:8026` first
	- Falls back to HTTP `:18025` / Protocol `:18026` if either default port is busy
- `make run-default` starts with app defaults:
	- HTTP: `:8025`
	- Protocol: `:8026`
- `make run-bg` starts in background using the safe ports and writes logs to `.tmp/authpilot.log`
- `make health` checks the current HTTP health endpoint for the configured run ports
- `make stop` stops the tracked process (PID file) and listeners on configured run ports
- `make stop ALL=1` (or `make stop all=1`) performs broader cleanup, including default ports and known authpilot process patterns

You can override `make run` ports at invocation time:

```bash
make run RUN_HTTP_ADDR=:19025 RUN_PROTOCOL_ADDR=:19026
```

Optional build flag for run targets:

- Set `BUILD=1` (or `BUILD=true`) to rebuild the admin SPA before starting.
- Lowercase alias: set `build=1` (or `build=true`) to do the same thing.

```bash
make run-auto BUILD=1
make run BUILD=1
```

This flag is supported by `make run`, `make run-auto`, and `make run-bg`.

Optional watch flag for foreground run targets:

- Set `WATCH=1` (or `WATCH=true`) to watch client changes and rebuild SPA assets while the server runs.
- Watch build logs are written to `.tmp/admin-watch.log`.

```bash
make run WATCH=1
make run-auto WATCH=1 BUILD=1
```

## Admin SPA Serving

The backend serves the built Vue admin SPA from `server/web/static/admin`.

- Build assets:

```bash
make admin-build
```

- Served routes:
	- `GET /admin` -> SPA `index.html`
	- `GET /admin/assets/*` -> static JS/CSS assets
	- `GET /admin/vite.svg` -> static icon asset
	- `GET /admin/*` -> SPA fallback to `index.html` for deep links

If `/admin` is missing after code changes, rebuild assets with `make admin-build`.

## Folder Structure

```text
.
├── client/
│   └── admin-spa/
│       ├── public/
│       └── src/
├── server/
│   ├── cmd/authpilot/
│   ├── internal/
│   │   ├── config/
│   │   ├── flow/
│   │   ├── httpapi/
│   │   ├── oidc/
│   │   ├── saml/
│   │   └── store/
│   └── web/
│       ├── static/
│       └── templates/
├── deploy/
├── scripts/
├── cmd/
├── internal/
└── configs/
```

Notes:
- `server/` and `client/` are now the active layout.
- Go backend code lives under `server/cmd` and `server/internal`.
- Vue admin code lives under `client/admin-spa` and builds to `server/web/static/admin` for embedding/serving.
- The runtime target remains a single binary that server-renders login pages and serves admin SPA assets.


