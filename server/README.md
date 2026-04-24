# Server

Go backend service for Furnace.

Planned ownership:
- `cmd/furnace`: binary entrypoint
- `internal/httpapi`: management APIs and handlers
- `internal/oidc`: OIDC engine
- `internal/saml`: SAML engine
- `internal/flow`: flow state machine and transitions
- `internal/store`: persistence interfaces and implementations
- `internal/config`: config loading and validation
- `web/templates`: server-rendered HTML (`/login`, `/login/mfa`)
- `web/static`: static assets served by backend

Runtime model:
- Single binary.
- Server renders auth simulation pages.
- Server serves embedded admin SPA assets.
