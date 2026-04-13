# Authpilot Onboarding

Quick guide to get a company set up with users, groups, and a working login flow.

## Prerequisites

- Go installed (`brew install go`)
- Authpilot running (`make run` from the project root)

---

## 1. Start the Server

```bash
make run
```

| Service | URL |
|---------|-----|
| Admin UI | http://localhost:18025/admin |
| Login UI | http://localhost:18025/login |
| Notification Hub | http://localhost:18025/notify |
| API Docs | http://localhost:18025/api/v1/docs |

---

## 2. Create a Group

```bash
curl -X POST http://localhost:18025/api/v1/groups \
  -H "Content-Type: application/json" \
  -d '{"id":"grp_engineering","display_name":"Engineering"}'
```

---

## 3. Create Users

**Alice — admin, no MFA:**

```bash
curl -X POST http://localhost:18025/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{
    "id": "usr_alice",
    "email": "alice@example.com",
    "display_name": "Alice",
    "active": true,
    "groups": ["grp_engineering"]
  }'
```

**Bob — TOTP MFA:**

```bash
curl -X POST http://localhost:18025/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{
    "id": "usr_bob",
    "email": "bob@example.com",
    "display_name": "Bob",
    "active": true,
    "mfa_method": "totp",
    "groups": ["grp_engineering"]
  }'
```

**Carol — push MFA:**

```bash
curl -X POST http://localhost:18025/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{
    "id": "usr_carol",
    "email": "carol@example.com",
    "display_name": "Carol",
    "active": true,
    "mfa_method": "push",
    "groups": ["grp_engineering"]
  }'
```

---

## 4. Verify Users

```bash
curl http://localhost:18025/api/v1/users
```

---

## 5. Test Login

1. Open http://localhost:18025/login in your browser
2. Select a user and click **Continue**
3. If the user has MFA, open http://localhost:18025/notify to retrieve the code or approve the push

---

## 6. MFA Reference

| Method | What to do |
|--------|-----------|
| _(none)_ | Login completes immediately |
| `totp` | Open Notify hub → TOTP tab, copy the 6-digit code |
| `push` | Open Notify hub → Push tab, click **Approve** |
| `sms` | Open Notify hub → SMS tab, copy the code |
| `magic_link` | Open Notify hub → Magic Links tab, click the link |
| `webauthn` | Open Notify hub → Passkeys tab, click **Authenticate** |

---

## 7. Mint a Token (CI / Testing)

Skip the browser flow and get a token directly:

```bash
curl -X POST http://localhost:18025/api/v1/tokens/mint \
  -H "Content-Type: application/json" \
  -d '{"user_id":"usr_alice","client_id":"myapp","expires_in":3600}'
```

---

## 8. Admin UI

Visit http://localhost:18025/admin to manage users, groups, sessions, and audit logs through the web interface. Build the SPA first if the page is blank:

```bash
make admin-build
```
