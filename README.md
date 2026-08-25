# go-secure-api

A clean Go HTTP API with JWT auth, wallet-bound sessions, RBAC, in-memory rate limiting, and graceful shutdown.

## Requirements

- Go 1.22+

## Project layout

```
cmd/server/                 Application entrypoint
internal/auth/              JWT, session store, auth middleware
internal/handler/           HTTP handlers (auth, user, admin)
internal/middleware/        Rate limiter
internal/model/             Shared domain types
internal/config/            Environment configuration
pkg/response/               JSON success/error helpers
```

## Setup

```bash
cp .env.example .env
# Edit .env — at minimum set a strong JWT_SECRET
```

The server automatically loads `.env` from the working directory (existing shell env vars take precedence).

## Run

```bash
go run ./cmd/server
```

Or build a binary:

```bash
go build -o bin/server ./cmd/server
./bin/server
```

Health check:

```bash
curl http://localhost:8080/health
```

Stop with `Ctrl+C` — in-flight requests are drained, then the process exits.

## API overview

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | public | Liveness |
| `POST` | `/auth/login` | public | Wallet login → access + refresh tokens |
| `POST` | `/auth/refresh` | public | Rotate tokens with a refresh token |
| `GET` | `/me` | Bearer access | Current wallet / role / session |
| `GET` | `/admin/dashboard` | Bearer + admin | Admin-only dashboard |

Access tokens expire in **15 minutes** (configurable). Refresh tokens and sessions default to **7 days**.

Wallets listed in `ADMIN_WALLETS` receive the `admin` role on login; everyone else gets `user`.

## Example curl flows

### 1. Login as a regular user

```bash
curl -s -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"wallet_address":"0xuser000000000000000000000000000000000001"}' | jq
```

Save the tokens from the response:

```bash
ACCESS=$(curl -s -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"wallet_address":"0xuser000000000000000000000000000000000001"}' \
  | jq -r .data.access_token)

REFRESH=$(curl -s -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"wallet_address":"0xuser000000000000000000000000000000000001"}' \
  | jq -r .data.refresh_token)
```

### 2. Call the protected `/me` route

```bash
curl -s http://localhost:8080/me \
  -H "Authorization: Bearer $ACCESS" | jq
```

### 3. Refresh tokens

```bash
curl -s -X POST http://localhost:8080/auth/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}" | jq
```

### 4. Admin dashboard

Login with a wallet from `ADMIN_WALLETS` (see `.env.example`):

```bash
ADMIN_ACCESS=$(curl -s -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"wallet_address":"0xadmin000000000000000000000000000000000001"}' \
  | jq -r .data.access_token)

curl -s http://localhost:8080/admin/dashboard \
  -H "Authorization: Bearer $ADMIN_ACCESS" | jq
```

A non-admin access token receives `403` on this route.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | Listen host |
| `PORT` | `8080` | Listen port |
| `JWT_SECRET` | _(required)_ | HS256 signing secret |
| `ACCESS_TOKEN_TTL_MINUTES` | `15` | Access token lifetime |
| `REFRESH_TOKEN_TTL_HOURS` | `168` | Refresh token + session lifetime |
| `ADMIN_WALLETS` | empty | Comma-separated admin wallet addresses |
| `RATE_LIMIT_REQUESTS` | `100` | Max requests per IP per window |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate-limit window |

## Notes

- Sessions are **in-memory** (one active session per wallet). Restarting the server invalidates all sessions.
- Rate limiting is **in-memory** and per process / per client IP.
- Login is a **simulation** (no cryptographic wallet signature verification).

## License

MIT
