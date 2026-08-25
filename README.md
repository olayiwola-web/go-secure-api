# go-secure-api

A clean Go HTTP API focused on authentication and basic security patterns.

This project includes:

- JWT Access + Refresh tokens
- Session binding to wallet addresses
- Role-based access control (user / admin)
- In-memory rate limiting
- Graceful shutdown

Built as a practical backend project while learning and exploring Go + Web3 related systems.

## Features

- `POST /auth/login`
- `POST /auth/refresh`
- `GET /me` (protected)
- `GET /admin/dashboard` (admin only)
- Rate limiting
- Graceful shutdown

## Project Structure

```text
cmd/server/          → Application entrypoint
internal/auth/       → JWT, session store, auth middleware
internal/handler/    → HTTP handlers
internal/middleware/ → Rate limiter
internal/config/     → Configuration
pkg/response/        → JSON response helpers
