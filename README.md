# CrazyShort — Production-Hardened Web Short-Link Platform

Cloudflare Pages Functions + D1 web short-link platform with user accounts, configurable multi-step website visits, rewards, referrals, withdrawals, developer API, responsive banner ads, and anti-bot controls.

## Security features

- HttpOnly + Secure + SameSite=Strict session cookies.
- CSRF protection on authenticated state-changing requests.
- PBKDF2-SHA256 password hashing with per-password random salts.
- Admin password hash support via `ADMIN_PASSWORD_HASH`.
- API keys are hashed for lookup and encrypted at rest.
- Developer API accepts API keys only via `Authorization: Bearer` or `X-API-Key`; query-string API keys are not supported.
- User/IP rate limiting for registration, login, visits, link creation, withdrawals, and developer API usage.
- Registration requires Cloudflare Turnstile.
- Visit start requires a single-use, expiring Proof-of-Work challenge. Current difficulty is 5 leading hexadecimal zeroes.
- Server-side visit timers and heartbeat freshness checks.
- Same-user/same-link reward cooldown.
- Self-click protection.
- Atomic/idempotent reward completion and withdrawal reserve/refund batches.
- Security event and admin audit logging.
- Strong response security headers and CSP.
- Responsive header, left-sidebar, right-sidebar, and bottom banner ad slots configurable from Admin.

## Required production configuration

### Environment variables

- `APP_ENCRYPTION_KEY` — stable random secret used to derive the AES-GCM key for encrypted API-key ciphertext.
- `ADMIN_PASSWORD_HASH` — PBKDF2 hash for the admin password.
- `TURNSTILE_SECRET_KEY` — Cloudflare Turnstile server-side secret.
- `TURNSTILE_SITE_KEY` — Cloudflare Turnstile public site key.

Compatibility fallback only:
- `ADMIN_PASSWORD_HASH` — the only supported admin credential; plaintext/default admin passwords are not supported.

### Cloudflare D1 binding

- Binding name must be `DB`.
- Run the complete `schema.sql` in a new D1 database.

## Developer API

```bash
curl -G 'https://YOUR-DOMAIN/api/shorten' \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  --data-urlencode 'url=https://example.com'
```

The same Bearer/X-API-Key authentication works with `/api`, `/api/shorten`, and `/api/v1/shorten`. API keys in query strings are intentionally rejected.

## Visit/reward verification limitation

The server can prove the authenticated session, single-use anti-bot challenge, elapsed server time, and recent heartbeat. A normal website cannot cryptographically prove that a user remained focused on an unrelated third-party site because of browser same-origin restrictions. If a target provider offers a documented server-to-server verification callback, integrate that provider-side signal before treating the event as strong proof of an external impression.

## Banner ads

Admin Settings provides four independent slots:
- Header
- Left sidebar
- Right sidebar
- Bottom banner

Only trusted administrators should paste ad-network HTML/JS because these snippets are intentionally rendered as executable ad code.

## Production deployment

Follow `DEPLOYMENT.md` for the complete step-by-step Cloudflare Pages + D1 + Turnstile setup and production test checklist.
