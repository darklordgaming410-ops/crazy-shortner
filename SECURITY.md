# CrazyShort Security Hardening

## Production requirements
- `APP_ENCRYPTION_KEY` is mandatory.
- `ADMIN_PASSWORD_HASH` is mandatory; plaintext/default admin passwords are not supported.
- Use HTTPS in production.
- Use Cloudflare WAF/rate limiting in front of public endpoints.
- Rotate API keys if exposed.
- Keep Turnstile secret server-side.

## Session security
- Session tokens are random 256-bit values and only SHA-256 hashes are stored.
- Cookies are `HttpOnly`, `Secure`, and `SameSite=Lax`.
- CSRF tokens are required for authenticated state-changing requests.
- Sessions expire and can be revoked.

## Secrets
Never place secrets in HTML, JavaScript, Git, README files, or query strings.

## Admin
Admin authentication uses the project PBKDF2 password format. Generate a hash locally and store it as `ADMIN_PASSWORD_HASH`.
