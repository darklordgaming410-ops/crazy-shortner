# TeleShort production deployment

## 1. Create Cloudflare D1
1. Cloudflare Dashboard -> Workers & Pages -> D1 -> Create database.
2. Name it, for example `teleshort-db`.
3. Open the database -> Console.
4. Run the complete `schema.sql` from this project.
5. Confirm the tables include `users`, `links`, `visit_sessions`, `visit_attempts`, `visit_pow_challenges`, `visit_rewards`, `earnings_ledger`, `withdrawals`, `rate_limits`, and `security_events`.

## 2. Create a Cloudflare Pages project
1. Workers & Pages -> Create application -> Pages.
2. Connect the Git repository containing this project, or upload the project through the supported Pages deployment flow.
3. No build command is required for this static Pages Functions project. The site root is the project root.
4. Deploy once so Cloudflare creates the production project.

## 3. Bind D1 to Pages Functions
Project -> Settings -> Functions -> D1 database bindings.
- Variable/binding name: `DB`
- Database: your `teleshort-db`

The code expects `env.DB`.

## 4. Create Cloudflare Turnstile
1. Cloudflare Dashboard -> Turnstile -> Add site.
2. Add your production domain.
3. Use the normal managed widget mode.
4. Copy the Site Key and Secret Key.

Registration requires Turnstile. Login does not, because login already has IP + account rate limiting.

## 5. Generate production secrets
Use unique random values. Do not reuse one secret for multiple variables.

Example using OpenSSL:
```bash
openssl rand -hex 32
```
Run it once for each of these:
- `APP_ENCRYPTION_KEY`
- `SESSION_SECRET`
- `CSRF_SECRET`
- `POW_SECRET`

The current code uses `APP_ENCRYPTION_KEY` for AES-GCM encryption of stored API-key ciphertext. The session/CSRF/PoW variables are reserved for the corresponding security controls and should be set as separate production secrets.

Generate the admin PBKDF2 hash with the project-compatible Node/WebCrypto helper supplied by your deployment tooling, or use the following browser-console snippet on a trusted local machine (never paste the password into a website):
```js
(async()=>{const p=prompt('Admin password');const salt=crypto.getRandomValues(new Uint8Array(16));const hx=a=>[...a].map(b=>b.toString(16).padStart(2,'0')).join('');const k=await crypto.subtle.importKey('raw',new TextEncoder().encode(p),'PBKDF2',false,['deriveBits']);const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:120000,hash:'SHA-256'},k,256);console.log(`pbkdf2$120000$${hx(salt)}$${hx(new Uint8Array(bits))}`)})()
```

## 6. Add Production environment variables
Pages -> Settings -> Environment variables -> Production.

Required:
- `APP_ENCRYPTION_KEY` = random secret
- `ADMIN_PASSWORD_HASH` = generated PBKDF2 hash
- `TURNSTILE_SECRET_KEY` = Turnstile Secret Key
- `TURNSTILE_SITE_KEY` = Turnstile Site Key

Recommended separately set secrets if your deployment layer uses them:
- `SESSION_SECRET`
- `CSRF_SECRET`
- `POW_SECRET`

Never put secret values in HTML, JS, Git, or README files. `TURNSTILE_SITE_KEY` is public; `TURNSTILE_SECRET_KEY` is secret.

## 7. Deploy and test
After saving variables and the D1 binding, deploy again.

Test in this order:
1. Open `/` -> Register -> Turnstile appears.
2. Complete Turnstile -> account registration succeeds.
3. Login/logout.
4. Create a short link.
5. Open `/s/<short_id>` from a second account/browser.
6. Solve the visit anti-bot challenge.
7. Confirm the configured wait time and heartbeat are enforced.
8. Complete all steps and confirm exactly one reward/ledger entry is created.
9. Test the Developer API using `Authorization: Bearer <API_KEY>`.
10. Confirm `?api=<API_KEY>` is rejected.
11. Open `/admin.html`, log in, configure banner ads and visit steps.
12. Test blocked users and rejected withdrawals.

## 8. Cloudflare edge protections (strongly recommended)
Use Cloudflare WAF/Rate Limiting rules in front of the deployment:
- `/api/auth` -> aggressive rate limit for POST requests.
- `/api/visit` -> rate limit by IP, especially `challenge`, `start`, `heartbeat`, `complete`.
- `/api/v1/*` and `/api/shorten` -> API rate limiting.
- `/admin.html` and `/api/admin` -> much stricter rate limiting.
- `/s/*` -> edge rate limiting appropriate to expected traffic.

Do not put API keys, admin passwords, or secrets into query strings.

## 9. Production checklist
- HTTPS/custom domain enabled.
- D1 binding name exactly `DB`.
- Turnstile site + secret configured.
- `ADMIN_PASSWORD_HASH` configured; do not rely on `ADMIN_PASSWORD` fallback.
- `APP_ENCRYPTION_KEY` configured.
- All production secrets are unique and randomly generated.
- Cloudflare WAF/rate limiting enabled.
- Admin account tested.
- Test user and test API key removed/rotated before launch.
- Backups/export strategy for D1 established.
