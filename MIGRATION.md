# CrazyShort production migration

## New deployment
1. Create a fresh Cloudflare D1 database.
2. Run the complete `schema.sql`.
3. Bind the D1 database to Pages Functions as `DB`.
4. Configure `APP_ENCRYPTION_KEY`, `ADMIN_PASSWORD_HASH`, `TURNSTILE_SECRET_KEY`, and `TURNSTILE_SITE_KEY`.
5. Deploy the project and complete the production test checklist in `DEPLOYMENT.md`.

## Existing legacy database
Do not run the new schema blindly against a live database. Export/backup the existing D1 database first and perform a deliberate migration. The current schema uses integer micro-units for monetary balances and stores API keys as a lookup hash plus encrypted ciphertext. Existing plaintext API keys should not be copied into the new structure.

Recommended approach: create a new schema/database, migrate only required account/profile data with a controlled script, force API-key rotation for migrated accounts, and verify balances/withdrawal states before switching production traffic.

## Security
Registration now requires Cloudflare Turnstile. Visit starts require a single-use expiring Proof-of-Work challenge. Developer API authentication uses `Authorization: Bearer` or `X-API-Key`; API keys in query strings are not supported.
