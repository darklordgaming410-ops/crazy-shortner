# CrazyShort repair notes

This build keeps the admin panel login as **password-only**.

## Fixed
- Visit timer now starts only after the user actually clicks **Open Website**.
- Server-side visit timing is reset at activation, preventing the timer from being bypassed by waiting on the start request before opening the target.
- Reloading an already-activated visit resumes the remaining server-side time instead of restarting the UI countdown.
- Visit completion now rejects attempts that were never activated.
- Fixed the `abandon` action crash caused by an undefined `safeError()` function.
- Popup-blocked target pages now show a clear error and do not start the visit timer.
- Admin login remains a single password field; no admin email/username field was added.
- Added a small deployment note: `ADMIN_PASSWORD_HASH` is the preferred admin credential; the legacy plain `ADMIN_PASSWORD` fallback remains supported for compatibility.

## Important deployment note
If an existing D1 database is already deployed, these code fixes do not require a schema change. Redeploy the Pages project after replacing the files.

The admin password itself is **not stored in the ZIP**. Set it through Cloudflare Pages/Workers environment variables.
