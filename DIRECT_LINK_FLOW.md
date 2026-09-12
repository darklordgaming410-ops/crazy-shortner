# Current web visit flow

1. User opens `/s/<short_id>`.
2. Server redirects to `/visit.html?short=<short_id>`.
3. User must be authenticated.
4. The browser obtains a single-use anti-bot Proof-of-Work challenge.
5. Server validates the challenge and creates/continues a visit session.
6. Each configured website is opened for the configured server-enforced minimum time.
7. Heartbeats are required for active visits; client countdown is only UX.
8. Server verifies elapsed time, heartbeat freshness, target identity, cooldowns, and session state.
9. On the final step, reward, ledger, click log, creator balance, referral commission, and session completion are committed together.

Important limitation: because the destination website is a different origin, this application cannot cryptographically prove that a visitor interacted with or remained focused on that third-party page. A provider-side server callback is required for stronger external-event proof.
