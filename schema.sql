PRAGMA foreign_keys = ON;

-- TeleShort Web Edition: Cloudflare D1 schema.
-- Monetary values use integer micros: $1.00 = 1,000,000.

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    first_name TEXT,
    last_name TEXT,
    username TEXT,
    api_key_hash TEXT UNIQUE NOT NULL,
    api_key_ciphertext TEXT NOT NULL,
    api_key_last4 TEXT NOT NULL,
    balance_micros INTEGER NOT NULL DEFAULT 0 CHECK (balance_micros >= 0),
    total_earnings_micros INTEGER NOT NULL DEFAULT 0 CHECK (total_earnings_micros >= 0),
    total_clicks INTEGER NOT NULL DEFAULT 0 CHECK (total_clicks >= 0),
    is_blocked INTEGER NOT NULL DEFAULT 0 CHECK (is_blocked IN (0,1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE TABLE IF NOT EXISTS user_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id, expires_at);

CREATE TABLE IF NOT EXISTS links (
    id TEXT PRIMARY KEY,
    original_url TEXT NOT NULL,
    short_id TEXT UNIQUE NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    clicks INTEGER NOT NULL DEFAULT 0 CHECK (clicks >= 0),
    earnings_micros INTEGER NOT NULL DEFAULT 0 CHECK (earnings_micros >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_links_user ON links(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS click_logs (
    id TEXT PRIMARY KEY,
    link_id TEXT NOT NULL REFERENCES links(id) ON DELETE RESTRICT,
    creator_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    clicker_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    ip_hash TEXT,
    user_agent_hash TEXT,
    risk_score INTEGER NOT NULL DEFAULT 0,
    rewarded_micros INTEGER NOT NULL DEFAULT 0,
    country_code TEXT DEFAULT 'Unknown',
    device_type TEXT DEFAULT 'Desktop',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_click_logs_link_user_time ON click_logs(link_id, clicker_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_click_logs_creator_time ON click_logs(creator_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_click_logs_ip_time ON click_logs(ip_hash, created_at DESC);

CREATE TABLE IF NOT EXISTS visit_steps (
    id TEXT PRIMARY KEY,
    step_number INTEGER NOT NULL UNIQUE,
    title TEXT,
    description TEXT,
    wait_seconds INTEGER NOT NULL DEFAULT 10 CHECK (wait_seconds BETWEEN 1 AND 120),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_visit_steps_order ON visit_steps(step_number);

CREATE TABLE IF NOT EXISTS step_websites (
    id TEXT PRIMARY KEY,
    step_id TEXT NOT NULL REFERENCES visit_steps(id) ON DELETE CASCADE,
    title TEXT,
    url TEXT NOT NULL,
    position INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_step_websites_step ON step_websites(step_id, position);

CREATE TABLE IF NOT EXISTS visit_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    link_id TEXT NOT NULL REFERENCES links(id) ON DELETE RESTRICT,
    current_step INTEGER NOT NULL DEFAULT 1,
    current_position INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','completed','expired','rejected')),
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_visit_sessions_user ON visit_sessions(user_id, status, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_visit_sessions_link ON visit_sessions(link_id, status, started_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_visit_sessions_active_unique ON visit_sessions(user_id, link_id) WHERE status='active';

CREATE TABLE IF NOT EXISTS visit_attempts (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES visit_sessions(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    link_id TEXT NOT NULL REFERENCES links(id) ON DELETE RESTRICT,
    step_id TEXT NOT NULL REFERENCES visit_steps(id) ON DELETE RESTRICT,
    website_id TEXT NOT NULL REFERENCES step_websites(id) ON DELETE RESTRICT,
    started_at TEXT NOT NULL,
    last_heartbeat_at TEXT,
    completed_at TEXT,
    required_seconds INTEGER NOT NULL DEFAULT 10 CHECK (required_seconds BETWEEN 1 AND 120),
    elapsed_seconds INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','completed','abandoned','rejected','expired')),
    ip_hash TEXT,
    user_agent_hash TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_visit_attempts_session ON visit_attempts(session_id, created_at);
CREATE INDEX IF NOT EXISTS idx_visit_attempts_user ON visit_attempts(user_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_visit_attempts_active_unique ON visit_attempts(session_id) WHERE status='active';

CREATE TABLE IF NOT EXISTS visit_rewards (
    id TEXT PRIMARY KEY,
    visit_session_id TEXT UNIQUE NOT NULL REFERENCES visit_sessions(id) ON DELETE RESTRICT,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    link_id TEXT NOT NULL REFERENCES links(id) ON DELETE RESTRICT,
    amount_micros INTEGER NOT NULL CHECK (amount_micros >= 0),
    referral_amount_micros INTEGER NOT NULL DEFAULT 0 CHECK (referral_amount_micros >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_visit_rewards_user_time ON visit_rewards(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS earnings_ledger (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    type TEXT NOT NULL CHECK (type IN ('link_visit','referral_commission','withdrawal_reserve','withdrawal_refund','admin_adjustment')),
    amount_micros INTEGER NOT NULL,
    reference_id TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ledger_user_time ON earnings_ledger(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS withdrawals (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    username TEXT,
    amount_micros INTEGER NOT NULL CHECK (amount_micros > 0),
    method TEXT NOT NULL,
    details TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','processing','paid','rejected','failed')),
    provider_reference TEXT,
    idempotency_key TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_withdrawals_status_time ON withdrawals(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_withdrawals_user_time ON withdrawals(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS referrals (
    id TEXT PRIMARY KEY,
    referrer_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    referred_user_id TEXT UNIQUE NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','blocked','invalid')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS settings (
    id TEXT PRIMARY KEY,
    cpm_micros INTEGER NOT NULL DEFAULT 2000000 CHECK (cpm_micros >= 0),
    refer_percent INTEGER NOT NULL DEFAULT 10 CHECK (refer_percent BETWEEN 0 AND 50),
    default_wait_seconds INTEGER NOT NULL DEFAULT 10 CHECK (default_wait_seconds BETWEEN 1 AND 120),
    heartbeat_seconds INTEGER NOT NULL DEFAULT 3 CHECK (heartbeat_seconds BETWEEN 2 AND 15),
    session_timeout_seconds INTEGER NOT NULL DEFAULT 600 CHECK (session_timeout_seconds BETWEEN 60 AND 3600),
    payment_methods TEXT DEFAULT 'FaucetPay, Binance Pay',
    banner_ads TEXT NOT NULL DEFAULT '{}',
    min_withdraw_micros INTEGER NOT NULL DEFAULT 5000000 CHECK (min_withdraw_micros > 0),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO settings (id) VALUES ('default');

CREATE TABLE IF NOT EXISTS admin_sessions (
    id TEXT PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_token ON admin_sessions(token_hash);

CREATE TABLE IF NOT EXISTS admin_audit_logs (
    id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_admin_audit_time ON admin_audit_logs(created_at DESC);


CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    window_started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    count INTEGER NOT NULL DEFAULT 0 CHECK (count >= 0)
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_started_at);

CREATE TABLE IF NOT EXISTS visit_pow_challenges (
    nonce TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_visit_pow_expiry ON visit_pow_challenges(expires_at);

CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    user_id TEXT,
    ip_hash TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_user_time ON security_events(user_id, created_at DESC);
