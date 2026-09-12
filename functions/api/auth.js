import { sha256Hex, json, getCookie, getClientIp, randomHex, cookie, clearCookie, passwordHash, verifyPassword, sameOrigin, rateLimit, rateHeaders } from '../../verifyAuth.js';

const COOKIE = 'teleshort_user_session';
const SESSION_SECONDS = 7 * 24 * 60 * 60;
const MICRO = 1_000_000;

function email(value) {
    const v = String(value || '').trim().toLowerCase();
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? v : null;
}

function generateApiKey() { return randomHex(32); }

async function verifyTurnstile(token, request, env) {
    if (!env.TURNSTILE_SECRET_KEY) return { ok:true };
    const t = String(token || '').trim();
    if (!t || t.length > 2048) {
        if (!env.TURNSTILE_SITE_KEY || env.TURNSTILE_SECRET_KEY.startsWith('1x000')) return { ok:true };
        return { ok:false, reason:'Anti-bot verification is required.' };
    }
    if (env.TURNSTILE_SECRET_KEY.startsWith('1x000') && (t === 'test' || t.startsWith('XXXX.'))) {
        return { ok: true };
    }
    const form = new FormData();
    form.append('secret', env.TURNSTILE_SECRET_KEY);
    form.append('response', t);
    const ip = getClientIp(request);
    if (ip && ip !== '0.0.0.0') form.append('remoteip', ip);
    try {
        const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method:'POST', body:form });
        const d = await r.json();
        return { ok: !!d.success, reason:'Anti-bot verification failed.' };
    } catch {
        if (env.TURNSTILE_SECRET_KEY.startsWith('1x000')) return { ok: true };
        return { ok:false, reason:'Anti-bot verification is temporarily unavailable.' };
    }
}


function b64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))); }
async function encryptionKey(env) {
    if (!env.APP_ENCRYPTION_KEY) throw new Error('APP_ENCRYPTION_KEY is not configured');
    const raw = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(env.APP_ENCRYPTION_KEY));
    return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function encryptSecret(value, env) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await encryptionKey(env);
    const cipher = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, new TextEncoder().encode(value));
    return `${b64(iv)}.${b64(cipher)}`;
}
async function decryptSecret(value, env) {
    const [ivB64, cipherB64] = String(value || '').split('.');
    if (!ivB64 || !cipherB64) return null;
    try {
        const raw = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
        const key = await encryptionKey(env);
        const plain = await crypto.subtle.decrypt({name:'AES-GCM',iv:raw(ivB64)}, key, raw(cipherB64));
        return new TextDecoder().decode(plain);
    } catch { return null; }
}

async function sessionUser(request, env) {
    const token = getCookie(request, COOKIE);
    if (!token) return null;
    const hash = await sha256Hex(token);
    const row = await env.DB.prepare(`SELECT s.*,u.* FROM user_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>datetime('now') LIMIT 1`).bind(hash).first();
    if (!row || row.is_blocked) return null;
    await env.DB.prepare('UPDATE user_sessions SET last_seen_at=CURRENT_TIMESTAMP WHERE id=?').bind(row.id).run();
    return row;
}

async function publicUser(env, user) {
    const today = await env.DB.prepare(`SELECT COALESCE(SUM(amount_micros),0) amount, COUNT(*) count FROM earnings_ledger WHERE user_id=? AND type='link_visit' AND created_at>=date('now')`).bind(user.user_id || user.id).first();
    const uid = user.user_id || user.id;
    return {
        id: uid, email: user.email, first_name: user.first_name, last_name: user.last_name, username: user.username,
        api_key_last4: user.api_key_last4,
        balance: Number(user.balance_micros||0)/MICRO, total_earnings:Number(user.total_earnings_micros||0)/MICRO,
        today_earnings:Number(today?.amount||0)/MICRO, total_clicks:Number(user.total_clicks||0),
        today_clicks:Number(today?.count||0), is_blocked:Number(user.is_blocked||0), created_at:user.created_at
    };
}

function referralCode(userId) { return userId; }

export async function onRequestPost(context) {
    const { request, env } = context;
    try {
        const body = await request.json().catch(()=>({}));
        const action = body.action;
        const ipHash = await sha256Hex(getClientIp(request));

        if (['register','login'].includes(action) && !sameOrigin(request)) return json({error:'Invalid request origin.'},403);

        if (action === 'register') {
            const rl = await rateLimit(env, `register:ip:${ipHash}`, 5, 3600);
            if (!rl.allowed) return json({error:'Too many registration attempts. Try again later.', retry_after:rl.retryAfter},429,rateHeaders(rl));
            const daily = await rateLimit(env, `register:daily:${ipHash}`, 10, 86400);
            if (!daily.allowed) return json({error:'Too many accounts from this network today. Try again tomorrow.', retry_after:daily.retryAfter},429,rateHeaders(daily));
            const turnstile = await verifyTurnstile(body.turnstile_token, request, env);
            if (!turnstile.ok) return json({error:turnstile.reason},403);
            const e = email(body.email);
            const password = String(body.password || '');
            const first = String(body.first_name || '').trim().slice(0,80);
            const last = String(body.last_name || '').trim().slice(0,80);
            const username = String(body.username || '').trim().slice(0,40);
            if (!e) return json({error:'Enter a valid email address.'},400);
            if (password.length < 8 || password.length > 128) return json({error:'Password must be 8-128 characters.'},400);
            const exists = await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(e).first();
            if (exists) return json({error:'An account with this email already exists.'},409);
            const id = crypto.randomUUID();
            const apiKey = generateApiKey();
            const [pwHash, apiHash, encrypted] = await Promise.all([passwordHash(password), sha256Hex(apiKey), encryptSecret(apiKey, env)]);
            await env.DB.prepare(`INSERT INTO users (id,email,password_hash,first_name,last_name,username,api_key_hash,api_key_ciphertext,api_key_last4) VALUES (?,?,?,?,?,?,?,?,?)`)
                .bind(id,e,pwHash,first,last,username,apiHash,encrypted,apiKey.slice(-4)).run();

            const ref = String(body.ref || '').trim();
            if (ref && ref !== id) {
                const referrer = await env.DB.prepare('SELECT id,is_blocked FROM users WHERE id=?').bind(ref).first();
                if (referrer && !referrer.is_blocked) {
                    await env.DB.prepare('INSERT OR IGNORE INTO referrals (id,referrer_user_id,referred_user_id) VALUES (?,?,?)').bind(crypto.randomUUID(),ref,id).run();
                }
            }
            const token = randomHex(32), tokenHash = await sha256Hex(token), csrf = randomHex(24);
            const expires = new Date(Date.now()+SESSION_SECONDS*1000).toISOString().replace('T',' ').replace('Z','');
            await env.DB.prepare('INSERT INTO user_sessions (id,user_id,token_hash,csrf_token,expires_at) VALUES (?,?,?,?,?)').bind(crypto.randomUUID(),id,tokenHash,csrf,expires).run();
            return json({success:true,user:await publicUser(env,await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(id).first()),csrf_token:csrf,api_key:apiKey},200,{'Set-Cookie':cookie(COOKIE,token,SESSION_SECONDS,'/')});
        }

        if (action === 'login') {
            const e = email(body.email), password = String(body.password || '');
            const rlIp = await rateLimit(env, `login:ip:${ipHash}`, 10, 900);
            const rlAccount = e ? await rateLimit(env, `login:email:${await sha256Hex(e)}`, 8, 900) : rlIp;
            if (!rlIp.allowed || !rlAccount.allowed) { const rl=!rlIp.allowed?rlIp:rlAccount; return json({error:'Too many login attempts. Try again later.', retry_after:rl.retryAfter},429,rateHeaders(rl)); }
            if (!e || !password) return json({error:'Email and password are required.'},400);
            const user = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(e).first();
            if (!user || !(await verifyPassword(password,user.password_hash))) {
                await env.DB.prepare('INSERT INTO security_events (id,event_type,ip_hash,metadata) VALUES (?,?,?,?)').bind(crypto.randomUUID(),'user_login_failed',ipHash,JSON.stringify({email:e})).run();
                return json({error:'Invalid email or password.'},401);
            }
            if (user.is_blocked) return json({error:'Account is blocked or suspended.'},403);
            const token = randomHex(32), tokenHash = await sha256Hex(token), csrf = randomHex(24);
            const expires = new Date(Date.now()+SESSION_SECONDS*1000).toISOString().replace('T',' ').replace('Z','');
            await env.DB.prepare('INSERT INTO user_sessions (id,user_id,token_hash,csrf_token,expires_at) VALUES (?,?,?,?,?)').bind(crypto.randomUUID(),user.id,tokenHash,csrf,expires).run();
            return json({success:true,user:await publicUser(env,user),csrf_token:csrf},200,{'Set-Cookie':cookie(COOKIE,token,SESSION_SECONDS,'/')});
        }

        if (action === 'logout') {
            const token = getCookie(request,COOKIE);
            if (token) await env.DB.prepare('UPDATE user_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE token_hash=?').bind(await sha256Hex(token)).run();
            return json({success:true},200,{'Set-Cookie':clearCookie(COOKIE,'/')});
        }

        const user = await sessionUser(request,env);
        if (!user) return json({error:'Unauthorized.'},401);
        if (action !== 'me' && action !== 'logout') { const csrf=request.headers.get('X-CSRF-Token'); if(!csrf || csrf!==user.csrf_token) return json({error:'CSRF validation failed.'},403); }
        if (action === 'me') return json({success:true,user:await publicUser(env,user),csrf_token:user.csrf_token});
        return json({error:'Unknown action.'},400);
    } catch (e) {
        console.error('AUTH_API_ERROR',e);
        return json({error:'Internal server error.'},500);
    }
}
