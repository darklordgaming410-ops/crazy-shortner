import { sha256Hex, json, getCookie, getClientIp, randomHex, sameOrigin, rateLimit, rateHeaders } from '../../verifyAuth.js';

const COOKIE='teleshort_user_session';
const MICRO=1_000_000;

function safeUrl(value){try{const u=new URL(String(value||'').trim());if(!['http:','https:'].includes(u.protocol)||u.username||u.password)return null;return u.href;}catch{return null;}}
function safeError(message,status=400){return json({error:message},status);}
function generateShortId(length=8){const chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';const bytes=new Uint8Array(length);crypto.getRandomValues(bytes);return [...bytes].map(b=>chars[b%chars.length]).join('');}
function b64(bytes){return btoa(String.fromCharCode(...new Uint8Array(bytes)));}
function unb64(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0));}
async function encryptionKey(env){if(!env.APP_ENCRYPTION_KEY)throw new Error('APP_ENCRYPTION_KEY is not configured');const raw=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(env.APP_ENCRYPTION_KEY));return crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']);}
async function encryptSecret(value,env){const iv=crypto.getRandomValues(new Uint8Array(12));const key=await encryptionKey(env);const cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(value));return `${b64(iv)}.${b64(cipher)}`;}
async function getSessionUser(request,env){const token=getCookie(request,COOKIE);if(!token)return null;const hash=await sha256Hex(token);const row=await env.DB.prepare(`SELECT s.*,u.* FROM user_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>datetime('now') LIMIT 1`).bind(hash).first();if(!row||row.is_blocked)return null;await env.DB.prepare('UPDATE user_sessions SET last_seen_at=CURRENT_TIMESTAMP WHERE id=?').bind(row.id).run();return row;}
async function loadSettings(env){return env.DB.prepare("SELECT * FROM settings WHERE id='default'").first();}
async function publicUser(env,user){const uid=user.user_id||user.id;const today=await env.DB.prepare("SELECT COALESCE(SUM(amount_micros),0) amount,COUNT(*) count FROM earnings_ledger WHERE user_id=? AND type='link_visit' AND created_at>=date('now')").bind(uid).first();return{id:uid,email:user.email,first_name:user.first_name,last_name:user.last_name,username:user.username,api_key_last4:user.api_key_last4,balance:Number(user.balance_micros||0)/MICRO,total_earnings:Number(user.total_earnings_micros||0)/MICRO,today_earnings:Number(today?.amount||0)/MICRO,total_clicks:Number(user.total_clicks||0),today_clicks:Number(today?.count||0),created_at:user.created_at};}

export async function onRequestPost(context){const{request,env}=context;try{const body=await request.json().catch(()=>({}));const action=body.action,payload=body.payload||{};if(!sameOrigin(request))return safeError('Invalid request origin.',403);

if(action==='get_public_config'){const s=await loadSettings(env);return json({success:true,settings:{cpm:Number(s?.cpm_micros||0)/MICRO,refer_percent:s?.refer_percent??10,min_withdraw:Number(s?.min_withdraw_micros||0)/MICRO,payment_methods:s?.payment_methods||'',default_wait_seconds:s?.default_wait_seconds??10,heartbeat_seconds:s?.heartbeat_seconds??3,session_timeout_seconds:s?.session_timeout_seconds??600,turnstile_site_key:env.TURNSTILE_SITE_KEY||''}});}

const user=await getSessionUser(request,env);if(!user)return safeError('Unauthorized.',401);if(user.is_blocked)return safeError('Account is blocked or suspended.',403);

if(action==='get_me'){return json({success:true,user:await publicUser(env,user)});}

if(action==='rotate_api_key'){const apiKey=randomHex(32),apiHash=await sha256Hex(apiKey),encrypted=await encryptSecret(apiKey,env);await env.DB.prepare('UPDATE users SET api_key_hash=?,api_key_ciphertext=?,api_key_last4=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(apiHash,encrypted,apiKey.slice(-4),user.id).run();return json({success:true,api_key:apiKey,api_key_last4:apiKey.slice(-4)});}

if(action==='update_profile'){const first=String(payload.first_name||'').trim().slice(0,80),last=String(payload.last_name||'').trim().slice(0,80),username=String(payload.username||'').trim().slice(0,40);await env.DB.prepare('UPDATE users SET first_name=?,last_name=?,username=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(first,last,username,user.id).run();return json({success:true});}

if(action==='create_link'){const rl=await rateLimit(env,`create_link:user:${user.id}`,30,60);if(!rl.allowed)return safeError('Too many link creation requests. Try again later.',429);const ipRl=await rateLimit(env,`create_link:ip:${await sha256Hex(getClientIp(request))}`,60,60);if(!ipRl.allowed)return safeError('Too many link creation requests from this network.',429);const originalUrl=safeUrl(payload.original_url);if(!originalUrl||originalUrl.length>4096)return safeError('Invalid URL. Only http:// and https:// URLs are allowed.');for(let attempt=0;attempt<6;attempt++){const shortId=generateShortId(attempt<4?8:10);try{await env.DB.prepare('INSERT INTO links(id,original_url,short_id,user_id) VALUES(?,?,?,?)').bind(crypto.randomUUID(),originalUrl,shortId,user.id).run();const shortUrl=new URL(`/s/${shortId}`,request.url).href;return json({success:true,short_id:shortId,short_url:shortUrl,shortenedUrl:shortUrl});}catch(e){if(attempt===5)throw e;}}}

if(action==='get_links'){const{results}=await env.DB.prepare('SELECT id,original_url,short_id,clicks,earnings_micros,created_at FROM links WHERE user_id=? ORDER BY created_at DESC LIMIT 100').bind(user.id).all();return json({links:(results||[]).map(l=>({...l,earnings:Number(l.earnings_micros)/MICRO}))});}

if(action==='get_link_stats'){
  const linkId=String(payload.link_id||'').trim();
  if(!linkId)return safeError('Link ID is required.');
  const link=await env.DB.prepare('SELECT id,original_url,short_id,clicks,earnings_micros,created_at FROM links WHERE id=? AND user_id=?').bind(linkId,user.id).first();
  if(!link)return safeError('Link not found.',404);

  const geoQuery="SELECT COALESCE(NULLIF(country_code, ''), 'Unknown') as country, COUNT(*) as clicks FROM click_logs WHERE link_id=? GROUP BY country ORDER BY clicks DESC LIMIT 15";
  const {results: geoResults}=await env.DB.prepare(geoQuery).bind(linkId).all();

  const devQuery="SELECT COALESCE(NULLIF(device_type, ''), 'Desktop') as device, COUNT(*) as clicks FROM click_logs WHERE link_id=? GROUP BY device ORDER BY clicks DESC";
  const {results: devResults}=await env.DB.prepare(devQuery).bind(linkId).all();

  const totalLogs=await env.DB.prepare("SELECT COUNT(*) as count, COALESCE(SUM(rewarded_micros),0) as earnings FROM click_logs WHERE link_id=?").bind(linkId).first();

  const days=[];
  const now=new Date();
  for(let i=6;i>=0;i--){
    const d=new Date(now.getTime()-i*86400000);
    days.push(d.toISOString().slice(0,10));
  }
  const minDate=days[0];
  const {results: dailyResults}=await env.DB.prepare("SELECT date(created_at) as click_date, COUNT(*) as clicks FROM click_logs WHERE link_id=? AND date(created_at)>=? GROUP BY date(created_at) ORDER BY click_date ASC").bind(linkId,minDate).all();
  const dailyMap=new Map((dailyResults||[]).map(r=>[r.click_date,Number(r.clicks)||0]));
  const timeline=days.map(dt=>({date:dt,clicks:dailyMap.get(dt)||0}));

  const {results: recentClicks}=await env.DB.prepare("SELECT created_at, COALESCE(NULLIF(country_code, ''), 'Unknown') as country_code, COALESCE(NULLIF(device_type, ''), 'Desktop') as device_type, rewarded_micros FROM click_logs WHERE link_id=? ORDER BY created_at DESC LIMIT 10").bind(linkId).all();

  const totalClicksCount=Math.max(Number(link.clicks)||0, Number(totalLogs?.count)||0);
  const totalEarningsAmt=Math.max(Number(link.earnings_micros)||0, Number(totalLogs?.earnings)||0)/MICRO;

  return json({
    success: true,
    link: {
      id: link.id,
      short_id: link.short_id,
      original_url: link.original_url,
      clicks: totalClicksCount,
      earnings: totalEarningsAmt,
      created_at: link.created_at
    },
    geo: geoResults||[],
    devices: devResults||[],
    timeline,
    recent_clicks: (recentClicks||[]).map(c=>({
      created_at: c.created_at,
      country_code: c.country_code,
      device_type: c.device_type,
      reward: Number(c.rewarded_micros||0)/MICRO
    }))
  });
}

if(action==='get_click_history'){const days=[];const now=new Date();for(let i=6;i>=0;i--){const d=new Date(now.getTime()-i*86400000);days.push(d.toISOString().slice(0,10));}const minDate=days[0];const linkId=payload.link_id?String(payload.link_id).trim():'';let query="SELECT date(created_at) as click_date, COUNT(*) as clicks, COALESCE(SUM(rewarded_micros),0) as earnings_micros FROM click_logs WHERE creator_user_id=? AND date(created_at)>=?";const params=[user.id,minDate];if(linkId){query+=" AND link_id=?";params.push(linkId);}query+=" GROUP BY date(created_at) ORDER BY click_date ASC";const{results}=await env.DB.prepare(query).bind(...params).all();const map=new Map((results||[]).map(r=>[r.click_date,{clicks:Number(r.clicks)||0,earnings:Number(r.earnings_micros)/MICRO}]));const history=days.map(dt=>{const d=map.get(dt)||{clicks:0,earnings:0};return{date:dt,clicks:d.clicks,earnings:d.earnings};});return json({success:true,history});}

if(action==='withdraw'){const rl=await rateLimit(env,`withdraw:user:${user.id}`,5,3600);if(!rl.allowed)return json({error:'Too many withdrawal requests. Try again later.',retry_after:rl.retryAfter},429,rateHeaders(rl));const ipRl=await rateLimit(env,`withdraw:ip:${await sha256Hex(getClientIp(request))}`,20,3600);if(!ipRl.allowed)return json({error:'Too many withdrawal requests from this network.',retry_after:ipRl.retryAfter},429,rateHeaders(ipRl));const method=String(payload.method||'').trim(),details=String(payload.details||'').trim(),amount=Number(payload.amount),idem=String(payload.idempotency_key||'').trim();const settings=await loadSettings(env);const minW=Number(settings?.min_withdraw_micros||5*MICRO);const allowed=String(settings?.payment_methods||'').split(',').map(x=>x.trim()).filter(Boolean);const amountMicros=Math.round(amount*MICRO);if(!Number.isFinite(amount)||amountMicros<=0||amountMicros<minW)return safeError(`Minimum withdrawal amount is $${(minW/MICRO).toFixed(2)}`);if(!allowed.includes(method))return safeError('Unsupported payment method.');if(!details||details.length>512)return safeError('Invalid payout details.');if(!/^[A-Za-z0-9._:-]{16,80}$/.test(idem))return safeError('A valid idempotency key is required.');const existing=await env.DB.prepare('SELECT id,status FROM withdrawals WHERE idempotency_key=? AND user_id=?').bind(idem,user.id).first();if(existing)return json({success:true,duplicate:true,withdrawal_id:existing.id,status:existing.status});const wid=crypto.randomUUID();const result=await env.DB.batch([env.DB.prepare('UPDATE users SET balance_micros=balance_micros-?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND is_blocked=0 AND balance_micros>=?').bind(amountMicros,user.id,amountMicros),env.DB.prepare('INSERT INTO withdrawals(id,user_id,username,amount_micros,method,details,idempotency_key) VALUES(?,?,?,?,?,?,?)').bind(wid,user.id,user.username||user.email,amountMicros,method,details,idem),env.DB.prepare("INSERT INTO earnings_ledger(id,user_id,type,amount_micros,reference_id,metadata) VALUES(?,?,?,?,?,?)").bind(crypto.randomUUID(),user.id,'withdrawal_reserve',-amountMicros,wid,JSON.stringify({method}))]);if(!result[0]?.meta?.changes)return safeError('Insufficient balance or transaction failed.');return json({success:true,new_balance:(Number(user.balance_micros)-amountMicros)/MICRO,withdrawal_id:wid});}

if(action==='get_withdrawals'){const{results}=await env.DB.prepare('SELECT id,amount_micros,method,details,status,provider_reference,created_at,processed_at FROM withdrawals WHERE user_id=? ORDER BY created_at DESC LIMIT 50').bind(user.id).all();return json({withdrawals:(results||[]).map(w=>({...w,amount:Number(w.amount_micros)/MICRO}))});}

if(action==='get_referrals'){const{results}=await env.DB.prepare('SELECT referred_user_id,created_at,status FROM referrals WHERE referrer_user_id=? ORDER BY created_at DESC LIMIT 100').bind(user.id).all();return json({referrals:results||[],referral_url:new URL(`/?ref=${encodeURIComponent(user.id)}`,request.url).href});}

return safeError('Invalid action.',400);}catch(e){console.error('USER_API_ERROR',e);return json({error:'Internal server error.'},500);}}
