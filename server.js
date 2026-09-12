import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createD1 } from './d1.js';

// Cloudflare function modules
import * as authHandler from './functions/api/auth.js';
import * as userHandler from './functions/api/user.js';
import * as adminHandler from './functions/api/admin.js';
import * as adminVisitsHandler from './functions/api/admin-visits.js';
import * as visitHandler from './functions/api/visit.js';
import * as adsHandler from './functions/api/ads.js';
import * as shortenHandler from './functions/api/shorten.js';
import * as v1ShortenHandler from './functions/api/v1/shorten.js';
import * as rootApiHandler from './functions/api.js';
import * as shortIdHandler from './functions/s/[short_id].js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;
const HOST = '0.0.0.0';

// Trust proxy headers for Cloud Run / reverse proxies
app.set('trust proxy', 1);

// Parse raw request body for standard Web Request consumption
app.use(express.raw({ type: '*/*', limit: '256kb' }));

// Initialize D1 SQLite database
const dbPath = path.join(process.cwd(), process.env.DB_FILE || 'crazyshort.db');
const d1 = createD1(dbPath);

// Environment object matching Cloudflare Pages Functions expectations
const env = {
  DB: d1,
  APP_ENCRYPTION_KEY: process.env.APP_ENCRYPTION_KEY || '',
  ADMIN_PASSWORD_HASH: process.env.ADMIN_PASSWORD_HASH || '',
  TURNSTILE_SECRET_KEY: process.env.TURNSTILE_SECRET_KEY || '',
  TURNSTILE_SITE_KEY: process.env.TURNSTILE_SITE_KEY || '',
};

function sameOriginRequest(req, origin) {
  try {
    const proto = req.get('x-forwarded-proto') || req.protocol || 'http';
    const host = req.get('x-forwarded-host') || req.get('host') || 'localhost:3000';
    return new URL(origin).origin === `${proto}://${host}`;
  } catch { return false; }
}

// Dispatcher that adapts an Express req/res to a Cloudflare Pages Function handler
async function dispatch(mod, req, res, params = {}) {
  try {
    const method = req.method.toUpperCase();
    let handler = null;
    if (method === 'GET' && mod.onRequestGet) handler = mod.onRequestGet;
    else if (method === 'POST' && mod.onRequestPost) handler = mod.onRequestPost;
    else if (method === 'PUT' && mod.onRequestPut) handler = mod.onRequestPut;
    else if (method === 'DELETE' && mod.onRequestDelete) handler = mod.onRequestDelete;
    else if (method === 'OPTIONS' && mod.onRequestOptions) handler = mod.onRequestOptions;
    else if (method === 'HEAD' && mod.onRequestHead) handler = mod.onRequestHead;

    if (!handler && mod.onRequest) handler = mod.onRequest;

    if (!handler) {
      if (method === 'OPTIONS') {
        const origin = req.get('origin');
        if (origin && sameOriginRequest(req, origin)) res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Headers', 'Authorization, X-API-Key, X-CSRF-Token, Content-Type');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
        return res.status(204).end();
      }
      return res.status(405).json({ error: `Method ${method} not allowed` });
    }

    // Build URL ensuring protocol and host match incoming request
    const proto = req.get('x-forwarded-proto') || req.protocol || 'http';
    const host = req.get('x-forwarded-host') || req.get('host') || 'localhost:3000';
    let url;
    const originHeader = req.get('origin');
    if (originHeader) {
      try {
        const u = new URL(req.originalUrl, originHeader);
        url = u.href;
      } catch {
        url = `${proto}://${host}${req.originalUrl}`;
      }
    } else {
      url = `${proto}://${host}${req.originalUrl}`;
    }

    const headers = new Headers();
    for (const [key, val] of Object.entries(req.headers)) {
      if (val !== undefined && val !== null) {
        if (Array.isArray(val)) {
          for (const v of val) headers.append(key, v);
        } else {
          headers.set(key, val);
        }
      }
    }

    const requestInit = {
      method,
      headers
    };

    if (method !== 'GET' && method !== 'HEAD') {
      if (req.body && Buffer.isBuffer(req.body) && req.body.length > 0) {
        requestInit.body = req.body;
      } else if (typeof req.body === 'string' && req.body.length > 0) {
        requestInit.body = req.body;
      }
    }

    const webRequest = new Request(url, requestInit);
    const response = await handler({ request: webRequest, env, params });

    res.status(response.status);

    for (const [k, v] of response.headers.entries()) {
      if (k.toLowerCase() === 'set-cookie') continue;
      res.setHeader(k, v);
    }

    if (typeof response.headers.getSetCookie === 'function') {
      const cookies = response.headers.getSetCookie();
      if (cookies && cookies.length > 0) {
        res.setHeader('Set-Cookie', cookies);
      }
    } else {
      const singleCookie = response.headers.get('set-cookie');
      if (singleCookie) res.setHeader('Set-Cookie', singleCookie);
    }

    const buf = Buffer.from(await response.arrayBuffer());
    res.send(buf);
  } catch (err) {
    console.error(`Handler error on ${req.originalUrl}:`, err);
    if (!res.headersSent) {
      res.status(500).json({ error: err.message || 'Internal server error' });
    }
  }
}

// Defense-in-depth security headers for the local/Node adapter.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Origin-Agent-Cluster', '?1');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://challenges.cloudflare.com; font-src 'self' data:; object-src 'none'; frame-src https://challenges.cloudflare.com https:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests");
  if (process.env.NODE_ENV === 'production') res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// Production startup must never silently fall back to known credentials/secrets.
if (process.env.NODE_ENV === 'production') {
  const required = ['APP_ENCRYPTION_KEY', 'ADMIN_PASSWORD_HASH'];
  const missing = required.filter(k => !String(process.env[k] || '').trim());
  if (missing.length) {
    console.error(`Missing required production secrets: ${missing.join(', ')}`);
    process.exit(1);
  }
}

// API Routes
app.all('/api/auth', (req, res) => dispatch(authHandler, req, res));
app.all('/api/user', (req, res) => dispatch(userHandler, req, res));
app.all('/api/admin', (req, res) => dispatch(adminHandler, req, res));
app.all('/api/admin-visits', (req, res) => dispatch(adminVisitsHandler, req, res));
app.all('/api/visit', (req, res) => dispatch(visitHandler, req, res));
app.all('/api/ads', (req, res) => dispatch(adsHandler, req, res));
app.all('/api/shorten', (req, res) => dispatch(shortenHandler, req, res));
app.all('/api/v1/shorten', (req, res) => dispatch(v1ShortenHandler, req, res));
app.all('/api', (req, res) => dispatch(rootApiHandler, req, res));

// Short-link redirect route
app.get('/s/:short_id', (req, res) => dispatch(shortIdHandler, req, res, { short_id: req.params.short_id }));

// Static Web Pages
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/index.html', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/visit.html', (req, res) => res.sendFile(path.join(__dirname, 'visit.html')));
app.get('/robots.txt', (req, res) => res.sendFile(path.join(__dirname, 'robots.txt')));

// Static asset fallback
app.use(express.static(__dirname));

// Start server
const server = app.listen(PORT, HOST, () => {
  console.log(`CrazyShort server running on http://${HOST}:${PORT}`);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing server...');
  server.close(() => {
    d1.close();
    process.exit(0);
  });
});
