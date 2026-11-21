// REST admin login — verifies the admin email + password server-side.
// POST { email, password } -> { ok: true, token } | { ok: false, error }
// On success it also issues a short-lived publish token (24h) that the
// admin panel sends as `Authorization: Bearer <token>` on /api/publish.
// The token is HMAC-SHA256(key=ADMIN_PASSWORD_HASH,
// message=`rest-admin:<email>:<expiry>`) — no separate secret to manage,
// and a password change invalidates every outstanding token.
// Env vars (set once in the Vercel dashboard, rest3 project):
//   ADMIN_EMAIL          e.g. admin@rest.local
//   ADMIN_PASSWORD_HASH  SHA-256 hex of the admin password (lowercase)
// No dependencies; CommonJS (Vercel Node runtime). The password itself is
// never stored here or in the browser — only its hash lives in Vercel.
//
// Rate limiting: a best-effort in-memory per-IP limiter (10 failed attempts
// per 15 minutes, then HTTP 429). Vercel serverless functions are stateless
// and may run on several instances, so this limiter is per-instance and not
// airtight — it raises the cost of online guessing, it does not replace a
// strong password. A distributed limiter (e.g. Upstash Redis) would be
// needed for a hard guarantee.
const crypto = require('crypto');

const TOKEN_TTL_SECONDS = 24 * 3600; // publish token lifetime
const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_MAX_FAILS = 10;

function sha256Hex(s) {
  return crypto.createHash('sha256').update(String(s || ''), 'utf8').digest('hex');
}
function safeEqual(a, b) {
  const ba = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  if (ba.length !== bb.length) return false;
  try { return crypto.timingSafeEqual(ba, bb); } catch (e) { return false; }
}
function hmacHex(key, msg) {
  return crypto.createHmac('sha256', String(key || '')).update(String(msg || ''), 'utf8').digest('hex');
}
function issuePublishToken(email, hash) {
  const expiry = Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS;
  const sig = hmacHex(hash, 'rest-admin:' + email + ':' + expiry);
  return expiry + '.' + sig;
}
// Shared by /api/publish.js (same HMAC scheme, same key). Kept here so the
// scheme is documented in one place; publish.js re-implements the check
// (serverless functions are deployed as separate files).
function clientIp(req) {
  const fwd = req.headers && (req.headers['x-forwarded-for'] || req.headers['x-real-ip']);
  if (typeof fwd === 'string' && fwd) return fwd.split(',')[0].trim();
  if (req.socket && req.socket.remoteAddress) return req.socket.remoteAddress;
  return 'unknown';
}
// In-memory per-IP failure counter. Reset on success.
const failures = new Map(); // ip -> { count, firstAt }
function rateLimited(ip) {
  const now = Date.now();
  const rec = failures.get(ip);
  if (!rec) return false;
  if (now - rec.firstAt > RATE_WINDOW_MS) { failures.delete(ip); return false; }
  return rec.count >= RATE_MAX_FAILS;
}
function recordFailure(ip) {
  const now = Date.now();
  const rec = failures.get(ip);
  if (!rec || now - rec.firstAt > RATE_WINDOW_MS) failures.set(ip, { count: 1, firstAt: now });
  else rec.count += 1;
}
function recordSuccess(ip) { failures.delete(ip); }

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.statusCode = 405;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ok: false, error: 'method' }));
    return;
  }
  const ip = clientIp(req);
  if (rateLimited(ip)) {
    res.statusCode = 429;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Retry-After', String(Math.ceil(RATE_WINDOW_MS / 1000)));
    res.end(JSON.stringify({ ok: false, error: 'too-many-attempts' }));
    return;
  }
  const email = process.env.ADMIN_EMAIL || '';
  const hash = (process.env.ADMIN_PASSWORD_HASH || '').toLowerCase();
  if (!email || !hash) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ok: false, error: 'no-auth-configured' }));
    return;
  }
  let body = {};
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
  } catch (e) {
    res.statusCode = 400;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ok: false, error: 'bad-json' }));
    return;
  }
  const okEmail = safeEqual((body.email || '').trim().toLowerCase(), email.trim().toLowerCase());
  const okPass = safeEqual(sha256Hex(body.password || ''), hash);
  if (okEmail && okPass) {
    recordSuccess(ip);
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ok: true, token: issuePublishToken(email.trim().toLowerCase(), hash) }));
    return;
  }
  recordFailure(ip);
  res.statusCode = 401;
  res.setHeader('Content-Type', 'application/json');
  // Deliberately the same generic message for a wrong email and a wrong
  // password, so the endpoint does not reveal which one failed (no
  // email enumeration).
  res.end(JSON.stringify({ ok: false, error: 'invalid' }));
};
