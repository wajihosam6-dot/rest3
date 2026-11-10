// REST admin login — verifies the admin email + password server-side.
// POST { email, password } -> { ok: true } | { ok: false, error }
// Env vars (set once in the Vercel dashboard, rest3 project):
//   ADMIN_EMAIL          e.g. admin@rest.local
//   ADMIN_PASSWORD_HASH  SHA-256 hex of the admin password (lowercase)
// No dependencies; CommonJS (Vercel Node runtime). The password itself is
// never stored here or in the browser — only its hash lives in Vercel.
const crypto = require('crypto');

function sha256Hex(s) {
  return crypto.createHash('sha256').update(String(s || ''), 'utf8').digest('hex');
}
function safeEqual(a, b) {
  const ba = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  if (ba.length !== bb.length) return false;
  try { return crypto.timingSafeEqual(ba, bb); } catch (e) { return false; }
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.statusCode = 405;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ok: false, error: 'method' }));
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
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ok: true }));
    return;
  }
  res.statusCode = 401;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ ok: false, error: 'invalid' }));
};
