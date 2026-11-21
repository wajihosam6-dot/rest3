// api/publish.js — Server-side auto-publish for the REST admin panel.
// The admin panel POSTs {overrides, waNumber, updatedAt} here with an
// `Authorization: Bearer <token>` header. The token is issued by
// /api/admin-auth on a successful admin login (24h HMAC token, keyed by
// ADMIN_PASSWORD_HASH). This endpoint is AUTHENTICATED — without a valid
// token it returns 401 and publishes nothing. It used to be public, which
// let anyone who found the URL deface the site for all visitors.
// There is NO GitHub token in the browser: this function commits the payload
// to public/overrides.json in the rest3 repo using a GitHub token stored as
// the Vercel env var GITHUB_TOKEN (a classic PAT with `repo` scope and no
// expiration — set once in the Vercel dashboard, never in the browser).
// Vercel auto-deploys on push, so the new overrides go live for all
// visitors within ~a minute.
//
// Payload validation (fail closed): `overrides` must be an object with at
// most 500 entries; each key must look like a stable admin id (t12 / i3 /
// v1) and each value must be {type: text|img|video, value: string,
// original: string}. Text values are capped at 100KB, media URLs at 2KB.
// `waNumber`, when present, must be 9–15 digits. Anything else -> 400.
const crypto = require('crypto');

function safeEqual(a, b) {
  const ba = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  if (ba.length !== bb.length) return false;
  try { return crypto.timingSafeEqual(ba, bb); } catch (e) { return false; }
}
function hmacHex(key, msg) {
  return crypto.createHmac('sha256', String(key || '')).update(String(msg || ''), 'utf8').digest('hex');
}
// Verify the Bearer token issued by /api/admin-auth:
// `<expiry>.<hmac>` where hmac = HMAC-SHA256(key=ADMIN_PASSWORD_HASH,
// message=`rest-admin:<email>:<expiry>`).
function verifyPublishToken(req) {
  const hash = (process.env.ADMIN_PASSWORD_HASH || '').toLowerCase();
  const email = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  if (!hash || !email) return false;
  const auth = (req.headers && (req.headers.authorization || req.headers.Authorization)) || '';
  const m = /^Bearer\s+(\S+)$/.exec(String(auth));
  if (!m) return false;
  const parts = m[1].split('.');
  if (parts.length !== 2) return false;
  const expiry = parseInt(parts[0], 10);
  if (!expiry || expiry * 1000 <= Date.now()) return false; // expired / malformed
  const expected = hmacHex(hash, 'rest-admin:' + email + ':' + expiry);
  return safeEqual(parts[1].toLowerCase(), expected);
}
function validOverrides(overrides) {
  if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) return false;
  const keys = Object.keys(overrides);
  if (keys.length > 500) return false;
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i];
    if (!/^[a-z]\d+$/.test(k)) return false;
    const v = overrides[k];
    if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
    if (v.type !== 'text' && v.type !== 'img' && v.type !== 'video') return false;
    if (typeof v.value !== 'string') return false;
    if (typeof v.original !== 'string') return false;
    const cap = v.type === 'text' ? 100 * 1024 : 2 * 1024;
    if (v.value.length > cap || v.original.length > cap) return false;
    if (v.poster != null && typeof v.poster !== 'string') return false;
    if (v.poster && v.poster.length > 2 * 1024) return false;
  }
  return true;
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ ok: false, error: 'method' });
    return;
  }
  // Authenticate first — before touching the token or the payload.
  if (!verifyPublishToken(req)) {
    res.status(401).json({ ok: false, error: 'unauthorized' });
    return;
  }
  var token = process.env.GITHUB_TOKEN;
  if (!token) {
    res.status(500).json({ ok: false, error: 'no-token-configured' });
    return;
  }
  var payload = req.body;
  if (typeof payload === 'string') {
    try { payload = JSON.parse(payload); } catch (e) { res.status(400).json({ ok: false, error: 'bad-json' }); return; }
  }
  if (!payload || typeof payload !== 'object' || !validOverrides(payload.overrides)) {
    res.status(400).json({ ok: false, error: 'bad-payload' });
    return;
  }
  if (payload.waNumber != null) {
    if (typeof payload.waNumber !== 'string' || !/^\d{9,15}$/.test(payload.waNumber)) {
      res.status(400).json({ ok: false, error: 'bad-payload' });
      return;
    }
  }
  payload.v = 1;
  payload.updatedAt = Date.now();
  var body = JSON.stringify(payload, null, 2);
  if (body.length > 20 * 1024 * 1024) {
    res.status(413).json({ ok: false, error: 'too-large' });
    return;
  }
  var apiUrl = 'https://api.github.com/repos/wajihosam6-dot/rest3/contents/public/overrides.json';
  var headers = {
    'Accept': 'application/vnd.github+json',
    'Authorization': 'Bearer ' + token,
    'X-GitHub-Api-Version': '2022-11-28',
    'Content-Type': 'application/json'
  };
  try {
    var getRes = await fetch(apiUrl, { headers: headers });
    var sha = null;
    if (getRes.status === 404) { sha = null; }
    else if (getRes.status === 401) { res.status(502).json({ ok: false, error: 'token-invalid' }); return; }
    else if (getRes.status === 403) { res.status(502).json({ ok: false, error: 'token-no-write' }); return; }
    else if (!getRes.ok) { res.status(502).json({ ok: false, error: 'read-' + getRes.status }); return; }
    else {
      var cur = await getRes.json();
      sha = cur && cur.sha ? cur.sha : null;
    }
    var putBody = { message: 'chore(admin): auto-publish overrides', content: Buffer.from(body, 'utf-8').toString('base64') };
    if (sha) putBody.sha = sha;
    var putRes = await fetch(apiUrl, { method: 'PUT', headers: headers, body: JSON.stringify(putBody) });
    if (putRes.status === 401) { res.status(502).json({ ok: false, error: 'token-invalid' }); return; }
    if (putRes.status === 403) { res.status(502).json({ ok: false, error: 'token-no-write' }); return; }
    if (!putRes.ok) { res.status(502).json({ ok: false, error: 'write-' + putRes.status }); return; }
    res.status(200).json({ ok: true });
  } catch (e) {
    res.status(502).json({ ok: false, error: 'network' });
  }
};
