// api/publish.js — Server-side auto-publish for the REST admin panel.
// The admin panel POSTs {overrides, waNumber, updatedAt} here. There is NO
// token in the browser anymore: this function commits the payload to
// public/overrides.json in the rest3 repo using a GitHub token stored as the
// Vercel env var GITHUB_TOKEN (a classic PAT with `repo` scope and no
// expiration — set once in the Vercel dashboard, never in the browser).
// Vercel auto-deploys on push, so the new overrides go live for all
// visitors within ~a minute. The endpoint is public but unlinked; a size
// limit guards against abuse. A login/secret can be added later if wanted.
module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ ok: false, error: 'method' });
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
  if (!payload || typeof payload !== 'object' || typeof payload.overrides !== 'object') {
    res.status(400).json({ ok: false, error: 'bad-payload' });
    return;
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
