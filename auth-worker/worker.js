/* Voxelify worker (Cloudflare Workers, the free plan is enough): sign-in with Discord and Yandex, relay for calls, notifications.
   Secrets live only in the Worker settings, never in the repository. Every part works on its own: leave out what you do not need.
     SITE            https://wisper-2010.github.io/Voxelify/
     FB_PROJECT      v0xelify
     FB_EMAIL, FB_KEY              client_email and private_key of the Firebase service account (sign-in, notifications)
     DISCORD_ID, DISCORD_SECRET, YANDEX_ID, YANDEX_SECRET
     TURN_ID, TURN_TOKEN           Cloudflare Realtime TURN key (relay for calls)
     VAPID_PUBLIC, VAPID_PRIVATE   made by tools/vapid.js (notifications)
   Redirect address to enter in Discord and in Yandex:  https://<worker address>/back */
const P = {
  discord: { auth: 'https://discord.com/oauth2/authorize', token: 'https://discord.com/api/oauth2/token', scope: 'identify', me: 'https://discord.com/api/users/@me', scheme: 'Bearer',
    user: u => ({ id: u.id, name: u.global_name || u.username, pic: u.avatar ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png?size=160` : '' }) },
  yandex: { auth: 'https://oauth.yandex.ru/authorize', token: 'https://oauth.yandex.ru/token', scope: 'login:info login:avatar', me: 'https://login.yandex.ru/info?format=json', scheme: 'OAuth',
    user: u => ({ id: u.id, name: u.display_name || u.login, pic: u.is_avatar_empty ? '' : `https://avatars.yandex.net/get-yapic/${u.default_avatar_id}/islands-200` }) }
};
const b64 = b => btoa(typeof b === 'string' ? unescape(encodeURIComponent(b)) : String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const un64 = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const now = () => Math.floor(Date.now() / 1000), enc = s => new TextEncoder().encode(s);
async function rs256(env, payload) {
  const pem = env.FB_KEY.replace(/\\n/g, '\n').replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const key = await crypto.subtle.importKey('pkcs8', Uint8Array.from(atob(pem), c => c.charCodeAt(0)), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const body = b64(JSON.stringify({ alg: 'RS256', typ: 'JWT' })) + '.' + b64(JSON.stringify(payload));
  return body + '.' + b64(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc(body)));
}
const customToken = (env, uid, claims) => rs256(env, { iss: env.FB_EMAIL, sub: env.FB_EMAIL, aud: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit', iat: now(), exp: now() + 600, uid, claims });
/* who is asking: the Firebase ID token is checked against Google's public keys */
let JWK = null, JWKT = 0;
async function who(req, env) {
  const t = (req.headers.get('authorization') || '').replace(/^Bearer /, ''), p = t.split('.');
  if (p.length !== 3) return '';
  try {
    const h = JSON.parse(new TextDecoder().decode(un64(p[0]))), c = JSON.parse(new TextDecoder().decode(un64(p[1])));
    if (h.alg !== 'RS256' || c.aud !== env.FB_PROJECT || c.iss !== 'https://securetoken.google.com/' + env.FB_PROJECT || c.exp < now() || c.iat > now() + 60 || !c.sub) return '';
    if (!JWK || Date.now() - JWKT > 3600000) { JWK = (await (await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com')).json()).keys; JWKT = Date.now(); }
    const k = JWK.find(x => x.kid === h.kid);
    if (!k) return '';
    const key = await crypto.subtle.importKey('jwk', k, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, un64(p[2]), enc(p[0] + '.' + p[1]));
    const pr = c.firebase && c.firebase.sign_in_provider;
    return ok && (c.email_verified || pr === 'github.com' || pr === 'custom') ? c.sub : '';
  } catch (e) { return ''; }
}
/* reading the database with the service account */
let AT = '', ATT = 0;
async function access(env) {
  if (AT && Date.now() < ATT) return AT;
  const a = await rs256(env, { iss: env.FB_EMAIL, scope: 'https://www.googleapis.com/auth/datastore', aud: 'https://oauth2.googleapis.com/token', iat: now(), exp: now() + 3600 });
  const j = await (await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: a }) })).json();
  AT = j.access_token || ''; ATT = Date.now() + 3000000; return AT;
}
async function doc(env, path) {
  const r = await fetch(`https://firestore.googleapis.com/v1/projects/${env.FB_PROJECT}/databases/(default)/documents/${path}`, { headers: { authorization: 'Bearer ' + await access(env) } });
  return r.ok ? (await r.json()).fields || {} : null;
}
const PUSH = /^https:\/\/(fcm\.googleapis\.com|updates\.push\.services\.mozilla\.com|([a-z0-9-]+\.)*push\.apple\.com|([a-z0-9-]+\.)*notify\.windows\.com)\//;
async function vapid(env, endpoint) {
  const pub = un64(env.VAPID_PUBLIC), key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: b64(pub.slice(1, 33)), y: b64(pub.slice(33, 65)), d: env.VAPID_PRIVATE, ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const body = b64(JSON.stringify({ typ: 'JWT', alg: 'ES256' })) + '.' + b64(JSON.stringify({ aud: new URL(endpoint).origin, exp: now() + 36000, sub: env.SITE }));
  return `vapid t=${body}.${b64(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc(body)))}, k=${env.VAPID_PUBLIC}`;
}
const go = (url, cookie) => new Response(null, { status: 302, headers: { location: url, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', ...(cookie ? { 'set-cookie': cookie } : {}) } });
const last = new Map();
const often = (k, ms, n) => { if (last.size > 5000) last.clear(); const a = (last.get(k) || []).filter(t => Date.now() - t < ms); if (a.length >= n) return true; a.push(Date.now()); last.set(k, a); return false; };
const ID = /^[A-Za-z0-9-]{1,64}$/;
export default {
  async fetch(req, env) {
    const url = new URL(req.url), origin = new URL(env.SITE).origin, cors = { 'access-control-allow-origin': origin, 'access-control-allow-headers': 'authorization,content-type', 'access-control-allow-methods': 'GET, POST', vary: 'origin' };
    const json = (o, s) => new Response(JSON.stringify(o), { status: s || 200, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...cors } });
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (url.pathname === '/cfg') return json({ discord: !!(env.DISCORD_ID && env.DISCORD_SECRET && env.FB_KEY), yandex: !!(env.YANDEX_ID && env.YANDEX_SECRET && env.FB_KEY), turn: !!(env.TURN_ID && env.TURN_TOKEN), vapid: env.VAPID_PUBLIC && env.VAPID_PRIVATE && env.FB_KEY ? env.VAPID_PUBLIC : '' });
    if (url.pathname === '/turn' && req.method === 'POST') {
      if (!env.TURN_ID) return json({ e: 'off' }, 404);
      const u = await who(req, env); if (!u) return json({ e: 'auth' }, 401);
      if (often('t' + u, 3600000, 12)) return json({ e: 'often' }, 429);
      const r = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_ID}/credentials/generate-ice-servers`, { method: 'POST', headers: { authorization: 'Bearer ' + env.TURN_TOKEN, 'content-type': 'application/json' }, body: JSON.stringify({ ttl: 28800 }) });
      if (!r.ok) return json({ e: 'turn' }, 502);
      const j = await r.json();
      return json({ iceServers: [].concat(j.iceServers || []).map(s => ({ ...s, urls: [].concat(s.urls).filter(x => !/:53(\?|$)/.test(x)) })) });
    }
    if (url.pathname === '/push' && req.method === 'POST') {
      if (!env.VAPID_PUBLIC) return json({ e: 'off' }, 404);
      const u = await who(req, env); if (!u) return json({ e: 'auth' }, 401);
      let b; try { b = await req.json(); } catch (e) { return json({ e: 'bad' }, 400); }
      const to = String(b.to || ''), sid = String(b.sid || '');
      if (!ID.test(to) || (sid && !ID.test(sid)) || to === u) return json({ e: 'bad' }, 400);
      if (often('p' + u, 60000, 12) || often('p' + u + to, 10000, 1)) return json({ e: 'often' }, 429);
      try {
        let ok = false;
        if (sid) { const [x, y] = await Promise.all([doc(env, `sv/${sid}/mem/${u}`), doc(env, `sv/${sid}/mem/${to}`)]); ok = !!(x && y); }
        else { const f = await doc(env, 'fr/' + (u < to ? u + '_' + to : to + '_' + u)); ok = !!(f && f.st && f.st.stringValue === 'ok'); }
        if (!ok) return json({ e: 'no' }, 403);
        const m = await doc(env, 'mod/' + u); if (m && m.ban && m.ban.booleanValue) return json({ e: 'no' }, 403);
        const d = await doc(env, 'push/' + to), l = ((d && d.subs && d.subs.arrayValue && d.subs.arrayValue.values) || []).map(v => (((v.mapValue || {}).fields || {}).endpoint || {}).stringValue).filter(x => x && PUSH.test(x)).slice(0, 8);
        await Promise.all(l.map(async e => fetch(e, { method: 'POST', headers: { authorization: await vapid(env, e), ttl: '3600', urgency: 'high', 'content-length': '0' } }).catch(() => {})));
        return json({ n: l.length });
      } catch (e) { return json({ e: 'err' }, 500); }
    }
    const back = url.origin + '/back', fail = () => go(env.SITE + '#vxe=1', 'vxs=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax');
    const idOf = p => [env[p.toUpperCase() + '_ID'], env[p.toUpperCase() + '_SECRET']];
    if (url.pathname === '/login') {
      const p = url.searchParams.get('p'), n = url.searchParams.get('n') || '';
      if (!Object.hasOwn(P, p) || !/^[0-9a-f]{32}$/.test(n) || !idOf(p)[0]) return fail();
      const st = p + '.' + n + '.' + crypto.randomUUID().replace(/-/g, '');
      return go(P[p].auth + '?' + new URLSearchParams({ client_id: idOf(p)[0], redirect_uri: back, response_type: 'code', scope: P[p].scope, state: st }), `vxs=${st}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax`);
    }
    if (url.pathname === '/back') {
      const st = url.searchParams.get('state') || '', code = url.searchParams.get('code'), ck = (req.headers.get('cookie') || '').match(/(?:^|;\s*)vxs=([^;]+)/);
      if (!code || !ck || ck[1] !== st) return fail();
      const [p, n] = st.split('.');
      if (!Object.hasOwn(P, p)) return fail();
      try {
        const [id, secret] = idOf(p);
        const t = await (await fetch(P[p].token, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: id, client_secret: secret, grant_type: 'authorization_code', code, redirect_uri: back }) })).json();
        if (!t.access_token) return fail();
        const r = await fetch(P[p].me, { headers: { authorization: P[p].scheme + ' ' + t.access_token } });
        if (!r.ok) return fail();
        const u = P[p].user(await r.json());
        if (!/^\d+$/.test(String(u.id))) return fail();
        const tok = await customToken(env, p + '-' + u.id, { vxp: p });
        return go(env.SITE + '#' + new URLSearchParams({ vxt: tok, vxn: n, nm: String(u.name || '').slice(0, 40), ph: u.pic }), 'vxs=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax');
      } catch (e) { return fail(); }
    }
    return new Response('Voxelify', { status: 404 });
  }
};
