/* Voxelify: sign-in with Discord and Yandex. A small Cloudflare Worker (free plan is enough).
   Secrets live only in the Worker settings, never in the repository:
     SITE            https://wisper-2010.github.io/Voxelify/
     FB_EMAIL        client_email from the Firebase service account file
     FB_KEY          private_key from the same file
     DISCORD_ID, DISCORD_SECRET
     YANDEX_ID, YANDEX_SECRET
   Redirect address to enter in Discord and in Yandex:  https://<worker address>/back */
const P = {
  discord: { auth: 'https://discord.com/oauth2/authorize', token: 'https://discord.com/api/oauth2/token', scope: 'identify', me: 'https://discord.com/api/users/@me', scheme: 'Bearer',
    user: u => ({ id: u.id, name: u.global_name || u.username, pic: u.avatar ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png?size=160` : '' }) },
  yandex: { auth: 'https://oauth.yandex.ru/authorize', token: 'https://oauth.yandex.ru/token', scope: 'login:info login:avatar', me: 'https://login.yandex.ru/info?format=json', scheme: 'OAuth',
    user: u => ({ id: u.id, name: u.display_name || u.login, pic: u.is_avatar_empty ? '' : `https://avatars.yandex.net/get-yapic/${u.default_avatar_id}/islands-200` }) }
};
const b64 = b => btoa(typeof b === 'string' ? unescape(encodeURIComponent(b)) : String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
async function customToken(env, uid, claims) {
  const pem = env.FB_KEY.replace(/\\n/g, '\n').replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const key = await crypto.subtle.importKey('pkcs8', Uint8Array.from(atob(pem), c => c.charCodeAt(0)), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const now = Math.floor(Date.now() / 1000);
  const body = b64(JSON.stringify({ alg: 'RS256', typ: 'JWT' })) + '.' + b64(JSON.stringify({
    iss: env.FB_EMAIL, sub: env.FB_EMAIL, aud: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit', iat: now, exp: now + 600, uid, claims }));
  return body + '.' + b64(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(body)));
}
const go = (url, cookie) => new Response(null, { status: 302, headers: { location: url, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', ...(cookie ? { 'set-cookie': cookie } : {}) } });
export default {
  async fetch(req, env) {
    const url = new URL(req.url), back = url.origin + '/back', fail = () => go(env.SITE + '#vxe=1', 'vxs=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax');
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
    return new Response('Voxelify sign-in', { status: 404 });
  }
};
