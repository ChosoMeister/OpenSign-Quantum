// Drives the backend SAML flow against the SimpleSAMLphp test IdP without a browser.
// Usage: node docs/sso-test-env/saml-e2e.mjs [user1|user2]   (server started with saml.env)
const SERVER = 'http://localhost:8080';
const user = process.argv[2] || 'user1';
const jar = new Map();

async function go(url, init = {}) {
  const cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  const res = await fetch(url, { redirect: 'manual', ...init, headers: { ...(init.headers || {}), cookie } });
  for (const c of res.headers.getSetCookie?.() || []) {
    const [kv] = c.split(';');
    const i = kv.indexOf('=');
    jar.set(kv.slice(0, i), kv.slice(i + 1));
  }
  return res;
}
const follow = async (url, init) => {
  let res = await go(url, init);
  while ([301, 302, 303].includes(res.status)) {
    url = new URL(res.headers.get('location'), url).href;
    if (url.startsWith('http://localhost:3000')) return { final: url };
    res = await go(url);
  }
  return { res, url };
};
const field = (html, name) =>
  new RegExp(`name="${name}"\\s+value="([^"]*)"`).exec(html)?.[1]?.replace(/&quot;/g, '"').replace(/&amp;/g, '&');

async function ssoLogin() {
  jar.clear();
  let { res, url } = await follow(`${SERVER}/auth/sso/login`);
  let html = await res.text();
  const authState = field(html, 'AuthState');
  ({ res, url } = await follow(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: user, password: "password", AuthState: authState }),
  }));
  html = await res.text();
  const samlResponse = field(html, 'SAMLResponse');
  if (process.env.DEBUG) {
    const xml = Buffer.from(samlResponse || '', 'base64').toString();
    console.log([...xml.matchAll(/Attribute Name="([^"]+)"/g)].map(m => m[1]), /NameID[^>]*>/.exec(xml)?.[0]);
  }
  const { final } = await follow(`${SERVER}/auth/saml/callback`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ SAMLResponse: samlResponse }),
  });
  const back = new URL(final);
  return { back, samlResponse };
}

const parse = (path, token) =>
  fetch(`${SERVER}/app/${path}`, {
    method: path.startsWith('functions') ? 'POST' : 'GET',
    headers: { 'X-Parse-Application-Id': 'opensign', 'X-Parse-Session-Token': token, 'content-type': 'application/json' },
    body: path.startsWith('functions') ? '{}' : undefined,
  }).then(r => r.json());

const { back, samlResponse } = await ssoLogin();
if (back.searchParams.get('sso_error')) throw new Error(`login failed: ${back.searchParams.get('sso_error')}`);
const ex = await fetch(`${SERVER}/auth/sso/exchange`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ code: back.searchParams.get('sso_code') }),
}).then(r => r.json());
const me = await parse('users/me', ex.sessionToken);
const ext = await parse('functions/getUserDetails', ex.sessionToken);
console.log('user', me.objectId, me.username, 'role', ext.result?.UserRole);

// Replay the exact same SAMLResponse.
const replay = await fetch(`${SERVER}/auth/saml/callback`, {
  method: 'POST',
  redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ SAMLResponse: samlResponse }),
});
console.log('replay ->', replay.headers.get('location'));

const again = await ssoLogin();
const ex2 = await fetch(`${SERVER}/auth/sso/exchange`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ code: again.back.searchParams.get('sso_code') }),
}).then(r => r.json());
console.log('same account on return?', (await parse('users/me', ex2.sessionToken)).objectId === me.objectId);
