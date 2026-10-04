// Scripted Keycloak login through OpenSign (OIDC or SAML), as a browser would do it.
// Usage: node docs/sso-test-env/keycloak-e2e.mjs <keycloak-user> [password]
// Prints the OpenSign session token's user, role and organization.
const SERVER = 'http://localhost:8080';
const [user = 'kc-user', password = 'Passw0rd!kc'] = process.argv.slice(2);
const jar = new Map();

async function go(url, init = {}) {
  const host = new URL(url).host;
  const cookie = [...jar].filter(([k]) => k.startsWith(host + '|')).map(([k, v]) => `${k.split('|')[1]}=${v}`).join('; ');
  const res = await fetch(url, { redirect: 'manual', ...init, headers: { ...(init.headers || {}), cookie } });
  for (const c of res.headers.getSetCookie()) {
    const kv = c.split(';')[0];
    const i = kv.indexOf('=');
    jar.set(`${host}|${kv.slice(0, i)}`, kv.slice(i + 1));
  }
  return res;
}
async function follow(url, init) {
  let res = await go(url, init);
  while ([301, 302, 303].includes(res.status)) {
    url = new URL(res.headers.get('location'), url).href;
    if (url.startsWith('http://localhost:3000')) return { final: url };
    res = await go(url);
  }
  return { res, url };
}
const unescape = s => s.replace(/&amp;/g, '&').replace(/&quot;/g, '"');

export async function keycloakLogin(username, pass) {
  jar.clear(); // fresh browser: no Keycloak SSO session from a previous user
  let { res, url, final } = await follow(`${SERVER}/auth/sso/login`);
  if (!final) {
    // Keycloak login form
    const html = await res.text();
    const action = unescape(/<form[^>]*action="([^"]+)"/.exec(html)[1]);
    ({ res, url, final } = await follow(action, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username, password: pass }),
    }));
  }
  if (!final) {
    // SAML: auto-submitting POST form back to the ACS
    const html = await res.text();
    const saml = /name="SAMLResponse" value="([^"]+)"/.exec(html);
    if (!saml) throw new Error('unexpected Keycloak page: ' + html.slice(0, 200));
    ({ final } = await follow(`${SERVER}/auth/saml/callback`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ SAMLResponse: unescape(saml[1]) }),
    }));
  }
  const back = new URL(final);
  if (back.searchParams.get('sso_error')) return { error: back.searchParams.get('sso_error') };
  const ex = await fetch(`${SERVER}/auth/sso/exchange`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ code: back.searchParams.get('sso_code') }),
  });
  return ex.json();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await keycloakLogin(user, password);
  if (r.error) {
    console.log(`${user}: login refused (${r.error})`);
  } else {
    const me = await (await fetch(`${SERVER}/app/functions/getUserDetails`, {
      method: 'POST',
      headers: { 'X-Parse-Application-Id': 'opensign', 'X-Parse-Session-Token': r.sessionToken, 'content-type': 'application/json' },
      body: '{}',
    })).json();
    console.log(`${user}: role=${me.result?.UserRole} org=${me.result?.OrganizationId?.objectId} tenant=${me.result?.TenantId?.objectId}`);
  }
}
