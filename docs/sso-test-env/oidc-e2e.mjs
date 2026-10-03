// Drives the backend OIDC flow against the mock IdP without a browser:
// login -> IdP login form -> callback -> code exchange -> Parse session -> user checks.
// Usage: node docs/sso-test-env/oidc-e2e.mjs [login]   (server started with oidc.env)
const SERVER = 'http://localhost:8080';
const APP_ID = 'opensign';
const login = process.argv[2] || 'alice';

async function ssoLogin(username) {
  let res = await fetch(`${SERVER}/auth/sso/login`, { redirect: 'manual' });
  res = await fetch(new URL(res.headers.get('location'), `${SERVER}/auth/sso/login`), { redirect: 'manual' });
  const cookie = res.headers.get('set-cookie').split(';')[0];
  const authorizeUrl = res.headers.get('location');
  // mock-oauth2-server interactive login: POST the form back to the authorize URL.
  res = await fetch(authorizeUrl, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      username,
      claims: JSON.stringify({ email: `${username}@example.com`, email_verified: true, name: `Test ${username}` }),
    }),
  });
  const callback = res.headers.get('location');
  res = await fetch(callback, { headers: { cookie }, redirect: 'manual' });
  const back = new URL(res.headers.get('location'));
  if (back.searchParams.get('sso_error')) return { error: back.searchParams.get('sso_error') };
  res = await fetch(`${SERVER}/auth/sso/exchange`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ code: back.searchParams.get('sso_code') }),
  });
  return res.json();
}

const parse = (path, sessionToken, init = {}) =>
  fetch(`${SERVER}/app/${path}`, {
    ...init,
    headers: {
      'X-Parse-Application-Id': APP_ID,
      'content-type': 'application/json',
      ...(sessionToken ? { 'X-Parse-Session-Token': sessionToken } : {}),
      ...init.headers,
    },
  }).then(r => r.json());

const first = await ssoLogin(login);
if (first.error) throw new Error(`login failed: ${first.error}`);
const me = await parse('users/me', first.sessionToken);
const ext = await parse('functions/getUserDetails', first.sessionToken, { method: 'POST', body: '{}' });
console.log('user', me.objectId, me.username, 'role', ext.result?.UserRole, 'tenant', ext.result?.TenantId?.objectId);
console.log('client sees ssoSubject?', 'ssoSubject' in me);

const tamper = await parse(`users/${me.objectId}`, first.sessionToken, {
  method: 'PUT',
  body: JSON.stringify({ ssoSubject: 'someone-else' }),
});
console.log('client may change ssoSubject?', !tamper.error, tamper.error || '');

const pwd = await parse('login', null, { method: 'POST', body: JSON.stringify({ username: me.username, password: 'x' }) });
console.log('local password login ->', pwd.error);

await fetch(`${SERVER}/auth/sso/logout`, { method: 'POST', headers: { 'X-Parse-Session-Token': first.sessionToken } });
const afterLogout = await parse('users/me', first.sessionToken);
console.log('session after logout ->', afterLogout.error);

const second = await ssoLogin(login);
const me2 = await parse('users/me', second.sessionToken);
console.log('same account on return?', me2.objectId === me.objectId);
