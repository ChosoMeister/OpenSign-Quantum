import http from 'node:http';
import express from 'express';
import { createOidcProvider } from '../../auth/sso/oidc/provider.js';
import { createSsoRouter } from '../../auth/sso/routes.js';
import { startOidcStub } from './support/oidcStub.js';
import { createMemoryStore } from './support/memoryStore.js';

const REDIRECT = 'https://sign.example.com/api/auth/oidc/callback';

describe('OIDC', () => {
  let idp;
  let oidcConfig;

  beforeAll(async () => {
    idp = await startOidcStub();
    oidcConfig = {
      issuer: idp.state.issuer,
      clientId: 'opensign',
      clientSecret: 'secret',
      scopes: 'openid profile email',
      redirectUri: REDIRECT,
      allowInsecureHttp: true,
    };
  });
  afterAll(() => idp.close());
  beforeEach(() => idp.reset());

  // Runs a login: build request, "authenticate", return to callback.
  async function login({
    provider = createOidcProvider(oidcConfig),
    mutateUrl,
    mutateFlow,
    requireVerifiedEmail = true,
    groupsClaim,
  } = {}) {
    const { url, flow } = await provider.buildLoginRequest();
    const authz = new URL(url);
    idp.state.lastNonce = authz.searchParams.get('nonce');
    let cb = `${REDIRECT}?code=good-code&state=${encodeURIComponent(authz.searchParams.get('state'))}`;
    if (mutateUrl) cb = mutateUrl(cb);
    return provider.handleCallback(cb, mutateFlow ? mutateFlow(flow) : flow, {
      requireVerifiedEmail,
      groupsClaim,
    });
  }

  async function expectCode(promise, code) {
    try {
      await promise;
      fail('expected rejection');
    } catch (e) {
      expect(e.code).toBe(code);
    }
  }

  it('discovers endpoints and builds a PKCE authorization request', async () => {
    const { url } = await createOidcProvider(oidcConfig).buildLoginRequest();
    const u = new URL(url);
    expect(u.origin + u.pathname).toBe(`${idp.state.issuer}/authorize`);
    expect(u.searchParams.get('code_challenge_method')).toBe('S256');
    expect(u.searchParams.get('state')).toBeTruthy();
    expect(u.searchParams.get('nonce')).toBeTruthy();
    expect(u.searchParams.get('redirect_uri')).toBe(REDIRECT);
    expect(url).not.toContain('secret');
  });

  it('reports discovery failure as provider unavailable', async () => {
    const p = createOidcProvider({ ...oidcConfig, issuer: 'http://127.0.0.1:1' });
    await expectCode(p.buildLoginRequest(), 'PROVIDER_UNAVAILABLE');
  });

  it('accepts a valid authorization code', async () => {
    const id = await login();
    expect(id).toEqual(
      jasmine.objectContaining({
        provider: 'oidc',
        issuer: idp.state.issuer,
        subject: 'user-sub-1',
        email: 'jane@example.com',
        name: 'Jane Doe',
      })
    );
  });

  it('rejects an invalid state', async () => {
    await expectCode(
      login({ mutateUrl: u => u.replace(/state=[^&]+/, 'state=forged') }),
      'INVALID_STATE'
    );
  });

  it('rejects a callback without flow state (login CSRF)', async () => {
    await expectCode(login({ mutateFlow: () => null }), 'INVALID_STATE');
  });

  it('rejects an invalid nonce', async () => {
    idp.state.claims = { nonce: 'wrong' };
    await expectCode(login(), 'VALIDATION_FAILED');
  });

  it('rejects an expired token', async () => {
    const past = Math.floor(Date.now() / 1000) - 3600;
    idp.state.claims = { iat: past - 300, exp: past };
    await expectCode(login(), 'VALIDATION_FAILED');
  });

  it('rejects an invalid signature', async () => {
    idp.state.signWithWrongKey = true;
    await expectCode(login(), 'VALIDATION_FAILED');
  });

  it('rejects the wrong issuer', async () => {
    idp.state.claims = { iss: 'https://evil.example.com' };
    await expectCode(login(), 'VALIDATION_FAILED');
  });

  it('rejects the wrong audience', async () => {
    idp.state.claims = { aud: 'someone-else' };
    await expectCode(login(), 'VALIDATION_FAILED');
  });

  it('rejects a missing email', async () => {
    idp.state.claims = { email: undefined, email_verified: undefined };
    await expectCode(login(), 'MISSING_EMAIL');
  });

  it('falls back to userinfo for email when the ID token has none', async () => {
    idp.state.claims = { email: undefined, email_verified: undefined };
    idp.state.userinfo = { sub: 'user-sub-1', email: 'jane@example.com', email_verified: true };
    expect((await login()).email).toBe('jane@example.com');
  });

  it('rejects userinfo belonging to another subject', async () => {
    idp.state.claims = { email: undefined, email_verified: undefined };
    idp.state.userinfo = { sub: 'someone-else', email: 'x@example.com', email_verified: true };
    await expectCode(login(), 'VALIDATION_FAILED');
  });

  it('reads IdP groups from the ID token when a role mapping is configured', async () => {
    idp.state.claims = { groups: ['/opensign-admins', 'sales'] };
    expect((await login({ groupsClaim: 'groups' })).groups).toEqual(['/opensign-admins', 'sales']);
    // Without a mapping the claim is not read at all.
    expect((await login()).groups).toEqual([]);
  });

  it('falls back to userinfo for groups (same subject only)', async () => {
    idp.state.userinfo = { sub: 'user-sub-1', groups: ['opensign-editors'] };
    expect((await login({ groupsClaim: 'groups' })).groups).toEqual(['opensign-editors']);
  });

  it('rejects an unverified email when verification is required', async () => {
    idp.state.claims = { email_verified: false };
    await expectCode(login(), 'UNVERIFIED_EMAIL');
    expect((await login({ requireVerifiedEmail: false })).email).toBe('jane@example.com');
  });

  describe('HTTP routes', () => {
    let server;
    let base;
    let store;
    beforeAll(async () => {
      process.env.SSO_INSECURE_COOKIES = 'true';
      store = createMemoryStore();
      const config = {
        enabled: true,
        protocol: 'oidc',
        displayName: 'Company SSO',
        autoProvision: true,
        requireVerifiedEmail: true,
        companyName: 'Acme',
        frontendUrl: 'https://sign.example.com',
        cookieSecret: 'cookie-secret',
        oidc: oidcConfig,
      };
      const app = express();
      app.use(express.json());
      app.use('/auth', createSsoRouter({ config, store }));
      server = http.createServer(app);
      await new Promise(r => server.listen(0, '127.0.0.1', r));
      base = `http://127.0.0.1:${server.address().port}`;
    });
    afterAll(() => {
      delete process.env.SSO_INSECURE_COOKIES;
      return new Promise(r => server.close(r));
    });

    it('runs the full flow: login -> callback -> exchange -> same account on return', async () => {
      const once = async () => {
        const start = await fetch(`${base}/auth/sso/login`, { redirect: 'manual' });
        expect(start.status).toBe(302);
        const login = await fetch(
          new URL(start.headers.get('location'), `${base}/auth/sso/login`),
          {
            redirect: 'manual',
          }
        );
        const cookie = login.headers.get('set-cookie').split(';')[0];
        expect(login.headers.get('set-cookie')).toMatch(/HttpOnly/i);
        const authz = new URL(login.headers.get('location'));
        idp.state.lastNonce = authz.searchParams.get('nonce');
        const cb = await fetch(
          `${base}/auth/oidc/callback?code=good-code&state=${authz.searchParams.get('state')}`,
          {
            headers: { cookie },
            redirect: 'manual',
          }
        );
        const back = new URL(cb.headers.get('location'));
        expect(back.origin).toBe('https://sign.example.com');
        const code = back.searchParams.get('sso_code');
        const ex = await fetch(`${base}/auth/sso/exchange`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ code }),
        });
        const { sessionToken } = await ex.json();
        expect(store.sessions.has(sessionToken)).toBe(true);
        const replay = await fetch(`${base}/auth/sso/exchange`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ code }),
        });
        expect(replay.status).toBe(400);
        return sessionToken;
      };
      const t1 = await once();
      const logout = await fetch(`${base}/auth/sso/logout`, {
        method: 'POST',
        headers: { 'X-Parse-Session-Token': t1 },
      });
      expect(store.sessions.has(t1)).toBe(false);
      const { logoutUrl } = await logout.json();
      expect(logoutUrl).toContain('/logout');
      expect(new URL(logoutUrl).searchParams.get('id_token_hint')).toMatch(/^eyJ/);
      await once();
      expect(store.users.length).toBe(1);
    });

    it('does not return an IdP logout URL for a local (non-SSO) session', async () => {
      const localId = store.addLocalUser('admin@example.com');
      const token = await store.createSession(localId);
      const res = await fetch(`${base}/auth/sso/logout`, {
        method: 'POST',
        headers: { 'X-Parse-Session-Token': token },
      });
      expect((await res.json()).logoutUrl).toBeNull();
      expect(store.sessions.has(token)).toBe(false);
    });

    it('redirects with a sanitized error code when the callback has no flow cookie', async () => {
      const cb = await fetch(`${base}/auth/oidc/callback?code=good-code&state=x`, {
        redirect: 'manual',
      });
      expect(cb.headers.get('location')).toBe('https://sign.example.com/?sso_error=INVALID_STATE');
    });

    it('serves a browser-safe config', async () => {
      const body = await (await fetch(`${base}/auth/sso/config`)).json();
      expect(body).toEqual({
        enabled: true,
        protocol: 'oidc',
        displayName: 'Company SSO',
        localLogin: true,
      });
    });
  });

  describe('when disabled', () => {
    it('only exposes enabled:false', async () => {
      const app = express();
      app.use('/auth', createSsoRouter({ config: { enabled: false }, store: createMemoryStore() }));
      const server = http.createServer(app);
      await new Promise(r => server.listen(0, '127.0.0.1', r));
      const base = `http://127.0.0.1:${server.address().port}`;
      expect(await (await fetch(`${base}/auth/sso/config`)).json()).toEqual({
        enabled: false,
        localLogin: true,
      });
      expect((await fetch(`${base}/auth/sso/login`, { redirect: 'manual' })).status).toBe(404);
      expect((await fetch(`${base}/auth/oidc/login`, { redirect: 'manual' })).status).toBe(404);
      await new Promise(r => server.close(r));
    });
  });
});
