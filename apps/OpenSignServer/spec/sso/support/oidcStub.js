// Minimal standards-shaped OIDC provider for tests (discovery, JWKS, token, userinfo).
import http from 'node:http';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';

export async function startOidcStub() {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const other = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };

  const state = {
    issuer: '',
    // Overrides applied to the next ID token.
    claims: {},
    signWithWrongKey: false,
    userinfo: null,
    lastNonce: null,
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, state.issuer);
    const json = (code, body) => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (url.pathname === '/.well-known/openid-configuration') {
      return json(200, {
        issuer: state.issuer,
        authorization_endpoint: `${state.issuer}/authorize`,
        token_endpoint: `${state.issuer}/token`,
        userinfo_endpoint: `${state.issuer}/userinfo`,
        jwks_uri: `${state.issuer}/jwks`,
        end_session_endpoint: `${state.issuer}/logout`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        code_challenge_methods_supported: ['S256'],
      });
    }
    if (url.pathname === '/jwks') return json(200, { keys: [jwk] });
    if (url.pathname === '/token' && req.method === 'POST') {
      let body = '';
      for await (const chunk of req) body += chunk;
      const params = new URLSearchParams(body);
      if (params.get('code') !== 'good-code' || !params.get('code_verifier')) {
        return json(400, { error: 'invalid_grant' });
      }
      const now = Math.floor(Date.now() / 1000);
      const claims = {
        iss: state.issuer,
        aud: 'opensign',
        sub: 'user-sub-1',
        nonce: state.lastNonce,
        email: 'jane@example.com',
        email_verified: true,
        name: 'Jane Doe',
        iat: now,
        exp: now + 300,
        ...state.claims,
      };
      for (const k of Object.keys(claims)) if (claims[k] === undefined) delete claims[k];
      const idToken = await new SignJWT(claims)
        .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
        .sign(state.signWithWrongKey ? other.privateKey : privateKey);
      return json(200, {
        access_token: 'at',
        token_type: 'Bearer',
        id_token: idToken,
        expires_in: 300,
      });
    }
    if (url.pathname === '/userinfo') return json(200, state.userinfo || { sub: 'user-sub-1' });
    json(404, {});
  });

  await new Promise(r => server.listen(0, '127.0.0.1', r));
  state.issuer = `http://127.0.0.1:${server.address().port}`;
  return {
    state,
    reset() {
      Object.assign(state, {
        claims: {},
        signWithWrongKey: false,
        userinfo: null,
        lastNonce: null,
      });
    },
    close: () => new Promise(r => server.close(r)),
  };
}
