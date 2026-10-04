// Generic OpenID Connect relying party (Authorization Code + PKCE) built on openid-client.
// Endpoints come exclusively from ${OIDC_ISSUER}/.well-known/openid-configuration.
import crypto from 'node:crypto';
import * as client from 'openid-client';
import { SsoError } from '../errors.js';
import { identityFromClaims } from './validation.js';

export function createOidcProvider(oidcConfig, { discover = client.discovery } = {}) {
  let discovered = null;

  async function getConfiguration() {
    if (discovered) return discovered;
    try {
      const clientAuth = oidcConfig.publicClient
        ? client.None()
        : client.ClientSecretPost(oidcConfig.clientSecret);
      const options = oidcConfig.allowInsecureHttp
        ? { execute: [client.allowInsecureRequests] }
        : undefined;
      const cfg = await discover(
        new URL(oidcConfig.issuer),
        oidcConfig.clientId,
        { redirect_uris: [oidcConfig.redirectUri] },
        clientAuth,
        options
      );
      // Verify the ID token JWS signature against the IdP JWKS (jwks_uri from discovery).
      client.enableNonRepudiationChecks(cfg);
      discovered = cfg;
      return cfg;
    } catch (err) {
      // Not cached: discovery is retried on the next login attempt.
      throw new SsoError('PROVIDER_UNAVAILABLE', `OIDC discovery failed: ${err?.message}`);
    }
  }

  return {
    getConfiguration,

    async buildLoginRequest() {
      const cfg = await getConfiguration();
      const flow = {
        state: client.randomState(),
        nonce: client.randomNonce(),
        codeVerifier: client.randomPKCECodeVerifier(),
      };
      const url = client.buildAuthorizationUrl(cfg, {
        redirect_uri: oidcConfig.redirectUri,
        scope: oidcConfig.scopes,
        response_type: 'code',
        state: flow.state,
        nonce: flow.nonce,
        code_challenge: await client.calculatePKCECodeChallenge(flow.codeVerifier),
        code_challenge_method: 'S256',
      });
      return { url: url.href, flow };
    },

    /**
     * Exchange the authorization code and validate everything server-side:
     * state, nonce, PKCE, ID token signature, iss, aud, exp (openid-client), then sub/email.
     */
    async handleCallback(currentUrl, flow, { requireVerifiedEmail, onIdToken, groupsClaim }) {
      if (!flow?.state || !flow?.nonce || !flow?.codeVerifier) {
        throw new SsoError('INVALID_STATE', 'missing OIDC flow state');
      }
      // Explicit state check first for a precise error; openid-client re-checks it below.
      const returnedState = Buffer.from(new URL(currentUrl).searchParams.get('state') || '');
      const expectedState = Buffer.from(flow.state);
      if (
        returnedState.length !== expectedState.length ||
        !crypto.timingSafeEqual(returnedState, expectedState)
      ) {
        throw new SsoError('INVALID_STATE', 'OIDC state mismatch');
      }
      const cfg = await getConfiguration();
      let tokens;
      try {
        tokens = await client.authorizationCodeGrant(cfg, new URL(currentUrl), {
          expectedState: flow.state,
          expectedNonce: flow.nonce,
          pkceCodeVerifier: flow.codeVerifier,
          idTokenExpected: true,
        });
      } catch (err) {
        throw new SsoError(
          'VALIDATION_FAILED',
          `OIDC token validation failed: ${err?.code || ''} ${err?.message}`
        );
      }
      const claims = tokens.claims();
      if (!claims?.sub) throw new SsoError('VALIDATION_FAILED', 'ID token has no sub');

      let userinfo = null;
      const serverMeta = cfg.serverMetadata();
      const needUserinfo =
        !claims.email ||
        claims.email_verified === undefined ||
        (groupsClaim && claims[groupsClaim] === undefined);
      if (needUserinfo && serverMeta.userinfo_endpoint) {
        try {
          // expectedSubject enforces userinfo.sub === id_token.sub.
          userinfo = await client.fetchUserInfo(cfg, tokens.access_token, claims.sub);
        } catch (err) {
          throw new SsoError('VALIDATION_FAILED', `OIDC userinfo failed: ${err?.message}`);
        }
      }
      const identity = identityFromClaims(claims, userinfo, { requireVerifiedEmail, groupsClaim });
      // Kept server-side only, as id_token_hint for RP-initiated logout.
      onIdToken?.(tokens.id_token);
      return identity;
    },

    async buildLogoutUrl(idTokenHint) {
      try {
        const cfg = await getConfiguration();
        if (!cfg.serverMetadata().end_session_endpoint) return null;
        return client
          .buildEndSessionUrl(cfg, {
            client_id: oidcConfig.clientId,
            post_logout_redirect_uri: oidcConfig.postLogoutRedirectUri,
            // Lets the IdP log out without an extra confirmation page.
            ...(idTokenHint ? { id_token_hint: idTokenHint } : {}),
          })
          .toString();
      } catch {
        return null;
      }
    },
  };
}
