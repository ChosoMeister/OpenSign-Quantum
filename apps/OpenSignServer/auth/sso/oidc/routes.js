import express from 'express';
import { completeSsoLogin, errorRedirect } from '../session.js';
import { toSsoError } from '../errors.js';
import { ssoLog, newCorrelationId } from '../log.js';
import { FLOW_COOKIE, setFlowCookie, readFlowCookie, clearFlowCookie } from '../cookies.js';

export function createOidcRouter({ config, provider, store }) {
  const router = express.Router();

  router.get('/login', async (req, res) => {
    const correlationId = newCorrelationId();
    try {
      const { url, flow } = await provider.buildLoginRequest();
      setFlowCookie(res, { ...flow, cid: correlationId });
      ssoLog('sso.login.initiated', { correlationId, provider: 'oidc' });
      res.redirect(302, url);
    } catch (err) {
      const e = toSsoError(err, 'PROVIDER_UNAVAILABLE');
      ssoLog(
        'sso.login.rejected',
        { correlationId, provider: 'oidc', code: e.code, detail: e.message },
        'error'
      );
      res.redirect(302, errorRedirect(config, e.code));
    }
  });

  router.get('/callback', async (req, res) => {
    const flow = readFlowCookie(req);
    clearFlowCookie(res); // state/nonce/verifier are single use
    const correlationId = flow?.cid || newCorrelationId();
    try {
      if (req.query.error) {
        // IdP-side rejection (e.g. user disabled or consent denied). Error strings are not echoed.
        throw toSsoError(
          new Error(`IdP returned error=${String(req.query.error).slice(0, 64)}`),
          'VALIDATION_FAILED'
        );
      }
      // Rebuild the callback URL from configuration so the token request uses the registered redirect_uri.
      const qs = req.originalUrl.includes('?')
        ? req.originalUrl.slice(req.originalUrl.indexOf('?'))
        : '';
      let idToken;
      const identity = await provider.handleCallback(config.oidc.redirectUri + qs, flow, {
        requireVerifiedEmail: config.requireVerifiedEmail,
        groupsClaim: config.roleMappingEnabled ? config.groupsClaim : undefined,
        onIdToken: token => (idToken = token),
      });
      const redirect = await completeSsoLogin(identity, {
        store,
        config,
        correlationId,
        idToken,
      });
      res.redirect(302, redirect);
    } catch (err) {
      const e = toSsoError(err);
      ssoLog(
        'sso.login.rejected',
        { correlationId, provider: 'oidc', code: e.code, detail: e.message },
        'warn'
      );
      res.redirect(302, errorRedirect(config, e.code));
    }
  });

  return router;
}

export { FLOW_COOKIE };
