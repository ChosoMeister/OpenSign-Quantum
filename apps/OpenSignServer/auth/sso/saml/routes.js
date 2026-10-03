import express from 'express';
import { completeSsoLogin, errorRedirect } from '../session.js';
import { toSsoError } from '../errors.js';
import { ssoLog, newCorrelationId } from '../log.js';

export function createSamlRouter({ config, provider, store }) {
  const router = express.Router();

  router.get('/login', async (req, res) => {
    const correlationId = newCorrelationId();
    try {
      const url = await provider.buildLoginUrl();
      ssoLog('sso.login.initiated', { correlationId, provider: 'saml' });
      res.redirect(302, url);
    } catch (err) {
      const e = toSsoError(err, 'PROVIDER_UNAVAILABLE');
      ssoLog(
        'sso.login.rejected',
        { correlationId, provider: 'saml', code: e.code, detail: e.message },
        'error'
      );
      res.redirect(302, errorRedirect(config, e.code));
    }
  });

  // ACS. Login CSRF is prevented by InResponseTo: only responses to requests this SP issued are accepted.
  router.post('/callback', async (req, res) => {
    const correlationId = newCorrelationId();
    try {
      const identity = await provider.handleCallback(req.body);
      const redirect = await completeSsoLogin(identity, { store, config, correlationId });
      res.redirect(303, redirect);
    } catch (err) {
      const e = toSsoError(err);
      ssoLog(
        'sso.login.rejected',
        { correlationId, provider: 'saml', code: e.code, detail: e.message },
        'warn'
      );
      res.redirect(303, errorRedirect(config, e.code));
    }
  });

  router.get('/metadata', async (req, res) => {
    try {
      res.type('application/samlmetadata+xml').send(await provider.generateMetadata());
    } catch (err) {
      ssoLog('sso.saml.metadata.error', { detail: err?.message }, 'error');
      res.status(500).json({ error: 'INTERNAL_ERROR' });
    }
  });

  return router;
}
