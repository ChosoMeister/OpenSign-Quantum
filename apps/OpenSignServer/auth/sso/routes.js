// Common SSO routing layer mounted at /auth. Dispatches on SSO_PROTOCOL.
import express from 'express';
import cookieParser from 'cookie-parser';
import { getPublicConfig } from './config.js';
import { ssoLog } from './log.js';
import { takeIdTokenHint } from './session.js';
import { createOidcProvider } from './oidc/provider.js';
import { createOidcRouter } from './oidc/routes.js';
import { createSamlProvider } from './saml/provider.js';
import { createSamlRouter } from './saml/routes.js';

export function createSsoRouter({ config, store, oidcProvider, samlProvider }) {
  const router = express.Router();
  const noStore = (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  };
  router.use(noStore);

  router.get('/sso/config', (req, res) => res.json(getPublicConfig(config)));

  if (!config.enabled) {
    // SSO_ENABLED=false: upstream behaviour, every other SSO route is inert.
    router.all(/^\/(sso|oidc|saml)\/.*/, (req, res) =>
      res.status(404).json({ error: 'SSO_DISABLED' })
    );
    return router;
  }

  router.use(cookieParser(config.cookieSecret));

  let provider;
  if (config.protocol === 'oidc') {
    provider = oidcProvider || createOidcProvider(config.oidc);
    router.use('/oidc', createOidcRouter({ config, provider, store }));
  } else {
    provider = samlProvider || createSamlProvider(config.saml, { store });
    router.use('/saml', createSamlRouter({ config, provider, store }));
  }

  router.get('/sso/login', (req, res) => res.redirect(302, `../${config.protocol}/login`));

  // Exchange the single-use handoff code for the Parse session token.
  router.post('/sso/exchange', async (req, res) => {
    const code = typeof req.body?.code === 'string' ? req.body.code : '';
    if (!code || code.length > 128) return res.status(400).json({ error: 'INVALID_CODE' });
    try {
      const sessionToken = await store.takeHandoff(code);
      if (!sessionToken) return res.status(400).json({ error: 'INVALID_CODE' });
      res.json({ sessionToken });
    } catch (err) {
      ssoLog('sso.exchange.error', { detail: err?.message }, 'error');
      res.status(500).json({ error: 'INTERNAL_ERROR' });
    }
  });

  // Application logout is mandatory; IdP logout (OIDC end_session_endpoint) is optional.
  router.post('/sso/logout', async (req, res) => {
    const sessionToken = req.get('X-Parse-Session-Token');
    let ssoUser = false;
    let idTokenHint = null;
    try {
      if (sessionToken) {
        idTokenHint = await takeIdTokenHint(store, sessionToken);
        ({ ssoUser } = await store.destroySession(sessionToken));
      }
    } catch (err) {
      ssoLog('sso.logout.error', { detail: err?.message }, 'warn');
    }
    const logoutUrl =
      ssoUser && config.protocol === 'oidc' && provider.buildLogoutUrl
        ? await provider.buildLogoutUrl(idTokenHint)
        : null;
    res.json({ logoutUrl });
  });

  return router;
}
