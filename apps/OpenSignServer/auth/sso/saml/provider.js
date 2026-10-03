// Generic SAML 2.0 Service Provider built on @node-saml/node-saml.
import axios from 'axios';
import { DOMParser } from '@xmldom/xmldom';
import xpath from 'xpath';
import { SAML, ValidateInResponseTo } from '@node-saml/node-saml';
import { SsoError } from '../errors.js';
import { checkResponseStructure, identityFromProfile } from './validation.js';

const REQUEST_TTL_MS = 10 * 60 * 1000;
const REPLAY_TTL_MS = 24 * 60 * 60 * 1000;
const REDIRECT_BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

const selectMd = xpath.useNamespaces({
  md: 'urn:oasis:names:tc:SAML:2.0:metadata',
  ds: 'http://www.w3.org/2000/09/xmldsig#',
});

/** Extract entityID, redirect-binding SSO URL and signing certs from IdP metadata XML. */
export function parseIdpMetadata(xml) {
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const entity = selectMd('//md:EntityDescriptor[md:IDPSSODescriptor]', doc)[0];
  if (!entity) throw new Error('metadata has no IDPSSODescriptor');
  const idp = selectMd('md:IDPSSODescriptor', entity)[0];
  const sso = selectMd(`md:SingleSignOnService[@Binding="${REDIRECT_BINDING}"]`, idp)[0];
  const certs = selectMd(
    'md:KeyDescriptor[not(@use) or @use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate',
    idp
  )
    .map(n => n.textContent.replace(/\s+/g, ''))
    .filter(Boolean);
  const entityId = entity.getAttribute('entityID');
  if (!entityId || !sso || !certs.length) {
    throw new Error(
      'metadata is missing entityID, HTTP-Redirect SingleSignOnService or signing certificate'
    );
  }
  return { entityId, ssoUrl: sso.getAttribute('Location'), certs };
}

// node-saml CacheProvider backed by the SSO store (survives restarts; no in-memory state).
function cacheProvider(store) {
  const prefix = 'saml-req:';
  return {
    async saveAsync(key, value) {
      await store.cache.put(prefix + key, value, REQUEST_TTL_MS);
      return { value, createdAt: Date.now() };
    },
    async getAsync(key) {
      return store.cache.get(prefix + key);
    },
    async removeAsync(key) {
      if (!key) return null;
      await store.cache.remove(prefix + key);
      return key;
    },
  };
}

export function createSamlProvider(samlConfig, { store, fetchMetadata } = {}) {
  let saml = null;
  let idpEntityId = null;

  const loadMetadata =
    fetchMetadata ||
    (async url => (await axios.get(url, { timeout: 10000, responseType: 'text' })).data);

  async function getSaml() {
    if (saml) return saml;
    let idp;
    try {
      idp = samlConfig.idpMetadataUrl
        ? parseIdpMetadata(await loadMetadata(samlConfig.idpMetadataUrl))
        : {
            entityId: samlConfig.idpEntityId,
            ssoUrl: samlConfig.idpSsoUrl,
            certs: [samlConfig.idpCert],
          };
    } catch (err) {
      // Not cached: retried on next attempt.
      throw new SsoError('PROVIDER_UNAVAILABLE', `SAML metadata unavailable: ${err?.message}`);
    }
    idpEntityId = idp.entityId;
    saml = new SAML({
      entryPoint: idp.ssoUrl,
      idpCert: idp.certs,
      idpIssuer: idp.entityId,
      issuer: samlConfig.spEntityId,
      audience: samlConfig.spEntityId,
      callbackUrl: samlConfig.acsUrl,
      wantAssertionsSigned: true,
      wantAuthnResponseSigned: samlConfig.wantResponseSigned !== false,
      signatureAlgorithm: 'sha256',
      digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
      acceptedClockSkewMs: samlConfig.clockSkewMs,
      validateInResponseTo: ValidateInResponseTo.always,
      requestIdExpirationPeriodMs: REQUEST_TTL_MS,
      cacheProvider: cacheProvider(store),
      identifierFormat: samlConfig.nameIdFormat || null, // null lets the IdP choose
      disableRequestedAuthnContext: true,
      ...(samlConfig.spPrivateKey
        ? { privateKey: samlConfig.spPrivateKey, publicCert: samlConfig.spCert }
        : {}),
    });
    return saml;
  }

  return {
    async buildLoginUrl(relayState = '') {
      const s = await getSaml();
      return s.getAuthorizeUrlAsync(relayState, undefined, {});
    },

    /** Validate a POSTed SAMLResponse and return the normalized identity. */
    async handleCallback(body) {
      if (!body?.SAMLResponse) throw new SsoError('VALIDATION_FAILED', 'missing SAMLResponse');
      const s = await getSaml();
      let profile;
      try {
        ({ profile } = await s.validatePostResponseAsync({ SAMLResponse: body.SAMLResponse }));
      } catch (err) {
        throw new SsoError('VALIDATION_FAILED', `SAML validation failed: ${err?.message}`);
      }
      if (!profile) throw new SsoError('VALIDATION_FAILED', 'SAML response had no assertion');

      const xml = Buffer.from(body.SAMLResponse, 'base64').toString('utf8');
      const { assertionId } = checkResponseStructure(xml, {
        acsUrl: samlConfig.acsUrl,
        idpEntityId,
      });

      // Replay protection beyond InResponseTo consumption: each assertion ID is accepted once.
      const replayKey = `saml-assertion:${assertionId}`;
      if (!assertionId || (await store.cache.get(replayKey))) {
        throw new SsoError('VALIDATION_FAILED', 'SAML assertion replay detected');
      }
      await store.cache.put(replayKey, '1', REPLAY_TTL_MS);

      return identityFromProfile(profile, {
        idpEntityId,
        emailAttribute: samlConfig.emailAttribute,
        nameAttribute: samlConfig.nameAttribute,
        subjectAttribute: samlConfig.subjectAttribute,
      });
    },

    async generateMetadata() {
      const s = await getSaml().catch(() => null);
      if (s) return s.generateServiceProviderMetadata(null, samlConfig.spCert || null);
      // Metadata must be obtainable even while the IdP is unreachable.
      const { generateServiceProviderMetadata } = await import('@node-saml/node-saml');
      return generateServiceProviderMetadata({
        issuer: samlConfig.spEntityId,
        callbackUrl: samlConfig.acsUrl,
        wantAssertionsSigned: true,
        publicCerts: samlConfig.spCert || null,
        privateKey: samlConfig.spPrivateKey || undefined,
      });
    },
  };
}
