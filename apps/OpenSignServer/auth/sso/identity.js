import { SsoError } from './errors.js';

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Normalized identity shared by OIDC and SAML.
 * `issuer` + `subject` is the stable external identity; email is not.
 * Only `groups` is kept from the IdP's authorization data; it is used solely through the
 * explicit SSO_*_GROUPS mapping. Other role/admin claims are dropped.
 */
export function normalizeIdentity({ provider, issuer, subject, email, name, groups }) {
  if (!['oidc', 'saml'].includes(provider)) {
    throw new SsoError('VALIDATION_FAILED', `unknown provider ${provider}`);
  }
  const iss = String(issuer ?? '').trim();
  const sub = String(subject ?? '').trim();
  if (!iss || !sub) throw new SsoError('VALIDATION_FAILED', 'missing issuer or subject');

  const mail = String(email ?? '')
    .replace(/\s/g, '')
    .toLowerCase();
  if (!mail || !emailRegex.test(mail))
    throw new SsoError('MISSING_EMAIL', 'missing or invalid email');

  const displayName = String(name ?? '').trim() || mail.split('@')[0];
  return Object.freeze({
    provider,
    issuer: iss,
    subject: sub,
    externalId: `${iss}|${sub}`,
    email: mail,
    name: displayName,
    groups: Object.freeze(normalizeGroups(groups)),
  });
}

// Accepts an array or a single string; keeps non-empty strings only.
function normalizeGroups(groups) {
  const arr = Array.isArray(groups) ? groups : groups ? [groups] : [];
  return arr.filter(g => typeof g === 'string' && g.trim()).map(g => g.trim());
}
