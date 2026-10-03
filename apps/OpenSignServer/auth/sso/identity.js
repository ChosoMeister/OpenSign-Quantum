import { SsoError } from './errors.js';

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Normalized identity shared by OIDC and SAML.
 * `issuer` + `subject` is the stable external identity; email is not.
 * Group/role/admin claims are deliberately dropped: they never affect authorization.
 */
export function normalizeIdentity({ provider, issuer, subject, email, name }) {
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
  });
}
