import { SsoError } from '../errors.js';
import { normalizeIdentity } from '../identity.js';

/**
 * Build the normalized identity from already-verified ID token claims
 * (plus optional userinfo whose `sub` has been checked to match).
 */
export function identityFromClaims(claims, userinfo, { requireVerifiedEmail, groupsClaim }) {
  const merged = { ...(userinfo || {}), ...claims };
  const email = claims.email || userinfo?.email;
  if (!email) throw new SsoError('MISSING_EMAIL', 'no email claim');

  const verified = claims.email_verified ?? userinfo?.email_verified;
  if (requireVerifiedEmail && !(verified === true || verified === 'true')) {
    throw new SsoError('UNVERIFIED_EMAIL', 'email_verified is not true');
  }

  const name =
    merged.name ||
    [merged.given_name, merged.family_name].filter(Boolean).join(' ') ||
    merged.preferred_username;

  return normalizeIdentity({
    provider: 'oidc',
    issuer: claims.iss,
    subject: claims.sub,
    email,
    name,
    groups: groupsClaim ? (claims[groupsClaim] ?? userinfo?.[groupsClaim]) : undefined,
  });
}
