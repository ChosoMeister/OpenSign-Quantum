import { SsoError } from './errors.js';
import { ssoLog } from './log.js';

// The existing standard OpenSign role (apps/OpenSign/src/constant/appinfo.js defaultRole).
// Hard-coded on purpose: IdP roles/groups/admin claims never influence authorization.
export const STANDARD_ROLE = 'contracts_User';

/**
 * Resolve a validated identity to an OpenSign user id, provisioning it if allowed.
 * Shared by OIDC and SAML.
 */
export async function resolveUser(identity, { store, config, correlationId }) {
  let user = await store.findUserBySsoIdentity(identity.issuer, identity.subject);

  if (user) {
    ssoLog('sso.user.existing', { correlationId, provider: identity.provider, userId: user.id });
  } else {
    // Never link an SSO identity to an existing account by email alone.
    if (await store.emailInUse(identity.email)) {
      ssoLog('sso.user.collision', { correlationId, provider: identity.provider }, 'warn');
      throw new SsoError('ACCOUNT_COLLISION', 'email already belongs to another account');
    }
    if (!config.autoProvision) {
      throw new SsoError('PROVISIONING_DISABLED', 'auto provisioning disabled');
    }
    user = await store.createUser({ identity, role: STANDARD_ROLE, company: config.companyName });
    ssoLog('sso.user.provisioned', { correlationId, provider: identity.provider, userId: user.id });
  }

  const ext = await store.getExtUser(user.id);
  if (!ext) throw new SsoError('INTERNAL_ERROR', 'user has no contracts_Users record');
  if (ext.isDisabled) throw new SsoError('USER_DISABLED', 'user disabled in OpenSign');
  return { userId: user.id, role: ext.role };
}
