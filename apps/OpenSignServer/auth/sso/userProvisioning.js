import { SsoError } from './errors.js';
import { ssoLog } from './log.js';
import { ROLES, MANAGED_ROLES, roleFromGroups } from './roles.js';
import { ensureCompanyOrg } from './company.js';

// The existing standard OpenSign role (apps/OpenSign/src/constant/appinfo.js defaultRole).
export const STANDARD_ROLE = ROLES.user;

/**
 * Resolve a validated identity to an OpenSign user id, provisioning it if allowed.
 * Shared by OIDC and SAML.
 *
 * Roles: without SSO_*_GROUPS every SSO user is a standard user and IdP claims are ignored.
 * With a group mapping, the role is derived from the IdP groups on every login (promotion
 * and demotion take effect at the next login) and users join the shared company organization.
 */
export async function resolveUser(identity, { store, config, correlationId }) {
  const mapped = Boolean(config.roleMappingEnabled);
  const role = mapped ? roleFromGroups(identity.groups, config.roleGroups) : STANDARD_ROLE;
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
    const placement = mapped ? await ensureCompanyOrg(store, config) : undefined;
    user = await store.createUser({ identity, role, company: config.companyName, placement });
    ssoLog('sso.user.provisioned', {
      correlationId,
      provider: identity.provider,
      userId: user.id,
      role,
    });
  }

  const ext = await store.getExtUser(user.id);
  if (!ext) throw new SsoError('INTERNAL_ERROR', 'user has no contracts_Users record');
  if (ext.isDisabled) throw new SsoError('USER_DISABLED', 'user disabled in OpenSign');

  if (mapped && ext.role !== role && MANAGED_ROLES.includes(ext.role)) {
    await store.setRole(ext.id, role);
    ssoLog('sso.user.role_changed', {
      correlationId,
      provider: identity.provider,
      userId: user.id,
      from: ext.role,
      to: role,
    });
    return { userId: user.id, role };
  }
  return { userId: user.id, role: ext.role };
}
