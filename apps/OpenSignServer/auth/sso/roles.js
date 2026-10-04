// Maps IdP groups to OpenSign roles. Only active when SSO_*_GROUPS are configured;
// otherwise every SSO user stays a standard user, as before.
export const ROLES = {
  admin: 'contracts_Admin',
  orgAdmin: 'contracts_OrgAdmin',
  editor: 'contracts_Editor',
  user: 'contracts_User',
};
// Roles this mapping manages; anything else on an existing account is left untouched.
export const MANAGED_ROLES = Object.values(ROLES);

const normalize = g => String(g).trim().replace(/^\/+/, '').toLowerCase();

/** Highest role granted by any group (Admin > OrgAdmin > Editor > User). */
export function roleFromGroups(groups, roleGroups) {
  const have = new Set((groups || []).map(normalize));
  const matches = list => (list || []).some(g => have.has(normalize(g)));
  if (matches(roleGroups.admin)) return ROLES.admin;
  if (matches(roleGroups.orgAdmin)) return ROLES.orgAdmin;
  if (matches(roleGroups.editor)) return ROLES.editor;
  return ROLES.user;
}
