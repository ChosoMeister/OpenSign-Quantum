// Guards contracts_Users against client-side privilege escalation.
// The class CLP allows public updates and many rows have no ACL, so without this trigger
// any logged-in user could change their own (or another user's) role, tenant or organization.
// Server code that legitimately changes these fields saves with the master key.

// Fields only the server (master key) may set or change.
export const PROTECTED_EXT_USER_FIELDS = [
  'UserRole',
  'TenantId',
  'OrganizationId',
  'TeamIds',
  'UserId',
  'CreatedBy',
  'Email',
  'IsDisabled',
  'ACL',
];

const ADMIN_ROLES = ['contracts_Admin', 'contracts_OrgAdmin'];
const forbidden = () => new Parse.Error(Parse.Error.OPERATION_FORBIDDEN, 'Unauthorized.');

async function getCallerExtUser(user) {
  const q = new Parse.Query('contracts_Users');
  q.equalTo('UserId', { __type: 'Pointer', className: '_User', objectId: user.id });
  q.notEqualTo('IsDisabled', true);
  return q.first({ useMasterKey: true });
}

// An admin may (de)activate other users in their tenant; an OrgAdmin only within their organization.
export async function canToggleDisabled(user, target) {
  const caller = await getCallerExtUser(user);
  const role = caller?.get('UserRole');
  if (!caller || !ADMIN_ROLES.includes(role)) return false;
  if (caller.id === target.id) return false;
  if (!caller.get('TenantId')?.id || caller.get('TenantId').id !== target.get('TenantId')?.id) {
    return false;
  }
  // Tenant admins cannot be disabled by anyone but the server.
  if (target.get('UserRole') === 'contracts_Admin') return false;
  if (role === 'contracts_OrgAdmin') {
    const orgId = caller.get('OrganizationId')?.id;
    if (!orgId || orgId !== target.get('OrganizationId')?.id) return false;
  }
  return true;
}

export default async function ExtUserBeforeSave(request) {
  if (request.master) return;
  const { object, original, user } = request;

  // Rows are created only by server code (signup, addUser, SSO provisioning).
  if (!original) throw forbidden();
  if (!user) throw forbidden();

  const changed = object.dirtyKeys();
  const protectedChanges = changed.filter(k => PROTECTED_EXT_USER_FIELDS.includes(k));
  const isOwnRow = original.get('UserId')?.id === user.id;

  if (isOwnRow) {
    // Users may edit their own profile fields, never their role/tenant/org/status.
    if (protectedChanges.length) throw forbidden();
    return;
  }

  // Another user's row: only the IsDisabled toggle, only by an authorized admin.
  if (
    changed.length === 1 &&
    changed[0] === 'IsDisabled' &&
    (await canToggleDisabled(user, original))
  ) {
    return;
  }
  throw forbidden();
}
