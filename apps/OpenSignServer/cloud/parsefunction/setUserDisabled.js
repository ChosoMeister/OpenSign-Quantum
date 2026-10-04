import { canToggleDisabled } from './ExtUserBeforeSave.js';

// Activate/deactivate a user from the Users page. Runs server-side with the master key after the
// same authorization as the contracts_Users guard: Admin within the tenant, OrgAdmin within the
// organization, never a tenant Admin or oneself.
export default async function setUserDisabled(request) {
  const { extUserId, isDisabled } = request.params;
  if (!request.user) {
    throw new Parse.Error(Parse.Error.INVALID_SESSION_TOKEN, 'User is not authenticated.');
  }
  if (!extUserId || typeof isDisabled !== 'boolean') {
    throw new Parse.Error(Parse.Error.INVALID_QUERY, 'Please provide extUserId and isDisabled.');
  }
  const target = await new Parse.Query('contracts_Users').get(extUserId, { useMasterKey: true });
  if (!(await canToggleDisabled(request.user, target))) {
    throw new Parse.Error(Parse.Error.OPERATION_FORBIDDEN, 'Unauthorized.');
  }
  target.set('IsDisabled', isDisabled);
  await target.save(null, { useMasterKey: true });
  return { objectId: target.id, IsDisabled: isDisabled };
}
