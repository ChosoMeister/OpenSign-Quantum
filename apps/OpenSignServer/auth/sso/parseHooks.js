// Parse triggers that protect SSO-provisioned accounts. Registered from cloud/main.js.
import { SSO_USER_FIELDS } from './store.js';
import { getSsoConfig } from './runtime.js';

const localLoginDisabled = () => getSsoConfig().localLoginEnabled === false;

/** Throws when LOCAL_LOGIN_ENABLED=false. Used by local signup/admin cloud functions. */
export function assertLocalAccountsEnabled() {
  if (localLoginDisabled()) {
    throw new Parse.Error(
      Parse.Error.OPERATION_FORBIDDEN,
      'Local accounts are disabled. Please sign in with SSO.'
    );
  }
}

const isSsoUser = user => Boolean(user?.get?.('ssoSubject'));

// Only the backend (master key) may set or change the external identity binding.
export function ssoUserBeforeSave(request) {
  if (request.master) return;
  const { object, original } = request;
  for (const field of SSO_USER_FIELDS) {
    const changed = original ? object.get(field) !== original.get(field) : object.has(field);
    if (changed) throw new Parse.Error(Parse.Error.OPERATION_FORBIDDEN, 'Field is read-only.');
  }
}

// SSO accounts authenticate at the IdP only, so an IdP-disabled user cannot fall back
// to a local password. Master-key /loginAs (used after SSO validation) skips this trigger.
export function ssoUserBeforeLogin(request) {
  if (localLoginDisabled() || isSsoUser(request.object)) {
    throw new Parse.Error(
      Parse.Error.OBJECT_NOT_FOUND,
      'This account uses Single Sign-On. Please sign in with SSO.'
    );
  }
}

export function ssoUserBeforePasswordReset(request) {
  if (localLoginDisabled() || isSsoUser(request.object)) {
    throw new Parse.Error(
      Parse.Error.OPERATION_FORBIDDEN,
      'This account uses Single Sign-On. Passwords are managed by your identity provider.'
    );
  }
}
