// Sanitized SSO error codes. Only the code ever reaches the browser.
export const SSO_ERRORS = {
  SSO_DISABLED: 'SSO_DISABLED',
  PROVIDER_UNAVAILABLE: 'PROVIDER_UNAVAILABLE',
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  INVALID_STATE: 'INVALID_STATE',
  MISSING_EMAIL: 'MISSING_EMAIL',
  UNVERIFIED_EMAIL: 'UNVERIFIED_EMAIL',
  USER_DISABLED: 'USER_DISABLED',
  ACCOUNT_COLLISION: 'ACCOUNT_COLLISION',
  PROVISIONING_DISABLED: 'PROVISIONING_DISABLED',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
};

export class SsoError extends Error {
  /**
   * @param {string} code one of SSO_ERRORS
   * @param {string} [detail] internal detail for server logs only
   */
  constructor(code, detail) {
    super(detail || code);
    this.name = 'SsoError';
    this.code = SSO_ERRORS[code] ? code : SSO_ERRORS.INTERNAL_ERROR;
  }
}

export function toSsoError(err, fallbackCode = SSO_ERRORS.INTERNAL_ERROR) {
  if (err instanceof SsoError) return err;
  return new SsoError(fallbackCode, err?.message);
}
