// Structured SSO event logging. Never pass tokens, assertions, secrets or raw IdP payloads.
import crypto from 'node:crypto';

export const newCorrelationId = () => crypto.randomUUID();

export function ssoLog(event, fields = {}, level = 'info') {
  if (process.env.TESTING && !process.env.SSO_TEST_LOGS) return;
  const line = JSON.stringify({ ts: new Date().toISOString(), event, ...fields });
  (level === 'warn' ? console.warn : level === 'error' ? console.error : console.log)(line);
}
