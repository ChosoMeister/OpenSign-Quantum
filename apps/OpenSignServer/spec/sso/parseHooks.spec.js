import {
  ssoUserBeforeSave,
  ssoUserBeforeLogin,
  ssoUserBeforePasswordReset,
  assertLocalAccountsEnabled,
} from '../../auth/sso/parseHooks.js';
import { setSsoConfigForTests } from '../../auth/sso/runtime.js';

// Minimal stand-ins for Parse objects used by the triggers.
const obj = fields => ({ get: k => fields[k], has: k => k in fields });

describe('SSO Parse hooks', () => {
  beforeAll(() => {
    globalThis.Parse = globalThis.Parse || {};
    class ParseError extends Error {
      constructor(code, message) {
        super(message);
        this.code = code;
      }
    }
    ParseError.OPERATION_FORBIDDEN = 119;
    ParseError.OBJECT_NOT_FOUND = 101;
    globalThis.Parse.Error = globalThis.Parse.Error || ParseError;
  });

  it('forbids clients from setting or changing the SSO identity binding', () => {
    expect(() => ssoUserBeforeSave({ object: obj({ ssoSubject: 'victim' }) })).toThrow();
    expect(() =>
      ssoUserBeforeSave({ object: obj({ ssoIssuer: 'b' }), original: obj({ ssoIssuer: 'a' }) })
    ).toThrow();
    expect(() =>
      ssoUserBeforeSave({ object: obj({ name: 'x' }), original: obj({}) })
    ).not.toThrow();
    expect(() =>
      ssoUserBeforeSave({ master: true, object: obj({ ssoSubject: 's' }) })
    ).not.toThrow();
  });

  it('blocks local password login and password reset for SSO accounts', () => {
    expect(() => ssoUserBeforeLogin({ object: obj({ ssoSubject: 's' }) })).toThrow();
    expect(() => ssoUserBeforePasswordReset({ object: obj({ ssoSubject: 's' }) })).toThrow();
  });

  it('leaves local administrators untouched', () => {
    expect(() => ssoUserBeforeLogin({ object: obj({}) })).not.toThrow();
    expect(() => ssoUserBeforePasswordReset({ object: obj({}) })).not.toThrow();
  });

  describe('with LOCAL_LOGIN_ENABLED=false', () => {
    beforeEach(() => setSsoConfigForTests({ enabled: true, localLoginEnabled: false }));
    afterEach(() => setSsoConfigForTests(undefined));

    it('rejects every password login and password reset', () => {
      expect(() => ssoUserBeforeLogin({ object: obj({}) })).toThrow();
      expect(() => ssoUserBeforePasswordReset({ object: obj({}) })).toThrow();
    });

    it('blocks local signup/admin functions', () => {
      expect(() => assertLocalAccountsEnabled()).toThrow();
    });

    it('still allows creating contact/signer accounts (they cannot log in with a password)', () => {
      expect(() =>
        ssoUserBeforeSave({ object: obj({ username: 'signer@example.com' }) })
      ).not.toThrow();
    });
  });
});
