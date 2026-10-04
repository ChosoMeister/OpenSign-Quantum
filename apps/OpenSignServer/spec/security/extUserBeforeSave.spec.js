import ExtUserBeforeSave from '../../cloud/parsefunction/ExtUserBeforeSave.js';

// Minimal stand-ins for the Parse objects the trigger touches.
const ptr = id => (id ? { id } : undefined);
function row({ id, userId, role = 'contracts_User', tenant = 't1', org = 'o1' }) {
  const f = {
    UserId: ptr(userId),
    UserRole: role,
    TenantId: ptr(tenant),
    OrganizationId: ptr(org),
  };
  return { id, get: k => f[k] };
}
const changes = keys => ({ dirtyKeys: () => keys });

describe('contracts_Users beforeSave (privilege escalation guard)', () => {
  let callerRow;
  beforeAll(() => {
    class ParseError extends Error {
      constructor(code, message) {
        super(message);
        this.code = code;
      }
    }
    ParseError.OPERATION_FORBIDDEN = 119;
    globalThis.Parse = globalThis.Parse || {};
    globalThis.Parse.Error = globalThis.Parse.Error || ParseError;
  });
  beforeEach(() => {
    callerRow = null;
    // Parse.Query is only used to load the caller's own contracts_Users row.
    globalThis.Parse.Query = class {
      equalTo() {}
      notEqualTo() {}
      async first() {
        return callerRow;
      }
    };
  });

  const user = { id: 'u1' };
  const ownRow = row({ id: 'e1', userId: 'u1' });
  const otherRow = row({ id: 'e2', userId: 'u2' });

  async function expectForbidden(req) {
    await expectAsync(ExtUserBeforeSave(req)).toBeRejectedWith(
      jasmine.objectContaining({ code: 119 })
    );
  }

  it('allows master-key writes (server code)', async () => {
    await expectAsync(
      ExtUserBeforeSave({ master: true, object: changes(['UserRole']), original: ownRow })
    ).toBeResolved();
  });

  it('blocks a user from changing their own role, tenant, org, teams or status', async () => {
    for (const field of [
      'UserRole',
      'TenantId',
      'OrganizationId',
      'TeamIds',
      'IsDisabled',
      'ACL',
      'UserId',
      'Email',
    ]) {
      await expectForbidden({ user, object: changes([field]), original: ownRow });
    }
  });

  it('allows a user to edit their own profile and tour status', async () => {
    await expectAsync(
      ExtUserBeforeSave({
        user,
        object: changes(['Name', 'Phone', 'JobTitle', 'Company', 'Language']),
        original: ownRow,
      })
    ).toBeResolved();
    await expectAsync(
      ExtUserBeforeSave({ user, object: changes(['TourStatus']), original: ownRow })
    ).toBeResolved();
  });

  it('blocks client-side creation of rows', async () => {
    await expectForbidden({ user, object: changes(['UserRole']), original: undefined });
  });

  it('blocks unauthenticated writes', async () => {
    await expectForbidden({ object: changes(['Name']), original: ownRow });
  });

  it("blocks a normal user from editing another user's row", async () => {
    callerRow = row({ id: 'e1', userId: 'u1' });
    await expectForbidden({ user, object: changes(['Name']), original: otherRow });
    await expectForbidden({ user, object: changes(['IsDisabled']), original: otherRow });
  });

  it('lets an admin toggle IsDisabled for a user in the same tenant, and nothing else', async () => {
    callerRow = row({ id: 'e1', userId: 'u1', role: 'contracts_Admin' });
    await expectAsync(
      ExtUserBeforeSave({ user, object: changes(['IsDisabled']), original: otherRow })
    ).toBeResolved();
    await expectForbidden({
      user,
      object: changes(['IsDisabled', 'UserRole']),
      original: otherRow,
    });
    await expectForbidden({ user, object: changes(['UserRole']), original: otherRow });
  });

  it('blocks admins acting on another tenant, and protects tenant admins', async () => {
    callerRow = row({ id: 'e1', userId: 'u1', role: 'contracts_Admin' });
    await expectForbidden({
      user,
      object: changes(['IsDisabled']),
      original: row({ id: 'e3', userId: 'u3', tenant: 't2' }),
    });
    await expectForbidden({
      user,
      object: changes(['IsDisabled']),
      original: row({ id: 'e4', userId: 'u4', role: 'contracts_Admin' }),
    });
  });

  it('limits an OrgAdmin to their own organization', async () => {
    callerRow = row({ id: 'e1', userId: 'u1', role: 'contracts_OrgAdmin', org: 'o1' });
    await expectAsync(
      ExtUserBeforeSave({ user, object: changes(['IsDisabled']), original: otherRow })
    ).toBeResolved();
    await expectForbidden({
      user,
      object: changes(['IsDisabled']),
      original: row({ id: 'e5', userId: 'u5', org: 'o2' }),
    });
  });
});
