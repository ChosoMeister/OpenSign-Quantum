import { resolveUser, STANDARD_ROLE } from '../../auth/sso/userProvisioning.js';
import { completeSsoLogin } from '../../auth/sso/session.js';
import { normalizeIdentity } from '../../auth/sso/identity.js';
import { createMemoryStore } from './support/memoryStore.js';

const config = {
  autoProvision: true,
  companyName: 'Acme',
  frontendUrl: 'https://sign.example.com',
};
const identity = (over = {}) =>
  normalizeIdentity({
    provider: 'oidc',
    issuer: 'https://idp.example.com',
    subject: 'abc123',
    email: 'User@Example.com',
    name: 'User Name',
    ...over,
  });

async function expectCode(promise, code) {
  try {
    await promise;
    fail('expected rejection');
  } catch (e) {
    expect(e.code).toBe(code);
  }
}

describe('SSO provisioning', () => {
  it('auto-provisions a new user with the standard role', async () => {
    const store = createMemoryStore();
    const res = await resolveUser(identity(), { store, config });
    expect(res.role).toBe(STANDARD_ROLE);
    expect(STANDARD_ROLE).toBe('contracts_User');
    expect(store.users[0].email).toBe('user@example.com');
  });

  it('never assigns an admin role even when the IdP claims it', async () => {
    const store = createMemoryStore();
    // Extra claims are not part of the normalized identity and cannot reach provisioning.
    const id = normalizeIdentity({
      ...identity(),
      isAdmin: true,
      groups: ['admins'],
      role: 'contracts_Admin',
    });
    expect(id.isAdmin).toBeUndefined();
    expect(id.role).toBeUndefined();
    // Without SSO_*_GROUPS configured, groups are carried but never used.
    const res = await resolveUser(id, { store, config });
    expect(res.role).toBe('contracts_User');
  });

  it('reuses the account for a returning user, even if the email changed', async () => {
    const store = createMemoryStore();
    const first = await resolveUser(identity(), { store, config });
    const again = await resolveUser(identity({ email: 'renamed@example.com' }), { store, config });
    expect(again.userId).toBe(first.userId);
    expect(store.users.length).toBe(1);
  });

  it('does not link an SSO identity to an existing local account with the same email', async () => {
    const store = createMemoryStore();
    store.addLocalUser('user@example.com');
    await expectCode(resolveUser(identity(), { store, config }), 'ACCOUNT_COLLISION');
    expect(store.users.length).toBe(1);
  });

  it('respects the OpenSign IsDisabled flag', async () => {
    const store = createMemoryStore();
    const { userId } = await resolveUser(identity(), { store, config });
    store.ext.get(userId).isDisabled = true;
    await expectCode(resolveUser(identity(), { store, config }), 'USER_DISABLED');
  });

  it('rejects unknown users when auto provisioning is disabled', async () => {
    const store = createMemoryStore();
    await expectCode(
      resolveUser(identity(), { store, config: { ...config, autoProvision: false } }),
      'PROVISIONING_DISABLED'
    );
  });

  it('treats the same subject from a different issuer as a different identity', async () => {
    const store = createMemoryStore();
    await resolveUser(identity(), { store, config });
    await expectCode(
      resolveUser(identity({ issuer: 'https://other-idp.example.com' }), { store, config }),
      'ACCOUNT_COLLISION'
    );
  });

  it('rejects identities without email', () => {
    expect(() => identity({ email: '' })).toThrowMatching(e => e.code === 'MISSING_EMAIL');
  });

  it('hands off the session through a single-use code, not the URL', async () => {
    const store = createMemoryStore();
    const url = await completeSsoLogin(identity(), { store, config });
    const code = new URL(url).searchParams.get('sso_code');
    expect(url).not.toContain('r:');
    const token = await store.takeHandoff(code);
    expect(store.sessions.has(token)).toBe(true);
    expect(await store.takeHandoff(code)).toBeNull();
  });
});
