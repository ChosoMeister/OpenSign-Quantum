import { roleFromGroups } from '../../auth/sso/roles.js';
import { loadSsoConfig, getPublicConfig } from '../../auth/sso/config.js';
import { resolveUser } from '../../auth/sso/userProvisioning.js';
import { normalizeIdentity } from '../../auth/sso/identity.js';
import { resetCompanyOrgCache } from '../../auth/sso/company.js';
import { createMemoryStore } from './support/memoryStore.js';

const roleGroups = {
  admin: ['opensign-admins'],
  orgAdmin: ['opensign-orgadmins'],
  editor: ['opensign-editors'],
};

describe('IdP group -> role mapping', () => {
  it('picks the highest role and defaults to User', () => {
    expect(roleFromGroups(['opensign-editors', 'opensign-admins'], roleGroups)).toBe(
      'contracts_Admin'
    );
    expect(roleFromGroups(['opensign-orgadmins'], roleGroups)).toBe('contracts_OrgAdmin');
    expect(roleFromGroups(['opensign-editors'], roleGroups)).toBe('contracts_Editor');
    expect(roleFromGroups(['sales'], roleGroups)).toBe('contracts_User');
    expect(roleFromGroups(undefined, roleGroups)).toBe('contracts_User');
  });

  it('accepts Keycloak full-path group names and ignores case', () => {
    expect(roleFromGroups(['/OpenSign-Admins'], roleGroups)).toBe('contracts_Admin');
  });
});

describe('role mapping and local login configuration', () => {
  const base = {
    PUBLIC_URL: 'https://sign.example.com',
    MASTER_KEY: 'mk',
    SSO_ENABLED: 'true',
    SSO_PROTOCOL: 'oidc',
    OIDC_ISSUER: 'https://idp.example.com',
    OIDC_CLIENT_ID: 'opensign',
    OIDC_CLIENT_SECRET: 's',
    OIDC_REDIRECT_URI: 'https://sign.example.com/api/auth/oidc/callback',
  };

  it('keeps local login on and no mapping by default', () => {
    const cfg = loadSsoConfig(base);
    expect(cfg.localLoginEnabled).toBe(true);
    expect(cfg.roleMappingEnabled).toBe(false);
  });

  it('parses comma-separated group lists', () => {
    const cfg = loadSsoConfig({ ...base, SSO_ADMIN_GROUPS: 'a, b ,a', SSO_EDITOR_GROUPS: 'e' });
    expect(cfg.roleGroups.admin).toEqual(['a', 'b']);
    expect(cfg.roleMappingEnabled).toBe(true);
  });

  it('refuses LOCAL_LOGIN_ENABLED=false without SSO or without an admin group', () => {
    expect(() => loadSsoConfig({ LOCAL_LOGIN_ENABLED: 'false' })).toThrowError(/SSO_ENABLED/);
    expect(() => loadSsoConfig({ ...base, LOCAL_LOGIN_ENABLED: 'false' })).toThrowError(
      /SSO_ADMIN_GROUPS/
    );
    expect(() =>
      loadSsoConfig({ ...base, LOCAL_LOGIN_ENABLED: 'false', SSO_ADMIN_GROUPS: 'opensign-admins' })
    ).not.toThrow();
  });

  it('tells the browser whether the local form is shown', () => {
    const cfg = loadSsoConfig({ ...base, LOCAL_LOGIN_ENABLED: 'false', SSO_ADMIN_GROUPS: 'x' });
    expect(getPublicConfig(cfg)).toEqual({
      enabled: true,
      protocol: 'oidc',
      displayName: 'Sign in with SSO',
      localLogin: false,
    });
    expect(JSON.stringify(getPublicConfig(cfg))).not.toContain('opensign');
  });
});

describe('provisioning with group role mapping', () => {
  const config = {
    autoProvision: true,
    companyName: 'Acme',
    frontendUrl: 'https://sign.example.com',
    roleMappingEnabled: true,
    roleGroups,
  };
  const identity = (groups, over = {}) =>
    normalizeIdentity({
      provider: 'oidc',
      issuer: 'https://idp',
      subject: 's1',
      email: 'a@example.com',
      name: 'A',
      groups,
      ...over,
    });

  beforeEach(() => resetCompanyOrgCache());

  it('creates admins and users in one shared company organization', async () => {
    const store = createMemoryStore();
    const admin = await resolveUser(identity(['opensign-admins']), { store, config });
    const user = await resolveUser(identity([], { subject: 's2', email: 'b@example.com' }), {
      store,
      config,
    });
    expect(admin.role).toBe('contracts_Admin');
    expect(user.role).toBe('contracts_User');
    expect(store.orgs.length).toBe(1);
    const tenants = [...store.ext.values()].map(e => e.tenantId);
    expect(new Set(tenants).size).toBe(1);
  });

  it('promotes and demotes on the next login from IdP groups', async () => {
    const store = createMemoryStore();
    expect((await resolveUser(identity([]), { store, config })).role).toBe('contracts_User');
    expect((await resolveUser(identity(['opensign-editors']), { store, config })).role).toBe(
      'contracts_Editor'
    );
    expect((await resolveUser(identity(['/opensign-admins']), { store, config })).role).toBe(
      'contracts_Admin'
    );
    expect((await resolveUser(identity([]), { store, config })).role).toBe('contracts_User');
    expect(store.users.length).toBe(1);
  });

  it('moves users created before the mapping into the company organization', async () => {
    const store = createMemoryStore();
    // Provisioned without a mapping: own tenant, no organization.
    const { userId } = await resolveUser(identity([]), {
      store,
      config: { ...config, roleMappingEnabled: false },
    });
    expect(store.ext.get(userId).orgId).toBeUndefined();
    const res = await resolveUser(identity(['opensign-admins']), { store, config });
    expect(res.role).toBe('contracts_Admin');
    expect(store.ext.get(userId).orgId).toBe(store.orgs[0].orgId);
  });

  it('does not touch roles it does not manage', async () => {
    const store = createMemoryStore();
    const { userId } = await resolveUser(identity([]), { store, config });
    store.ext.get(userId).role = 'contracts_Guest';
    expect((await resolveUser(identity(['opensign-admins']), { store, config })).role).toBe(
      'contracts_Guest'
    );
  });

  it('still refuses disabled users before changing their role', async () => {
    const store = createMemoryStore();
    const { userId } = await resolveUser(identity([]), { store, config });
    store.ext.get(userId).isDisabled = true;
    await expectAsync(
      resolveUser(identity(['opensign-admins']), { store, config })
    ).toBeRejectedWith(jasmine.objectContaining({ code: 'USER_DISABLED' }));
    expect(store.ext.get(userId).role).toBe('contracts_User');
  });

  it('ignores groups entirely without a mapping', async () => {
    const store = createMemoryStore();
    const res = await resolveUser(identity(['opensign-admins']), {
      store,
      config: { ...config, roleMappingEnabled: false },
    });
    expect(res.role).toBe('contracts_User');
    expect(store.orgs.length).toBe(0);
  });
});
