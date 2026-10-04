// Parse-backed persistence for SSO. Tests substitute an in-memory store with the same shape.
import axios from 'axios';
import crypto from 'node:crypto';
import { cloudServerUrl, serverAppId } from '../../Utils.js';
import { createTenantAndExtUser } from '../../cloud/parsefunction/usersignup.js';

export const SSO_USER_FIELDS = ['ssoProvider', 'ssoIssuer', 'ssoSubject'];
const HANDOFF_CLASS = 'SsoHandoff';
const CACHE_CLASS = 'SsoCache';
const MASTER = { useMasterKey: true };

const sha256 = value => crypto.createHash('sha256').update(String(value)).digest('hex');

// Internal classes are master-key only: no client may read or write them.
export async function ensureSsoSchemas() {
  const lockedClp = {
    find: {},
    count: {},
    get: {},
    create: {},
    update: {},
    delete: {},
    addField: {},
    protectedFields: {},
  };
  const defs = {
    [HANDOFF_CLASS]: s => s.addString('codeHash').addString('sessionToken').addDate('expiresAt'),
    [CACHE_CLASS]: s => s.addString('key').addString('value').addDate('expiresAt'),
  };
  for (const [className, addFields] of Object.entries(defs)) {
    const schema = new Parse.Schema(className);
    let exists = true;
    try {
      await schema.get();
    } catch {
      exists = false;
    }
    if (!exists) {
      addFields(schema);
      schema.setCLP(lockedClp);
      await schema.save();
    } else {
      schema.setCLP(lockedClp);
      await schema.update();
    }
  }
}

function pointer(className, objectId) {
  return { __type: 'Pointer', className, objectId };
}

// Same shape as users created by an admin through addUser (tenant + organization + team).
async function createExtUserInOrg(userId, { identity, role, company, placement }) {
  const ext = new Parse.Object('contracts_Users');
  ext.set('UserId', pointer('_User', userId));
  ext.set('UserRole', role);
  ext.set('Email', identity.email);
  ext.set('Name', identity.name);
  ext.set('Company', company);
  ext.set('TenantId', pointer('partners_Tenant', placement.tenantId));
  ext.set('OrganizationId', pointer('contracts_Organizations', placement.orgId));
  ext.set('TeamIds', [pointer('contracts_Teams', placement.teamId)]);
  ext.set('CreatedBy', pointer('_User', userId));
  await ext.save(null, MASTER);
}

export const parseStore = {
  async findUserBySsoIdentity(issuer, subject) {
    const q = new Parse.Query(Parse.User);
    q.equalTo('ssoIssuer', issuer);
    q.equalTo('ssoSubject', subject);
    const user = await q.first(MASTER);
    return user ? { id: user.id } : null;
  },

  async emailInUse(email) {
    const userQ = new Parse.Query(Parse.User);
    userQ.equalTo('username', email);
    const emailQ = new Parse.Query(Parse.User);
    emailQ.equalTo('email', email);
    if (await Parse.Query.or(userQ, emailQ).first(MASTER)) return true;
    const extQ = new Parse.Query('contracts_Users');
    extQ.equalTo('Email', email);
    return Boolean(await extQ.first(MASTER));
  },

  // `placement` ({ tenantId, orgId, teamId }) puts the user into the shared company
  // organization (group role mapping); without it the user gets an own tenant as before.
  async createUser({ identity, role, company, placement }) {
    const user = new Parse.User();
    user.set('username', identity.email);
    // Unusable random password: SSO users never log in with a local password.
    user.set('password', crypto.randomBytes(48).toString('base64url'));
    user.set('email', identity.email);
    user.set('normalizedEmail', identity.email);
    user.set('name', identity.name);
    user.set('ssoProvider', identity.provider);
    user.set('ssoIssuer', identity.issuer);
    user.set('ssoSubject', identity.subject);
    await user.signUp(null, MASTER);
    try {
      if (placement) {
        await createExtUserInOrg(user.id, { identity, role, company, placement });
      } else {
        await createTenantAndExtUser(user.id, {
          email: identity.email,
          name: identity.name,
          role,
          company,
        });
      }
    } catch (err) {
      // Do not leave a half-provisioned _User behind.
      await user.destroy(MASTER).catch(() => {});
      throw err;
    }
    return { id: user.id };
  },

  async getExtUser(userId) {
    const q = new Parse.Query('contracts_Users');
    q.equalTo('UserId', pointer('_User', userId));
    const ext = await q.first(MASTER);
    return ext
      ? {
          id: ext.id,
          role: ext.get('UserRole'),
          isDisabled: ext.get('IsDisabled') === true,
          tenantId: ext.get('TenantId')?.id,
        }
      : null;
  },

  async setRole(extUserId, role) {
    const ext = new Parse.Object('contracts_Users');
    ext.id = extUserId;
    ext.set('UserRole', role);
    await ext.save(null, MASTER);
  },

  // The shared tenant/organization/team for SSO users; created once (see ensureCompanyOrg).
  async findCompanyOrg() {
    const q = new Parse.Query('contracts_Organizations');
    q.equalTo('SsoManaged', true);
    q.ascending('createdAt');
    const org = await q.first(MASTER);
    if (!org) return null;
    const teamQ = new Parse.Query('contracts_Teams');
    teamQ.equalTo('OrganizationId', pointer('contracts_Organizations', org.id));
    teamQ.equalTo('Name', 'All Users');
    const team = await teamQ.first(MASTER);
    return { tenantId: org.get('TenantId')?.id, orgId: org.id, teamId: team?.id };
  },

  async createCompanyOrg(company) {
    const tenant = new Parse.Object('partners_Tenant');
    tenant.set('TenantName', company);
    tenant.set('IsActive', true);
    await tenant.save(null, MASTER);
    const org = new Parse.Object('contracts_Organizations');
    org.set('Name', company);
    org.set('IsActive', true);
    org.set('SsoManaged', true);
    org.set('TenantId', pointer('partners_Tenant', tenant.id));
    await org.save(null, MASTER);
    const team = new Parse.Object('contracts_Teams');
    team.set('Name', 'All Users');
    team.set('IsActive', true);
    team.set('OrganizationId', pointer('contracts_Organizations', org.id));
    await team.save(null, MASTER);
    return { tenantId: tenant.id, orgId: org.id, teamId: team.id };
  },
  // Same mechanism as usersignup.js: Parse's master-key /loginAs creates a normal Parse session.
  async createSession(userId) {
    const res = await axios.post(`${cloudServerUrl}/loginAs`, null, {
      headers: {
        'X-Parse-Application-Id': serverAppId,
        'X-Parse-Master-Key': process.env.MASTER_KEY,
      },
      params: { userId },
    });
    return res.data.sessionToken;
  },

  // Returns whether the session belonged to an SSO user (only they get the IdP logout URL).
  async destroySession(sessionToken) {
    const q = new Parse.Query(Parse.Session);
    q.equalTo('sessionToken', sessionToken);
    q.include('user');
    const session = await q.first(MASTER);
    if (!session) return { ssoUser: false };
    const ssoUser = Boolean(session.get('user')?.get('ssoSubject'));
    await session.destroy(MASTER);
    return { ssoUser };
  },

  async saveHandoff(code, sessionToken, ttlMs) {
    const obj = new Parse.Object(HANDOFF_CLASS);
    obj.set('codeHash', sha256(code));
    obj.set('sessionToken', sessionToken);
    obj.set('expiresAt', new Date(Date.now() + ttlMs));
    await obj.save(null, MASTER);
  },

  async takeHandoff(code) {
    const q = new Parse.Query(HANDOFF_CLASS);
    q.equalTo('codeHash', sha256(code));
    const obj = await q.first(MASTER);
    if (!obj) return null;
    await obj.destroy(MASTER); // single use
    if (obj.get('expiresAt') < new Date()) return null;
    return obj.get('sessionToken');
  },

  cache: {
    async put(key, value, ttlMs) {
      const obj = new Parse.Object(CACHE_CLASS);
      obj.set('key', key);
      obj.set('value', String(value));
      obj.set('expiresAt', new Date(Date.now() + ttlMs));
      await obj.save(null, MASTER);
    },
    async get(key) {
      const q = new Parse.Query(CACHE_CLASS);
      q.equalTo('key', key);
      q.greaterThan('expiresAt', new Date());
      const obj = await q.first(MASTER);
      return obj ? obj.get('value') : null;
    },
    async remove(key) {
      const q = new Parse.Query(CACHE_CLASS);
      q.equalTo('key', key);
      const objs = await q.find(MASTER);
      await Parse.Object.destroyAll(objs, MASTER).catch(() => {});
    },
  },
};
