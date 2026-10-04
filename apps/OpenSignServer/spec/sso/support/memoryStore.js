// In-memory implementation of the SSO store interface (auth/sso/store.js) for tests.
export function createMemoryStore() {
  const users = []; // { id, email, ssoIssuer, ssoSubject }
  const ext = new Map(); // userId -> { id, role, isDisabled }
  const handoffs = new Map();
  const cache = new Map();
  const sessions = new Set();
  let seq = 0;

  return {
    users,
    ext,
    sessions,
    addLocalUser(email, { role = 'contracts_Admin', isDisabled = false } = {}) {
      const id = `local${++seq}`;
      users.push({ id, email });
      ext.set(id, { id: `ext${id}`, role, isDisabled });
      return id;
    },
    async findUserBySsoIdentity(issuer, subject) {
      const u = users.find(x => x.ssoIssuer === issuer && x.ssoSubject === subject);
      return u ? { id: u.id } : null;
    },
    async emailInUse(email) {
      return users.some(u => u.email === email);
    },
    orgs: [],
    async createUser({ identity, role, placement }) {
      const id = `sso${++seq}`;
      users.push({
        id,
        email: identity.email,
        ssoIssuer: identity.issuer,
        ssoSubject: identity.subject,
        name: identity.name,
      });
      ext.set(id, { id: `ext${id}`, role, isDisabled: false, tenantId: placement?.tenantId });
      return { id };
    },
    async setRole(extId, role) {
      for (const e of ext.values()) if (e.id === extId) e.role = role;
    },
    async findCompanyOrg() {
      return this.orgs[0] || null;
    },
    async createCompanyOrg(company) {
      const org = { tenantId: `t${++seq}`, orgId: `o${seq}`, teamId: `team${seq}`, company };
      this.orgs.push(org);
      return org;
    },
    async getExtUser(userId) {
      return ext.get(userId) || null;
    },
    async createSession(userId) {
      const token = `r:${userId}:${++seq}`;
      sessions.add(token);
      return token;
    },
    async destroySession(token) {
      const existed = sessions.delete(token);
      const userId = token.split(':')[1];
      return { ssoUser: existed && users.some(u => u.id === userId && u.ssoSubject) };
    },
    async saveHandoff(code, token, ttl) {
      handoffs.set(code, { token, exp: Date.now() + ttl });
    },
    async takeHandoff(code) {
      const h = handoffs.get(code);
      handoffs.delete(code);
      return h && h.exp > Date.now() ? h.token : null;
    },
    cache: {
      async put(k, v, ttl) {
        cache.set(k, { v, exp: Date.now() + ttl });
      },
      async get(k) {
        const e = cache.get(k);
        return e && e.exp > Date.now() ? e.v : null;
      },
      async remove(k) {
        cache.delete(k);
      },
    },
  };
}
