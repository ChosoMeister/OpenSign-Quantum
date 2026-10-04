// The single company organization that SSO users join when group role mapping is enabled.
// OpenSign admins manage users within their tenant/organization, so all SSO users must share
// one; otherwise a group-mapped admin could not see or manage anyone.
let cached = null;
let pending = null;

export async function ensureCompanyOrg(store, config) {
  if (cached) return cached;
  // Single in-process lock: concurrent first logins must not create two organizations.
  pending ??= (async () => {
    const found = await store.findCompanyOrg();
    cached = found?.teamId ? found : await store.createCompanyOrg(config.companyName);
    return cached;
  })().finally(() => {
    pending = null;
  });
  return pending;
}

// Test helper.
export function resetCompanyOrgCache() {
  cached = null;
  pending = null;
}
