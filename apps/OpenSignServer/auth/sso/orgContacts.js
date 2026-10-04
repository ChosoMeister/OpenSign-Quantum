// Lists colleagues from the SSO-managed company organization as signers.
// OpenSign signers are contracts_Contactbook records owned by the requesting user, so each
// colleague gets a contact in the caller's book (linked to the colleague's own _User),
// created on demand. Only applies to the SSO company organization; upstream behaviour
// for other organizations is unchanged.
const MASTER = { useMasterKey: true };
const ptr = (className, objectId) => ({ __type: 'Pointer', className, objectId });
const escapeRegExp = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

async function callerCompanyOrg(user) {
  const q = new Parse.Query('contracts_Users');
  q.equalTo('UserId', ptr('_User', user.id));
  q.include('OrganizationId');
  const ext = await q.first(MASTER);
  const org = ext?.get('OrganizationId');
  return org?.get('SsoManaged') ? { ext, org } : null;
}

export async function withOrgColleagues(user, search, contacts) {
  const scope = await callerCompanyOrg(user);
  if (!scope) return contacts;

  const regex = new RegExp(escapeRegExp(search || ''), 'i');
  const byName = new Parse.Query('contracts_Users');
  byName.matches('Name', regex);
  const byEmail = new Parse.Query('contracts_Users');
  byEmail.matches('Email', regex);
  const colleaguesQ = Parse.Query.or(byName, byEmail);
  colleaguesQ.equalTo('OrganizationId', ptr('contracts_Organizations', scope.org.id));
  colleaguesQ.notEqualTo('IsDisabled', true);
  colleaguesQ.notEqualTo('UserId', ptr('_User', user.id));
  colleaguesQ.limit(500);
  const colleagues = await colleaguesQ.find(MASTER);

  const known = new Set(contacts.map(c => String(c.Email || '').toLowerCase()));
  const added = [];
  for (const col of colleagues) {
    const email = String(col.get('Email') || '').toLowerCase();
    if (!email || known.has(email)) continue;
    const contact = new Parse.Object('contracts_Contactbook');
    contact.set('Name', col.get('Name'));
    contact.set('Email', email);
    contact.set('UserRole', 'contracts_Guest');
    contact.set('IsDeleted', false);
    contact.set('TenantId', ptr('partners_Tenant', scope.ext.get('TenantId').id));
    contact.set('CreatedBy', ptr('_User', user.id));
    contact.set('UserId', col.get('UserId'));
    const acl = new Parse.ACL();
    acl.setReadAccess(user.id, true);
    acl.setWriteAccess(user.id, true);
    acl.setReadAccess(col.get('UserId').id, true);
    contact.setACL(acl);
    await contact.save(null, MASTER);
    known.add(email);
    added.push(JSON.parse(JSON.stringify(contact)));
  }
  // Hide contacts of colleagues an admin has deactivated in OpenSign.
  const disabledQ = new Parse.Query('contracts_Users');
  disabledQ.equalTo('OrganizationId', ptr('contracts_Organizations', scope.org.id));
  disabledQ.equalTo('IsDisabled', true);
  disabledQ.limit(500);
  const disabled = new Set(
    (await disabledQ.find(MASTER)).map(u => String(u.get('Email') || '').toLowerCase())
  );
  return [...contacts, ...added].filter(c => !disabled.has(String(c.Email || '').toLowerCase()));
}
