// SAML checks layered on top of node-saml's cryptographic validation, plus attribute mapping.
// node-saml verifies signatures, audience, NotBefore/NotOnOrAfter and InResponseTo;
// it does not check Issuer on login responses, Response@Destination or
// SubjectConfirmationData@Recipient, so we do.
import { DOMParser } from '@xmldom/xmldom';
import xpath from 'xpath';
import { SsoError } from '../errors.js';
import { normalizeIdentity } from '../identity.js';

const select = xpath.useNamespaces({
  samlp: 'urn:oasis:names:tc:SAML:2.0:protocol',
  saml: 'urn:oasis:names:tc:SAML:2.0:assertion',
});

/**
 * Structural checks on the (already signature-verified) response XML.
 * Requiring exactly one Response and one Assertion also defeats signature-wrapping tricks.
 */
export function checkResponseStructure(samlResponseXml, { acsUrl, idpEntityId }) {
  const doc = new DOMParser().parseFromString(samlResponseXml, 'text/xml');
  const responses = select('//samlp:Response', doc);
  const assertions = select('//saml:Assertion', doc);
  if (responses.length !== 1 || assertions.length !== 1) {
    throw new SsoError(
      'VALIDATION_FAILED',
      'SAML response must contain exactly one Response and one Assertion'
    );
  }
  if (select('//saml:EncryptedAssertion', doc).length) {
    throw new SsoError('VALIDATION_FAILED', 'encrypted assertions are not supported');
  }
  for (const node of [responses[0], assertions[0]]) {
    const issuer = select('saml:Issuer', node)[0]?.textContent?.trim();
    if (issuer !== idpEntityId) throw new SsoError('VALIDATION_FAILED', 'SAML Issuer mismatch');
  }
  const destination = responses[0].getAttribute('Destination');
  if (!destination || destination !== acsUrl) {
    throw new SsoError('VALIDATION_FAILED', 'SAML Destination mismatch');
  }
  const confirmations = select(
    './/saml:SubjectConfirmation/saml:SubjectConfirmationData',
    assertions[0]
  );
  if (!confirmations.length) {
    throw new SsoError('VALIDATION_FAILED', 'SAML SubjectConfirmationData missing');
  }
  for (const node of confirmations) {
    if (node.getAttribute('Recipient') !== acsUrl) {
      throw new SsoError('VALIDATION_FAILED', 'SAML Recipient mismatch');
    }
  }
  return { assertionId: assertions[0].getAttribute('ID') };
}

const first = value => (Array.isArray(value) ? value[0] : value);
const EMAIL_ATTRS = [
  'email',
  'mail',
  'emailAddress',
  'urn:oid:0.9.2342.19200300.100.1.3',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
];
const NAME_ATTRS = [
  'name',
  'displayName',
  'urn:oid:2.16.840.1.113730.3.1.241',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
];
const GIVEN_ATTRS = [
  'givenName',
  'urn:oid:2.5.4.42',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
];
const SURNAME_ATTRS = [
  'surname',
  'sn',
  'urn:oid:2.5.4.4',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
];

function pick(profile, names) {
  for (const n of names) {
    const v = first(profile?.[n]);
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return '';
}

/** Map a validated node-saml profile to the normalized identity. */
export function identityFromProfile(
  profile,
  { idpEntityId, emailAttribute, nameAttribute, subjectAttribute, groupsAttribute }
) {
  if (!profile?.nameID) throw new SsoError('VALIDATION_FAILED', 'SAML assertion has no NameID');
  let subject;
  if (subjectAttribute) {
    subject = pick(profile, [subjectAttribute]);
    if (!subject)
      throw new SsoError('VALIDATION_FAILED', `missing subject attribute ${subjectAttribute}`);
  } else if (profile.nameIDFormat === 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient') {
    // Transient IDs change every login and cannot identify a returning user.
    throw new SsoError('VALIDATION_FAILED', 'transient NameID is not a stable identifier');
  } else {
    subject = profile.nameID;
  }
  const emailFromNameId = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(profile.nameID) ? profile.nameID : '';
  const email = pick(profile, [emailAttribute, ...EMAIL_ATTRS]) || emailFromNameId;
  if (!email) throw new SsoError('MISSING_EMAIL', 'no email attribute');
  const name =
    pick(profile, [nameAttribute, ...NAME_ATTRS]) ||
    [pick(profile, GIVEN_ATTRS), pick(profile, SURNAME_ATTRS)].filter(Boolean).join(' ');

  return normalizeIdentity({
    provider: 'saml',
    issuer: idpEntityId || profile.issuer,
    subject,
    email,
    name,
    // Multi-valued attribute: node-saml returns a string for one value, an array for several.
    groups: groupsAttribute ? profile[groupsAttribute] : undefined,
  });
}
