// Test SAML IdP: generates a key pair, publishes metadata, and issues signed Responses.
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import forge from 'node-forge';
import { SignedXml } from 'xml-crypto';

export const IDP_ENTITY = 'https://idp.test/saml';
export const SP_ENTITY = 'https://sign.example.com';
export const ACS = 'https://sign.example.com/api/auth/saml/callback';

export function makeKeyPair(cn = 'test-idp') {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 86400000);
  cert.validity.notAfter = new Date(Date.now() + 365 * 86400000);
  const attrs = [{ name: 'commonName', value: cn }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  const certPem = forge.pki.certificateToPem(cert);
  return {
    privateKey: forge.pki.privateKeyToPem(keys.privateKey),
    certPem,
    certB64: certPem.replace(/-----[^-]+-----|\s/g, ''),
  };
}

export function idpMetadata(certB64) {
  return `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="${IDP_ENTITY}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${certB64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;
}

export function requestIdFromLoginUrl(url) {
  const xml = zlib
    .inflateRawSync(Buffer.from(new URL(url).searchParams.get('SAMLRequest'), 'base64'))
    .toString();
  return /ID="([^"]+)"/.exec(xml)[1];
}

const iso = ms => new Date(Date.now() + ms).toISOString();

function sign(xml, xpath, key, certPem) {
  const sig = new SignedXml({
    privateKey: key,
    publicCert: certPem,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  });
  sig.addReference({
    xpath,
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
  });
  sig.computeSignature(xml, {
    location: { reference: `${xpath}/*[local-name(.)='Issuer']`, action: 'after' },
  });
  return sig.getSignedXml();
}

/** Build a base64 SAMLResponse. Every field can be overridden to produce invalid variants. */
export function buildResponse(keys, o = {}) {
  const v = {
    inResponseTo: 'unknown',
    issuer: IDP_ENTITY,
    audience: SP_ENTITY,
    destination: ACS,
    recipient: ACS,
    notBefore: iso(-60000),
    notOnOrAfter: iso(5 * 60000),
    nameId: 'persistent-abc',
    nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    attributes: { email: 'sam@example.com', displayName: 'Sam Smith', groups: 'admins' },
    assertionId: `_a${crypto.randomBytes(8).toString('hex')}`,
    signingKeys: keys,
    ...o,
  };
  const attrs = Object.entries(v.attributes)
    .map(
      ([k, val]) =>
        `<saml:Attribute Name="${k}"><saml:AttributeValue>${val}</saml:AttributeValue></saml:Attribute>`
    )
    .join('');
  const now = iso(0);
  const assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${v.assertionId}" Version="2.0" IssueInstant="${now}"><saml:Issuer>${v.issuer}</saml:Issuer><saml:Subject><saml:NameID Format="${v.nameIdFormat}">${v.nameId}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${v.inResponseTo}" NotOnOrAfter="${v.notOnOrAfter}" Recipient="${v.recipient}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${v.notBefore}" NotOnOrAfter="${v.notOnOrAfter}"><saml:AudienceRestriction><saml:Audience>${v.audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${now}" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement>${attrs}</saml:AttributeStatement></saml:Assertion>`;
  const signedAssertion = sign(
    assertion,
    "/*[local-name(.)='Assertion']",
    v.signingKeys.privateKey,
    v.signingKeys.certPem
  );
  const response = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r${crypto.randomBytes(8).toString('hex')}" Version="2.0" IssueInstant="${now}" Destination="${v.destination}" InResponseTo="${v.inResponseTo}"><saml:Issuer>${v.issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${signedAssertion.replace(/^<\?xml[^>]*>/, '')}</samlp:Response>`;
  const signed = sign(
    response,
    "/*[local-name(.)='Response']",
    v.signingKeys.privateKey,
    v.signingKeys.certPem
  );
  return Buffer.from(signed).toString('base64');
}
