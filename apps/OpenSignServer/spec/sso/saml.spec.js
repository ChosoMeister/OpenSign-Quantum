import { createSamlProvider } from '../../auth/sso/saml/provider.js';
import { identityFromProfile } from '../../auth/sso/saml/validation.js';
import { createMemoryStore } from './support/memoryStore.js';
import {
  makeKeyPair,
  idpMetadata,
  buildResponse,
  requestIdFromLoginUrl,
  IDP_ENTITY,
  SP_ENTITY,
  ACS,
} from './support/samlIdp.js';

describe('SAML', () => {
  let keys;
  let attackerKeys;
  let store;
  let provider;
  const samlConfig = {
    idpMetadataUrl: 'https://idp.test/metadata',
    spEntityId: SP_ENTITY,
    acsUrl: ACS,
    emailAttribute: 'email',
    nameAttribute: 'name',
    clockSkewMs: 1000,
  };

  beforeAll(() => {
    keys = makeKeyPair();
    attackerKeys = makeKeyPair('attacker');
  });
  beforeEach(() => {
    store = createMemoryStore();
    provider = createSamlProvider(samlConfig, {
      store,
      fetchMetadata: async () => idpMetadata(keys.certB64),
    });
  });

  async function freshRequestId() {
    return requestIdFromLoginUrl(await provider.buildLoginUrl());
  }

  async function expectCode(promise, code) {
    try {
      await promise;
      fail('expected rejection');
    } catch (e) {
      expect(e.code).toBe(code);
    }
  }

  it('sends an AuthnRequest to the IdP from metadata', async () => {
    const url = await provider.buildLoginUrl();
    expect(url.startsWith('https://idp.test/sso?SAMLRequest=')).toBe(true);
  });

  it('accepts a valid signed SAML response', async () => {
    const inResponseTo = await freshRequestId();
    const id = await provider.handleCallback({
      SAMLResponse: buildResponse(keys, { inResponseTo }),
    });
    expect(id).toEqual(
      jasmine.objectContaining({
        provider: 'saml',
        issuer: IDP_ENTITY,
        subject: 'persistent-abc',
        email: 'sam@example.com',
        name: 'Sam Smith',
      })
    );
    expect(id.groups).toBeUndefined();
  });

  it('rejects an invalid signature', async () => {
    const inResponseTo = await freshRequestId();
    await expectCode(
      provider.handleCallback({
        SAMLResponse: buildResponse(keys, { inResponseTo, signingKeys: attackerKeys }),
      }),
      'VALIDATION_FAILED'
    );
  });

  it('rejects a tampered response', async () => {
    const inResponseTo = await freshRequestId();
    const xml = Buffer.from(buildResponse(keys, { inResponseTo }), 'base64')
      .toString()
      .replace('sam@example.com', 'admin@example.com');
    await expectCode(
      provider.handleCallback({ SAMLResponse: Buffer.from(xml).toString('base64') }),
      'VALIDATION_FAILED'
    );
  });

  it('rejects an incorrect issuer', async () => {
    const inResponseTo = await freshRequestId();
    await expectCode(
      provider.handleCallback({
        SAMLResponse: buildResponse(keys, { inResponseTo, issuer: 'https://evil.test' }),
      }),
      'VALIDATION_FAILED'
    );
  });

  it('rejects an incorrect audience', async () => {
    const inResponseTo = await freshRequestId();
    await expectCode(
      provider.handleCallback({
        SAMLResponse: buildResponse(keys, { inResponseTo, audience: 'https://other-sp' }),
      }),
      'VALIDATION_FAILED'
    );
  });

  it('rejects an expired assertion', async () => {
    const inResponseTo = await freshRequestId();
    const past = new Date(Date.now() - 3600000).toISOString();
    await expectCode(
      provider.handleCallback({
        SAMLResponse: buildResponse(keys, {
          inResponseTo,
          notOnOrAfter: past,
          notBefore: new Date(Date.now() - 7200000).toISOString(),
        }),
      }),
      'VALIDATION_FAILED'
    );
  });

  it('rejects an invalid destination', async () => {
    const inResponseTo = await freshRequestId();
    await expectCode(
      provider.handleCallback({
        SAMLResponse: buildResponse(keys, { inResponseTo, destination: 'https://evil.test/acs' }),
      }),
      'VALIDATION_FAILED'
    );
  });

  it('rejects an invalid recipient', async () => {
    const inResponseTo = await freshRequestId();
    await expectCode(
      provider.handleCallback({
        SAMLResponse: buildResponse(keys, { inResponseTo, recipient: 'https://evil.test/acs' }),
      }),
      'VALIDATION_FAILED'
    );
  });

  it('rejects an invalid InResponseTo (unsolicited / login CSRF)', async () => {
    await freshRequestId();
    await expectCode(
      provider.handleCallback({
        SAMLResponse: buildResponse(keys, { inResponseTo: '_not-issued-by-us' }),
      }),
      'VALIDATION_FAILED'
    );
  });

  it('rejects a missing email', async () => {
    const inResponseTo = await freshRequestId();
    await expectCode(
      provider.handleCallback({
        SAMLResponse: buildResponse(keys, { inResponseTo, attributes: { displayName: 'No Mail' } }),
      }),
      'MISSING_EMAIL'
    );
  });

  it('rejects a replayed response', async () => {
    const inResponseTo = await freshRequestId();
    const SAMLResponse = buildResponse(keys, { inResponseTo });
    await provider.handleCallback({ SAMLResponse });
    await expectCode(provider.handleCallback({ SAMLResponse }), 'VALIDATION_FAILED');
  });

  it('reports unavailable metadata as provider unavailable', async () => {
    const p = createSamlProvider(samlConfig, {
      store,
      fetchMetadata: async () => {
        throw new Error('ECONNREFUSED');
      },
    });
    await expectCode(p.buildLoginUrl(), 'PROVIDER_UNAVAILABLE');
  });

  it('generates SP metadata with entity ID and ACS', async () => {
    const xml = await provider.generateMetadata();
    expect(xml).toContain(`entityID="${SP_ENTITY}"`);
    expect(xml).toContain(`Location="${ACS}"`);
    expect(xml).toContain('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');
  });

  describe('attribute mapping', () => {
    const opts = { idpEntityId: IDP_ENTITY, emailAttribute: 'corpMail', nameAttribute: 'corpName' };
    it('prefers configured attributes', () => {
      const id = identityFromProfile(
        {
          issuer: IDP_ENTITY,
          nameID: 'n1',
          corpMail: 'a@example.com',
          email: 'b@example.com',
          corpName: 'A',
        },
        opts
      );
      expect(id.email).toBe('a@example.com');
      expect(id.name).toBe('A');
    });
    it('falls back to standard attributes and givenName + surname', () => {
      const id = identityFromProfile(
        { issuer: IDP_ENTITY, nameID: 'n1', mail: ['c@example.com'], givenName: 'C', surname: 'D' },
        opts
      );
      expect(id.email).toBe('c@example.com');
      expect(id.name).toBe('C D');
    });
    it('uses a configured stable subject attribute (allows transient NameID)', () => {
      const id = identityFromProfile(
        {
          issuer: IDP_ENTITY,
          nameID: '_transient123',
          nameIDFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
          uid: 'emp-42',
          email: 'e@example.com',
        },
        { ...opts, subjectAttribute: 'uid' }
      );
      expect(id.subject).toBe('emp-42');
    });
    it('rejects transient NameIDs', () => {
      expect(() =>
        identityFromProfile(
          {
            issuer: IDP_ENTITY,
            nameID: 'x',
            nameIDFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
            email: 'e@example.com',
          },
          opts
        )
      ).toThrowMatching(e => e.code === 'VALIDATION_FAILED');
    });
  });
});
