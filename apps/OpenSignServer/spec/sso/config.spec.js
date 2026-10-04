import { loadSsoConfig, getPublicConfig } from '../../auth/sso/config.js';

const base = { PUBLIC_URL: 'https://sign.example.com', MASTER_KEY: 'mk' };
const oidcEnv = {
  ...base,
  SSO_ENABLED: 'true',
  SSO_PROTOCOL: 'oidc',
  OIDC_ISSUER: 'https://idp.example.com',
  OIDC_CLIENT_ID: 'opensign',
  OIDC_CLIENT_SECRET: 'super-secret',
  OIDC_REDIRECT_URI: 'https://sign.example.com/api/auth/oidc/callback',
};
const samlEnv = {
  ...base,
  SSO_ENABLED: 'true',
  SSO_PROTOCOL: 'saml',
  SAML_IDP_METADATA_URL: 'https://idp.example.com/metadata',
  SAML_SP_ENTITY_ID: 'https://sign.example.com',
  SAML_ACS_URL: 'https://sign.example.com/api/auth/saml/callback',
};

describe('SSO config', () => {
  it('is disabled by default and exposes nothing else', () => {
    const cfg = loadSsoConfig({});
    expect(cfg.enabled).toBe(false);
    expect(getPublicConfig(cfg)).toEqual({ enabled: false, localLogin: true });
  });

  it('applies recommended defaults', () => {
    const cfg = loadSsoConfig(oidcEnv);
    expect(cfg.autoProvision).toBe(true);
    expect(cfg.requireVerifiedEmail).toBe(true);
    expect(cfg.displayName).toBe('Sign in with SSO');
    expect(cfg.oidc.scopes).toBe('openid profile email');
  });

  it('rejects an invalid SSO_PROTOCOL', () => {
    expect(() => loadSsoConfig({ ...oidcEnv, SSO_PROTOCOL: 'ldap' })).toThrowError(
      /SSO_PROTOCOL must be one of/
    );
  });

  it('requires OIDC settings', () => {
    expect(() => loadSsoConfig({ ...oidcEnv, OIDC_ISSUER: '' })).toThrowError(/OIDC_ISSUER/);
    expect(() => loadSsoConfig({ ...oidcEnv, OIDC_CLIENT_SECRET: '' })).toThrowError(
      /OIDC_CLIENT_SECRET/
    );
    expect(() =>
      loadSsoConfig({ ...oidcEnv, OIDC_CLIENT_SECRET: '', OIDC_PUBLIC_CLIENT: 'true' })
    ).not.toThrow();
  });

  it('requires SAML settings', () => {
    expect(() => loadSsoConfig(samlEnv)).not.toThrow();
    expect(() => loadSsoConfig({ ...samlEnv, SAML_IDP_METADATA_URL: '' })).toThrowError(
      /SAML_IDP_METADATA_URL/
    );
    expect(() => loadSsoConfig({ ...samlEnv, SAML_ACS_URL: '' })).toThrowError(/SAML_ACS_URL/);
  });

  it('public config never contains secrets', () => {
    const pub = getPublicConfig(loadSsoConfig({ ...oidcEnv, SSO_DISPLAY_NAME: 'Company SSO' }));
    expect(pub).toEqual({
      enabled: true,
      protocol: 'oidc',
      displayName: 'Company SSO',
      localLogin: true,
    });
    expect(JSON.stringify(pub)).not.toContain('super-secret');
  });
});
