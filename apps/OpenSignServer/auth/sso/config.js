// OpenSign-Quantum SSO configuration.
// All settings are global deployment settings read from the environment.

export const PROTOCOLS = ['oidc', 'saml'];

export class SsoConfigError extends Error {
  constructor(message) {
    super(`[SSO] Invalid configuration: ${message}`);
    this.name = 'SsoConfigError';
  }
}

function bool(value, fallback) {
  if (value === undefined || value === null || String(value).trim() === '') return fallback;
  return ['true', '1', 'yes', 'on'].includes(String(value).trim().toLowerCase());
}

function str(value, fallback = '') {
  const v = value === undefined || value === null ? '' : String(value).trim();
  return v === '' ? fallback : v;
}

// PEM values in env files usually carry literal "\n" sequences.
function pem(value) {
  const v = str(value);
  return v ? v.replace(/\\n/g, '\n') : '';
}

// Comma-separated group list -> trimmed, de-duplicated array.
function list(value) {
  return [
    ...new Set(
      str(value)
        .split(',')
        .map(v => v.trim())
        .filter(Boolean)
    ),
  ];
}

function requireVars(env, names, protocol) {
  const missing = names.filter(name => !str(env[name]));
  if (missing.length) {
    throw new SsoConfigError(`SSO_PROTOCOL=${protocol} requires ${missing.join(', ')}`);
  }
}

function requireUrl(env, name) {
  try {
    new URL(str(env[name]));
  } catch {
    throw new SsoConfigError(`${name} must be an absolute URL`);
  }
}

/**
 * Parse and validate SSO configuration.
 * Throws SsoConfigError when SSO is enabled but misconfigured.
 */
export function loadSsoConfig(env = process.env) {
  const enabled = bool(env.SSO_ENABLED, false);
  const base = {
    enabled,
    protocol: str(env.SSO_PROTOCOL, 'oidc').toLowerCase(),
    displayName: str(env.SSO_DISPLAY_NAME, 'Sign in with SSO'),
    autoProvision: bool(env.SSO_AUTO_PROVISION, true),
    requireVerifiedEmail: bool(env.SSO_REQUIRE_VERIFIED_EMAIL, true),
    companyName: str(env.SSO_COMPANY_NAME, str(env.SSO_DISPLAY_NAME, 'SSO')),
    frontendUrl: str(env.SSO_FRONTEND_URL, str(env.PUBLIC_URL)).replace(/\/+$/, ''),
    cookieSecret: str(env.SSO_COOKIE_SECRET, str(env.MASTER_KEY)),
    // Email/password login. Turning it off requires SSO with an admin group mapping.
    localLoginEnabled: bool(env.LOCAL_LOGIN_ENABLED, true),
    // Optional IdP group -> OpenSign role mapping (exact group names, no nesting).
    roleGroups: {
      admin: list(env.SSO_ADMIN_GROUPS),
      orgAdmin: list(env.SSO_ORGADMIN_GROUPS),
      editor: list(env.SSO_EDITOR_GROUPS),
    },
    groupsClaim: str(env.SSO_GROUPS_CLAIM, 'groups'),
  };
  base.roleMappingEnabled =
    base.roleGroups.admin.length + base.roleGroups.orgAdmin.length + base.roleGroups.editor.length >
    0;
  if (!base.localLoginEnabled && !enabled) {
    throw new SsoConfigError('LOCAL_LOGIN_ENABLED=false requires SSO_ENABLED=true');
  }
  if (!enabled) return base;
  if (!base.localLoginEnabled && !base.roleGroups.admin.length) {
    throw new SsoConfigError(
      'LOCAL_LOGIN_ENABLED=false requires SSO_ADMIN_GROUPS, otherwise nobody can administer OpenSign'
    );
  }

  if (!PROTOCOLS.includes(base.protocol)) {
    throw new SsoConfigError(
      `SSO_PROTOCOL must be one of ${PROTOCOLS.join(', ')} (got "${env.SSO_PROTOCOL ?? ''}")`
    );
  }
  if (!base.frontendUrl) {
    throw new SsoConfigError('SSO_FRONTEND_URL or PUBLIC_URL is required');
  }
  if (!base.cookieSecret) {
    throw new SsoConfigError('SSO_COOKIE_SECRET (or MASTER_KEY) is required');
  }

  if (base.protocol === 'oidc') {
    requireVars(env, ['OIDC_ISSUER', 'OIDC_CLIENT_ID', 'OIDC_REDIRECT_URI'], 'oidc');
    requireUrl(env, 'OIDC_ISSUER');
    requireUrl(env, 'OIDC_REDIRECT_URI');
    const publicClient = bool(env.OIDC_PUBLIC_CLIENT, false);
    if (!publicClient && !str(env.OIDC_CLIENT_SECRET)) {
      throw new SsoConfigError(
        'OIDC_CLIENT_SECRET is required for a confidential client (set OIDC_PUBLIC_CLIENT=true for a public PKCE client)'
      );
    }
    base.oidc = {
      issuer: str(env.OIDC_ISSUER),
      clientId: str(env.OIDC_CLIENT_ID),
      clientSecret: str(env.OIDC_CLIENT_SECRET),
      publicClient,
      scopes: str(env.OIDC_SCOPES, 'openid profile email'),
      redirectUri: str(env.OIDC_REDIRECT_URI),
      postLogoutRedirectUri: str(env.OIDC_POST_LOGOUT_REDIRECT_URI, base.frontendUrl),
      // Only for local test providers served over plain http.
      allowInsecureHttp: bool(env.OIDC_ALLOW_INSECURE_HTTP, false),
    };
  } else {
    const hasStatic =
      str(env.SAML_IDP_SSO_URL) && str(env.SAML_IDP_ENTITY_ID) && str(env.SAML_IDP_CERT);
    if (!str(env.SAML_IDP_METADATA_URL) && !hasStatic) {
      throw new SsoConfigError(
        'SSO_PROTOCOL=saml requires SAML_IDP_METADATA_URL (or SAML_IDP_SSO_URL, SAML_IDP_ENTITY_ID and SAML_IDP_CERT)'
      );
    }
    requireVars(env, ['SAML_SP_ENTITY_ID', 'SAML_ACS_URL'], 'saml');
    requireUrl(env, 'SAML_ACS_URL');
    const spPrivateKey = pem(env.SAML_SP_PRIVATE_KEY);
    const spCert = pem(env.SAML_SP_CERT);
    if (Boolean(spPrivateKey) !== Boolean(spCert)) {
      throw new SsoConfigError('SAML_SP_PRIVATE_KEY and SAML_SP_CERT must be set together');
    }
    base.saml = {
      idpMetadataUrl: str(env.SAML_IDP_METADATA_URL),
      idpSsoUrl: str(env.SAML_IDP_SSO_URL),
      idpEntityId: str(env.SAML_IDP_ENTITY_ID),
      idpCert: pem(env.SAML_IDP_CERT),
      spEntityId: str(env.SAML_SP_ENTITY_ID),
      acsUrl: str(env.SAML_ACS_URL),
      logoutUrl: str(env.SAML_LOGOUT_URL),
      emailAttribute: str(env.SAML_EMAIL_ATTRIBUTE, 'email'),
      nameAttribute: str(env.SAML_NAME_ATTRIBUTE, 'name'),
      // Optional stable attribute to use as subject instead of the NameID (e.g. uid, objectGUID).
      subjectAttribute: str(env.SAML_SUBJECT_ATTRIBUTE),
      // Read only when SSO_*_GROUPS are set (same name as SSO_GROUPS_CLAIM).
      groupsAttribute: base.roleMappingEnabled ? base.groupsClaim : '',
      // Optional NameID format to request, e.g. urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
      nameIdFormat: str(env.SAML_NAMEID_FORMAT),
      // Assertion signatures are always required; the outer Response signature is required by default.
      wantResponseSigned: bool(env.SAML_WANT_RESPONSE_SIGNED, true),
      spPrivateKey,
      spCert,
      clockSkewMs: Number(str(env.SAML_CLOCK_SKEW_MS, '60000')),
    };
  }
  return base;
}

/** Browser-safe subset. Never add secrets here. */
export function getPublicConfig(config) {
  if (!config?.enabled) return { enabled: false, localLogin: true };
  return {
    enabled: true,
    protocol: config.protocol,
    displayName: config.displayName,
    localLogin: config.localLoginEnabled !== false,
  };
}
