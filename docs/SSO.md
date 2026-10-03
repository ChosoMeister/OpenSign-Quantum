# OpenSign-Quantum Single Sign-On

OpenSign-Quantum adds vendor-neutral enterprise SSO to self-hosted OpenSign. It supports **OpenID Connect** or **SAML 2.0** with a single Identity Provider (IdP) per deployment. Local email/password login stays available for administrators.

- Any standards-compliant IdP can be used: Keycloak, Entra ID, Okta, ADFS, Authentik, Ping, OneLogin, SimpleSAMLphp and others. The code contains no vendor-specific logic.
- `SSO_ENABLED=false` (the default) gives upstream OpenSign behaviour.
- No OpenSignLabs-hosted service is involved. The upstream `sso.opensignlabs.com` adapter has been removed.

## Architecture

```
Browser ──► /api/auth/sso/login ──► /api/auth/{oidc|saml}/login ──► IdP
                                                                     │
Browser ◄── /?sso_code=… ◄── /api/auth/{oidc|saml}/callback ◄────────┘
   │                          validate → find/provision user → Parse session
   └──► POST /api/auth/sso/exchange {code} ──► { sessionToken } ──► existing OpenSign login flow
```

**Where the code lives**
- The backend module is `apps/OpenSignServer/auth/sso/`:
  - `config.js`: env parsing and startup validation
  - `routes.js`: the common `/auth` router
  - `identity.js`: the normalized identity (`provider`, `issuer`, `subject`, `email`, `name`)
  - `userProvisioning.js`: JIT provisioning shared by both protocols
  - `session.js`: Parse session creation and the handoff code
  - `store.js`: Parse persistence
  - `parseHooks.js`: account protection triggers
  - `oidc/`: built on [`openid-client`](https://github.com/panva/openid-client)
  - `saml/`: built on [`@node-saml/node-saml`](https://github.com/node-saml/node-saml)
- The frontend changes are the SSO button and code exchange in `apps/OpenSign/src/pages/Login.jsx`, plus `apps/OpenSign/src/utils/sso.js`.

**How a login completes**
- The IdP token or assertion only establishes identity.
- After validation, the server creates a normal Parse session with the same master-key `/loginAs` mechanism `usersignup.js` uses.
- The browser receives a single-use, 60-second code. It exchanges the code via POST, so the session token never appears in a URL.
- The existing `thirdpartyLoginfn` in `Login.jsx` then runs the normal OpenSign initialization: `getUserDetails`, `Extand_Class`, `TenantId`, `UserRole`, `PageLanding`.

**URL prefix.** With the bundled Caddy proxy, the backend is served under `/api`. All SSO URLs are therefore `https://<host>/api/auth/...`. If you expose the server without the `/api` prefix, drop it from the URLs below.

## Routes

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/auth/sso/config` | Browser-safe `{enabled, protocol, displayName}` |
| GET | `/api/auth/sso/login` | Starts login with the configured protocol |
| POST | `/api/auth/sso/exchange` | Exchanges the one-time `code` for a Parse session token |
| POST | `/api/auth/sso/logout` | Destroys the Parse session (`X-Parse-Session-Token` header); returns the OIDC `end_session_endpoint` URL if available |
| GET | `/api/auth/oidc/login`, `/api/auth/oidc/callback` | OIDC authorization code flow |
| GET | `/api/auth/saml/login` | Sends the SAML AuthnRequest (HTTP-Redirect binding) |
| POST | `/api/auth/saml/callback` | SAML Assertion Consumer Service (HTTP-POST binding) |
| GET | `/api/auth/saml/metadata` | SP metadata XML to import into the IdP |

## Common configuration

| Variable | Default | Description |
|---|---|---|
| `SSO_ENABLED` | `false` | Master switch |
| `SSO_PROTOCOL` | `oidc` | `oidc` or `saml` |
| `SSO_DISPLAY_NAME` | `Sign in with SSO` | Button label; `Company SSO` renders as "Sign in with Company SSO" |
| `SSO_AUTO_PROVISION` | `true` | Create unknown users on first login |
| `SSO_REQUIRE_VERIFIED_EMAIL` | `true` | OIDC: require `email_verified=true` |
| `SSO_COMPANY_NAME` | `SSO_DISPLAY_NAME` | Tenant/company name for JIT users |
| `SSO_COOKIE_SECRET` | `MASTER_KEY` | Signs the short-lived OIDC flow cookie |
| `SSO_FRONTEND_URL` | `PUBLIC_URL` | Where users land after SSO |

**Startup validation.** If `SSO_ENABLED=true` and the configuration is invalid, the server refuses to start with a clear `[SSO] Invalid configuration: …` message. It never falls back silently.

## OIDC

Register OpenSign in your IdP as follows:

| Setting | Value |
|---|---|
| Protocol | OpenID Connect |
| Flow | Authorization Code (with PKCE S256) |
| Client type | Confidential (client secret, `client_secret_post`) |
| Scopes | `openid profile email` |
| Redirect URI | `https://sign.example.com/api/auth/oidc/callback` |
| Post-logout redirect URI (optional) | `https://sign.example.com` |

Then set:

```env
SSO_ENABLED=true
SSO_PROTOCOL=oidc
SSO_DISPLAY_NAME=Company SSO
OIDC_ISSUER=https://sso.example.com/realms/company
OIDC_CLIENT_ID=opensign
OIDC_CLIENT_SECRET=xxxxxxxx
OIDC_SCOPES=openid profile email
OIDC_REDIRECT_URI=https://sign.example.com/api/auth/oidc/callback
```

**Endpoints.** Every endpoint is discovered from `${OIDC_ISSUER}/.well-known/openid-configuration`: authorize, token, userinfo, `jwks_uri` and `end_session_endpoint`. None are hard-coded.

**Public client.** Set `OIDC_PUBLIC_CLIENT=true` to use a PKCE-only client with no secret.

**What the backend validates:**
- `state` (from a signed HttpOnly cookie) and the PKCE verifier.
- The ID token signature against the IdP's JWKS.
- The `iss`, `aud`, `exp` and `nonce` claims, and that `sub` is present.
- `email_verified` when required.
- If the ID token has no email, it calls userinfo and requires `userinfo.sub` to equal the ID token's `sub`.

**Stable identity.** The external identity is `issuer + sub`.

## SAML 2.0

OpenSign-Quantum is the Service Provider (SP). Configure your IdP with:

| Setting | Value |
|---|---|
| SP Entity ID / Audience | `https://sign.example.com` (`SAML_SP_ENTITY_ID`) |
| Assertion Consumer Service (HTTP-POST) | `https://sign.example.com/api/auth/saml/callback` |
| SP metadata | `https://sign.example.com/api/auth/saml/metadata` (importable by most IdPs) |
| NameID | A **persistent** or other stable identifier (not transient) |
| Attributes | email (required) and name / displayName / givenName + surname |
| Signing | Sign the Assertion, and also the Response unless `SAML_WANT_RESPONSE_SIGNED=false` |

Then set:

```env
SSO_ENABLED=true
SSO_PROTOCOL=saml
SSO_DISPLAY_NAME=Company SSO
SAML_IDP_METADATA_URL=https://sso.example.com/saml/metadata
SAML_SP_ENTITY_ID=https://sign.example.com
SAML_ACS_URL=https://sign.example.com/api/auth/saml/callback
SAML_EMAIL_ATTRIBUTE=email
SAML_NAME_ATTRIBUTE=name
```

**IdP configuration source**
- Prefer `SAML_IDP_METADATA_URL`. It provides the IdP entity ID, the HTTP-Redirect SSO URL and the signing certificates.
- Without metadata, set `SAML_IDP_SSO_URL`, `SAML_IDP_ENTITY_ID` and `SAML_IDP_CERT` instead.

**Attributes**
- **Email** is read from `SAML_EMAIL_ATTRIBUTE`, then the standard names: `email`, `mail`, `emailAddress`, the `mail` OID and the WS-Fed emailaddress claim. The NameID is used only if it is an email address.
- **Name** is read from `SAML_NAME_ATTRIBUTE`, then `name` or `displayName`, then `givenName` + `surname`.
- **Stable subject.** The subject is the IdP entity ID + NameID. If your IdP only issues transient NameIDs, set `SAML_SUBJECT_ATTRIBUTE` to an immutable attribute such as an employee ID or `objectGUID`. Transient NameIDs are rejected otherwise. `SAML_NAMEID_FORMAT` can request a specific format, for example `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`.

**Signed AuthnRequests (optional).** Set `SAML_SP_PRIVATE_KEY` and `SAML_SP_CERT` (PEM; `\n` escapes allowed). The certificate is then published in SP metadata.

**What the backend validates**
- node-saml checks:
  - The XML signatures against the IdP certificates. The Assertion must be signed, and so must the Response unless `SAML_WANT_RESPONSE_SIGNED=false`.
  - `Audience`, `NotBefore` / `NotOnOrAfter` (with 60 s default skew, `SAML_CLOCK_SKEW_MS`), and `InResponseTo`, which must match a request this SP issued.
- OpenSign-Quantum then checks:
  - The `Issuer` on both the Response and the Assertion.
  - `Destination` and `SubjectConfirmationData@Recipient` (both must equal the ACS URL).
  - That there is exactly one Response and one Assertion (signature-wrapping defence).
- Replay protection:
  - The request ID is consumed on use.
  - Each assertion ID is accepted once.
- Encrypted assertions are not supported in this version.
- Single Logout (SLO) is not implemented. Logout ends the OpenSign session only.

## Example: Keycloak

This is an example only; the code has no Keycloak-specific logic. It was tested with Keycloak 26.3 for both protocols.

**OIDC**
- `OIDC_ISSUER=https://<keycloak>/realms/<realm>`
- Client settings: Client authentication **On**, Standard flow **On**, PKCE method **S256**.
- Valid redirect URI: `https://sign.example.com/api/auth/oidc/callback`. Valid post-logout redirect URI: `https://sign.example.com`.
- OpenSign sends `id_token_hint` at logout, so Keycloak logs the user out without a confirmation page.

**SAML**
- `SAML_IDP_METADATA_URL=https://<keycloak>/realms/<realm>/protocol/saml/descriptor`
- Client ID = `SAML_SP_ENTITY_ID`.
- Master SAML processing URL / ACS POST = `SAML_ACS_URL`.
- **Sign documents** On and **Sign assertions** On.
- Name ID format **persistent**.
- Add user-property mappers for `email`, plus `firstName` → `givenName` and `lastName` → `surname`.
- Client signature required **Off**, unless you set `SAML_SP_PRIVATE_KEY` / `SAML_SP_CERT`.

## Users and provisioning

**Mapping**
- SSO users are `_User` records carrying `ssoProvider`, `ssoIssuer` and `ssoSubject`.
- A returning user is found by `ssoIssuer` + `ssoSubject` first, never by email. A user whose email changes at the IdP keeps the same account.
- Clients cannot write these fields (`beforeSave` trigger), and they are hidden from other users (`protectedFields`).

**Just-in-time provisioning** (on by default)
- A new SSO user gets a `_User` with an unusable random password, plus their own `partners_Tenant` and a `contracts_Users` record.
- This reuses `createTenantAndExtUser` from `usersignup.js`.
- The role is always the standard `contracts_User`.

**No IdP-driven authorization.** IdP `role`, `groups`, `admin` or `department` claims are ignored. SSO never creates administrators; administrators are managed locally.

**Existing-account collision.** If an account with the same email already exists and is not linked to this SSO identity, login is refused with this message:

> An account with this email already exists. Please contact the OpenSign administrator to migrate or link this account.

The accounts are never merged automatically. To migrate a local user to SSO, an administrator sets `ssoProvider`, `ssoIssuer` and `ssoSubject` on that `_User` with the master key, for example in the Parse Dashboard.

**Disabled users**
- Users disabled at the IdP cannot authenticate.
- OpenSign's own `IsDisabled` flag is enforced server-side before a session is created.
- SSO accounts cannot use local password login or password reset (`beforeLogin` / `beforePasswordResetRequest` triggers), so an IdP-disabled user has no local fallback.

**Local administrators** log in with email and password exactly as before. The form remains visible below the SSO button as a recovery path.

## Security notes

- **Secrets stay on the backend.**
  - `OIDC_CLIENT_SECRET` and the SAML private key exist only in the backend environment.
  - `/auth/sso/config` returns only `enabled`, `protocol` and `displayName`.
  - Never put SSO secrets in `REACT_APP_*` variables.
- **Logging.** Events are JSON lines with a correlation ID: `sso.login.initiated`, `sso.login.success`, `sso.login.rejected`, `sso.user.provisioned`, `sso.user.existing` and `sso.user.collision`. Tokens, assertions and secrets are never logged.
- **Errors in the browser.** Users only ever see a fixed error code, such as `/?sso_error=ACCOUNT_COLLISION`, mapped to a friendly message. No stack traces or IdP payloads are shown.
- **Flow cookie.** It is `HttpOnly`, `Secure` and `SameSite=Lax`, signed, and lasts 10 minutes. `SSO_INSECURE_COOKIES=true` exists only for plain-http local testing.
- **Internal storage.** The `SsoHandoff` and `SsoCache` classes are master-key only. Their class-level permissions are locked at startup.

## Docker Compose

- The stock `docker-compose.yml` pulls the upstream images, which have no SSO.
- `docker-compose.sso.yml` builds both images from this repository.
- It also passes `.env.sso` to the **server container only**. Template: `.env.sso.example`.

```bash
cp .env.sso.example .env.sso   # fill in
docker compose -f docker-compose.yml -f docker-compose.sso.yml up -d --build
```

Step-by-step deployment instructions are in [RUNBOOK.md](RUNBOOK.md).

## Testing

- **Unit and protocol tests:** `cd apps/OpenSignServer && npm run test:sso`. These need no MongoDB. They cover:
  - Configuration.
  - Provisioning: role, returning user, collision, disabled user.
  - OIDC against a local stub IdP: discovery, state, nonce, expiry, signature, issuer, audience, email.
  - SAML with signed test responses: signature, tamper, issuer, audience, expiry, destination, recipient, `InResponseTo`, email, replay.
- **Integration with real generic IdPs:** see [`docs/sso-test-env/README.md`](sso-test-env/README.md).

## Troubleshooting

| Symptom / code | Cause |
|---|---|
| Server exits with `[SSO] Invalid configuration` | A required variable is missing; the message names it |
| `PROVIDER_UNAVAILABLE` | Discovery or metadata URL unreachable from the **server** (it is retried on the next login) |
| `INVALID_STATE` | Flow cookie missing or expired. Check that the site uses HTTPS (Secure cookie), that `OIDC_REDIRECT_URI` uses the same host the user started on, and that the login took less than 10 minutes |
| `VALIDATION_FAILED` (OIDC) | Wrong client ID/secret, issuer mismatch (`OIDC_ISSUER` must exactly equal the discovery `issuer`), clock skew |
| `VALIDATION_FAILED` (SAML) | See the server log `detail` field. Common causes: ACS URL mismatch (`Destination`/`Recipient`), unsigned Response (sign it or set `SAML_WANT_RESPONSE_SIGNED=false`), transient NameID (set `SAML_SUBJECT_ATTRIBUTE`), IdP login not started from OpenSign (unsolicited responses are rejected) |
| `MISSING_EMAIL` / `UNVERIFIED_EMAIL` | The IdP does not release the email attribute or claim, or does not mark it as verified |
| `ACCOUNT_COLLISION` | A local account already uses that email (see the collision section above) |
| `USER_DISABLED` | The OpenSign user has `IsDisabled=true` |
| `PROVISIONING_DISABLED` | `SSO_AUTO_PROVISION=false` and the user does not exist yet |
