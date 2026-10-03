# Runbook: deploying OpenSign-Quantum with SSO

This runbook takes you from an empty server to a working OpenSign-Quantum with OIDC or SAML SSO, step by step.
- For background and every option, see [SSO.md](SSO.md).
- To try it locally first against a test Keycloak, see [sso-test-env/README.md](sso-test-env/README.md).

**Time:** about 30–45 minutes.
**Roles:** an operator with shell access to the Docker host, plus someone who can create a client/application in the company Identity Provider (IdP).

---

## 0. Before you start

Collect these before touching anything:

| Item | Example | Notes |
|---|---|---|
| Public URL of OpenSign | `https://sign.example.com` | Becomes `HOST_URL`. DNS must point to the Docker host. Ports 80/443 open. |
| Protocol | `oidc` or `saml` | Prefer OIDC if your IdP supports both |
| OIDC issuer URL | `https://sso.example.com/realms/company` | Must serve `/.well-known/openid-configuration` |
| SAML IdP metadata URL | `https://sso.example.com/.../metadata` | SAML only |
| Document-signing certificate | `.pfx` / `.p12` + password | OpenSign needs it to complete signatures |
| SMTP / Mailgun settings | | Needed to email signers (not part of SSO) |

**Docker host requirements**
- Docker with Compose v2.
- 4 GB RAM.
- The host must reach the IdP over HTTPS (the server calls discovery, token and metadata endpoints).
- The clock must be NTP-synced; clock skew breaks token and assertion validation.

---

## 1. Get the code

```bash
git clone https://github.com/ChosoMeister/OpenSign-Quantum.git
cd OpenSign-Quantum
```

The stock `docker-compose.yml` pulls upstream OpenSign images, which **do not contain SSO**. Step 5 builds both images from this repository with `docker-compose.sso.yml`.

---

## 2. Base OpenSign configuration (`.env.prod`)

```bash
cp .env.local_dev .env.prod
export HOST_URL=https://sign.example.com     # your public URL, no trailing slash
```

Edit `.env.prod` and set at least:

| Variable | Value |
|---|---|
| `MASTER_KEY` | Long random string: `openssl rand -hex 32` |
| `PFX_BASE64` | `base64 -i cert.pfx \| tr -d '\n'` |
| `PASS_PHRASE` | Password of that PFX |
| SMTP_* or MAILGUN_* | Your mail settings, so signers receive emails |

`SERVER_URL` and `PUBLIC_URL` are derived from `HOST_URL` by `docker-compose.yml`. Leave them alone.

---

## 3. Register OpenSign in the Identity Provider

All URLs below use `https://sign.example.com`. Replace it with your `HOST_URL`. The `/api` prefix is required, because the bundled Caddy routes `/api/*` to the backend.

### Option A: OIDC

Create an application/client with:

| Setting | Value |
|---|---|
| Type | OpenID Connect, **confidential** (client secret) |
| Grant / flow | Authorization Code. PKCE S256 allowed or required. |
| Redirect URI | `https://sign.example.com/api/auth/oidc/callback` |
| Post-logout redirect URI | `https://sign.example.com` |
| Scopes | `openid profile email` |
| Token claims | `sub`, `email`, `email_verified`, `name` |

Write down the **client ID**, the **client secret** and the **issuer URL**. The issuer URL must exactly match the `issuer` value at `<issuer>/.well-known/openid-configuration`.

<details><summary>Keycloak specifics</summary>

- Clients → Create client: OpenID Connect, Client ID `opensign`.
- Client authentication **On**, Standard flow **On**, Direct access grants Off.
- Valid redirect URIs and Valid post logout redirect URIs as above.
- Advanced → Proof Key for Code Exchange Code Challenge Method **S256**.
- Credentials tab → copy the client secret.
- Issuer: `https://<keycloak>/realms/<realm>`.

</details>

### Option B: SAML 2.0

1. Start OpenSign once (step 5) with `SSO_PROTOCOL=saml`.
2. Give the IdP admin `https://sign.example.com/api/auth/saml/metadata`, or configure manually:

| Setting | Value |
|---|---|
| SP Entity ID / Audience | `https://sign.example.com` |
| ACS URL (HTTP-POST) | `https://sign.example.com/api/auth/saml/callback` |
| Signing | Sign the **Assertion** (required) and the **Response** (recommended) |
| NameID | **Persistent**, or another stable ID (not transient) |
| Attributes | `email` (required), plus `name` or `givenName` + `surname` |

Write down the **IdP metadata URL**.

<details><summary>Keycloak specifics</summary>

- Clients → Create client: SAML, Client ID = `https://sign.example.com`.
- Valid redirect URIs: the ACS URL. Master SAML processing URL: the ACS URL.
- Settings → Name ID format **persistent**. Sign documents **On**. Sign assertions **On**.
- Keys tab → Client signature required **Off**.
- Client scopes → dedicated scope → add mappers (By configuration → User Property):
  - `email` → SAML attribute `email`
  - `firstName` → `givenName`
  - `lastName` → `surname`
- Metadata URL: `https://<keycloak>/realms/<realm>/protocol/saml/descriptor`.

</details>

---

## 4. SSO configuration (`.env.sso`)

```bash
cp .env.sso.example .env.sso
chmod 600 .env.sso
```

Fill it in:

**OIDC**
```env
SSO_ENABLED=true
SSO_PROTOCOL=oidc
SSO_DISPLAY_NAME=Company SSO
SSO_COOKIE_SECRET=<openssl rand -hex 32>
OIDC_ISSUER=https://sso.example.com/realms/company
OIDC_CLIENT_ID=opensign
OIDC_CLIENT_SECRET=<from step 3>
OIDC_REDIRECT_URI=https://sign.example.com/api/auth/oidc/callback
```

**SAML**
```env
SSO_ENABLED=true
SSO_PROTOCOL=saml
SSO_DISPLAY_NAME=Company SSO
SSO_COOKIE_SECRET=<openssl rand -hex 32>
SAML_IDP_METADATA_URL=<from step 3>
SAML_SP_ENTITY_ID=https://sign.example.com
SAML_ACS_URL=https://sign.example.com/api/auth/saml/callback
```

**Rules for `.env.sso`**
- It is git-ignored. It is read **only** by the server container, never by the frontend.
- Never put SSO values in `REACT_APP_*` variables.

---

## 5. Build and start

```bash
export HOST_URL=https://sign.example.com
docker compose -f docker-compose.yml -f docker-compose.sso.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.sso.yml logs -f server
```

Expected in the server log: `opensign-server running on port 8080.`

If the server exits with `[SSO] Invalid configuration: …`, the message names the missing or invalid variable. Fix `.env.sso` and run the `up` command again.

---

## 6. Create the local administrator

- Open `https://sign.example.com`. On a fresh database you are redirected to **OpenSign setup** (`/addadmin`).
- Create the administrator here with a strong password.
- This local account is your **break-glass** access when the IdP is down. Store its credentials in your password vault.
- SSO never creates administrators.

---

## 7. Verify (smoke test)

Run these checks in order. Each must pass before you hand over.

| # | Check | Expected |
|---|---|---|
| 1 | `curl -s https://sign.example.com/api/auth/sso/config` | `{"enabled":true,"protocol":"oidc","displayName":"Company SSO"}`, with no secrets |
| 2 | (SAML) `curl -s https://sign.example.com/api/auth/saml/metadata` | XML with your entity ID and ACS URL |
| 3 | Open the login page | "Sign in with Company SSO" button, then "OR", then the email/password form |
| 4 | Click the SSO button and log in at the IdP with a normal user | Lands on the OpenSign dashboard |
| 5 | Admin checks the new user (Settings → Users, or the DB) | Role `contracts_User`. No admin menus for that user. |
| 6 | As that user: Sign yourself → upload PDF → place signature → Finish | "Successfully signed!" |
| 7 | Request signatures → add a signer → Send | Document sent; signer receives the email |
| 8 | Log out → SSO login again | Same account and documents (no duplicate user) |
| 9 | Local admin logs in with email/password | Works (break-glass path) |
| 10 | Disable the test user in the IdP and try SSO | Login refused |

Server log lines to look for: `sso.login.initiated`, `sso.user.provisioned`, `sso.login.success`. Tokens and assertions are never logged.

---

## 8. Day-2 operations

| Task | How |
|---|---|
| **Disable a user** | Disable them in the IdP. They can no longer log in. Optionally also set `IsDisabled` in OpenSign (Settings → Users); that is enforced server-side too. |
| **User sees "An account with this email already exists"** | A local account already uses that email. Accounts are never merged automatically. An admin either deletes or renames the local account, or links it: set `ssoProvider`, `ssoIssuer` and `ssoSubject` on that `_User` with the master key (values are in the server log or from the IdP). |
| **Rotate the OIDC client secret** | Update it in the IdP and in `.env.sso`, then run `docker compose -f docker-compose.yml -f docker-compose.sso.yml up -d server` |
| **IdP signing-certificate rollover (SAML)** | Metadata is re-read on server restart: `... restart server` |
| **Change the button label** | Set `SSO_DISPLAY_NAME`, then restart the server |
| **Upgrade** | `git pull`, then `docker compose -f docker-compose.yml -f docker-compose.sso.yml up -d --build` |

---

## 9. Rollback / emergency

- **IdP outage:** local administrators keep logging in with email and password. SSO users wait for the IdP; there is no local password fallback for them, by design.
- **Turn SSO off completely:** set `SSO_ENABLED=false` in `.env.sso` and restart the server. OpenSign then behaves like upstream, and the SSO button disappears. Existing SSO users keep their data but cannot log in until SSO is re-enabled.

---

## 10. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Server exits `[SSO] Invalid configuration` | Missing variable; the message names it |
| Login page shows **"The Single Sign-On provider is currently unavailable"** | The server cannot reach the issuer or metadata URL. Test from the container: `docker compose exec server curl -sS <issuer>/.well-known/openid-configuration` |
| IdP shows **"Invalid redirect_uri"** | The redirect URI in the IdP must equal `OIDC_REDIRECT_URI` exactly, including `/api` |
| **"Your sign-in session expired or is invalid"** | The site is not served over HTTPS (the cookie is Secure), the login took more than 10 minutes, or the user started on a different host name |
| **"Single Sign-On could not be verified"** | Check the server log `detail`: issuer mismatch, wrong client secret, clock skew, SAML Destination/Recipient ≠ ACS URL, unsigned Assertion, or transient NameID (set `SAML_SUBJECT_ATTRIBUTE`) |
| **"…did not supply an email address"** / **"…not verified"** | Release `email` (and `email_verified`) to the client, or set `SSO_REQUIRE_VERIFIED_EMAIL=false` if your IdP has no such claim |
| Signing fails with "Something went wrong" on Finish | `PFX_BASE64` / `PASS_PHRASE` missing in `.env.prod` (not SSO related) |
| Signers get no email | SMTP / Mailgun not configured (not SSO related) |
