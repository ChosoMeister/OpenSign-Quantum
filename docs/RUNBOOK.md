# OpenSign-Quantum Deployment Runbook

This runbook takes you from an empty Linux server to a production OpenSign-Quantum running in Docker. Part B adds Single Sign-On (OIDC or SAML 2.0) on top.

| Part | What you get | Time |
|---|---|---|
| **A. Dockerized deployment** | OpenSign over HTTPS with a local administrator | ~30 min |
| **B. Single Sign-On** | Company users log in through your Identity Provider | ~20 min |
| **C. Operations** | Backup, update, rollback, troubleshooting | reference |

**Related documents**
- Background and every SSO option: [SSO.md](SSO.md).
- Try SSO locally first against a test Keycloak: [sso-test-env/README.md](sso-test-env/README.md).

All commands run from the repository root on the Docker host. Replace `sign.example.com` with your domain throughout.

---

# Part A: Dockerized deployment

## A1. Prerequisites

| Item | Requirement |
|---|---|
| Server | Linux x86_64, 2+ vCPU, 4 GB RAM, 20 GB disk (plus document storage) |
| Software | Docker Engine 24+ with the Compose v2 plugin (`docker compose version`), and `git` |
| DNS | An `A`/`AAAA` record for `sign.example.com` pointing to the server |
| Firewall | Inbound 80 and 443 open (Caddy obtains the TLS certificate automatically) |
| Time | NTP enabled (`timedatectl`), required for TLS and for SSO token validation |
| Mail | SMTP account or Mailgun domain, so signers receive emails |
| Signing certificate | A `.pfx` / `.p12` file and its password, used to digitally seal signed PDFs |

## A2. Architecture

```
Internet ──443──► caddy ──/api/*──► server:8080 (Node/Parse) ──► mongo:27017
                    │                     │
                    └──── /* ────► client:3000 (React)   files volume (local storage)
```

`docker-compose.yml` defines these services:

| Service | Purpose | Persistent volume |
|---|---|---|
| `caddy` | TLS and reverse proxy | `caddy_data` (certificates) |
| `client` | Web UI | none |
| `server` | API | `opensign-files` (uploaded/signed documents when `USE_LOCAL=true`) |
| `mongo` | Database | `data-volume` |

**Image overlay.** `docker-compose.sso.yml` is layered on top of `docker-compose.yml`. It builds `server` and `client` from this repository; the upstream images do not contain OpenSign-Quantum. It also gives the server an extra env file, `.env.sso`. **Always start the stack with both files**, even if SSO is off.

## A3. Get the code

```bash
git clone https://github.com/ChosoMeister/OpenSign-Quantum.git
cd OpenSign-Quantum
git checkout staging            # or the release tag/branch you deploy
```

## A4. Configure `.env.prod`

```bash
cp .env.local_dev .env.prod
chmod 600 .env.prod
```

Edit `.env.prod`. Values you **must** change:

| Variable | Set to | Why |
|---|---|---|
| `MASTER_KEY` | Output of `openssl rand -hex 32` | Full database access key. The template value is public. |
| `MONGODB_URI` | `mongodb://mongo-container:27017/OpenSignDB` (default) | Keep the default unless you use an external MongoDB |
| `PFX_BASE64` | `base64 -w0 your-cert.pfx` (macOS: `base64 -i your-cert.pfx \| tr -d '\n'`) | The template contains a **public demo certificate**; never use it in production |
| `PASS_PHRASE` | Password of your PFX | |
| `SMTP_ENABLE`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER_EMAIL`, `SMTP_PASS` | Your SMTP server | Or leave `SMTP_ENABLE` unset and fill in the `MAILGUN_*` variables |

**Storage** (pick one):
- **Local disk:** keep `USE_LOCAL=true`. Files go to the `opensign-files` Docker volume, so back it up (C1).
- **S3 / DigitalOcean Spaces:** set `USE_LOCAL=false` and fill in the `DO_*` variables.

**Leave alone:**
- `SERVER_URL` and `PUBLIC_URL`. `docker-compose.yml` derives them from `HOST_URL`.
- `PARSE_MOUNT=/app` and `APP_ID=opensign`.

No signing certificate yet? For a **test** install only, generate one:
```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -days 365 -subj "/CN=OpenSign Test"
openssl pkcs12 -export -inkey k.pem -in c.pem -out test.p12 -passout pass:changeit
base64 -w0 test.p12      # → PFX_BASE64, PASS_PHRASE=changeit
```

## A5. Create `.env.sso`

This file must exist even when SSO is off:

```bash
cp .env.sso.example .env.sso
chmod 600 .env.sso
sed -i 's/^SSO_ENABLED=.*/SSO_ENABLED=false/' .env.sso      # SSO is enabled in Part B
```

## A6. Build and start

```bash
export HOST_URL=https://sign.example.com
echo "HOST_URL=$HOST_URL" > .env            # makes HOST_URL persistent for later compose commands
docker compose -f docker-compose.yml -f docker-compose.sso.yml up -d --build
```

The first build takes 5–10 minutes. Then check:

```bash
docker compose -f docker-compose.yml -f docker-compose.sso.yml ps        # all services "running"
docker compose -f docker-compose.yml -f docker-compose.sso.yml logs server | tail -20
```

**Expected server log:** `opensign-server running on port 8080.`

**Tip:** to avoid repeating both file names, set an alias:
```bash
alias dc='docker compose -f docker-compose.yml -f docker-compose.sso.yml'
```
The rest of this runbook uses `dc`.

## A7. First administrator

1. Open `https://sign.example.com`. Caddy fetches the TLS certificate on the first request; wait a few seconds.
2. On a new database you land on **OpenSign setup** (`/addadmin`). Create the administrator with a strong password.
3. Store these credentials in your password vault. This local account is also the **break-glass** login when SSO is unavailable.

## A8. Verify Part A

| # | Check | Expected |
|---|---|---|
| 1 | `curl -sI https://sign.example.com` | `HTTP/2 200`, valid certificate |
| 2 | `curl -s https://sign.example.com/api/app/health` | `{"status":"ok"}` |
| 3 | Admin logs in | Dashboard opens |
| 4 | Sign yourself → upload PDF → place signature → Finish | "Successfully signed!"; the downloaded PDF shows a digital signature |
| 5 | Request signatures → add your own second mailbox → Send | Email arrives with the signing link |

If check 4 fails with "Something went wrong", `PFX_BASE64` / `PASS_PHRASE` are wrong. If check 5 fails, mail settings are wrong.

---

# Part B: Single Sign-On

Prerequisite: Part A is complete and verified.

**Protocol choice**
- **OIDC** if your IdP supports it. It is simpler, and logout also ends the IdP session.
- **SAML 2.0** otherwise.

## B1. Register OpenSign in the Identity Provider

The `/api` prefix in every URL is required: Caddy routes `/api/*` to the backend.

### Option 1: OIDC

| IdP setting | Value |
|---|---|
| Client type | OpenID Connect, **confidential** (client secret) |
| Flow | Authorization Code (PKCE S256 allowed or required) |
| Redirect URI | `https://sign.example.com/api/auth/oidc/callback` |
| Post-logout redirect URI | `https://sign.example.com` |
| Scopes / claims | `openid profile email`; the token must carry `sub`, `email`, `email_verified`, `name` |

Note the **issuer URL**, **client ID** and **client secret**. The issuer must exactly equal the `issuer` value at `<issuer>/.well-known/openid-configuration`.

<details><summary>Keycloak</summary>

- Clients → Create client: OpenID Connect, Client ID `opensign`.
- Client authentication **On**, Standard flow **On**, Direct access grants Off.
- Fill in Valid redirect URIs and Valid post logout redirect URIs as above.
- Advanced → PKCE method **S256**.
- Credentials tab → copy the secret.
- Issuer: `https://<keycloak>/realms/<realm>`.

</details>

### Option 2: SAML 2.0

| IdP setting | Value |
|---|---|
| SP Entity ID / Audience | `https://sign.example.com` |
| ACS URL (HTTP-POST) | `https://sign.example.com/api/auth/saml/callback` |
| Signing | Assertion signed (required); Response signed (recommended) |
| NameID | **Persistent** or another stable ID (not transient) |
| Attributes | `email` (required), plus `name` or `givenName` + `surname` |

- Note the **IdP metadata URL**.
- After B3, OpenSign also serves its SP metadata at `https://sign.example.com/api/auth/saml/metadata`. Most IdPs can import it directly.

<details><summary>Keycloak</summary>

- Clients → Create client: SAML, Client ID = `https://sign.example.com`.
- Valid redirect URIs and Master SAML processing URL = the ACS URL.
- Name ID format **persistent**. Sign documents **On**. Sign assertions **On**.
- Keys → Client signature required **Off**.
- Dedicated client scope → add User Property mappers:
  - `email` → `email`
  - `firstName` → `givenName`
  - `lastName` → `surname`
- Metadata URL: `https://<keycloak>/realms/<realm>/protocol/saml/descriptor`.

</details>

## B2. Fill in `.env.sso`

**OIDC**
```env
SSO_ENABLED=true
SSO_PROTOCOL=oidc
SSO_DISPLAY_NAME=Company SSO
SSO_COOKIE_SECRET=<openssl rand -hex 32>
OIDC_ISSUER=https://sso.example.com/realms/company
OIDC_CLIENT_ID=opensign
OIDC_CLIENT_SECRET=<from B1>
OIDC_REDIRECT_URI=https://sign.example.com/api/auth/oidc/callback
```

**SAML**
```env
SSO_ENABLED=true
SSO_PROTOCOL=saml
SSO_DISPLAY_NAME=Company SSO
SSO_COOKIE_SECRET=<openssl rand -hex 32>
SAML_IDP_METADATA_URL=<from B1>
SAML_SP_ENTITY_ID=https://sign.example.com
SAML_ACS_URL=https://sign.example.com/api/auth/saml/callback
```

**Rules for `.env.sso`**
- It is read **only** by the server container and is git-ignored.
- Never put SSO values into `.env.prod`, which the client container also reads, or into any `REACT_APP_*` variable.

### Optional: admins from IdP groups, SSO-only login

To manage OpenSign roles in the IdP instead of locally:

1. **Create the groups in the IdP**, e.g. `opensign-admins`, `opensign-orgadmins` and `opensign-editors`. Put the right people in them.
2. **Release the user's groups to OpenSign** in a `groups` claim/attribute:
   - **Keycloak OIDC client:** Client scopes → dedicated scope → Add mapper → *Group Membership*, with token claim name `groups` and *Full group path* **Off**.
   - **Keycloak SAML client:** add mapper *Group list*, with attribute name `groups` and *Single group attribute* **Off**.
3. **Add to `.env.sso`:**

```env
SSO_ADMIN_GROUPS=opensign-admins
SSO_ORGADMIN_GROUPS=opensign-orgadmins
SSO_EDITOR_GROUPS=opensign-editors
SSO_COMPANY_NAME=Acme Inc
# SSO-only: hide and disable email/password login, /addadmin and local signup
LOCAL_LOGIN_ENABLED=false
```

**What this changes**
- All SSO users then join one company organization.
- Roles are re-evaluated at each login, so a group change applies at the user's next login.
- With `LOCAL_LOGIN_ENABLED=false` there is no local administrator. Skip A7: the first person in `opensign-admins` who logs in is an admin.
- In SSO-only mode the Users page has no **Add user** or **Reset password**. New people get access by being added in the IdP; they appear in OpenSign after their first login. Admins can still activate/deactivate users there.
- Whoever can edit these groups in the IdP controls OpenSign administration. Restrict that right in the IdP.

## B3. Apply

```bash
dc up -d server
dc logs -f server
```

- **Expected:** `opensign-server running on port 8080.`
- **If you see `[SSO] Invalid configuration: …`:** the message names the missing or invalid variable. Fix it and run `dc up -d server` again.
- **Network check:** the server must reach the IdP. Test it with:

```bash
dc exec server curl -sS https://sso.example.com/realms/company/.well-known/openid-configuration | head -c 200
```

## B4. Verify Part B

| # | Check | Expected |
|---|---|---|
| 1 | `curl -s https://sign.example.com/api/auth/sso/config` | `{"enabled":true,"protocol":"oidc","displayName":"Company SSO"}`, with no secrets |
| 2 | (SAML) `curl -s https://sign.example.com/api/auth/saml/metadata` | XML with your entity ID and ACS URL |
| 3 | Login page | **Sign in with Company SSO** button, then OR, then the email/password form |
| 4 | Click SSO and log in at the IdP as a normal employee | Lands on the OpenSign dashboard; the account is created automatically |
| 5 | That user's menu | No admin entries (role `contracts_User`) |
| 6 | As that user: sign a document, and request a signature from someone else | Both work |
| 7 | Log out, then SSO again | Same account and documents. With OIDC, the IdP asks for credentials again. |
| 8 | Local admin with email/password | Still works (break-glass) |
| 9 | Disable the test user in the IdP, then try SSO | Refused |
| 10 | (Group mapping) A member of `SSO_ADMIN_GROUPS` logs in | Admin menus (Settings → Users) visible; sees all SSO users |
| 11 | (Group mapping) Remove that person from the group, log out and in | Standard user, no admin menus |
| 12 | (`LOCAL_LOGIN_ENABLED=false`) Login page and `/addadmin` | Only the SSO button; `/addadmin` is never offered |
| 14 | (Group mapping) Request signatures → Signers dropdown | Colleagues of the organization are listed without adding them as contacts |
| 13 | (`LOCAL_LOGIN_ENABLED=false`) Admin opens Settings → Users | No "Add user" button and no "Reset password" action; the Active toggle works |

**Server log events:** `sso.login.initiated`, `sso.user.provisioned`, `sso.login.success`. Failures appear as `sso.login.rejected`, with a `code` and an internal `detail`.

## B5. What users will see

- **New employees:** an account is created on first SSO login, with no admin action needed. Without a group mapping everyone is a standard user; with one, the role follows the IdP groups.
- **"An account with this email already exists":** a local account already uses that email. Accounts are never merged automatically; see C3.
- **Users disabled in the IdP** cannot log in, and SSO accounts have no local password to fall back on.

---

# Part C: Operations

## C1. Backup and restore

**Back up daily.** Store the backups off the host.

```bash
mkdir -p backup
dc exec -T mongo mongodump --archive --gzip --db OpenSignDB > backup/opensign-$(date +%F).archive.gz
# Only with USE_LOCAL=true:
docker run --rm -v opensign-quantum_opensign-files:/data -v "$PWD/backup":/b alpine \
  tar czf /b/files-$(date +%F).tgz -C /data .
cp .env.prod .env.sso backup/      # keep secrets backups encrypted
```

The volume name is prefixed with the compose project, which is the directory name by default. Check it with `docker volume ls`.

**Restore:**
```bash
dc exec -T mongo mongorestore --archive --gzip --drop < backup/opensign-YYYY-MM-DD.archive.gz
docker run --rm -v opensign-quantum_opensign-files:/data -v "$PWD/backup":/b alpine \
  sh -c "cd /data && tar xzf /b/files-YYYY-MM-DD.tgz"
dc restart server
```

## C2. Update

```bash
git fetch && git checkout <new tag or branch> && git pull
dc up -d --build
dc logs -f server
```

Run A8 and B4 again afterwards.

## C3. Routine SSO tasks

| Task | How |
|---|---|
| Disable a user | Disable them in the IdP. Optionally also set `IsDisabled` in OpenSign (Settings → Users); that is enforced server-side too. |
| Link an existing local account to SSO | With the master key (Parse Dashboard or REST), set `ssoProvider`, `ssoIssuer` and `ssoSubject` on that `_User`. The values are the IdP issuer/entity ID and the user's `sub`/NameID. |
| Rotate the OIDC client secret | Change it in the IdP and in `.env.sso`, then `dc up -d server` |
| SAML IdP certificate rollover | `dc restart server` re-reads the metadata |
| Give someone access (SSO-only) | Create or enable them in the IdP. Their OpenSign account is created at their first SSO login. |
| Make someone an admin / editor | Add them to the `SSO_ADMIN_GROUPS` / `SSO_EDITOR_GROUPS` group in the IdP; it applies at their next login |
| Remove admin rights | Remove them from the group in the IdP; they become a standard user at their next login |
| Change the button text | `SSO_DISPLAY_NAME` in `.env.sso`, then `dc up -d server` |

## C4. Rollback and emergency

| Situation | Action |
|---|---|
| IdP outage | Local administrators keep logging in with email and password. SSO users wait for the IdP. |
| Turn SSO off | Set `SSO_ENABLED=false` (and remove `LOCAL_LOGIN_ENABLED=false`) in `.env.sso`, then `dc up -d server`. The SSO button disappears and data is kept. |
| SSO-only and the IdP is down or the admin group is broken | Set `LOCAL_LOGIN_ENABLED=true` in `.env.sso`, then `dc up -d server`. Existing local accounts can log in again. |
| Bad release | `git checkout <previous tag>`, `dc up -d --build`. If the database changed, restore it from C1. |

## C5. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Caddy fails to obtain a certificate | DNS does not point to the host, or ports 80/443 are blocked: `dc logs caddy` |
| Browser shows "server down" on the login page | Server not running. Run `dc logs server`; check that `MASTER_KEY` and `MONGODB_URI` are set. |
| Server exits `[SSO] Invalid configuration` | The message names the variable; fix `.env.sso` |
| `env file .env.sso not found` | Create it (A5); it is required even with SSO off |
| "The Single Sign-On provider is currently unavailable" | Server cannot reach the issuer or metadata URL. Test with `dc exec server curl …` (B3). |
| IdP error "Invalid redirect_uri" | IdP redirect URI ≠ `OIDC_REDIRECT_URI`. They must match exactly, including `/api`. |
| "Your sign-in session expired or is invalid" | Not using HTTPS, the login took more than 10 minutes, or a different host name was used |
| "Single Sign-On could not be verified" | Read the `detail` field in `dc logs server`. Usual causes: issuer mismatch, wrong secret, clock skew, SAML ACS/Destination mismatch, unsigned Assertion, or transient NameID (set `SAML_SUBJECT_ATTRIBUTE`). |
| Admin from the IdP group is a normal user in OpenSign | The token/assertion carries no groups. Add the group mapper (B1, optional section) and check the name against `SSO_ADMIN_GROUPS`. The change applies at the next login. |
| Server exits "LOCAL_LOGIN_ENABLED=false requires SSO_ADMIN_GROUPS" | SSO-only needs at least one admin group |
| "…did not supply an email address" / "…not verified" | Release `email` / `email_verified` to the client, or set `SSO_REQUIRE_VERIFIED_EMAIL=false` |
| Finish on signing shows "Something went wrong" | Invalid `PFX_BASE64` / `PASS_PHRASE` |
| Signers receive no email | SMTP/Mailgun settings; check `dc logs server` for mail errors |
