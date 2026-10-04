# SSO integration test environment

These environments use generic, vendor-neutral test IdPs:
- OIDC: [navikt/mock-oauth2-server](https://github.com/navikt/mock-oauth2-server)
- SAML: [SimpleSAMLphp](https://hub.docker.com/r/kenchan0130/simplesamlphp)

Each environment also runs MongoDB. The OpenSign server runs on the host, so the IdP URLs are the same for the browser and the server. Everything is plain http and meant for local testing only.

## OIDC

```bash
docker compose -f docs/sso-test-env/docker-compose.oidc.yml -p ssooidc up -d
cd apps/OpenSignServer && source ../../docs/sso-test-env/oidc.env && npm start
# in another shell: scripted flow (login, provisioning, tamper checks, logout, re-login)
node docs/sso-test-env/oidc-e2e.mjs alice
```

## SAML

```bash
docker compose -f docs/sso-test-env/docker-compose.saml.yml -p ssosaml up -d
cd apps/OpenSignServer && source ../../docs/sso-test-env/saml.env && npm start
curl http://localhost:8080/auth/saml/metadata
node docs/sso-test-env/saml-e2e.mjs user1      # users: user1/password, user2/password
```

The test IdP issues transient NameIDs and releases only `email`. For that reason, `saml.env` sets `SAML_SUBJECT_ATTRIBUTE=email`. In production, use a persistent NameID or an immutable attribute.

## Keycloak (OIDC and SAML)

```bash
docker compose -f docs/sso-test-env/docker-compose.keycloak.yml -p ssokc up -d
docs/sso-test-env/keycloak-setup.sh        # realm "company", clients, users kc-user / kc-saml (password Passw0rd!kc)
cd apps/OpenSignServer && source ../../docs/sso-test-env/keycloak-oidc.env && npm start   # or keycloak-saml.env
```

- **OIDC client `opensign`:** confidential, PKCE S256, redirect `http://localhost:8080/auth/oidc/callback`. Logout sends `id_token_hint`, so Keycloak ends its session without a confirmation page.
- **SAML client `http://localhost:8080`:** Response and Assertion signed, persistent NameID, `email` / `givenName` / `surname` mappers. The IdP metadata is at `http://localhost:8180/realms/company/protocol/saml/descriptor`.
- **Groups:** `opensign-admins`, `opensign-orgadmins` and `opensign-editors`; `kc-user` is in `opensign-admins`. `keycloak-oidc.env` and `keycloak-saml.env` enable the role mapping and `LOCAL_LOGIN_ENABLED=false`.
- **Scripted login:** `node docs/sso-test-env/keycloak-e2e.mjs kc-user` prints the role and organization.
- **SAML logout:** it ends only the OpenSign session (no SLO), so the next SSO click may log in directly while the Keycloak session is alive.

## Browser end-to-end checklist

1. Run the frontend with `REACT_APP_SERVERURL=http://localhost:8080/app` (`cd apps/OpenSign && npm start`) and open http://localhost:3000.
2. Click **Sign in with Test SSO**.
   - OIDC: type any username, and put claims such as `{"email":"alice@example.com","email_verified":true,"name":"Alice"}` in the claims box.
   - SAML: log in as `user1` / `password`.
3. You are returned to OpenSign and logged in.
   - The user is created automatically with the `contracts_User` role.
4. Create a document, prepare it, send it for signature, and sign it.
5. Log out, sign in via SSO again, and check that it is the same account (same documents).
6. A local administrator can still sign in with email and password.
7. With `SSO_ENABLED=false`, the login page looks and behaves like upstream OpenSign.

## Clean up

```bash
docker compose -f docs/sso-test-env/docker-compose.oidc.yml -p ssooidc down -v
docker compose -f docs/sso-test-env/docker-compose.saml.yml -p ssosaml down -v
```

## Local test administrator

A fresh test database first asks for an OpenSign admin (`/addadmin`). For local testing, use:
`admin@example.test` / `TestAdmin#2026` (test-only credentials; never reuse them).

## Document signing certificate

OpenSign needs a PKCS#12 certificate to complete signing (`PFX_BASE64` / `PASS_PHRASE`). For local tests, generate a throwaway one. Do not commit it:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -days 365 -subj "/CN=OpenSign SSO Test"
openssl pkcs12 -export -inkey k.pem -in c.pem -out test.p12 -passout pass:testpass
export PFX_BASE64=$(base64 -i test.p12 | tr -d '\n') PASS_PHRASE=testpass
```
