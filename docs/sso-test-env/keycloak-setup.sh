#!/usr/bin/env bash
# Configures the local test Keycloak (docker-compose.keycloak.yml) for OpenSign-Quantum:
#   realm "company", OIDC client "opensign", SAML client "http://localhost:8080",
#   test user kc-user / Passw0rd!kc (email verified). Test-only values.
set -euo pipefail
C=ssokc-keycloak-1
kc() { docker exec -i "$C" /opt/keycloak/bin/kcadm.sh "$@"; }

kc config credentials --server http://localhost:8180 --realm master --user admin --password admin >/dev/null
kc create realms -s realm=company -s enabled=true 2>/dev/null || echo "realm exists"

# --- OIDC: confidential client, authorization code + PKCE ---
kc create clients -r company -f - <<'JSON' || echo "oidc client exists"
{
  "clientId": "opensign",
  "protocol": "openid-connect",
  "publicClient": false,
  "secret": "kc-test-secret",
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": false,
  "redirectUris": ["http://localhost:8080/auth/oidc/callback"],
  "webOrigins": ["http://localhost:3000"],
  "attributes": {
    "pkce.code.challenge.method": "S256",
    "post.logout.redirect.uris": "http://localhost:3000"
  },
  "protocolMappers": [
    {"name": "groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
     "config": {"claim.name": "groups", "full.path": "false", "id.token.claim": "true",
                "access.token.claim": "true", "userinfo.token.claim": "true"}}
  ]
}
JSON

# --- SAML: SP = OpenSign, signed Response and Assertion, email/name attributes ---
kc create clients -r company -f - <<'JSON' || echo "saml client exists"
{
  "clientId": "http://localhost:8080",
  "protocol": "saml",
  "enabled": true,
  "frontchannelLogout": true,
  "redirectUris": ["http://localhost:8080/auth/saml/callback"],
  "attributes": {
    "saml_assertion_consumer_url_post": "http://localhost:8080/auth/saml/callback",
    "saml.server.signature": "true",
    "saml.assertion.signature": "true",
    "saml.client.signature": "false",
    "saml.authnstatement": "true",
    "saml_name_id_format": "persistent",
    "saml.signature.algorithm": "RSA_SHA256"
  },
  "protocolMappers": [
    {"name": "email", "protocol": "saml", "protocolMapper": "saml-user-property-mapper",
     "config": {"user.attribute": "email", "attribute.name": "email", "attribute.nameformat": "Basic"}},
    {"name": "givenName", "protocol": "saml", "protocolMapper": "saml-user-property-mapper",
     "config": {"user.attribute": "firstName", "attribute.name": "givenName", "attribute.nameformat": "Basic"}},
    {"name": "surname", "protocol": "saml", "protocolMapper": "saml-user-property-mapper",
     "config": {"user.attribute": "lastName", "attribute.name": "surname", "attribute.nameformat": "Basic"}},
    {"name": "groups", "protocol": "saml", "protocolMapper": "saml-group-membership-mapper",
     "config": {"attribute.name": "groups", "full.path": "false", "single": "false", "attribute.nameformat": "Basic"}}
  ]
}
JSON

# --- Test user ---
kc create users -r company -s username=kc-user -s email=kc-user@example.com -s emailVerified=true \
  -s firstName=Kay -s lastName=Cloak -s enabled=true 2>/dev/null || echo "user exists"
kc set-password -r company --username kc-user --new-password 'Passw0rd!kc'
echo "Keycloak configured."

# Second test user for the SAML run (kc-user is already bound to the OIDC identity).
kc create users -r company -s username=kc-saml -s email=kc-saml@example.com -s emailVerified=true \
  -s firstName=Sam -s lastName=Lee -s enabled=true 2>/dev/null || echo "user kc-saml exists"
kc set-password -r company --username kc-saml --new-password 'Passw0rd!kc'

# --- Groups for OpenSign role mapping (SSO_ADMIN_GROUPS / SSO_ORGADMIN_GROUPS / SSO_EDITOR_GROUPS) ---
for g in opensign-admins opensign-orgadmins opensign-editors; do
  kc create groups -r company -s name=$g 2>/dev/null || true
done
group_id() { kc get groups -r company -q search="$1" --fields id,name | python3 -c "import sys,json;print([g['id'] for g in json.load(sys.stdin) if g['name']=='$1'][0])"; }
user_id() { kc get users -r company -q username="$1" --fields id | python3 -c "import sys,json;print(json.load(sys.stdin)[0]['id'])"; }
# kc-user is an OpenSign admin; kc-saml stays a standard user.
kc update "users/$(user_id kc-user)/groups/$(group_id opensign-admins)" -r company -n
echo "Groups configured (kc-user -> opensign-admins)."
