#!/usr/bin/env bash
# Create the realm and OIDC client this app expects in a local FerrisKey (the
# `ferriskey` compose service) so AUTH_MODE=ferriskey works without touching the
# admin console. Safe to re-run: every step checks before it creates.
#
# In FerrisKey terms it sets up:
#   - realm $FERRISKEY_REALM
#   - a confidential client $FERRISKEY_CLIENT_ID with a service account
#   - redirect URI $BASE_URL/auth/callback
#   - a realm role with manage/view/query users, assigned to the service
#     account, which is what lets the app create users through the
#     client_credentials grant
#
# Prints the FERRISKEY_* values and, when .env has an empty
# FERRISKEY_CLIENT_SECRET=, fills it in.
#
# The admin login is the console's own flow (an authorization code obtained
# through login-actions/authenticate and exchanged without a secret), because
# the security-admin-console client has no password grant.
set -euo pipefail

FK_URL=${FERRISKEY_URL:-http://localhost:8090/api}
REALM=${FERRISKEY_REALM:-myapp}
CLIENT_ID=${FERRISKEY_CLIENT_ID:-myapp-dashboard}
BASE_URL=${BASE_URL:-http://localhost:8080}
ADMIN_USER=${FERRISKEY_ADMIN_USERNAME:-admin}
ADMIN_PASS=${FERRISKEY_ADMIN_PASSWORD:-admin}
ROLE_NAME="app-service-account"

# Evaluate a Python expression over the JSON on stdin, bound to `d`.
json() { python3 -c "import sys, json; d = json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
urlencode() { python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"; }

echo "Waiting for FerrisKey at $FK_URL ..."
for _ in $(seq 1 60); do
    curl -sf -o /dev/null "$FK_URL/config" && break
    sleep 2
done
curl -sf -o /dev/null "$FK_URL/config" || { echo "FerrisKey is not reachable at $FK_URL"; exit 1; }

# ── admin token ──────────────────────────────────────────────────────
CONSOLE_REDIRECT="${FK_URL%/api}/"
COOKIE=$(curl -si "$FK_URL/realms/master/protocol/openid-connect/auth?response_type=code&client_id=security-admin-console&redirect_uri=$(urlencode "$CONSOLE_REDIRECT")&scope=openid&state=bootstrap" \
    | grep -i '^set-cookie' | sed -E 's/.*FERRISKEY_SESSION=([^;]+).*/\1/')
[[ -n "$COOKIE" ]] || { echo "FerrisKey did not open a login session"; exit 1; }

CODE=$(curl -s -X POST "$FK_URL/realms/master/login-actions/authenticate?client_id=security-admin-console" \
    -H "Cookie: FERRISKEY_SESSION=$COOKIE" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
    | python3 -c "import sys, json, urllib.parse as u; d = json.load(sys.stdin); print(u.parse_qs(u.urlparse(d.get('url') or '').query).get('code', [''])[0])")
[[ -n "$CODE" ]] || { echo "Admin login failed (check FERRISKEY_ADMIN_USERNAME / _PASSWORD)"; exit 1; }

TOKEN=$(curl -s -X POST "$FK_URL/realms/master/protocol/openid-connect/token" \
    -d "grant_type=authorization_code&code=$CODE&client_id=security-admin-console&redirect_uri=$CONSOLE_REDIRECT" \
    | json "d['access_token']")
AUTH=(-H "Authorization: Bearer $TOKEN")
JSON=(-H 'Content-Type: application/json')

# ── realm ────────────────────────────────────────────────────────────
if curl -sf -o /dev/null "$FK_URL/realms/$REALM" "${AUTH[@]}"; then
    echo "Realm $REALM exists"
else
    curl -sf -o /dev/null -X POST "$FK_URL/realms" "${AUTH[@]}" "${JSON[@]}" -d "{\"name\":\"$REALM\"}"
    echo "Created realm $REALM"
fi

# ── client ───────────────────────────────────────────────────────────
CLIENT=$(curl -s "$FK_URL/realms/$REALM/clients" "${AUTH[@]}" \
    | python3 -c "import sys, json; cs = [c for c in json.load(sys.stdin)['data'] if c['client_id'] == sys.argv[1]]; print(json.dumps(cs[0]) if cs else '')" "$CLIENT_ID")
if [[ -n "$CLIENT" ]]; then
    echo "Client $CLIENT_ID exists"
else
    CLIENT=$(curl -sf -X POST "$FK_URL/realms/$REALM/clients" "${AUTH[@]}" "${JSON[@]}" -d "{
        \"client_id\": \"$CLIENT_ID\", \"name\": \"$CLIENT_ID\", \"client_type\": \"confidential\",
        \"public_client\": false, \"service_account_enabled\": true,
        \"direct_access_grants_enabled\": false, \"oauth_device_code_grant_enabled\": false,
        \"enabled\": true, \"protocol\": \"openid-connect\"}")
    echo "Created client $CLIENT_ID"
fi
CLIENT_UUID=$(echo "$CLIENT" | json "d['id']")
SECRET=$(echo "$CLIENT" | json "d['secret']")

# ── redirect URI ─────────────────────────────────────────────────────
CALLBACK="$BASE_URL/auth/callback"
if curl -s "$FK_URL/realms/$REALM/clients/$CLIENT_UUID/redirects" "${AUTH[@]}" | grep -q "\"$CALLBACK\""; then
    echo "Redirect URI $CALLBACK exists"
else
    curl -sf -o /dev/null -X POST "$FK_URL/realms/$REALM/clients/$CLIENT_UUID/redirects" "${AUTH[@]}" "${JSON[@]}" \
        -d "{\"value\":\"$CALLBACK\",\"enabled\":true}"
    echo "Added redirect URI $CALLBACK"
fi

# ── service-account role ─────────────────────────────────────────────
ROLE_ID=$(curl -s "$FK_URL/realms/$REALM/roles" "${AUTH[@]}" \
    | python3 -c "import sys, json; d = json.load(sys.stdin); rs = [r for r in d.get('data', d) if r['name'] == sys.argv[1]]; print(rs[0]['id'] if rs else '')" "$ROLE_NAME")
if [[ -n "$ROLE_ID" ]]; then
    echo "Role $ROLE_NAME exists"
else
    ROLE_ID=$(curl -sf -X POST "$FK_URL/realms/$REALM/roles" "${AUTH[@]}" "${JSON[@]}" -d "{
        \"name\": \"$ROLE_NAME\",
        \"description\": \"Lets the app manage its users through the client_credentials grant\",
        \"permissions\": [\"manage_users\", \"view_users\", \"query_users\"]}" | json "d['data']['id']")
    echo "Created role $ROLE_NAME"
fi

SA_USER_ID=$(curl -s "$FK_URL/realms/$REALM/users" "${AUTH[@]}" \
    | python3 -c "import sys, json; us = [u for u in json.load(sys.stdin)['data'] if u['username'] == sys.argv[1]]; print(us[0]['id'] if us else '')" "service-account-$CLIENT_ID")
[[ -n "$SA_USER_ID" ]] || { echo "Service account user for $CLIENT_ID not found"; exit 1; }
if curl -s "$FK_URL/realms/$REALM/users/$SA_USER_ID/roles" "${AUTH[@]}" | grep -q "\"$ROLE_ID\""; then
    echo "Service account already has $ROLE_NAME"
else
    curl -sf -o /dev/null -X POST "$FK_URL/realms/$REALM/users/$SA_USER_ID/roles/$ROLE_ID" "${AUTH[@]}"
    echo "Assigned $ROLE_NAME to the service account"
fi

# ── output ───────────────────────────────────────────────────────────
echo
echo "AUTH_MODE=ferriskey"
echo "FERRISKEY_URL=$FK_URL"
echo "FERRISKEY_REALM=$REALM"
echo "FERRISKEY_CLIENT_ID=$CLIENT_ID"
echo "FERRISKEY_CLIENT_SECRET=$SECRET"

if [[ -f .env ]] && grep -qE '^FERRISKEY_CLIENT_SECRET=$' .env; then
    perl -i -pe "s/^FERRISKEY_CLIENT_SECRET=\$/FERRISKEY_CLIENT_SECRET=$SECRET/" .env
    echo
    echo "Wrote FERRISKEY_CLIENT_SECRET into .env."
fi
