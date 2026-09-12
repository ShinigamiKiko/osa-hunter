#!/usr/bin/env bash
# Create the proxy repositories OSA expects, over the Nexus REST API.
#
#   ./bootstrap.sh <nexus-url> <admin-password>
#   ./bootstrap.sh http://10.0.0.12:8081 'my-password'
#
# Safe to re-run: a repository that already exists is reported and skipped.
set -euo pipefail

URL="${1:?usage: bootstrap.sh <nexus-url> <admin-password>}"
PASS="${2:?usage: bootstrap.sh <nexus-url> <admin-password>}"
API="${URL%/}/service/rest/v1"

create() {
  local kind="$1" name="$2" remote="$3"
  local code
  code=$(curl -s -o /tmp/nexus-boot.out -w '%{http_code}' \
    -u "admin:${PASS}" -X POST "${API}/repositories/${kind}/proxy" \
    -H 'Content-Type: application/json' \
    -d "{
      \"name\": \"${name}\",
      \"online\": true,
      \"storage\": { \"blobStoreName\": \"default\", \"strictContentTypeValidation\": true },
      \"proxy\": { \"remoteUrl\": \"${remote}\", \"contentMaxAge\": 1440, \"metadataMaxAge\": 1440 },
      \"negativeCache\": { \"enabled\": true, \"timeToLive\": 1440 },
      \"httpClient\": { \"blocked\": false, \"autoBlock\": true }
    }")
  case "$code" in
    201) printf '  %-14s created\n' "$name" ;;
    400) printf '  %-14s already exists\n' "$name" ;;
    401) printf '  %-14s FAILED: wrong admin password\n' "$name"; exit 1 ;;
    *)   printf '  %-14s FAILED (HTTP %s): %s\n' "$name" "$code" "$(cat /tmp/nexus-boot.out)"; exit 1 ;;
  esac
}

echo "Waiting for ${URL} …"
for _ in $(seq 1 60); do
  curl -sf "${API}/status" >/dev/null 2>&1 && break
  sleep 5
done
curl -sf "${API}/status" >/dev/null || { echo "Nexus is not answering at ${URL}"; exit 1; }

# apt takes an extra field: which distribution of the remote to mirror.
create_apt() {
  local name="$1" remote="$2" dist="$3"
  local code
  code=$(curl -s -o /tmp/nexus-boot.out -w '%{http_code}' \
    -u "admin:${PASS}" -X POST "${API}/repositories/apt/proxy" \
    -H 'Content-Type: application/json' \
    -d "{
      \"name\": \"${name}\",
      \"online\": true,
      \"storage\": { \"blobStoreName\": \"default\", \"strictContentTypeValidation\": true },
      \"proxy\": { \"remoteUrl\": \"${remote}\", \"contentMaxAge\": 1440, \"metadataMaxAge\": 1440 },
      \"negativeCache\": { \"enabled\": true, \"timeToLive\": 1440 },
      \"httpClient\": { \"blocked\": false, \"autoBlock\": true },
      \"apt\": { \"distribution\": \"${dist}\", \"flat\": false }
    }")
  case "$code" in
    201) printf '  %-14s created\n' "$name" ;;
    400) printf '  %-14s already exists\n' "$name" ;;
    *)   printf '  %-14s FAILED (HTTP %s): %s\n' "$name" "$code" "$(cat /tmp/nexus-boot.out)"; exit 1 ;;
  esac
}

echo "Creating proxy repositories:"
create npm   npm-proxy    https://registry.npmjs.org
create pypi  pypi-proxy   https://pypi.org
create maven maven-public https://repo1.maven.org/maven2
create_apt   debian-bookworm http://deb.debian.org/debian bookworm

cat <<EOF

Done. On the OSA host set:

  NEXUS_UPSTREAM=${URL}
  NEXUS_AUTH=Basic \$(printf 'admin:%s' '<password>' | base64)

Leave NEXUS_AUTH unset only if anonymous read access stays enabled in Nexus.
EOF
