#!/usr/bin/env bash
# setup-rekor-v2.sh — Start a local Rekor v2 instance via docker compose.
#
# Rekor v2 uses tile-backed transparency logs (Trillian-Tessera) with
# checkpoint-based inclusion proofs, as opposed to Rekor v1's Merkle tree
# approach. This script provides a local Rekor v2 environment for integration
# testing of sigstore-go's Rekor v2 code path.
#
# The script:
#   1. Clones sigstore/rekor-tiles (the official Rekor v2 implementation)
#   2. Starts the stack via docker compose (Spanner emulator, fake GCS,
#      witness, rekor-server)
#   3. Generates a trusted_root.json with the correct Ed25519 signing key
#      and C2SP note key hash for checkpoint verification
#   4. Prints shell exports for the integration test env vars
#
# All log output goes to stderr; only the export block goes to stdout so the
# script can be used with eval:
#
#   eval "$(./setup-rekor-v2.sh)"
#
# Prerequisites: docker (with compose plugin), git, openssl, xxd, shasum
#
# The default HTTP port is 3003 (avoiding conflict with Rekor v1 on 3001).
# Override with REKOR_V2_HTTP_PORT.

set -euo pipefail

# --- Configuration -----------------------------------------------------------

REKOR_TILES_DIR="${REKOR_TILES_DIR:-/tmp/rekor-tiles}"
REKOR_TILES_REPO="${REKOR_TILES_REPO:-https://github.com/sigstore/rekor-tiles.git}"
REKOR_V2_HTTP_PORT="${REKOR_V2_HTTP_PORT:-3003}"
REKOR_V2_GRPC_PORT="${REKOR_V2_GRPC_PORT:-3004}"
REKOR_V2_GCS_PORT="${REKOR_V2_GCS_PORT:-7080}"
COMPOSE_PROJECT="${REKOR_V2_COMPOSE_PROJECT:-rekor-v2-ocm}"

log() { echo "==> $*" >&2; }

# --- 1. Check prerequisites --------------------------------------------------

for cmd in docker git openssl xxd shasum jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: $cmd is required but not found in PATH" >&2
    exit 1
  fi
done

if ! docker compose version &>/dev/null; then
  echo "ERROR: docker compose plugin is required (https://docs.docker.com/compose/install/)" >&2
  exit 1
fi

# --- 2. Clone rekor-tiles repository -----------------------------------------

if [[ -d "${REKOR_TILES_DIR}/.git" ]]; then
  log "Updating rekor-tiles at ${REKOR_TILES_DIR}"
  git -C "${REKOR_TILES_DIR}" pull --ff-only >&2 2>&1 || true
else
  log "Cloning rekor-tiles to ${REKOR_TILES_DIR}"
  git clone --depth 1 "${REKOR_TILES_REPO}" "${REKOR_TILES_DIR}" >&2
fi

# --- 3. Create compose override to remap ports -------------------------------
#
# The upstream compose.yml uses default ports that may conflict with Rekor v1
# (port 3001) running in the Kind cluster. We remap them to avoid collisions.

OVERRIDE_FILE="${REKOR_TILES_DIR}/compose.override.yml"
cat > "${OVERRIDE_FILE}" <<YAML
services:
  rekor:
    ports:
    - "${REKOR_V2_HTTP_PORT}:3000"
    - "${REKOR_V2_GRPC_PORT}:3001"
  gcs:
    ports:
    - "${REKOR_V2_GCS_PORT}:7080"
YAML
log "Created compose override: HTTP=${REKOR_V2_HTTP_PORT}, gRPC=${REKOR_V2_GRPC_PORT}"

# --- 4. Start the stack ------------------------------------------------------
#
# The stack includes:
#   - Spanner emulator (in-memory database backend for Tessera)
#   - fake-gcs-server (object storage for tiles)
#   - witness (countersigns checkpoints)
#   - rekor-server (the Rekor v2 HTTP/gRPC server)
#
# First run pulls images and builds; subsequent runs reuse cached layers.

log "Starting Rekor v2 stack (first run may take a few minutes to build)..."
docker compose \
  -p "${COMPOSE_PROJECT}" \
  -f "${REKOR_TILES_DIR}/compose.yml" \
  -f "${OVERRIDE_FILE}" \
  up -d --build --wait >&2

# --- 5. Wait for health ------------------------------------------------------

log "Waiting for Rekor v2 to become healthy..."
MAX_RETRIES=30
RETRY_INTERVAL=3
for i in $(seq 1 $MAX_RETRIES); do
  if curl -sf "http://localhost:${REKOR_V2_HTTP_PORT}/healthz" 2>/dev/null | grep -q "SERVING"; then
    log "Rekor v2 is healthy"
    break
  fi
  if [[ $i -eq $MAX_RETRIES ]]; then
    echo "ERROR: Rekor v2 failed to become healthy after $((MAX_RETRIES * RETRY_INTERVAL))s" >&2
    docker compose \
      -p "${COMPOSE_PROJECT}" \
      -f "${REKOR_TILES_DIR}/compose.yml" \
      -f "${OVERRIDE_FILE}" \
      logs --tail=50 >&2
    exit 1
  fi
  sleep $RETRY_INTERVAL
done

# --- 6. Generate a trusted root for Rekor v2 ---------------------------------
#
# sigstore-go requires a trusted_root.json to verify Rekor v2 transparency log
# entries. The trusted root must contain:
#
#   - The Ed25519 public key used by this Rekor instance to sign checkpoints
#   - A logId.keyId computed using the C2SP signed-note key hash format
#   - A baseUrl whose hostname matches the Rekor --hostname flag (the "origin")
#
# Why the origin matters:
#   Rekor v2 signs checkpoints in the C2SP signed-note format. The note
#   verifier key hash is derived from SHA-256(origin + "\n" + 0x01 + key),
#   where origin is the --hostname flag. sigstore-go extracts the origin from
#   url.Parse(baseUrl).Hostname(), so the baseUrl hostname must match exactly.
#   The actual HTTP connection uses localhost via SIGSTORE_REKOR_V2_URL.
#
# See: https://pkg.go.dev/golang.org/x/mod/sumdb/note
# See: https://c2sp.org/signed-note

REKOR_V2_PUBKEY_PEM="${REKOR_TILES_DIR}/tests/testdata/pki/ed25519-pub-key.pem"
if [[ ! -f "${REKOR_V2_PUBKEY_PEM}" ]]; then
  echo "ERROR: Rekor v2 public key not found at ${REKOR_V2_PUBKEY_PEM}" >&2
  exit 1
fi

# Convert PEM to DER for key extraction and base64 encoding.
REKOR_V2_PUBKEY_DER_FILE=$(mktemp)
trap 'rm -f "${REKOR_V2_PUBKEY_DER_FILE}" "${REKOR_V2_RAW_KEY_FILE:-}"' EXIT
openssl pkey -pubin -in "${REKOR_V2_PUBKEY_PEM}" -outform DER -out "${REKOR_V2_PUBKEY_DER_FILE}" 2>/dev/null
REKOR_V2_PUBKEY_B64=$(base64 < "${REKOR_V2_PUBKEY_DER_FILE}" | tr -d '\n')

# Extract the origin name from compose.yml. The --hostname flag determines
# the origin string used in signed-note checkpoints.
REKOR_V2_ORIGIN=$(grep -- '--hostname=' "${REKOR_TILES_DIR}/compose.yml" | head -1 | sed 's/.*--hostname=//;s/[" ].*//')
if [[ -z "${REKOR_V2_ORIGIN}" ]]; then
  echo "ERROR: could not extract --hostname from compose.yml" >&2
  exit 1
fi
log "Rekor v2 origin (--hostname): ${REKOR_V2_ORIGIN}"

# Compute the log key ID using C2SP signed-note key hash format:
#
#   keyId = SHA-256(origin + "\n" + 0x01 + raw_ed25519_public_key)
#
# The raw Ed25519 public key is the last 32 bytes of the SPKI DER encoding
# (SPKI header is 12 bytes for Ed25519). The 0x01 byte is the Ed25519
# algorithm identifier in the C2SP note format.
REKOR_V2_RAW_KEY_FILE=$(mktemp)
tail -c 32 "${REKOR_V2_PUBKEY_DER_FILE}" > "${REKOR_V2_RAW_KEY_FILE}"

REKOR_V2_LOG_KEY_ID=$( \
  printf '%s\n\x01' "${REKOR_V2_ORIGIN}" \
  | cat - "${REKOR_V2_RAW_KEY_FILE}" \
  | shasum -a 256 \
  | cut -d' ' -f1 \
  | xxd -r -p \
  | base64 \
  | tr -d '\n' \
)

ARTIFACTS_DIR="${REKOR_TILES_DIR}/.artifacts"
mkdir -p "${ARTIFACTS_DIR}"
TRUSTED_ROOT_PATH="${ARTIFACTS_DIR}/trusted_root.json"

# The baseUrl hostname must be the Rekor origin (not localhost). See the
# comment above about why the origin must match.
REKOR_V2_TRUSTED_BASE_URL="http://${REKOR_V2_ORIGIN}:${REKOR_V2_HTTP_PORT}"

# Build the Rekor v2 tlog entry as a JSON object.
REKOR_V2_TLOG_ENTRY=$(jq -n \
  --arg baseUrl "${REKOR_V2_TRUSTED_BASE_URL}" \
  --arg rawBytes "${REKOR_V2_PUBKEY_B64}" \
  --arg keyId "${REKOR_V2_LOG_KEY_ID}" \
  '{
    baseUrl: $baseUrl,
    hashAlgorithm: "SHA2_256",
    publicKey: {
      rawBytes: $rawBytes,
      keyDetails: "PKIX_ED25519",
      validFor: { start: "2020-01-01T00:00:00Z" }
    },
    logId: { keyId: $keyId }
  }')

# When a Kind cluster trusted root is available (SIGSTORE_TRUSTED_ROOT_PATH),
# create a composite trusted root that combines:
#   - Rekor v2 tlog entry (from docker compose)
#   - Certificate authorities, CT logs, and TSAs (from Kind's Sigstore stack)
#
# This allows keyless signing tests that use Fulcio (from Kind) + Rekor v2
# (from docker compose). Without this, keyless verification would fail because
# the trusted root wouldn't contain the Fulcio CA chain.
V1_TRUSTED_ROOT="${SIGSTORE_TRUSTED_ROOT_PATH:-}"

if [[ -n "${V1_TRUSTED_ROOT}" && -f "${V1_TRUSTED_ROOT}" ]]; then
  log "Creating composite trusted root (Fulcio CA from Kind + Rekor v2 log key)"
  jq --argjson v2tlog "${REKOR_V2_TLOG_ENTRY}" \
    '.tlogs = [$v2tlog]' \
    "${V1_TRUSTED_ROOT}" > "${TRUSTED_ROOT_PATH}"
else
  log "Creating Rekor-v2-only trusted root (no Kind cluster trusted root available)"
  jq -n --argjson v2tlog "${REKOR_V2_TLOG_ENTRY}" \
    '{
      mediaType: "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
      tlogs: [$v2tlog],
      certificateAuthorities: [],
      ctlogs: [],
      timestampAuthorities: []
    }' > "${TRUSTED_ROOT_PATH}"
fi
log "Generated trusted root at ${TRUSTED_ROOT_PATH}"

# --- 7. Output env vars ------------------------------------------------------

REKOR_V2_URL="http://localhost:${REKOR_V2_HTTP_PORT}"

log "Setup complete. Export the following variables:"

cat <<EXPORTS
export SIGSTORE_REKOR_V2=1
export SIGSTORE_REKOR_V2_URL=${REKOR_V2_URL}
export SIGSTORE_REKOR_V2_TRUSTED_ROOT_PATH=${TRUSTED_ROOT_PATH}
export REKOR_TILES_DIR=${REKOR_TILES_DIR}
export REKOR_V2_COMPOSE_PROJECT=${COMPOSE_PROJECT}
EXPORTS

log ""
log "Run the Rekor v2 integration test with:"
log "  task bindings/go/sigstore/integration:test/integration"
