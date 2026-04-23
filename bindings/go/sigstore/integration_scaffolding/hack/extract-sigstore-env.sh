#!/usr/bin/env bash
set -euo pipefail

# Extract sigstore verification material from a running scaffolding cluster
# and output env vars for the integration test suite.
#
# Prerequisites: kubectl, cosign, curl must be on PATH.
# The current kubectl context must point to the scaffolding cluster.
#
# Flags:
#   --local   Use localhost URLs from port-forwarded services instead of
#             Knative URLs.  Requires hack/port-forward.sh to be running.
#             This is needed on macOS (Colima / Docker Desktop) where the
#             MetalLB IPs are not routable from the host.

LOCAL_MODE=false
for arg in "$@"; do
  case "$arg" in
    --local) LOCAL_MODE=true ;;
  esac
done

require_nonempty() {
  local name="$1" val="$2"
  if [[ -z "$val" ]]; then
    echo "extract-sigstore-env: $name is empty (scaffolding cluster not ready?)" >&2
    exit 1
  fi
}

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if $LOCAL_MODE; then
  # In local mode, use localhost URLs from port-forward.sh.
  PF_ENV="$ROOT_DIR/tmp/port-forward-env.sh"
  if [[ ! -f "$PF_ENV" ]]; then
    echo "extract-sigstore-env: --local requires port-forward.sh to be running" >&2
    echo "  Run: bash hack/port-forward.sh --bg" >&2
    exit 1
  fi
  # shellcheck disable=SC1090
  . "$PF_ENV"

  FULCIO_URL="${LOCAL_FULCIO_URL}"
  REKOR_URL="${LOCAL_REKOR_URL}"
  TSA_URL="${LOCAL_TSA_URL}"
  CTLOG_URL="${LOCAL_CTLOG_URL}"
else
  # Standard mode: read URLs from Knative services.
  FULCIO_URL=$(kubectl -n fulcio-system get ksvc fulcio -ojsonpath='{.status.url}')
  REKOR_URL=$(kubectl -n rekor-system get ksvc rekor -ojsonpath='{.status.url}')
  TSA_URL=$(kubectl -n tsa-system get ksvc tsa -ojsonpath='{.status.url}')
  CTLOG_URL=$(kubectl -n ctlog-system get ksvc ctlog -ojsonpath='{.status.url}')
fi
require_nonempty FULCIO_URL "$FULCIO_URL"
require_nonempty REKOR_URL  "$REKOR_URL"
require_nonempty TSA_URL    "$TSA_URL"
require_nonempty CTLOG_URL  "$CTLOG_URL"

# Extract public keys and certificates.
# Fulcio: fetch the CA cert from the running Fulcio API, NOT the K8s secret.
# The scaffolding's testrelease.yaml rotates the fulcio-pub-key secret but the
# original Fulcio instance keeps signing with its original CA cert.  The API
# endpoint always returns the cert that the running Fulcio actually uses.
curl -sSf "${FULCIO_URL}/api/v1/rootCert" > "$WORK_DIR/fulcio-root.pem"
require_nonempty "fulcio-root.pem" "$(cat "$WORK_DIR/fulcio-root.pem")"
kubectl -n rekor-system get secret rekor-pub-key -ojsonpath='{.data.public}' | base64 -d > "$WORK_DIR/rekor.pub"
require_nonempty "rekor.pub" "$(cat "$WORK_DIR/rekor.pub")"
kubectl -n ctlog-system get secret ctlog-public-key -ojsonpath='{.data.public}' | base64 -d > "$WORK_DIR/ctlog.pub"
require_nonempty "ctlog.pub" "$(cat "$WORK_DIR/ctlog.pub")"
kubectl -n tsa-system get secret tsa-cert-chain -ojsonpath='{.data.cert-chain}' | base64 -d > "$WORK_DIR/tsa-chain.pem"
require_nonempty "tsa-chain.pem" "$(cat "$WORK_DIR/tsa-chain.pem")"

# Build trusted root containing only local cluster material.
# We use a Go helper instead of "cosign trusted-root create" because:
#   1. cosign's trusted-root create may not set publicKey.keyDetails correctly
#      for all key types.
#   2. The Go helper gives us full control over the trusted root structure,
#      allowing us to produce exactly the fields and values we need.
go run "${ROOT_DIR}/hack/build-trusted-root" \
  --fulcio-cert="$WORK_DIR/fulcio-root.pem" \
  --rekor-key="$WORK_DIR/rekor.pub" \
  --rekor-url="$REKOR_URL" \
  --ctlog-key="$WORK_DIR/ctlog.pub" \
  --ctlog-url="$CTLOG_URL" \
  --tsa-chain="$WORK_DIR/tsa-chain.pem" \
  --tsa-url="$TSA_URL/api/v1/timestamp" \
  --fulcio-url="$FULCIO_URL" \
  --out "${WORK_DIR}/trusted_root.json"

# Build signing config pointing at local cluster services
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
cosign signing-config create \
  --fulcio="url=${FULCIO_URL},api-version=1,start-time=${NOW},operator=scaffolding" \
  --rekor="url=${REKOR_URL},api-version=1,start-time=${NOW},operator=scaffolding" \
  --rekor-config=ANY \
  --tsa="url=${TSA_URL}/api/v1/timestamp,api-version=1,start-time=${NOW},operator=scaffolding" \
  --tsa-config=ANY \
  --out "${WORK_DIR}/signing_config.json"

# Copy artifacts to a stable location (not cleaned up by trap)
OUTDIR="${SIGSTORE_ENV_DIR:-$(pwd)/tmp/sigstore}"
mkdir -p "$OUTDIR"
cp "$WORK_DIR/trusted_root.json" "$OUTDIR/"
cp "$WORK_DIR/signing_config.json" "$OUTDIR/"

# Initialize cosign's local TUF cache with the scaffolding's TUF mirror.
# The signing handler builds a curated env for the cosign subprocess (only
# PATH, HOME, proxy, and TLS vars), so SIGSTORE_*/TUF_* vars are not
# forwarded.  Cosign must therefore find trust material in ~/.sigstore/root/.
if $LOCAL_MODE; then
  TUF_MIRROR="${LOCAL_TUF_URL}"
else
  TUF_MIRROR=$(kubectl -n tuf-system get ksvc tuf -ojsonpath='{.status.url}')
fi
require_nonempty TUF_MIRROR "$TUF_MIRROR"
kubectl -n tuf-system get secrets tuf-root -ojsonpath='{.data.root}' | base64 -d > "$WORK_DIR/tuf-root.json"
cosign initialize --mirror "$TUF_MIRROR" --root "$WORK_DIR/tuf-root.json" >&2

# Fetch OIDC token
if $LOCAL_MODE; then
  ISSUER_URL="${LOCAL_GETTOKEN_URL}"
else
  ISSUER_URL=$(kubectl -n default get ksvc gettoken -ojsonpath='{.status.url}')
fi
require_nonempty ISSUER_URL "$ISSUER_URL"
OIDC_TOKEN=$(curl -sSf "$ISSUER_URL")
require_nonempty OIDC_TOKEN "$OIDC_TOKEN"

# Output env vars (sourceable) — use printf %q to safely escape values
emit_export() {
  local name="$1" val="$2"
  printf 'export %s=%q\n' "$name" "$val"
}

# The FULCIO/REKOR/TSA URL exports below are for developer convenience (e.g.
# manual cosign invocations) -- the integration tests do not consume them.
emit_export SIGSTORE_FULCIO_URL    "$FULCIO_URL"
emit_export SIGSTORE_REKOR_URL     "$REKOR_URL"
emit_export SIGSTORE_TSA_URL       "$TSA_URL"
emit_export SIGSTORE_OIDC_TOKEN    "$OIDC_TOKEN"
emit_export SIGSTORE_TRUSTED_ROOT  "$OUTDIR/trusted_root.json"
emit_export SIGSTORE_SIGNING_CONFIG "$OUTDIR/signing_config.json"
emit_export SIGSTORE_OIDC_ISSUER   "https://kubernetes.default.svc.cluster.local"
emit_export SIGSTORE_OIDC_IDENTITY "https://kubernetes.io/namespaces/default/serviceaccounts/default"
