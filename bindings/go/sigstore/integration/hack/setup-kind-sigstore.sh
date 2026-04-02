#!/usr/bin/env bash
# setup-kind-sigstore.sh — Create a Kind cluster with the full Sigstore stack.
#
# Deploys Rekor v1 (scaffold), Rekor v2 (rekor-tiles), Fulcio, CTLog,
# Trillian, TUF, and TSA. All services are port-forwarded to localhost.
#
# Usage:
#   ./setup-kind-sigstore.sh
#
# The script writes hack/generated.env which is automatically loaded
# by the Taskfile's test/integration task via dotenv.
#
# Prerequisites: kind, kubectl, helm, curl, openssl, xxd, shasum, jq

set -euo pipefail

# --- Configuration -----------------------------------------------------------

CLUSTER_NAME="${SIGSTORE_KIND_CLUSTER:-sigstore-ocm}"
SCAFFOLD_VERSION="${SIGSTORE_SCAFFOLD_VERSION:-0.6.106}"
REKOR_TILES_CHART_VERSION="${REKOR_TILES_CHART_VERSION:-1.1.3}"
REKOR_V2_HOSTNAME="rekor-local"
TIMEOUT="300s"

SCAFFOLD_NAMESPACE="sigstore-system"
REKOR_TILES_NAMESPACE="rekor-tiles-system"

FULCIO_LOCAL_PORT=5555
REKOR_V1_LOCAL_PORT=3001
TSA_LOCAL_PORT=3002
REKOR_V2_LOCAL_PORT="${REKOR_V2_HTTP_PORT:-3003}"
TUF_LOCAL_PORT=8088

log() { echo "==> $*" >&2; }

# Set KUBECONFIG to the KIND cluster if not already set
if [[ -z "${KUBECONFIG:-}" ]]; then
  KUBECONFIG=$(mktemp)
  kind get kubeconfig --name "$CLUSTER_NAME" > "$KUBECONFIG" 2>/dev/null || true
  export KUBECONFIG
  trap "rm -f '$KUBECONFIG'" EXIT
fi

# --- Prerequisites -----------------------------------------------------------

for cmd in kind kubectl helm curl openssl xxd shasum jq; do
  command -v "$cmd" &>/dev/null || { echo "ERROR: $cmd not found" >&2; exit 1; }
done

# --- inotify limits ----------------------------------------------------------
# The Sigstore stack runs many pods. If you hit "too many open files":
#   Colima:  colima ssh -- sudo sysctl fs.inotify.max_user_instances=8192
#   Podman:  podman machine ssh sudo sysctl -w fs.inotify.max_user_instances=8192
#   Linux:   sudo sysctl -w fs.inotify.max_user_instances=8192

if [[ "$(uname)" == "Linux" ]]; then
  log "Tuning inotify limits for Sigstore stack"
  sudo sysctl -w fs.inotify.max_user_instances=8192 2>/dev/null || true
  sudo sysctl -w fs.inotify.max_user_watches=1048576 2>/dev/null || true
fi

# --- Kind cluster ------------------------------------------------------------

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  log "Kind cluster '$CLUSTER_NAME' already exists, reusing"
else
  log "Creating Kind cluster '$CLUSTER_NAME'"
  kind create cluster --name "$CLUSTER_NAME" --config - <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
EOF
fi

kubectl config use-context "kind-${CLUSTER_NAME}"

# --- Helm repo ---------------------------------------------------------------

helm repo add sigstore https://sigstore.github.io/helm-charts 2>/dev/null || true
helm repo update sigstore >&2

# --- Prepare Rekor v2 signing key (before parallel installs) -----------------
# Fresh Ed25519 keypair per deployment. Private key → K8s secret, public key → trusted root.

ARTIFACTS_DIR=$(mktemp -d)
PRIVKEY_PEM="${ARTIFACTS_DIR}/signing-key.pem"
PUBKEY_PEM="${ARTIFACTS_DIR}/signing-key-pub.pem"

log "Generating Rekor v2 Ed25519 signing keypair"
openssl genpkey -algorithm Ed25519 -out "${PRIVKEY_PEM}" 2>/dev/null
openssl pkey -in "${PRIVKEY_PEM}" -pubout -out "${PUBKEY_PEM}" 2>/dev/null

kubectl create namespace "${REKOR_TILES_NAMESPACE}" 2>/dev/null || true
kubectl create secret generic signing-key \
  --namespace "${REKOR_TILES_NAMESPACE}" \
  --from-file=signing-key="${PRIVKEY_PEM}" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# --- Install Scaffold + Rekor v2 in parallel --------------------------------
# These two Helm installs have no dependency on each other. Config generation
# (TUF root fetch, trusted root composition) happens after both complete.

install_scaffold() {
  if helm status scaffold -n "$SCAFFOLD_NAMESPACE" &>/dev/null; then
    log "Sigstore scaffold already installed"
    return 0
  fi

  log "Installing Sigstore scaffold (v${SCAFFOLD_VERSION})"
  helm upgrade --install scaffold sigstore/scaffold \
    --namespace "$SCAFFOLD_NAMESPACE" \
    --create-namespace \
    --version "$SCAFFOLD_VERSION" \
    --set fulcio.enabled=true \
    --set rekor.enabled=true \
    --set ctlog.enabled=true \
    --set trillian.enabled=true \
    --set tuf.enabled=true \
    --set tsa.enabled=true \
    --set "tsa.server.args.signer=memory" \
    --set "tsa.server.ingress.http.enabled=false" \
    --set copySecretJob.enabled=true \
    --set "fulcio.server.ingress.http.enabled=false" \
    --set "rekor.server.ingress.enabled=false" \
    --set "tuf.ingress.create=false" \
    --set-json 'fulcio.config.contents={
      "OIDCIssuers": {
        "https://kubernetes.default.svc": {
          "IssuerURL": "https://kubernetes.default.svc",
          "ClientID": "sigstore",
          "Type": "kubernetes"
        },
        "https://kubernetes.default.svc.cluster.local": {
          "IssuerURL": "https://kubernetes.default.svc.cluster.local",
          "ClientID": "sigstore",
          "Type": "kubernetes"
        }
      },
      "MetaIssuers": {
        "https://kubernetes.*.svc": {
          "ClientID": "sigstore",
          "Type": "kubernetes"
        }
      }
    }' \
    --timeout "$TIMEOUT" \
    --wait >&2
}

install_rekor_v2() {
  # nodeSelector override: GKE label doesn't exist on Kind nodes.
  # readOnlyRootFilesystem=false: POSIX backend writes tiles to local FS.
  if helm status rekor-tiles -n "${REKOR_TILES_NAMESPACE}" &>/dev/null; then
    log "rekor-tiles already installed, upgrading"
  fi

  log "Installing rekor-tiles (v${REKOR_TILES_CHART_VERSION}, POSIX backend)"
  helm upgrade --install rekor-tiles sigstore/rekor-tiles \
    --namespace "${REKOR_TILES_NAMESPACE}" \
    --version "${REKOR_TILES_CHART_VERSION}" \
    --skip-schema-validation \
    --set "image.flavor=posix" \
    --set-json 'nodeSelector=null' \
    --set "namespace.create=false" \
    --set "namespace.name=${REKOR_TILES_NAMESPACE}" \
    --set "server.hostname=${REKOR_V2_HOSTNAME}" \
    --set "server.posix.storageDir.path=/storage" \
    --set "server.posix.storageDir.name=storage" \
    --set "server.posix.storageDir.volume.emptyDir.sizeLimit=1Gi" \
    --set "server.signer.file.path=/pki/signer.pem" \
    --set "server.signer.file.secret.name=signing-key" \
    --set "server.signer.file.secret.key=signing-key" \
    --set "server.signer.file.secret.mountPath=/pki" \
    --set "server.signer.file.secret.mountSubPath=signer.pem" \
    --set "securityContext.readOnlyRootFilesystem=false" \
    --timeout "$TIMEOUT" \
    --wait >&2
}

install_scaffold &
SCAFFOLD_PID=$!
install_rekor_v2 &
REKOR_V2_PID=$!

INSTALL_FAILED=0
wait $SCAFFOLD_PID || { echo "ERROR: scaffold Helm install failed" >&2; INSTALL_FAILED=1; }
wait $REKOR_V2_PID || { echo "ERROR: rekor-tiles Helm install failed" >&2; INSTALL_FAILED=1; }
[[ $INSTALL_FAILED -eq 0 ]] || exit 1

# --- Port-forwards -----------------------------------------------------------

log "Starting background port-forwards"

kubectl port-forward -n fulcio-system    svc/fulcio-server "${FULCIO_LOCAL_PORT}:80"    &>/dev/null &
kubectl port-forward -n rekor-system     svc/rekor-server  "${REKOR_V1_LOCAL_PORT}:80"  &>/dev/null &
kubectl port-forward -n tsa-system       svc/tsa-server    "${TSA_LOCAL_PORT}:80"       &>/dev/null &
kubectl port-forward -n tuf-system       svc/tuf-server    "${TUF_LOCAL_PORT}:80"       &>/dev/null &
kubectl port-forward -n "${REKOR_TILES_NAMESPACE}" svc/rekor-tiles "${REKOR_V2_LOCAL_PORT}:80" &>/dev/null &

wait_for_portforward() {
  local name="$1" url="$2" max_attempts="${3:-15}"
  for i in $(seq 1 "$max_attempts"); do
    if curl -sf "$url" -o /dev/null 2>/dev/null; then
      log "$name is ready"
      return 0
    fi
    sleep 1
  done
  log "Warning: $name not reachable after ${max_attempts}s"
  return 1
}

log "Waiting for port-forwards to become ready"
wait_for_portforward "Fulcio"   "http://localhost:${FULCIO_LOCAL_PORT}/healthz"
wait_for_portforward "Rekor v1" "http://localhost:${REKOR_V1_LOCAL_PORT}/api/v1/log"
wait_for_portforward "TUF"      "http://localhost:${TUF_LOCAL_PORT}"

# Rekor v2 needs more time — its healthz returns "SERVING" when ready.
log "Waiting for Rekor v2 to become healthy..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${REKOR_V2_LOCAL_PORT}/healthz" 2>/dev/null | grep -q "SERVING"; then
    log "Rekor v2 is healthy"
    break
  fi
  if [[ $i -eq 30 ]]; then
    echo "ERROR: Rekor v2 failed to become healthy after 60s" >&2
    kubectl logs -n "${REKOR_TILES_NAMESPACE}" -l app.kubernetes.io/name=rekor-tiles --tail=50 >&2
    exit 1
  fi
  sleep 2
done

# --- OIDC token --------------------------------------------------------------
# Short-lived (1h) token for keyless (Fulcio) signing. Audience must match Fulcio config.
# Refresh: kubectl create token sigstore-test -n default --audience sigstore

log "Generating Kubernetes OIDC token"
kubectl create serviceaccount sigstore-test -n default 2>/dev/null || true
OIDC_TOKEN=$(kubectl create token sigstore-test -n default --audience sigstore --duration 1h 2>/dev/null || echo "")

if [[ -z "$OIDC_TOKEN" ]]; then
  log "Warning: Could not generate OIDC token"
fi

# --- Fetch v1 trusted_root.json from TUF server ------------------------------
# TUF uses content-addressable filenames (<hash>.trusted_root.json).

V1_TRUSTED_ROOT_PATH="${ARTIFACTS_DIR}/v1_trusted_root.json"

log "Fetching trusted_root.json from TUF server"
TRUSTED_ROOT_FILE=$(curl -sf "http://localhost:${TUF_LOCAL_PORT}/targets/" \
  | grep -o '[a-f0-9]*\.trusted_root\.json' | head -1)

if [[ -n "$TRUSTED_ROOT_FILE" ]]; then
  curl -sf "http://localhost:${TUF_LOCAL_PORT}/targets/${TRUSTED_ROOT_FILE}" \
    > "$V1_TRUSTED_ROOT_PATH"
  log "v1 trusted_root.json saved to $V1_TRUSTED_ROOT_PATH"
else
  log "Warning: Could not find trusted_root.json in TUF targets"
fi

# --- Fetch TUF initial root (trust anchor for custom TUF mirrors) -----------
# The TUF root.json at the repository base is the initial trust anchor.
# sigstore-go's tuf.New() requires opts.Root to be set for custom mirrors.

TUF_INITIAL_ROOT_PATH="${ARTIFACTS_DIR}/tuf_initial_root.json"

log "Fetching TUF initial root.json"
if curl -sf "http://localhost:${TUF_LOCAL_PORT}/root.json" > "$TUF_INITIAL_ROOT_PATH"; then
  log "TUF initial root.json saved to $TUF_INITIAL_ROOT_PATH"
else
  log "Warning: Could not fetch TUF initial root.json"
fi

# --- Generate Rekor v2 composite trusted root --------------------------------
#
# sigstore-go verifies Rekor v2 log entries via trusted_root.json containing:
#   - Ed25519 public key from this Rekor instance
#   - logId.keyId: C2SP signed-note key hash = SHA-256(origin + "\n" + 0x01 + raw_key)
#   - baseUrl hostname must match the Rekor --hostname flag (the "origin")
#     because sigstore-go derives the note verifier key hash from it
#
# The composite root combines the v1 root (Fulcio CA, CTLog, TSA) with the
# v2 tlog entry so keyless verification works with both backends.
#
# See: https://c2sp.org/signed-note

PUBKEY_DER_FILE=$(mktemp)
RAW_KEY_FILE=$(mktemp)
trap 'rm -f "${PUBKEY_DER_FILE}" "${RAW_KEY_FILE}"' EXIT

openssl pkey -pubin -in "${PUBKEY_PEM}" -outform DER -out "${PUBKEY_DER_FILE}" 2>/dev/null
PUBKEY_B64=$(base64 < "${PUBKEY_DER_FILE}" | tr -d '\n')

# SPKI DER header is 12 bytes for Ed25519; raw key is the last 32 bytes.
tail -c 32 "${PUBKEY_DER_FILE}" > "${RAW_KEY_FILE}"

REKOR_V2_LOG_KEY_ID=$( \
  printf '%s\n\x01' "${REKOR_V2_HOSTNAME}" \
  | cat - "${RAW_KEY_FILE}" \
  | shasum -a 256 \
  | cut -d' ' -f1 \
  | xxd -r -p \
  | base64 \
  | tr -d '\n' \
)

REKOR_V2_TRUSTED_BASE_URL="http://${REKOR_V2_HOSTNAME}:${REKOR_V2_LOCAL_PORT}"

REKOR_V2_TLOG_ENTRY=$(jq -n \
  --arg baseUrl "${REKOR_V2_TRUSTED_BASE_URL}" \
  --arg rawBytes "${PUBKEY_B64}" \
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

V2_TRUSTED_ROOT_PATH="${ARTIFACTS_DIR}/v2_trusted_root.json"

log "Creating composite trusted root (Fulcio CA + Rekor v2 log key)"
jq --argjson v2tlog "${REKOR_V2_TLOG_ENTRY}" \
  '.tlogs = [$v2tlog]' \
  "${V1_TRUSTED_ROOT_PATH}" > "${V2_TRUSTED_ROOT_PATH}"

# --- Generate signing configs -------------------------------------------------
# Two separate configs so tests can deterministically target v1 or v2.
# Using a combined config with selector:ANY would make service selection
# non-deterministic, and v1/v2 require different trusted roots for verification.

FULCIO_LOCAL_URL="http://localhost:${FULCIO_LOCAL_PORT}"
REKOR_V1_LOCAL_URL="http://localhost:${REKOR_V1_LOCAL_PORT}"
REKOR_V2_LOCAL_URL="http://localhost:${REKOR_V2_LOCAL_PORT}"
TSA_LOCAL_URL="http://localhost:${TSA_LOCAL_PORT}/api/v1/timestamp"
TUF_LOCAL_URL="http://localhost:${TUF_LOCAL_PORT}"

SIGNING_CONFIG_V1_PATH="${ARTIFACTS_DIR}/signing_config_v1.json"
SIGNING_CONFIG_V2_PATH="${ARTIFACTS_DIR}/signing_config_v2.json"

cat > "$SIGNING_CONFIG_V1_PATH" <<SIGCFG
{
  "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
  "caUrls": [
    {
      "url": "${FULCIO_LOCAL_URL}",
      "majorApiVersion": 1,
      "validFor": {"start": "2020-01-01T00:00:00Z"}
    }
  ],
  "rekorTlogUrls": [
    {
      "url": "${REKOR_V1_LOCAL_URL}",
      "majorApiVersion": 1,
      "validFor": {"start": "2020-01-01T00:00:00Z"}
    }
  ],
  "rekorTlogConfig": {"selector": "ANY"}
}
SIGCFG

cat > "$SIGNING_CONFIG_V2_PATH" <<SIGCFG
{
  "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
  "caUrls": [
    {
      "url": "${FULCIO_LOCAL_URL}",
      "majorApiVersion": 1,
      "validFor": {"start": "2020-01-01T00:00:00Z"}
    }
  ],
  "rekorTlogUrls": [
    {
      "url": "${REKOR_V2_LOCAL_URL}",
      "majorApiVersion": 2,
      "validFor": {"start": "2020-01-01T00:00:00Z"}
    }
  ],
  "rekorTlogConfig": {"selector": "ANY"},
  "tsaUrls": [
    {
      "url": "${TSA_LOCAL_URL}",
      "majorApiVersion": 1,
      "validFor": {"start": "2020-01-01T00:00:00Z"}
    }
  ]
}
SIGCFG

# --- Write generated env file ------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/generated.env"

cat > "${ENV_FILE}" <<ENVFILE
SIGSTORE_KIND_CLUSTER=${CLUSTER_NAME}
SIGSTORE_REKOR_URL=${REKOR_V1_LOCAL_URL}
SIGSTORE_FULCIO_URL=${FULCIO_LOCAL_URL}
SIGSTORE_TSA_URL=${TSA_LOCAL_URL}
SIGSTORE_TUF_MIRROR_URL=${TUF_LOCAL_URL}
SIGSTORE_TUF_INITIAL_ROOT_PATH=${TUF_INITIAL_ROOT_PATH}
SIGSTORE_OIDC_TOKEN=${OIDC_TOKEN}
SIGSTORE_TRUSTED_ROOT_PATH=${V1_TRUSTED_ROOT_PATH}
SIGSTORE_SIGNING_CONFIG_V1_PATH=${SIGNING_CONFIG_V1_PATH}
SIGSTORE_SIGNING_CONFIG_V2_PATH=${SIGNING_CONFIG_V2_PATH}
SIGSTORE_REKOR_V2_URL=${REKOR_V2_LOCAL_URL}
SIGSTORE_REKOR_V2_TRUSTED_ROOT_PATH=${V2_TRUSTED_ROOT_PATH}
ENVFILE

log "Wrote env file: ${ENV_FILE}"
log ""
log "Port-forwards running:"
log "  Fulcio:   http://localhost:${FULCIO_LOCAL_PORT}"
log "  Rekor v1: http://localhost:${REKOR_V1_LOCAL_PORT}"
log "  Rekor v2: http://localhost:${REKOR_V2_LOCAL_PORT}"
log "  TSA:      http://localhost:${TSA_LOCAL_PORT}"
log "  TUF:      http://localhost:${TUF_LOCAL_PORT}"
log ""
log "Run: task bindings/go/sigstore/integration:test/integration"
