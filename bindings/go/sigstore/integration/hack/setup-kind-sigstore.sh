#!/usr/bin/env bash
# setup-kind-sigstore.sh — Create a Kind cluster with a full Sigstore stack.
#
# This script deploys:
#   - Kind cluster with ingress-ready node labels and port mappings
#   - nginx-ingress controller (required for scaffold Helm chart routing)
#   - Sigstore scaffold Helm chart: Fulcio (CA), Rekor v1 (transparency log),
#     CTLog (certificate transparency), Trillian (Merkle tree backend),
#     TUF (trusted root distribution), TSA (RFC 3161 timestamp authority)
#
# After setup, it prints shell exports for the integration test env vars.
# All log output goes to stderr; only the export block goes to stdout so
# the script can be used with eval:
#
#   eval "$(./setup-kind-sigstore.sh)"
#
# Prerequisites: kind, kubectl, helm, curl
#
# The resulting cluster provides Rekor v1 only. For Rekor v2, run
# setup-rekor-v2.sh alongside this cluster — it starts Rekor v2 via
# docker compose on separate ports.

set -euo pipefail

# --- Configuration -----------------------------------------------------------

CLUSTER_NAME="${SIGSTORE_KIND_CLUSTER:-sigstore-ocm}"
SCAFFOLD_VERSION="${SIGSTORE_SCAFFOLD_VERSION:-0.6.106}"
NAMESPACE="sigstore-system"
TIMEOUT="300s"

# Local port assignments for kubectl port-forward.
# These must not conflict with each other or with Rekor v2 (default 3003).
FULCIO_LOCAL_PORT=5555
REKOR_LOCAL_PORT=3001
TUF_LOCAL_PORT=8088
TSA_LOCAL_PORT=3002

log() { echo "==> $*" >&2; }

# --- 1. Check prerequisites --------------------------------------------------

for cmd in kind kubectl helm curl; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: $cmd is required but not found in PATH" >&2
    exit 1
  fi
done

# --- inotify limits -----------------------------------------------------------
#
# The Sigstore stack runs many pods whose containerd-shims each create
# inotify file watches. The Linux default of max_user_instances=128 is
# often too low and causes "too many open files" errors during pod startup.
#
# Raise the limit on your container runtime's host before running:
#
#   Colima:         colima ssh -- sudo sysctl fs.inotify.max_user_instances=8192
#   Docker Desktop: usually fine (ships with higher defaults)
#   Podman:         podman machine ssh sudo sysctl -w fs.inotify.max_user_instances=8192
#   Native Linux:   sudo sysctl -w fs.inotify.max_user_instances=8192
#
# To persist on Colima, add to ~/.colima/default/colima.yaml:
#   provision:
#     - mode: system
#       script: sysctl -w fs.inotify.max_user_instances=8192
# -----------------------------------------------------------------------------

# --- 2. Create Kind cluster ---------------------------------------------------
#
# The cluster is configured with:
#   - node-labels "ingress-ready=true" (required by nginx-ingress Kind provider)
#   - extraPortMappings for host ports 8080/8443 (ingress HTTP/HTTPS)

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  log "Kind cluster '$CLUSTER_NAME' already exists, reusing"
else
  log "Creating Kind cluster '$CLUSTER_NAME'"
  kind create cluster --name "$CLUSTER_NAME" --config - <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 8080
    protocol: TCP
  - containerPort: 443
    hostPort: 8443
    protocol: TCP
EOF
fi

kubectl config use-context "kind-${CLUSTER_NAME}"

# --- 3. Install nginx-ingress controller -------------------------------------
#
# Required by the scaffold Helm chart for routing to Sigstore services.
# Uses the Kind-specific provider manifest which configures hostPort binding.

if kubectl get namespace ingress-nginx &>/dev/null; then
  log "nginx-ingress already installed"
else
  log "Installing nginx-ingress controller"
  kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
fi

log "Waiting for nginx-ingress controller deployment"
kubectl rollout status deployment/ingress-nginx-controller \
  --namespace ingress-nginx \
  --timeout="$TIMEOUT"

# --- 4. Install Sigstore scaffold via Helm ------------------------------------
#
# The scaffold chart deploys all Sigstore components into dedicated namespaces
# (fulcio-system, rekor-system, etc.). Ingress is disabled because we use
# kubectl port-forward for direct service access.
#
# TSA is configured with an in-memory signer (suitable for testing only).

helm repo add sigstore https://sigstore.github.io/helm-charts 2>/dev/null || true
helm repo update sigstore >&2

if helm status scaffold -n "$NAMESPACE" &>/dev/null; then
  log "Sigstore scaffold already installed"
else
  log "Installing Sigstore scaffold (v${SCAFFOLD_VERSION})"
  helm upgrade --install scaffold sigstore/scaffold \
    --namespace "$NAMESPACE" \
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
    --timeout "$TIMEOUT" \
    --wait >&2
fi

# --- 5. Wait for all components to be ready -----------------------------------

log "Waiting for Sigstore components to become ready"

for ns in fulcio-system rekor-system trillian-system ctlog-system tsa-system tuf-system; do
  if kubectl get namespace "$ns" &>/dev/null; then
    log "Waiting for pods in $ns"
    kubectl wait --namespace "$ns" \
      --for=condition=ready pod \
      --all \
      --timeout="$TIMEOUT" 2>/dev/null || log "Warning: some pods in $ns may not be ready"
  fi
done

# --- 6. Verify service health ------------------------------------------------
#
# Temporarily port-forward to check that Fulcio and Rekor respond to health
# checks. The port-forwards are killed after the check; persistent ones are
# started by the user (see instructions at the end).

log "Checking service health"

kubectl port-forward -n fulcio-system svc/fulcio-server "${FULCIO_LOCAL_PORT}:80" &>/dev/null &
FULCIO_PF=$!
kubectl port-forward -n rekor-system svc/rekor-server "${REKOR_LOCAL_PORT}:80" &>/dev/null &
REKOR_PF=$!
sleep 3

if curl -sf "http://localhost:${FULCIO_LOCAL_PORT}/healthz" -o /dev/null; then
  log "Fulcio is healthy"
else
  log "Warning: Fulcio health check failed"
fi

if curl -sf "http://localhost:${REKOR_LOCAL_PORT}/api/v1/log" -o /dev/null; then
  log "Rekor is healthy"
else
  log "Warning: Rekor health check failed"
fi

kill "$FULCIO_PF" "$REKOR_PF" 2>/dev/null || true
wait "$FULCIO_PF" "$REKOR_PF" 2>/dev/null || true

# --- 7. Generate a Kubernetes OIDC token --------------------------------------
#
# Creates a service account and generates a short-lived (1h) OIDC token for
# keyless (Fulcio) signing tests. The token audience "sigstore" must match
# the Fulcio server's OIDC configuration.
#
# Note: this token expires after 1 hour. Re-run this script or manually
# generate a new token with:
#   kubectl create token sigstore-test -n default --audience sigstore

log "Generating Kubernetes OIDC token"

kubectl create serviceaccount sigstore-test -n default 2>/dev/null || true

OIDC_TOKEN=$(kubectl create token sigstore-test -n default --audience sigstore --duration 1h 2>/dev/null || echo "")

if [ -z "$OIDC_TOKEN" ]; then
  log "Warning: Could not generate OIDC token (kubectl create token not supported?)"
fi

# --- 8. Fetch trusted_root.json from the TUF server --------------------------
#
# The TUF server distributes the trusted root containing Fulcio CA certificates,
# Rekor v1 public key, and CTLog keys. This is the standard Sigstore mechanism
# for trust anchor distribution.
#
# The TUF server uses content-addressable filenames (<hash>.trusted_root.json)
# so we list the targets directory and find the filename dynamically.

ARTIFACTS_DIR=$(mktemp -d)
TRUSTED_ROOT_PATH="${ARTIFACTS_DIR}/trusted_root.json"

log "Fetching trusted_root.json from TUF server"

kubectl port-forward -n tuf-system svc/tuf-server "${TUF_LOCAL_PORT}:80" &>/dev/null &
TUF_PF=$!
sleep 3

TRUSTED_ROOT_FILE=$(curl -sf "http://localhost:${TUF_LOCAL_PORT}/targets/" \
  | grep -o '[a-f0-9]*\.trusted_root\.json' | head -1)

if [ -n "$TRUSTED_ROOT_FILE" ]; then
  curl -sf "http://localhost:${TUF_LOCAL_PORT}/targets/${TRUSTED_ROOT_FILE}" \
    > "$TRUSTED_ROOT_PATH"
  log "trusted_root.json saved to $TRUSTED_ROOT_PATH"
else
  log "Warning: Could not find trusted_root.json in TUF targets"
fi

kill "$TUF_PF" 2>/dev/null || true
wait "$TUF_PF" 2>/dev/null || true

# --- 9. Generate signing_config.json -----------------------------------------
#
# signing_config.json is the standard Sigstore service discovery mechanism
# (protobuf-specs SigningConfig message). It tells clients which Fulcio, Rekor,
# and TSA endpoints are available, their API versions, and validity periods.
#
# This is one of three ways to configure service endpoints in the sigstore
# handler (the others being individual URL fields in Config, or relying on
# public Sigstore defaults). The integration test for signing_config exercises
# this path specifically.
#
# Field names use protobuf JSON camelCase convention (e.g., "caUrls" not
# "ca_urls", "rekorTlogUrls" not "rekor_tlog_urls").

FULCIO_LOCAL_URL="http://localhost:${FULCIO_LOCAL_PORT}"
REKOR_LOCAL_URL="http://localhost:${REKOR_LOCAL_PORT}"
TSA_LOCAL_URL="http://localhost:${TSA_LOCAL_PORT}"
TUF_LOCAL_URL="http://localhost:${TUF_LOCAL_PORT}"
SIGNING_CONFIG_PATH="${ARTIFACTS_DIR}/signing_config.json"

log "Generating signing_config.json pointing to local services"
cat > "$SIGNING_CONFIG_PATH" <<SIGCFG
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
      "url": "${REKOR_LOCAL_URL}",
      "majorApiVersion": 1,
      "validFor": {"start": "2020-01-01T00:00:00Z"}
    }
  ],
  "rekorTlogConfig": {"selector": "ANY"}
}
SIGCFG

# --- 10. Output env vars for integration tests --------------------------------

log "Setup complete. Export the following variables:"

cat <<EXPORTS
export SIGSTORE_INTEGRATION_TEST=1
export SIGSTORE_KIND_CLUSTER=${CLUSTER_NAME}
export SIGSTORE_REKOR_URL=${REKOR_LOCAL_URL}
export SIGSTORE_FULCIO_URL=${FULCIO_LOCAL_URL}
export SIGSTORE_TSA_URL=${TSA_LOCAL_URL}
export SIGSTORE_TUF_MIRROR_URL=${TUF_LOCAL_URL}
export SIGSTORE_OIDC_TOKEN=${OIDC_TOKEN}
export SIGSTORE_TRUSTED_ROOT_PATH=${TRUSTED_ROOT_PATH}
export SIGSTORE_SIGNING_CONFIG_PATH=${SIGNING_CONFIG_PATH}
EXPORTS

log ""
log "Start port-forwards with:"
log "  kubectl port-forward -n rekor-system svc/rekor-server ${REKOR_LOCAL_PORT}:80 &"
log "  kubectl port-forward -n fulcio-system svc/fulcio-server ${FULCIO_LOCAL_PORT}:80 &"
log "  kubectl port-forward -n tsa-system svc/tsa-server ${TSA_LOCAL_PORT}:80 &"
log "  kubectl port-forward -n tuf-system svc/tuf-server ${TUF_LOCAL_PORT}:80 &"
log ""
log "Then run: task bindings/go/sigstore/integration:test/integration"
