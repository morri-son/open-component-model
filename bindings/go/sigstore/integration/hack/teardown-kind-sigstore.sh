#!/usr/bin/env bash
# teardown-kind-sigstore.sh — Delete the Kind cluster created by setup-kind-sigstore.sh.
#
# This removes the entire cluster including all Sigstore components.
# Port-forwards are terminated automatically when the cluster is deleted.
#
# Usage:
#   ./teardown-kind-sigstore.sh

set -euo pipefail

CLUSTER_NAME="${SIGSTORE_KIND_CLUSTER:-sigstore-ocm}"

log() { echo "==> $*" >&2; }

if ! command -v kind &>/dev/null; then
  echo "ERROR: kind is required but not found in PATH" >&2
  exit 1
fi

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  log "Deleting Kind cluster '$CLUSTER_NAME'"
  kind delete cluster --name "$CLUSTER_NAME"
  log "Cluster deleted"
else
  log "Kind cluster '$CLUSTER_NAME' does not exist, nothing to do"
fi
