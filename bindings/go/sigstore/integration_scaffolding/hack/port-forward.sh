#!/usr/bin/env bash
set -euo pipefail

# port-forward.sh -- Forward sigstore scaffolding Knative services to localhost.
#
# On macOS (Colima / Docker Desktop) the MetalLB IPs used by Knative's Kourier
# ingress (172.18.x.x) are not routable from the host.  This script sets up
# kubectl port-forwards to the underlying K8s services created by Knative so
# that tests can reach Fulcio, Rekor, TSA, CTLog, TUF, and gettoken via
# localhost.
#
# Usage:
#   bash hack/port-forward.sh              # foreground; Ctrl-C to stop
#   bash hack/port-forward.sh --bg         # background; writes PID file
#   bash hack/port-forward.sh --stop       # stop a backgrounded instance
#
# The script writes a sourceable env file to tmp/port-forward-env.sh that
# contains the LOCAL_* variables for each service.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PID_FILE="$ROOT_DIR/tmp/port-forward.pids"
ENV_FILE="$ROOT_DIR/tmp/port-forward-env.sh"

# ---------------------------------------------------------------------------
# Port assignments (chosen to avoid common conflicts)
# ---------------------------------------------------------------------------
LOCAL_PORT_FULCIO=8281
LOCAL_PORT_REKOR=8282
LOCAL_PORT_TSA=8283
LOCAL_PORT_CTLOG=8284
LOCAL_PORT_TUF=8285
LOCAL_PORT_GETTOKEN=8286

# ---------------------------------------------------------------------------
# Service definitions: namespace, ksvc-name, local-port
# ---------------------------------------------------------------------------
declare -a SERVICES=(
  "fulcio-system  fulcio    $LOCAL_PORT_FULCIO"
  "rekor-system   rekor     $LOCAL_PORT_REKOR"
  "tsa-system     tsa       $LOCAL_PORT_TSA"
  "ctlog-system   ctlog     $LOCAL_PORT_CTLOG"
  "tuf-system     tuf       $LOCAL_PORT_TUF"
  "default        gettoken  $LOCAL_PORT_GETTOKEN"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

check_prerequisites() {
  command -v kubectl >/dev/null 2>&1 || die "kubectl not found on PATH"
  kubectl cluster-info >/dev/null 2>&1 || die "kubectl cannot reach cluster (wrong context?)"
}

# resolve_k8s_service NAMESPACE KSVC_NAME
#
# Finds the underlying K8s service created by Knative for a given ksvc.
# Knative creates a service named "<ksvc>-<revision-suffix>" for each revision.
# We look for the latest-ready revision's K8s service.
resolve_k8s_service() {
  local ns="$1" name="$2"

  # First try: use the Knative service's latestReadyRevisionName to find the
  # corresponding K8s service.
  local revision
  revision=$(kubectl -n "$ns" get ksvc "$name" \
    -ojsonpath='{.status.latestReadyRevisionName}' 2>/dev/null) || true

  if [[ -n "$revision" ]]; then
    # Prefer the -private variant: it has a pod selector, which is required
    # for kubectl port-forward.  The non-private revision service is a
    # headless/selectorless service that port-forward cannot attach to.
    if kubectl -n "$ns" get svc "${revision}-private" >/dev/null 2>&1; then
      echo "${revision}-private"
      return
    fi
    if kubectl -n "$ns" get svc "$revision" >/dev/null 2>&1; then
      echo "$revision"
      return
    fi
  fi

  # Fallback: look for any -private K8s service whose name starts with the
  # ksvc name.  Private services have pod selectors needed by port-forward.
  local svc
  svc=$(kubectl -n "$ns" get svc -o name 2>/dev/null \
    | sed 's|^service/||' \
    | grep "^${name}-.*-private$" \
    | head -1) || true

  if [[ -n "$svc" ]]; then
    echo "$svc"
    return
  fi

  # Last resort: use the ksvc name itself (some scaffolding versions create a
  # same-name K8s service).
  if kubectl -n "$ns" get svc "$name" >/dev/null 2>&1; then
    echo "$name"
    return
  fi

  return 1
}

# resolve_service_port NAMESPACE SVC_NAME
#
# Returns the first port number exposed by a K8s service (the service port used
# for port-forward).  Knative services expose port 80 on the K8s service.
resolve_service_port() {
  local ns="$1" svc="$2"
  local port
  port=$(kubectl -n "$ns" get svc "$svc" \
    -ojsonpath='{.spec.ports[0].port}' 2>/dev/null) || true
  echo "${port:-80}"
}

# wait_for_ksvc NAMESPACE NAME
#
# Waits until the Knative service reports a ready URL.
wait_for_ksvc() {
  local ns="$1" name="$2"
  local timeout=120 elapsed=0
  log "Waiting for ksvc $name in $ns to become ready..."
  while (( elapsed < timeout )); do
    local url
    url=$(kubectl -n "$ns" get ksvc "$name" \
      -ojsonpath='{.status.url}' 2>/dev/null) || true
    if [[ -n "$url" ]]; then
      return 0
    fi
    sleep 2
    (( elapsed += 2 ))
  done
  die "Timeout waiting for ksvc $name in $ns (${timeout}s)"
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

PIDS=()

cleanup() {
  log "Stopping port-forwards..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  rm -f "$PID_FILE"
  log "All port-forwards stopped."
}

# ---------------------------------------------------------------------------
# Stop a backgrounded instance
# ---------------------------------------------------------------------------

do_stop() {
  if [[ ! -f "$PID_FILE" ]]; then
    log "No PID file found at $PID_FILE -- nothing to stop."
    exit 0
  fi
  log "Stopping backgrounded port-forwards..."
  while IFS= read -r pid; do
    kill "$pid" 2>/dev/null || true
  done < "$PID_FILE"
  rm -f "$PID_FILE"
  log "Done."
  exit 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  local background=false

  for arg in "$@"; do
    case "$arg" in
      --bg|--background) background=true ;;
      --stop)            do_stop ;;
      -h|--help)
        echo "Usage: $0 [--bg|--stop]"
        echo ""
        echo "Forward sigstore scaffolding Knative services to localhost."
        echo ""
        echo "  --bg     Run port-forwards in background (writes PID file)"
        echo "  --stop   Stop a previously backgrounded instance"
        exit 0
        ;;
      *) die "Unknown argument: $arg" ;;
    esac
  done

  check_prerequisites
  mkdir -p "$ROOT_DIR/tmp"

  trap cleanup EXIT INT TERM

  log "Resolving Knative services and starting port-forwards..."
  echo ""

  # Accumulate env lines
  local env_lines=()

  for entry in "${SERVICES[@]}"; do
    local ns name local_port
    read -r ns name local_port <<< "$entry"

    wait_for_ksvc "$ns" "$name"

    local k8s_svc
    k8s_svc=$(resolve_k8s_service "$ns" "$name") \
      || die "Could not resolve K8s service for ksvc $name in $ns"

    local svc_port
    svc_port=$(resolve_service_port "$ns" "$k8s_svc")

    log "  $name: kubectl port-forward -n $ns svc/$k8s_svc $local_port:$svc_port"

    kubectl port-forward -n "$ns" "svc/$k8s_svc" "$local_port:$svc_port" \
      >/dev/null 2>&1 &
    local pid=$!
    PIDS+=("$pid")

    local upper
    upper=$(echo "$name" | tr '[:lower:]' '[:upper:]')
    env_lines+=("export LOCAL_${upper}_URL=http://localhost:${local_port}")
  done

  # Brief health check: verify all port-forward processes are still alive.
  sleep 1
  for pid in "${PIDS[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      die "A port-forward process (PID $pid) exited immediately. Check service availability."
    fi
  done

  # Write PID file
  printf '%s\n' "${PIDS[@]}" > "$PID_FILE"

  # Write env file
  {
    echo "# Generated by port-forward.sh -- do not edit"
    echo "# Source this file to get LOCAL_*_URL variables pointing at"
    echo "# the port-forwarded sigstore scaffolding services."
    for line in "${env_lines[@]}"; do
      echo "$line"
    done
  } > "$ENV_FILE"

  echo ""
  log "Port-forwards are running.  Localhost URLs:"
  echo ""
  printf '  %-12s %s\n' "Service" "URL"
  printf '  %-12s %s\n' "-------" "---"
  for entry in "${SERVICES[@]}"; do
    local ns name local_port
    read -r ns name local_port <<< "$entry"
    printf '  %-12s http://localhost:%d\n' "$name" "$local_port"
  done
  echo ""
  log "Env file written to: $ENV_FILE"
  log "PID file written to: $PID_FILE"
  echo ""

  if $background; then
    # Detach the cleanup trap so the background processes survive
    trap - EXIT INT TERM
    log "Running in background.  Use '$0 --stop' to clean up."
  else
    log "Press Ctrl-C to stop all port-forwards."
    # Wait for all background port-forward processes.  If any exits, the EXIT
    # trap will clean up remaining processes.
    wait
  fi
}

main "$@"
