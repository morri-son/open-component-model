#!/usr/bin/env bash
# teardown-rekor-v2.sh — Stop the Rekor v2 stack started by setup-rekor-v2.sh.
#
# Stops all containers and removes volumes. The cloned rekor-tiles repository
# is left in place (set REKOR_TILES_DIR to match the setup script).
#
# Usage:
#   ./teardown-rekor-v2.sh

set -euo pipefail

REKOR_TILES_DIR="${REKOR_TILES_DIR:-/tmp/rekor-tiles}"
COMPOSE_PROJECT="${REKOR_V2_COMPOSE_PROJECT:-rekor-v2-ocm}"

log() { echo "==> $*" >&2; }

if ! docker compose version &>/dev/null; then
  echo "ERROR: docker compose plugin is required" >&2
  exit 1
fi

COMPOSE_FILE="${REKOR_TILES_DIR}/compose.yml"
OVERRIDE_FILE="${REKOR_TILES_DIR}/compose.override.yml"

if [[ ! -f "${COMPOSE_FILE}" ]]; then
  log "No compose file at ${COMPOSE_FILE}, nothing to do"
  exit 0
fi

FILES=(-f "${COMPOSE_FILE}")
if [[ -f "${OVERRIDE_FILE}" ]]; then
  FILES+=(-f "${OVERRIDE_FILE}")
fi

log "Stopping Rekor v2 stack (project: ${COMPOSE_PROJECT})"
docker compose -p "${COMPOSE_PROJECT}" "${FILES[@]}" down -v
log "Rekor v2 stack stopped and volumes removed"
