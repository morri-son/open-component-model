#!/usr/bin/env bash
# Render an OCM Marp deck variant to HTML for review.
#
# Marp is the *content iteration* tool. The brand-correct PPTX is built by
# decks/exec-phase1/build-pptx/build_pptx.py against OCM-Master.potx — Marp's
# pptx export is lossy and ignores the .potx, so we don't use it here.
#
# Local <img> in HTML doesn't load via file:// — this script renders the
# HTML and then serves it from a local web server so images resolve.
#
# Usage:
#   ./build.sh                      # renders slides.md, serves on :8080
#   ./build.sh slides-risk.md       # renders a variant
#   ./build.sh slides.md norender   # skip render, just serve dist/
#   ./build.sh slides.md noserve    # render only, don't serve

set -euo pipefail

DECK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$DECK_DIR/dist"
SOURCE="${1:-slides.md}"
MODE="${2:-serve}"
PORT="${PORT:-8080}"

if [[ "$MODE" != "norender" ]]; then
  if [[ ! -f "$DECK_DIR/$SOURCE" ]]; then
    echo "Source not found: $DECK_DIR/$SOURCE" >&2
    exit 1
  fi

  NAME="${SOURCE%.md}"
  # Render HTML *next to* slides.md so relative `../diagrams/` and
  # `../../../assets/` paths inside slides.md resolve as written. Putting
  # the HTML one dir deeper (e.g. dist/) silently breaks every <img>.
  OUT_HTML="$DECK_DIR/$NAME.html"

  echo "==> Rendering $SOURCE → $NAME.html"
  npx --yes @marp-team/marp-cli@latest --config-file "$DECK_DIR/.marprc.yml" \
    --html \
    -o "$OUT_HTML" \
    "$DECK_DIR/$SOURCE"

  echo "==> HTML: $OUT_HTML"
fi

if [[ "$MODE" != "noserve" ]]; then
  SERVE_ROOT="$(git -C "$DECK_DIR" rev-parse --show-toplevel)"
  REL_HTML="$(realpath --relative-to="$SERVE_ROOT" "$DECK_DIR/${SOURCE%.md}.html")"
  URL="http://localhost:$PORT/$REL_HTML"
  echo "==> Serving $SERVE_ROOT on :$PORT"
  echo "    Open: $URL"
  echo "    Ctrl-C to stop."
  ( sleep 0.5; open "$URL" 2>/dev/null || true ) &
  cd "$SERVE_ROOT"
  exec python3 -m http.server "$PORT"
fi
