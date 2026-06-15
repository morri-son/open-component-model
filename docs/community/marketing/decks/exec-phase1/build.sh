#!/usr/bin/env bash
# Build the OCM Phase 1 executive deck.
# - Generates theme/_with-banner.css from theme/ocm-neonephos.css by
#   inlining the banner PNG as a base64 data URI (PPTX-safe).
# - Runs marp-cli to produce PPTX, HTML, and per-slide PNG previews.
#
# Run from the deck directory: ./build.sh

set -euo pipefail

DECK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
THEME_DIR="$DECK_DIR/theme"
DIST_DIR="$DECK_DIR/dist"

BASE_THEME="$THEME_DIR/ocm-neonephos.css"
BANNER_PNG="$THEME_DIR/neonephos-banner.png"
GENERATED_THEME="$THEME_DIR/_with-banner.css"

mkdir -p "$DIST_DIR"

# 1. Inline the banner PNG as a data URI in a generated theme file.
echo "==> Generating theme with inlined banner data URI"
BANNER_B64=$(base64 -i "$BANNER_PNG")
{
  cat "$BASE_THEME"
  printf '\n/* Auto-generated: banner backdrop as data URI */\n'
  printf 'section.hero-split .hero-bg {\n'
  printf '  background-image: url("data:image/png;base64,%s");\n' "$BANNER_B64"
  printf '}\n'
} > "$GENERATED_THEME"

# 2. Render PPTX, HTML, and per-slide PNG previews via marp-cli.
echo "==> Rendering PPTX"
npx --yes @marp-team/marp-cli@latest --config-file "$DECK_DIR/.marprc.yml" \
  --pptx \
  -o "$DIST_DIR/OCM-Sovereign-Delivery-Exec.pptx" \
  "$DECK_DIR/slides.md"

echo "==> Rendering HTML preview"
npx --yes @marp-team/marp-cli@latest --config-file "$DECK_DIR/.marprc.yml" \
  --html \
  -o "$DIST_DIR/preview.html" \
  "$DECK_DIR/slides.md"

echo "==> Rendering per-slide PNG previews"
npx --yes @marp-team/marp-cli@latest --config-file "$DECK_DIR/.marprc.yml" \
  --images png \
  -o "$DIST_DIR/preview.png" \
  "$DECK_DIR/slides.md"

echo "==> Done."
echo "PPTX: $DIST_DIR/OCM-Sovereign-Delivery-Exec.pptx"
echo "HTML: $DIST_DIR/preview.html"
echo "PNGs: $DIST_DIR/preview.*.png"
