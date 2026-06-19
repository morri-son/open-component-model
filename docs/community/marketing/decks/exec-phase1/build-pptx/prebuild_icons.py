#!/usr/bin/env python3
"""Pre-render Tabler icons into the deck's asset library.

Why this script exists
----------------------
The native deck slides need Tabler outline icons in specific stroke
weights (1.0, 1.25, 1.5, 2.0) and brand colours (brand-blue 0F6BFF,
white FFFFFF). Doing this on the fly during the build produces opaque
cached PNGs in build-pptx/_raster/ that nobody finds again when
editing the deck in PowerPoint outside the Python pipeline.

Solution: pre-render every needed combination once, save it under
diagrams/icons/prebuilt/ as both SVG (for vector tools / future use)
and PNG (for direct PowerPoint drag-and-drop), with a clear filename
scheme. The build pipeline reads from there.

Filename scheme
---------------
    <icon>-stroke-<weight>-<colour>.<ext>

For example:
    package-stroke-1.0-brand-blue.svg
    package-stroke-1.0-brand-blue.png
    lock-stroke-1.5-white.svg
    lock-stroke-1.5-white.png

`<weight>` is the stroke-width as written into the SVG (1.0, 1.25,
1.5, 2.0). `<colour>` is one of the named brand colours below.

Usage
-----
    python prebuild_icons.py

Run this whenever you add a new Tabler icon to ICONS or want a new
stroke weight on the menu. The script is idempotent — files only
get rewritten when their inputs change.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DECK_DIR = SCRIPT_DIR.parent
ICONS_DIR = DECK_DIR / "diagrams" / "icons"
OUT_DIR = ICONS_DIR / "prebuilt"

# All Tabler icons used by the native slide modules. Listed here so a
# single grep tells you what the deck depends on; a missing entry just
# means the runtime rasteriser will fall back to the original SVG.
#
# Brand-logo icons (kubernetes, docker, helm) are filled SVGs from
# simple-icons.org with their fill rewritten to `currentColor`. The
# stroke-width patching in the rasteriser is a no-op on them, so they
# render the same at every "stroke" weight in the prebuilt library —
# but having all four weights present keeps the asset folder uniform.
ICONS = [
    "cluster.svg",
    "docker.svg",
    "file-text.svg",
    "git-merge.svg",
    "helm.svg",
    "kubernetes.svg",
    "list-search.svg",
    "lock.svg",
    "package.svg",
    "registry.svg",
    "rocket.svg",
    "shield.svg",
    "shield-check.svg",
    "signature.svg",
    "world.svg",
]

# Colour name → hex pair (the rasteriser writes the hex into the SVG).
# `brand-blue` is the OCM accent; `white` is used for the lock glyph
# inside the Sovereign Cloud silhouette.
COLOURS = {
    "brand-blue": "0F6BFF",
    "white":      "FFFFFF",
}

# Stroke weights to ship. 1.0 is the deck default (matches the SVG-
# variant slide). 1.25 / 1.5 / 2.0 are alternates kept on the asset
# shelf so a hand-editor can swap to a heavier outline without
# regenerating anything.
STROKES = [1.0, 1.25, 1.5, 2.0]

# Render PNG at this width. Tabler icons are 24×24 in viewBox terms;
# 192 px gives PowerPoint at 60-px display ~3.2× supersampling, which
# stays crisp after the resize.
PNG_WIDTH = 192


def _stroke_tag(stroke: float) -> str:
    """1.0 → '1.0', 1.25 → '1.25'. Used in filenames."""
    if stroke.is_integer():
        return f"{int(stroke)}.0"
    return f"{stroke:g}"


def _patch_svg(src_text: str, colour_hex: str, stroke: float) -> str:
    """Replace `currentColor` with the colour hex and force the
    stroke-width attribute to the requested weight. The Tabler outline
    icons have a single stroke-width on the root <svg>, so a single
    regex substitution covers every child path."""
    patched = src_text.replace("currentColor", f"#{colour_hex}")
    patched = re.sub(
        r'stroke-width="[^"]*"',
        f'stroke-width="{stroke:g}"',
        patched,
    )
    return patched


def _need_rebuild(out_path: Path, src_path: Path) -> bool:
    """File-mtime check. Cheap, good enough for a 50-file build."""
    if not out_path.exists():
        return True
    return out_path.stat().st_mtime < src_path.stat().st_mtime


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped = 0
    missing = []

    for icon in ICONS:
        src_path = ICONS_DIR / icon
        if not src_path.exists():
            missing.append(icon)
            continue
        src_text = src_path.read_text(encoding="utf-8")
        stem = src_path.stem  # "package", "shield-check", ...

        for colour_name, colour_hex in COLOURS.items():
            for stroke in STROKES:
                tag = f"{stem}-stroke-{_stroke_tag(stroke)}-{colour_name}"
                svg_out = OUT_DIR / f"{tag}.svg"
                png_out = OUT_DIR / f"{tag}.png"

                if _need_rebuild(svg_out, src_path):
                    svg_out.write_text(
                        _patch_svg(src_text, colour_hex, stroke),
                        encoding="utf-8",
                    )
                    written += 1
                else:
                    skipped += 1

                if _need_rebuild(png_out, svg_out):
                    subprocess.run(
                        [
                            "rsvg-convert",
                            "--width", str(PNG_WIDTH),
                            "--keep-aspect-ratio",
                            str(svg_out),
                            "-o", str(png_out),
                        ],
                        check=True,
                        capture_output=True,
                    )
                    written += 1
                else:
                    skipped += 1

    print(f"prebuild_icons: wrote {written} files, "
          f"{skipped} up to date, output in {OUT_DIR}")
    if missing:
        print(f"prebuild_icons: missing source SVGs: {', '.join(missing)}")


if __name__ == "__main__":
    main()
