#!/usr/bin/env python3
"""
Build OCM-Sovereign-Delivery-Exec.pptx by instantiating slides from the
OCM-Master-Template.potx layouts and filling placeholders.

Why this is structured this way: the .potx template owns visual styling
(palette, type scale, eyebrow + title + footer chrome, column rules, tile
backgrounds). This script only supplies content. To restyle the whole deck,
edit the layouts in build_potx.py and rebuild the .potx — every deck that
uses it picks up the change automatically.

Layout-specific extras (banner image on slide 1, brand row on slide 1 + slide
10, diagram images on content slides) are added inline because they're
deck-specific, not template-wide.

Usage:
    .venv/bin/python build_pptx.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from lxml import etree
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.util import Emu, Pt


# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
DECK_DIR = SCRIPT_DIR.parent
MARKETING_DIR = DECK_DIR.parent.parent
ASSETS_DIR = MARKETING_DIR / "assets"
DIAGRAMS_DIR = DECK_DIR / "diagrams"
ICONS_DIR = DIAGRAMS_DIR / "icons"
THEME_DIR = DECK_DIR / "theme"
RASTER_DIR = SCRIPT_DIR / "_raster"

POTX_PATH = DECK_DIR / "OCM-Master.potx"
OUTPUT_PPTX = DECK_DIR / "OCM-Sovereign-Delivery-Exec.pptx"

RASTER_DIR.mkdir(exist_ok=True)


# -----------------------------------------------------------------------------
# Slide geometry — 16:9 @ 1920×1080
# -----------------------------------------------------------------------------

SLIDE_W_PX = 1920
SLIDE_H_PX = 1080
PX = 9525  # 1 px in EMU at 96 dpi

def px(n: float) -> Emu:
    return Emu(int(n * PX))


# -----------------------------------------------------------------------------
# OCM brand palette (canonical, mirror of build_potx.py PALETTE)
# -----------------------------------------------------------------------------

class C:
    BLUE       = RGBColor(0x0F, 0x6B, 0xFF)   # accent1 / brand-blue-dark
    BLUE_MID   = RGBColor(0x0A, 0x3A, 0x99)   # accent2 / brand-blue-mid
    CYAN       = RGBColor(0x5C, 0xD6, 0xFF)   # accent3 / brand-cyan
    GREY_MID   = RGBColor(0x6B, 0x72, 0x80)   # accent4
    BLUE_NIGHT = RGBColor(0x0A, 0x15, 0x30)   # accent5
    GREY_SOFT  = RGBColor(0xF3, 0xF4, 0xF6)   # accent6
    BLACK      = RGBColor(0x00, 0x00, 0x00)
    WHITE      = RGBColor(0xFF, 0xFF, 0xFF)


# -----------------------------------------------------------------------------
# OOXML namespaces (used for the gradient title surgery)
# -----------------------------------------------------------------------------

A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"


# -----------------------------------------------------------------------------
# SVG → PNG rasterization (for diagrams + icons)
# -----------------------------------------------------------------------------

def rasterize_svg(svg_path: Path, target_w_px: int) -> Path:
    if not svg_path.exists():
        raise FileNotFoundError(svg_path)
    out = RASTER_DIR / (svg_path.stem + f"_{target_w_px}.png")
    if out.exists() and out.stat().st_mtime >= svg_path.stat().st_mtime:
        return out
    subprocess.run(
        ["rsvg-convert", "--width", str(target_w_px), "--keep-aspect-ratio",
         str(svg_path), "-o", str(out)],
        check=True, capture_output=True,
    )
    return out


def first_existing(*candidates: Path) -> Path | None:
    for c in candidates:
        if c.exists():
            return c
    return None


# -----------------------------------------------------------------------------
# Open .potx as .pptx
# -----------------------------------------------------------------------------

def open_template_as_pptx() -> Presentation:
    """python-pptx refuses .potx files, so transparently swap the
    presentation content type to .pptx-flavored when loading. The output we
    save will still be a valid .pptx (we never write the template type back)."""
    if not POTX_PATH.exists():
        raise FileNotFoundError(
            f"{POTX_PATH} not found — run `python build_potx.py` first."
        )
    tmp_pptx = RASTER_DIR / "_potx_loaded.pptx"
    with zipfile.ZipFile(POTX_PATH, "r") as src:
        data = {n: src.read(n) for n in src.namelist()}
    ct = data["[Content_Types].xml"].decode("utf-8")
    ct = ct.replace(
        "presentationml.template.main+xml",
        "presentationml.presentation.main+xml",
    )
    data["[Content_Types].xml"] = ct.encode("utf-8")
    with zipfile.ZipFile(tmp_pptx, "w", zipfile.ZIP_DEFLATED) as out:
        for name, blob in data.items():
            out.writestr(name, blob)
    return Presentation(str(tmp_pptx))


# -----------------------------------------------------------------------------
# Placeholder helpers
# -----------------------------------------------------------------------------

def find_placeholder(slide, idx: int):
    for ph in slide.placeholders:
        if ph.placeholder_format.idx == idx:
            return ph
    raise KeyError(f"placeholder idx={idx} not found on slide using "
                   f"layout {slide.slide_layout.name!r}")


def delete_placeholder(slide, idx: int):
    """Remove a placeholder shape entirely from the slide. Use when a layout
    supplies a placeholder you don't want on this particular slide (e.g. the
    body box on the Plain layout for slides that draw their own content)."""
    ph = find_placeholder(slide, idx)
    sp = ph._element
    sp.getparent().remove(sp)


def set_text(slide, idx: int, text: str, *, color: RGBColor | None = None,
             align_left: bool = False):
    """Set a placeholder's text. Layout's lstStyle supplies size/font/case;
    we only override color when needed (e.g. hero title white).

    align_left=True forces left alignment via <a:pPr algn="l"/> — useful on
    placeholders that PowerPoint might otherwise center (Hero title, etc.).
    """
    from pptx.enum.text import PP_ALIGN
    ph = find_placeholder(slide, idx)
    tf = ph.text_frame
    tf.clear()
    paragraphs = text.split("\n")
    for i, line in enumerate(paragraphs):
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        if align_left:
            p.alignment = PP_ALIGN.LEFT
        run = p.add_run()
        run.text = line
        if color is not None:
            run.font.color.rgb = color


def set_split_gradient_title(slide, idx: int, prefix: str, noun: str,
                              align_left: bool = True):
    """Hero title second line: prefix in white, noun with the OCM gradient."""
    from pptx.enum.text import PP_ALIGN
    ph = find_placeholder(slide, idx)
    tf = ph.text_frame
    tf.clear()
    p = tf.paragraphs[0]
    if align_left:
        p.alignment = PP_ALIGN.LEFT
    r1 = p.add_run()
    r1.text = prefix
    r1.font.color.rgb = C.WHITE
    r2 = p.add_run()
    r2.text = noun
    # Replace solid fill with the OCM gradient on this run.
    rPr = r2._r.get_or_add_rPr()
    for tag in ("solidFill", "gradFill", "noFill"):
        existing = rPr.find(f"{{{A_NS}}}{tag}")
        if existing is not None:
            rPr.remove(existing)
    grad_xml = (
        f'<a:gradFill xmlns:a="{A_NS}" flip="none" rotWithShape="1">'
        '<a:gsLst>'
        '<a:gs pos="0"><a:srgbClr val="FFFFFF"/></a:gs>'
        '<a:gs pos="35000"><a:srgbClr val="5CD6FF"/></a:gs>'
        '<a:gs pos="75000"><a:srgbClr val="0F6BFF"/></a:gs>'
        '</a:gsLst>'
        '<a:lin ang="0" scaled="1"/>'
        '</a:gradFill>'
    )
    rPr.insert(0, etree.fromstring(grad_xml))


def set_gradient_title(slide, idx: int, text: str, *, align_left: bool = False):
    """Set a title with the OCM gradient applied to the entire run."""
    from pptx.enum.text import PP_ALIGN
    ph = find_placeholder(slide, idx)
    tf = ph.text_frame
    tf.clear()
    p = tf.paragraphs[0]
    if align_left:
        p.alignment = PP_ALIGN.LEFT
    r = p.add_run()
    r.text = text
    rPr = r._r.get_or_add_rPr()
    for tag in ("solidFill", "gradFill", "noFill"):
        existing = rPr.find(f"{{{A_NS}}}{tag}")
        if existing is not None:
            rPr.remove(existing)
    grad_xml = (
        f'<a:gradFill xmlns:a="{A_NS}" flip="none" rotWithShape="1">'
        '<a:gsLst>'
        '<a:gs pos="0"><a:srgbClr val="FFFFFF"/></a:gs>'
        '<a:gs pos="35000"><a:srgbClr val="5CD6FF"/></a:gs>'
        '<a:gs pos="75000"><a:srgbClr val="0F6BFF"/></a:gs>'
        '</a:gsLst>'
        '<a:lin ang="0" scaled="1"/>'
        '</a:gradFill>'
    )
    rPr.insert(0, etree.fromstring(grad_xml))


def set_action_path_lines(slide, idx: int, lines: list[tuple[str, str]],
                            sep: str = " — "):
    """Render a body placeholder where each line is split into ACTION (blue)
    and PATH (white) by `sep`. Used for the CTA slide."""
    ph = find_placeholder(slide, idx)
    tf = ph.text_frame
    tf.clear()
    for i, (action, path) in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        r1 = p.add_run()
        r1.text = action
        r1.font.color.rgb = C.CYAN
        r1.font.bold = True
        r2 = p.add_run()
        r2.text = sep + path
        r2.font.color.rgb = C.WHITE


def set_blue_box_bullets(slide, idx: int, items: list[str]):
    """Render a body placeholder as a list with blue square bullets.

    Each item gets a small filled square (▪) prefix in OCM brand blue, then
    the body text in black. We don't use PowerPoint's <a:buChar> machinery —
    Aptos doesn't render the small filled square consistently — so we put a
    blue-coloured glyph as the first run of each paragraph.
    """
    ph = find_placeholder(slide, idx)
    tf = ph.text_frame
    tf.clear()
    for i, body in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.space_before = Pt(8)
        p.space_after = Pt(8)
        bullet = p.add_run()
        bullet.text = "▪  "
        bullet.font.color.rgb = C.BLUE
        bullet.font.bold = True
        text_run = p.add_run()
        text_run.text = body
        text_run.font.color.rgb = C.BLACK


# -----------------------------------------------------------------------------
# Static decoration helpers (banner, brand row, diagram embeds)
# -----------------------------------------------------------------------------

def add_banner_full_bleed(slide, image_path: Path):
    """Place an image as full-slide background. Sent to back."""
    if not image_path.exists():
        return
    pic = slide.shapes.add_picture(str(image_path), 0, 0,
                                    width=px(SLIDE_W_PX),
                                    height=px(SLIDE_H_PX))
    # Move to bottom of z-order so placeholders sit on top.
    spTree = pic._element.getparent()
    spTree.remove(pic._element)
    # Insert just after grpSpPr (the first non-element header).
    insert_at = 0
    for i, el in enumerate(spTree):
        if el.tag.endswith("}grpSpPr"):
            insert_at = i + 1
            break
    spTree.insert(insert_at, pic._element)


def add_brand_row(slide):
    """Bottom-of-slide brand row: OCM logo left, NeoNephos logo right (white
    variants for use over dark backgrounds)."""
    ocm_svg = ASSETS_DIR / "ocm" / "ocm-horizontal-white.svg"
    nn_svg = ASSETS_DIR / "neonephos" / "neonephos-foundation-horizontal-white.svg"
    ocm_png = rasterize_svg(ocm_svg, target_w_px=400)
    nn_png = rasterize_svg(nn_svg, target_w_px=400)
    ocm_pic = slide.shapes.add_picture(
        str(ocm_png), px(96), px(SLIDE_H_PX - 56 - 76), height=px(76)
    )
    nn_pic = slide.shapes.add_picture(
        str(nn_png), px(96), px(SLIDE_H_PX - 56 - 52), height=px(52)
    )
    nn_pic.left = px(SLIDE_W_PX - 96) - nn_pic.width


def add_diagram(slide, svg_path: Path | None,
                 x_px: int, y_px: int,
                 max_w_px: int, max_h_px: int):
    """Rasterize a diagram SVG and place it. Caller controls the bounding box.

    Also drops the layout's empty picture placeholder (idx=10 on the Diagram
    layout) — otherwise PowerPoint shows a dotted outline + 'Insert picture'
    prompt next to our embedded picture.
    """
    if svg_path is None or not svg_path.exists():
        return
    try:
        delete_placeholder(slide, 10)
    except KeyError:
        pass
    png = rasterize_svg(svg_path, target_w_px=max_w_px)
    pic = slide.shapes.add_picture(str(png), px(x_px), px(y_px),
                                    width=px(max_w_px))
    if pic.height > px(max_h_px):
        ratio = px(max_h_px) / pic.height
        pic.height = px(max_h_px)
        pic.width = int(pic.width * ratio)
    pic.left = px(x_px) + (px(max_w_px) - pic.width) // 2


def add_tile_icon(slide, tile_x_px: int, tile_y_px: int, icon_name: str):
    """Place an icon at the top-left of a tile."""
    icon_path = ICONS_DIR / icon_name
    if not icon_path.exists():
        return
    png = rasterize_svg(icon_path, target_w_px=72)
    slide.shapes.add_picture(
        str(png),
        px(tile_x_px + 24), px(tile_y_px + 24),
        width=px(40), height=px(40),
    )


def _crop_to_content(png_path: Path) -> Path:
    """Crop trailing transparent / white margins off a logo PNG so that
    `add_logo_row` can normalise on *content* height (not file height).

    Without this step, logos that bake whitespace into the file (e.g. the
    SAP-NS2 PNG, BwI's SVG with .de wordmark padding) render visibly smaller
    next to logos that fill their bbox edge-to-edge (SAP, Platform Mesh).

    Crops are always written into the local `_raster` cache (never back into
    the assets tree, even when the input lives there).
    """
    from PIL import Image
    out = RASTER_DIR / (png_path.stem + "_crop.png")
    if out.exists() and out.stat().st_mtime >= png_path.stat().st_mtime:
        return out
    im = Image.open(png_path).convert("RGBA")
    w, h = im.size
    px_data = im.load()
    left, top, right, bot = w, h, 0, 0
    found = False
    for y in range(h):
        for x in range(w):
            r, g, b, a = px_data[x, y]
            if a > 8 and not (r > 240 and g > 240 and b > 240):
                found = True
                if x < left: left = x
                if x > right: right = x
                if y < top: top = y
                if y > bot: bot = y
    if not found:
        # Defensive fallback: nothing to crop, return original.
        return png_path
    im.crop((left, top, right + 1, bot + 1)).save(out)
    return out


def add_logo_row(slide, logos: list[Path], y_px: int,
                  row_h_px: int = 120,
                  max_logo_w_px: int = 320, max_logo_h_px: int = 80):
    """Three logos centred in a row, normalised on visible content height.

    Each input logo is rasterised (or used directly for PNG) and then cropped
    to its visible bounding box, so wordmarks with baked-in whitespace
    (BwI's tall ".de" frame, the SAP-NS2 PNG, Gardener's tagline) render at
    the same optical height as logos that already fill their bbox (SAP,
    Platform Mesh). Final placement uses height-first normalisation with a
    width cap as the safety net for very wide logos.
    """
    margin_x = 160
    inner_w = SLIDE_W_PX - 2 * margin_x
    n = len(logos)
    slot_w = inner_w // n
    for i, path in enumerate(logos):
        if path is None or not path.exists():
            continue
        if path.suffix.lower() == ".svg":
            img = rasterize_svg(path, target_w_px=max_logo_w_px * 2)
        else:
            img = path
        # Crop to visible content so we normalise on logo height, not file
        # height. Always go through this — even SVG output can carry padding.
        img = _crop_to_content(img)
        slot_x = margin_x + i * slot_w
        # Add at native size, then scale to fit the height constraint first.
        pic = slide.shapes.add_picture(str(img), px(slot_x), px(y_px))
        if pic.height != px(max_logo_h_px):
            ratio = px(max_logo_h_px) / pic.height
            pic.height = px(max_logo_h_px)
            pic.width = int(pic.width * ratio)
        # Then enforce width cap (rare — only triggers for very wide logos).
        if pic.width > px(max_logo_w_px):
            ratio = px(max_logo_w_px) / pic.width
            pic.width = px(max_logo_w_px)
            pic.height = int(pic.height * ratio)
        pic.left = px(slot_x) + (px(slot_w) - pic.width) // 2
        pic.top = px(y_px) + (px(row_h_px) - pic.height) // 2


# -----------------------------------------------------------------------------
# Hero / Tile geometry helpers — must mirror what the .potx layouts use
# -----------------------------------------------------------------------------

# These constants drive where the on-slide decoration (banner, brand row,
# tile icons) is placed. They MUST match the corresponding layout positions
# in build_potx.py — if you change one place, change the other.

TILE_X0_PX = 120
TILE_Y0_PX = 520
TILE_W_PX = 544
TILE_H_PX = 230
TILE_GUTTER_PX = 24


def tile_origin(index: int) -> tuple[int, int]:
    col = index % 3
    row = index // 3
    return (TILE_X0_PX + col * (TILE_W_PX + TILE_GUTTER_PX),
            TILE_Y0_PX + row * (TILE_H_PX + TILE_GUTTER_PX))


# -----------------------------------------------------------------------------
# Layout lookup
# -----------------------------------------------------------------------------

def layouts_by_name(prs: Presentation) -> dict[str, object]:
    return {l.name: l for l in prs.slide_masters[0].slide_layouts}


# =============================================================================
# Build the deck
# =============================================================================

def build():
    prs = open_template_as_pptx()
    layouts = layouts_by_name(prs)

    expected = {"Hero", "CTA", "Content / 3-Column",
                "Content / Diagram", "Content / Tiles", "Content / 2-Column",
                "Section Divider", "Plain", "Plain / Compact"}
    missing = expected - set(layouts)
    if missing:
        sys.exit(f"template missing expected layouts: {missing}")

    # ---- SLIDE 1 — HERO (cold-room canonical, revised 2026-06-17) -----------
    # Stake-led title + spannungs-subtitle. The original 11-word "Three minutes
    # from now, you'll know what your supply chain doesn't" was decomposed:
    # the *stake* lands in the title, the *time-bound promise* lands in the
    # subtitle. Title fits cleanly on ONE line at 115pt; the gradient sits on
    # a short second-line noun for visual punch.
    s = prs.slides.add_slide(layouts["Hero"])
    add_banner_full_bleed(s, THEME_DIR / "OCM-Banner.png")
    set_text(s, 1, "Your supply chain has", color=C.WHITE)
    set_split_gradient_title(s, 2, prefix="", noun="blind spots.")
    set_text(s, 3,
             "Three minutes from now, you'll know what they are.",
             color=C.CYAN)
    set_text(s, 4,
             "Open Component Model — open source, NeoNephos Foundation.",
             color=C.WHITE)
    add_brand_row(s)

    # ---- SLIDE 2 — WHY NOW (V1, sovereignty-led) ----------------------------
    s = prs.slides.add_slide(layouts["Content / 3-Column"])
    set_text(s, 1, "WHY NOW")
    set_text(s, 2, "Sovereignty is no longer optional")
    set_text(s, 10, "SOVEREIGNTY PRESSURE")
    set_text(s, 11, "Wherever the law puts the boundary — by jurisdiction, "
                     "sector, or air-gap — software must be deliverable, "
                     "verifiable, and operable inside it.")
    set_text(s, 12, "REGULATION TIGHTENING")
    set_text(s, 13, "EU DORA · NIS2 · CRA. Provable supply-chain control, "
                     "not best effort.")
    set_text(s, 14, "SUPPLY-CHAIN ATTACKS ARE REAL")
    set_text(s, 15, "SolarWinds. xz. log4shell. Signatures must survive the "
                     "journey, or compliance is theatre.")

    # ---- SLIDE 3 — MEET OCM (hub-and-spoke diagram, Option 3 reframe) -------
    # Diagram positioned per user spec 2026-06-17: 50.02 × 15.93 cm,
    # x=-2.4cm (slight bleed left), y=11.65cm.
    s = prs.slides.add_slide(layouts["Content / Diagram"])
    set_text(s, 1, "THE ANSWER")
    set_text(s, 2, "Meet OCM. One identity, every boundary.")
    add_diagram(s, DIAGRAMS_DIR / "03-meet-ocm-hub-and-spoke.svg",
                 x_px=-91, y_px=440, max_w_px=1890, max_h_px=602)

    # ---- SLIDE 4a — THE SHIFT, SBoD (text-only) -----------------------------
    s = prs.slides.add_slide(layouts["Plain / Compact"])
    set_text(s, 1, "THE SHIFT")
    set_text(s, 2, "SBOM lists. SBoD delivers.")
    set_blue_box_bullets(s, 10, [
        "An SBOM (Software Bill of Materials) tells you what's in your software. It was built for inventory.",
        "A Software Bill of Delivery (SBoD) tells you what you delivered, "
        "how to verify it, how to transport it, and how to operate it. "
        "It was built for delivery.",
        "The SBoD contains the SBOM. OCM doesn't replace your SBOM tooling — "
        "it gives the SBOM an envelope that's compliance-native, signed once, "
        "and travels intact across any boundary.",
    ])

    # ---- SLIDE 4b — THE SHIFT (diagram only) --------------------------------
    s = prs.slides.add_slide(layouts["Content / Diagram"])
    set_text(s, 1, "THE SHIFT — SBOM INSIDE SBoD")
    set_text(s, 2, "An envelope, not a list.")
    diagram = first_existing(
        DIAGRAMS_DIR / "04-sbom-inside-sbod.svg",
        DIAGRAMS_DIR / "04-sbom-vs-sbod.svg",
    )
    if diagram:
        # Slide 4b diagram positioned per user spec 2026-06-17:
        # 39.09 × 17.59 cm at x=5.15cm, y=10.99cm.
        add_diagram(s, diagram, x_px=195, y_px=415, max_w_px=1478, max_h_px=665)

    # ---- SLIDE 5 — HOW OCM COMPOSES (NEW, comparator slide) ----------------
    # Disarms three "we already have this" objections on one slide:
    # signing, transport, compliance. Each column says "what you have today"
    # then "what OCM adds" — OCM doesn't replace, it composes around them.
    s = prs.slides.add_slide(layouts["Content / 3-Column"])
    set_text(s, 1, "HOW OCM COMPOSES")
    set_text(s, 2, "OCM doesn't replace your tools. It gives them an envelope to compose around.")
    set_text(s, 10, "SIGNING")
    set_text(s, 11, "Keyless (Sigstore) or key-based (your PKI) signs one "
                     "artifact at a time. OCM gives them the complete SBoD "
                     "to sign — one signature covers every artifact in the "
                     "delivery, by digest.")
    set_text(s, 12, "TRANSPORT")
    set_text(s, 13, "Helm registries, S3, OCI — each moves artifacts. OCM "
                     "moves a signed envelope across any boundary: registry "
                     "to registry, registry to air-gapped archive. The "
                     "signature travels intact.")
    set_text(s, 14, "COMPLIANCE")
    set_text(s, 15, "Trivy, Grype, your SBOM tools — each scans in isolation. "
                     "OCM (via Open Delivery Gear) correlates every finding "
                     "by component identity. Compliance is a system output, "
                     "not a quarterly project.")

    # ---- SLIDE 6 — OCM IN ONE PICTURE (was slide 5) -------------------------
    s = prs.slides.add_slide(layouts["Content / Diagram"])
    set_text(s, 1, "OCM IN ONE PICTURE")
    set_text(s, 2, "Pack · Sign · Transport · Deploy")
    diagram6 = first_existing(
        DIAGRAMS_DIR / "05-pack-sign-transport-deploy-v2.svg",
        DIAGRAMS_DIR / "05-pack-sign-transport-deploy.svg",
    )
    add_diagram(s, diagram6, x_px=80, y_px=460, max_w_px=1760, max_h_px=560)

    # ---- SLIDE 7a — SOVEREIGN-READY (text-only, was 6a) --------------------
    s = prs.slides.add_slide(layouts["Plain / Compact"])
    set_text(s, 1, "SOVEREIGN-READY")
    set_text(s, 2, "Trust, but verify.")
    set_blue_box_bullets(s, 10, [
        "Identity is location-independent. A component carries its name "
        "regardless of which registry it lives in.",
        "Signatures are location-independent. Sign once at source; verify at "
        "the destination, or at any hop in between, with no callback upstream.",
        "Day-2 ops happen inside the boundary. Subscribe to the component and "
        "pull upgrades on your schedule, scale across regions, all without "
        "reaching back upstream.",
        "On transfer into a sovereign environment, a component can carry every "
        "artifact it needs along with it. The destination needs nothing more.",
    ])

    # ---- SLIDE 7b — SOVEREIGN-READY (diagram only, was 6b) -----------------
    s = prs.slides.add_slide(layouts["Content / Diagram"])
    set_text(s, 1, "SOVEREIGN-READY — AIR-GAP")
    set_text(s, 2, "Trust travels with the component.")
    # Diagram positioned per user spec 2026-06-17:
    # 40.22 × 17.6 cm at x=3.72cm, y=10.25cm.
    add_diagram(s, DIAGRAMS_DIR / "06-sovereign-airgap.svg",
                 x_px=141, y_px=387, max_w_px=1519, max_h_px=665)

    # ---- SLIDE 8 — SCAN / Compliance-native (was 7) ------------------------
    s = prs.slides.add_slide(layouts["Plain"])
    set_text(s, 1, "SCAN — COMPLIANCE-NATIVE WITH OPEN DELIVERY GEAR")
    set_text(s, 2, "Compliance as a system property —\nnot a quarterly retrofit.")
    set_blue_box_bullets(s, 10, [
        "Open Delivery Gear (ODG) is the OCM compliance automation engine.",
        "The Compliance Dashboard is your entry point: every component, "
        "every finding, every signature in one view.",
        "Continuous scans run asynchronously — even after release.",
        "Findings get rescored against contextual risk, so your team patches "
        "what actually matters.",
        "Every compliance signal correlates by component identity. Auditors "
        "get evidence, not spreadsheets.",
    ])
    add_source_line(s, 1020,
                     "github.com/open-component-model/open-delivery-gear")

    # ---- SLIDE 9 — WHAT OCM UNLOCKS (tiles, was 8) -------------------------
    s = prs.slides.add_slide(layouts["Content / Tiles"])
    set_text(s, 1, "WHAT OCM UNLOCKS")
    set_text(s, 2, "One model unlocks all of this.")
    tiles = [
        ("lock.svg", "Code signing across stacks",
         "Sign once at source; verify everywhere, with no per-stack tooling."),
        ("cloud-upload.svg", "Air-gapped delivery",
         "Walk a complete component across an air gap; verify at destination."),
        ("rocket.svg", "Kubernetes-native deployment",
         "OCM controllers deploy components directly into clusters."),
        ("radar.svg", "Asynchronous security scans",
         "Continuous scanning, even after release; findings tied to component identity."),
        ("source-of-truth.svg", "One source of truth",
         "Rebuild any landscape from a single signed descriptor."),
        ("report-analytics.svg", "Automated compliance reporting",
         "Reports composed from SBoD metadata — no spreadsheet drift."),
    ]
    for i, (icon, label, body) in enumerate(tiles):
        # Tile placeholders alternate label/body: idx 20+2i = label, 21+2i = body
        set_text(s, 20 + i * 2, label)
        set_text(s, 21 + i * 2, body)
        x, y = tile_origin(i)
        add_tile_icon(s, x, y, icon)

    # ---- SLIDE 10 — Adopters (two-column logo wall, was 9) ------------------
    # Plain layout + manual logo rows (not enough placeholders for a logo
    # wall; cleaner to draw it inline than add a new layout to the template).
    s = prs.slides.add_slide(layouts["Plain"])
    set_text(s, 1, "TRUSTED IN PRODUCTION")
    set_text(s, 2, "Aligned with NeoNephos.")
    # Plain layout has a body placeholder at idx=10. We want neither text nor
    # an empty container; the ALL-CAPS labels and logo rows below replace it.
    delete_placeholder(s, 10)
    # Top section label + logos
    add_label_at(s, 510, "ADOPTED BY ENTERPRISES SHIPPING INTO REGULATED ENVIRONMENTS")
    add_logo_row(s, [
        ASSETS_DIR / "adopters" / "sap" / "sap-horizontal-color.svg",
        ASSETS_DIR / "adopters" / "bwi" / "bwi-horizontal-color.svg",
        ASSETS_DIR / "adopters" / "sap-ns2" / "sap-ns2-getlogovector.png",
    ], y_px=580)
    add_label_at(s, 740, "BUILT INTO THE OPEN-SOURCE ECOSYSTEM")
    add_logo_row(s, [
        ASSETS_DIR / "adopters" / "gardener" / "gardener-horizontal-color.svg",
        ASSETS_DIR / "adopters" / "konfidence" / "konfidence-horizontal-light.svg",
        ASSETS_DIR / "adopters" / "platform-mesh" / "platform-mesh-horizontal-color.svg",
    ], y_px=810)
    add_centred_proof(s, 970,
                       "An open standard, neutrally governed — your stack "
                       "stays portable, your dependencies stay yours.")
    add_source_line(s, 1040,
                     "neonephos.org · gardener.cloud · konfidence.cloud · "
                     "platform-mesh.io · open-control-plane.io")

    # ---- SLIDE 11 — CTA (was 10) --------------------------------------------
    s = prs.slides.add_slide(layouts["CTA"])
    set_text(s, 1, "Start delivering with confidence.", color=C.WHITE)
    set_action_path_lines(s, 2, [
        ("Try it",        "ocm.software"),
        ("Build with us", "github.com/open-component-model"),
        ("Talk to us",    "community channels on the website"),
    ])
    add_brand_row(s)

    prs.save(str(OUTPUT_PPTX))
    print(f"Wrote {OUTPUT_PPTX}")


# -----------------------------------------------------------------------------
# Inline-decoration helpers used by slide 9
# -----------------------------------------------------------------------------

def add_label_at(slide, y_px: int, text: str):
    """Brand-blue ALL-CAPS section label — slide 9 logo wall headers."""
    from pptx.enum.text import PP_ALIGN
    tb = slide.shapes.add_textbox(px(120), px(y_px),
                                   px(SLIDE_W_PX - 240), px(36))
    tf = tb.text_frame
    tf.margin_left = tf.margin_right = 0
    tf.margin_top = tf.margin_bottom = 0
    p = tf.paragraphs[0]
    r = p.add_run()
    r.text = text
    f = r.font
    f.name = "Aptos"
    f.size = Pt(18)
    f.bold = True
    f.color.rgb = C.BLUE
    rPr = r._r.get_or_add_rPr()
    rPr.set("cap", "all")
    rPr.set("spc", "110")


def add_centred_proof(slide, y_px: int, text: str):
    from pptx.enum.text import PP_ALIGN
    tb = slide.shapes.add_textbox(px(120), px(y_px),
                                   px(SLIDE_W_PX - 240), px(80))
    tf = tb.text_frame
    tf.margin_left = tf.margin_right = 0
    tf.margin_top = tf.margin_bottom = 0
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    p.line_spacing = 1.4
    r = p.add_run()
    r.text = text
    r.font.name = "Aptos"
    r.font.size = Pt(18)
    r.font.color.rgb = C.BLUE_MID


def add_source_line(slide, y_px: int, text: str):
    """Small grey source/reference line — for slide footers that name the
    canonical URL of a project (NeoNephos, ODG, OpenControlPlane, etc.).
    Renders at the bottom of the slide as a discreet citation, not a CTA."""
    from pptx.enum.text import PP_ALIGN
    tb = slide.shapes.add_textbox(px(120), px(y_px),
                                   px(SLIDE_W_PX - 240), px(40))
    tf = tb.text_frame
    tf.margin_left = tf.margin_right = 0
    tf.margin_top = tf.margin_bottom = 0
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = text
    r.font.name = "Aptos"
    r.font.size = Pt(13)
    r.font.color.rgb = C.GREY_MID


# =============================================================================
if __name__ == "__main__":
    if not shutil.which("rsvg-convert"):
        sys.exit("rsvg-convert not found; install via `brew install librsvg`")
    build()
