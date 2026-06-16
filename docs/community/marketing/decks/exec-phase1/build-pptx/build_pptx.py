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
    """Rasterize a diagram SVG and place it. Caller controls the bounding box."""
    if svg_path is None or not svg_path.exists():
        return
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


def add_logo_row(slide, logos: list[Path], y_px: int,
                  row_h_px: int = 120,
                  max_logo_w_px: int = 320, max_logo_h_px: int = 100):
    """Three logos centred in a row. Used on slide 9 (adopters)."""
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
        slot_x = margin_x + i * slot_w
        pic = slide.shapes.add_picture(str(img), px(slot_x), px(y_px),
                                        width=px(max_logo_w_px))
        if pic.height > px(max_logo_h_px):
            ratio = px(max_logo_h_px) / pic.height
            pic.height = px(max_logo_h_px)
            pic.width = int(pic.width * ratio)
        pic.left = px(slot_x) + (px(slot_w) - pic.width) // 2
        pic.top = px(y_px) + (px(row_h_px) - pic.height) // 2


# -----------------------------------------------------------------------------
# Hero / Tile geometry helpers — must mirror what the .potx layouts use
# -----------------------------------------------------------------------------

# These constants drive where the on-slide decoration (banner, brand row,
# tile icons) is placed. They MUST match the corresponding layout positions
# in build_potx.py — if you change one place, change the other.

TILE_X0_PX = 80
TILE_Y0_PX = 400
TILE_W_PX = 570
TILE_H_PX = 270
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

    expected = {"Hero", "CTA", "Content / 3-Column", "Content / Diagram",
                "Content / Tiles", "Content / 2-Column", "Section Divider", "Plain"}
    missing = expected - set(layouts)
    if missing:
        sys.exit(f"template missing expected layouts: {missing}")

    # ---- SLIDE 1 — HERO -----------------------------------------------------
    s = prs.slides.add_slide(layouts["Hero"])
    add_banner_full_bleed(s, THEME_DIR / "OCM-Banner.png")
    set_text(s, 1, "Secure Delivery for", color=C.WHITE)
    set_split_gradient_title(s, 2, prefix="Sovereign ", noun="Clouds")
    set_text(s, 3,
             "Deliver and deploy your software securely. Anywhere, at any scale.",
             color=C.CYAN)
    set_text(s, 4,
             "Open Component Model — open source, NeoNephos Foundation.",
             color=C.WHITE)
    add_brand_row(s)

    # ---- SLIDE 2 — WHY NOW (V1, sovereignty-led) ----------------------------
    s = prs.slides.add_slide(layouts["Content / 3-Column"])
    set_text(s, 1, "WHY NOW — V1 · SOVEREIGNTY-LED")
    set_text(s, 2, "Sovereignty is no longer optional")
    set_text(s, 10, "SOVEREIGNTY PRESSURE")
    set_text(s, 11, "Wherever the law puts the boundary — by jurisdiction, "
                     "sector, or air-gap — software must be deliverable, "
                     "verifiable, and operable inside it.")
    set_text(s, 12, "REGULATION TIGHTENING")
    set_text(s, 13, "EU DORA · NIS2 · GDPR. Provable supply-chain control, "
                     "not best effort.")
    set_text(s, 14, "SUPPLY-CHAIN ATTACKS ARE REAL")
    set_text(s, 15, "SolarWinds. xz. log4shell. Signatures must survive the "
                     "journey, or compliance is theatre.")

    # ---- SLIDE 3 — THE PAIN (diagram) ---------------------------------------
    s = prs.slides.add_slide(layouts["Content / Diagram"])
    set_text(s, 1, "THE PAIN")
    set_text(s, 2, "Software delivery is fragmented.\n"
                    "Compliance retrofits don't scale.")
    add_diagram(s, DIAGRAMS_DIR / "03-fragmented.svg",
                 x_px=80, y_px=440, max_w_px=1760, max_h_px=540)

    # ---- SLIDE 4 — THE SHIFT, SBoD ------------------------------------------
    s = prs.slides.add_slide(layouts["Content / 2-Column"])
    set_text(s, 1, "THE SHIFT")
    set_text(s, 2, "SBOM lists. SBoD delivers.")
    set_text(s, 10,
             "An SBOM tells you what's in your software. It was built for inventory.\n"
             "A Software Bill of Delivery (SBoD) tells you what you delivered, "
             "how to verify it, how to transport it, and how to operate it. "
             "It was built for delivery.\n"
             "The SBoD contains the SBOM. OCM doesn't replace your SBOM tooling — "
             "it gives the SBOM an envelope that's compliance-native, signed once, "
             "and travels intact across any boundary.")
    diagram = first_existing(
        DIAGRAMS_DIR / "04-sbom-inside-sbod.svg",
        DIAGRAMS_DIR / "04-sbom-vs-sbod.svg",
    )
    if diagram:
        add_diagram(s, diagram, x_px=980, y_px=400, max_w_px=860, max_h_px=540)
    # Right column placeholder is empty (diagram replaces it).

    # ---- SLIDE 5 — OCM IN ONE PICTURE ---------------------------------------
    s = prs.slides.add_slide(layouts["Content / Diagram"])
    set_text(s, 1, "OCM IN ONE PICTURE")
    set_text(s, 2, "Pack · Sign · Transport · Deploy")
    diagram5 = first_existing(
        DIAGRAMS_DIR / "05-pack-sign-transport-deploy-v2.svg",
        DIAGRAMS_DIR / "05-pack-sign-transport-deploy.svg",
    )
    add_diagram(s, diagram5, x_px=80, y_px=440, max_w_px=1760, max_h_px=540)

    # ---- SLIDE 6 — SOVEREIGN-READY ------------------------------------------
    s = prs.slides.add_slide(layouts["Content / 2-Column"])
    set_text(s, 1, "SOVEREIGN-READY")
    set_text(s, 2, "Trust, but verify.")
    set_text(s, 10,
             "• Identity is location-independent. A component carries its "
             "name regardless of which registry it lives in.\n"
             "• Signatures are location-independent. Sign once at source; "
             "verify at the destination, or at any hop in between, with no "
             "callback upstream.\n"
             "• Day-2 ops happen inside the boundary. Subscribe to the "
             "component and pull upgrades on your schedule, scale across "
             "regions, all without reaching back upstream.\n"
             "• On transfer into a sovereign environment, a component can "
             "carry every artifact it needs along with it. The destination "
             "needs nothing more.")
    add_diagram(s, DIAGRAMS_DIR / "06-sovereign-airgap.svg",
                 x_px=980, y_px=400, max_w_px=860, max_h_px=540)

    # ---- SLIDE 7 — SCAN / Compliance-native ---------------------------------
    s = prs.slides.add_slide(layouts["Plain"])
    set_text(s, 1, "SCAN — COMPLIANCE-NATIVE WITH OPEN DELIVERY GEAR")
    set_text(s, 2, "Compliance as a system property —\nnot a quarterly project.")
    set_text(s, 10,
             "• Open Delivery Gear (ODG) is OCM's compliance automation engine.\n"
             "• The Compliance Dashboard is your entry point: every component, "
             "every finding, every signature in one view.\n"
             "• Continuous scans run asynchronously — even after release.\n"
             "• Findings get rescored against contextual risk, so your team "
             "patches what actually matters.\n"
             "• Every compliance signal correlates by component identity. "
             "Auditors get evidence, not spreadsheets.")

    # ---- SLIDE 8 — WHAT OCM UNLOCKS (tiles) ---------------------------------
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

    # ---- SLIDE 9 — Adopters (two-column logo wall) --------------------------
    # Plain layout + manual logo rows (not enough placeholders for a logo
    # wall; cleaner to draw it inline than add a new layout to the template).
    s = prs.slides.add_slide(layouts["Plain"])
    set_text(s, 1, "TRUSTED IN PRODUCTION")
    set_text(s, 2, "Aligned with NeoNephos.")
    # Hide the body placeholder by setting it to a single space — placeholders
    # don't render if empty, but adding an empty paragraph keeps layout tidy.
    set_text(s, 10, "")
    # Top section label + logos
    add_label_at(s, 380, "ADOPTED BY ENTERPRISES SHIPPING INTO REGULATED ENVIRONMENTS")
    add_logo_row(s, [
        ASSETS_DIR / "adopters" / "sap" / "sap-horizontal-color.svg",
        ASSETS_DIR / "adopters" / "bwi" / "bwi-horizontal-color.svg",
        ASSETS_DIR / "adopters" / "sap-ns2" / "sap-ns2-getlogovector.png",
    ], y_px=420)
    add_label_at(s, 620, "BUILT INTO THE OPEN-SOURCE ECOSYSTEM")
    add_logo_row(s, [
        ASSETS_DIR / "adopters" / "gardener" / "gardener-horizontal-color.svg",
        ASSETS_DIR / "adopters" / "konfidence" / "konfidence-horizontal-light.svg",
        ASSETS_DIR / "adopters" / "platform-mesh" / "platform-mesh-horizontal-color.svg",
    ], y_px=660)
    add_centred_proof(s, 860,
                       "An open standard, neutrally governed — your stack "
                       "stays portable, your dependencies stay yours.")

    # ---- SLIDE 10 — CTA ------------------------------------------------------
    s = prs.slides.add_slide(layouts["CTA"])
    set_text(s, 1, "Start delivering with confidence.", color=C.WHITE)
    set_text(s, 2,
             "Try it — ocm.software\n"
             "Build with us — github.com/open-component-model\n"
             "Talk to us — community channels on the website",
             color=C.WHITE)
    add_brand_row(s)

    prs.save(str(OUTPUT_PPTX))
    print(f"Wrote {OUTPUT_PPTX}")


# -----------------------------------------------------------------------------
# Inline-decoration helpers used by slide 9
# -----------------------------------------------------------------------------

def add_label_at(slide, y_px: int, text: str):
    """Brand-blue ALL-CAPS section label — slide 9 logo wall headers."""
    from pptx.enum.text import PP_ALIGN
    tb = slide.shapes.add_textbox(px(80), px(y_px),
                                   px(SLIDE_W_PX - 160), px(28))
    tf = tb.text_frame
    tf.margin_left = tf.margin_right = 0
    tf.margin_top = tf.margin_bottom = 0
    p = tf.paragraphs[0]
    r = p.add_run()
    r.text = text
    f = r.font
    f.name = "Aptos"
    f.size = Pt(14)
    f.bold = True
    f.color.rgb = C.BLUE
    rPr = r._r.get_or_add_rPr()
    rPr.set("cap", "all")
    rPr.set("spc", "110")


def add_centred_proof(slide, y_px: int, text: str):
    from pptx.enum.text import PP_ALIGN
    tb = slide.shapes.add_textbox(px(80), px(y_px),
                                   px(SLIDE_W_PX - 160), px(80))
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


# =============================================================================
if __name__ == "__main__":
    if not shutil.which("rsvg-convert"):
        sys.exit("rsvg-convert not found; install via `brew install librsvg`")
    build()
