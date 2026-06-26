#!/usr/bin/env python3
"""
Build OCM-Sovereign-Delivery-Architect-External.pptx — 15-slide trunk.

Trunk story arc (locked, autonomous-loop handoff §4):

  1  Pain          You ship pieces. / Nothing carries the release.
  2  Cause         In every existing tool, identity is bound to location.
  3  Insight       Identity that travels with the artifact.
  4  Positioning   One wrapper. All artifacts. Signed once.
  5  Constructor   What you write. (YAML)
  6  Descriptor    What gets signed and travels. (YAML)
  7  Overview      Pack · Sign · Transport · Deploy. (reused SVG)
  8  Pack          Bundle once. Name once.
  9  Sign          One signature shape. Three trust models.
 10  Transport     Three patterns, one command.
 11  Deploy        Repository → Component → Resource → Deployer.
 12  Composition   One product. Three components. One line to upgrade.
 13  What's sharp  Three honest edges.
 14  Adoption     Two paths to a first OCM component in production.
 15  CTA           Build with us.

No warm-ups, no appendix, no hidden trademarks (the user copies trademark
slides in from the exec deck after the loop completes — handoff §2).

Usage:
    .venv/bin/python build_pptx_architect_external.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from lxml import etree
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.util import Emu, Pt

from speaker_notes import SPEAKER_NOTES


# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
DECK_DIR = SCRIPT_DIR.parent
DIAGRAMS_DIR = DECK_DIR / "diagrams"
EXEC_DIAGRAMS_DIR = DECK_DIR.parent / "exec-phase1" / "diagrams"
ASSETS_DIR = DECK_DIR.parent.parent / "assets"
THEME_DIR = DECK_DIR / "theme"
RASTER_DIR = SCRIPT_DIR / "_raster"

POTX_PATH = DECK_DIR / "OCM-Master.potx"
OUTPUT_PPTX = DECK_DIR / "OCM-Sovereign-Delivery-Architect-External.pptx"

RASTER_DIR.mkdir(exist_ok=True)


# -----------------------------------------------------------------------------
# Slide geometry — 16:9 @ 1920x1080
# -----------------------------------------------------------------------------

SLIDE_W_PX = 1920
SLIDE_H_PX = 1080
PX = 9525  # 1 px in EMU at 96 dpi

def px(n: float) -> Emu:
    return Emu(int(n * PX))


# -----------------------------------------------------------------------------
# OCM brand palette
# -----------------------------------------------------------------------------

class C:
    BLUE       = RGBColor(0x0F, 0x6B, 0xFF)
    BLUE_MID   = RGBColor(0x0A, 0x3A, 0x99)
    CYAN       = RGBColor(0x5C, 0xD6, 0xFF)
    GREY_MID   = RGBColor(0x6B, 0x72, 0x80)
    BLUE_NIGHT = RGBColor(0x0A, 0x15, 0x30)
    GREY_SOFT  = RGBColor(0xF3, 0xF4, 0xF6)
    BLACK      = RGBColor(0x00, 0x00, 0x00)
    WHITE      = RGBColor(0xFF, 0xFF, 0xFF)


A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"


# -----------------------------------------------------------------------------
# SVG -> PNG rasterization (for diagrams)
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


def find_diagram(name: str) -> Path | None:
    for candidate in (DIAGRAMS_DIR / name,
                      DIAGRAMS_DIR / "architect" / name,
                      EXEC_DIAGRAMS_DIR / name):
        if candidate.exists():
            return candidate
    return None


# -----------------------------------------------------------------------------
# Open .potx as .pptx
# -----------------------------------------------------------------------------

def open_template_as_pptx() -> Presentation:
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
    ph = find_placeholder(slide, idx)
    sp = ph._element
    sp.getparent().remove(sp)


def set_text(slide, idx: int, text: str, *, color: RGBColor | None = None,
             align_left: bool = False):
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


def set_blue_box_bullets(slide, idx: int, items: list[str],
                          *, font_size: int | None = None):
    """Render a body placeholder as a list with blue square bullets.

    Each item may optionally start with **anchor** ... — the anchor (the part
    before the first ' — ') is rendered bold-blue; the rest in black.

    font_size (pt) overrides the placeholder's default size. Pass None to
    keep the master's size.
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
        if font_size is not None:
            bullet.font.size = Pt(font_size)
        # Split on first em-dash if present, to bold the anchor.
        sep = " — "
        if sep in body:
            anchor, rest = body.split(sep, 1)
            r_anchor = p.add_run()
            r_anchor.text = anchor
            r_anchor.font.color.rgb = C.BLUE
            r_anchor.font.bold = True
            if font_size is not None:
                r_anchor.font.size = Pt(font_size)
            r_rest = p.add_run()
            r_rest.text = sep + rest
            r_rest.font.color.rgb = C.BLACK
            if font_size is not None:
                r_rest.font.size = Pt(font_size)
        else:
            text_run = p.add_run()
            text_run.text = body
            text_run.font.color.rgb = C.BLACK
            if font_size is not None:
                text_run.font.size = Pt(font_size)


def set_action_path_lines(slide, idx: int, lines: list[tuple[str, str]],
                            sep: str = " — "):
    """CTA-style: ACTION (cyan, bold) + sep + path (white)."""
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


# -----------------------------------------------------------------------------
# Static decoration helpers
# -----------------------------------------------------------------------------

def add_banner_full_bleed(slide, image_path: Path):
    if not image_path.exists():
        return
    pic = slide.shapes.add_picture(str(image_path), 0, 0,
                                    width=px(SLIDE_W_PX),
                                    height=px(SLIDE_H_PX))
    spTree = pic._element.getparent()
    spTree.remove(pic._element)
    insert_at = 0
    for i, el in enumerate(spTree):
        if el.tag.endswith("}grpSpPr"):
            insert_at = i + 1
            break
    spTree.insert(insert_at, pic._element)


def add_brand_row(slide):
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
    pic.top  = px(y_px) + (px(max_h_px) - pic.height) // 2


def set_speaker_notes(slide, text: str):
    """Embed presenter prompts into the slide's notes pane.

    python-pptx exposes notes via slide.notes_slide.notes_text_frame. We
    clear whatever the master left there and write one paragraph per
    newline-separated line. The result lives in the speaker view in
    PowerPoint and in printed handouts. Canonical full notes (with timers,
    Q&A prep, stage directions) stay in ../notes/SPEAKER-NOTES-ARCHITECT-
    EXTERNAL.md; what's embedded here is the trimmed beat-list."""
    tf = slide.notes_slide.notes_text_frame
    tf.clear()
    lines = text.split("\n")
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        r = p.add_run()
        r.text = line
        # Notes pane uses the master's default font; no explicit styling.


def add_footer_caption(slide, y_px: int, text: str, *, italic: bool = False):
    tb = slide.shapes.add_textbox(px(120), px(y_px),
                                   px(SLIDE_W_PX - 240), px(60))
    tf = tb.text_frame
    tf.margin_left = tf.margin_right = 0
    tf.margin_top = tf.margin_bottom = 0
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.LEFT
    r = p.add_run()
    r.text = text
    r.font.name = "Aptos"
    r.font.size = Pt(18)
    r.font.italic = italic
    r.font.color.rgb = C.GREY_MID


def add_textbox(slide, x_px: int, y_px: int, w_px: int, h_px: int):
    """Helper: returns a textbox with margins zeroed and word-wrap on."""
    tb = slide.shapes.add_textbox(px(x_px), px(y_px), px(w_px), px(h_px))
    tf = tb.text_frame
    tf.margin_left = tf.margin_right = 0
    tf.margin_top = tf.margin_bottom = 0
    tf.word_wrap = True
    return tb, tf


def add_yaml_block(slide, x_px: int, y_px: int, w_px: int, h_px: int,
                    yaml_lines: list[tuple[str, RGBColor]],
                    *, font_size: int = 16,
                    bg_color: RGBColor = C.GREY_SOFT,
                    border: bool = True):
    """Render a YAML-style block. Each line is a (text, color) pair.
    Background is a rounded rectangle in GREY_SOFT by default."""
    box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                  px(x_px), px(y_px), px(w_px), px(h_px))
    box.fill.solid()
    box.fill.fore_color.rgb = bg_color
    if border:
        box.line.color.rgb = C.GREY_MID
        box.line.width = Pt(0.75)
    else:
        box.line.fill.background()
    tf = box.text_frame
    tf.margin_left = tf.margin_right = Emu(140000)
    tf.margin_top = tf.margin_bottom = Emu(120000)
    tf.word_wrap = False
    tf.vertical_anchor = MSO_ANCHOR.TOP
    for i, (line, color) in enumerate(yaml_lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = PP_ALIGN.LEFT
        p.space_before = Pt(0)
        p.space_after = Pt(0)
        p.line_spacing = 1.15
        r = p.add_run()
        r.text = line if line else " "
        r.font.name = "Consolas"
        r.font.size = Pt(font_size)
        r.font.color.rgb = color


def add_callout(slide, x_px: int, y_px: int, w_px: int, h_px: int,
                 anchor: str, body: str,
                 *, anchor_color: RGBColor = C.BLUE):
    """Small explanatory callout box used next to YAML blocks.
    Anchor word bold-blue, body in black. White background, blue left bar."""
    # left accent bar
    bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                                  px(x_px), px(y_px), px(6), px(h_px))
    bar.fill.solid()
    bar.fill.fore_color.rgb = anchor_color
    bar.line.fill.background()
    # text
    tb, tf = add_textbox(slide, x_px + 18, y_px, w_px - 18, h_px)
    tf.vertical_anchor = MSO_ANCHOR.TOP
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.LEFT
    r_a = p.add_run()
    r_a.text = anchor
    r_a.font.name = "Aptos"
    r_a.font.size = Pt(16)
    r_a.font.bold = True
    r_a.font.color.rgb = anchor_color
    p2 = tf.add_paragraph()
    p2.alignment = PP_ALIGN.LEFT
    p2.space_before = Pt(4)
    r_b = p2.add_run()
    r_b.text = body
    r_b.font.name = "Aptos"
    r_b.font.size = Pt(15)
    r_b.font.color.rgb = C.GREY_MID


def add_left_bullets(slide, x_px: int, y_px: int, w_px: int, h_px: int,
                      items: list[str], *,
                      font_size: int = 20, line_spacing: float = 1.35):
    """Render a custom textbox with blue-bullet + bold-anchor + body bullets,
    used when the layout body placeholder is too narrow / wide for the slide.
    Each item: '**Anchor** — body.' uses ' — ' as separator."""
    tb, tf = add_textbox(slide, x_px, y_px, w_px, h_px)
    sep = " — "
    for i, body in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.line_spacing = line_spacing
        p.space_before = Pt(0) if i == 0 else Pt(10)
        p.space_after = Pt(0)
        bullet = p.add_run()
        bullet.text = "▪  "
        bullet.font.name = "Aptos"
        bullet.font.size = Pt(font_size)
        bullet.font.color.rgb = C.BLUE
        bullet.font.bold = True
        if sep in body:
            anchor, rest = body.split(sep, 1)
            r_a = p.add_run()
            r_a.text = anchor
            r_a.font.name = "Aptos"
            r_a.font.size = Pt(font_size)
            r_a.font.color.rgb = C.BLUE
            r_a.font.bold = True
            r_b = p.add_run()
            r_b.text = sep + rest
            r_b.font.name = "Aptos"
            r_b.font.size = Pt(font_size)
            r_b.font.color.rgb = C.BLACK
        else:
            r = p.add_run()
            r.text = body
            r.font.name = "Aptos"
            r.font.size = Pt(font_size)
            r.font.color.rgb = C.BLACK


# -----------------------------------------------------------------------------
# Layout lookup
# -----------------------------------------------------------------------------

def layouts_by_name(prs: Presentation) -> dict[str, object]:
    return {l.name: l for l in prs.slide_masters[0].slide_layouts}


def customize_hero_for_architect(prs):
    layouts = layouts_by_name(prs)
    hero = layouts.get("Hero")
    if hero is None:
        return
    size_changed = False
    for ph in hero.placeholders:
        try:
            idx = ph.placeholder_format.idx
        except Exception:
            continue
        if idx not in (1, 2):
            continue
        try:
            ph.width = px(1824)
        except Exception:
            pass
        sp = ph._element
        for def_rpr in sp.iter(f"{{{A_NS}}}defRPr"):
            sz = def_rpr.get("sz")
            if sz == "13200":
                def_rpr.set("sz", "11500")
                size_changed = True
    if not size_changed:
        print("NOTE: Hero font size unchanged (sz=13200 not found on "
              "layout placeholders); width widen applied.")


def shrink_plain_titles(prs, target_pt: int = 56):
    """Drop the Plain & Plain/Compact title size so longer titles don't wrap
    into the body slot. target_pt expressed in standard pt (e.g. 56 -> 5600).
    Hazard mitigation per handoff §5 — content-first deck, geometry second."""
    layouts = layouts_by_name(prs)
    target_sz = str(target_pt * 100)
    for layout_name in ("Plain", "Plain / Compact"):
        layout = layouts.get(layout_name)
        if layout is None:
            continue
        for ph in layout.placeholders:
            try:
                idx = ph.placeholder_format.idx
            except Exception:
                continue
            if idx != 2:  # title
                continue
            sp = ph._element
            for def_rpr in sp.iter(f"{{{A_NS}}}defRPr"):
                # The Plain title is 74pt = 7400 in lstStyle.
                if def_rpr.get("sz") == "7400":
                    def_rpr.set("sz", target_sz)


def shrink_diagram_title(prs, target_pt: int = 44):
    """Content/Diagram title slot is only h=80px but defaults to 74pt — any
    multi-line title clips off the bottom. Slides 5/6/7/12 share this layout
    in the architect deck, so we shrink the title to fit a single line of
    most reasonable titles, or two short lines."""
    layouts = layouts_by_name(prs)
    layout = layouts.get("Content / Diagram")
    if layout is None:
        return
    target_sz = str(target_pt * 100)
    for ph in layout.placeholders:
        try:
            idx = ph.placeholder_format.idx
        except Exception:
            continue
        if idx != 2:
            continue
        sp = ph._element
        for def_rpr in sp.iter(f"{{{A_NS}}}defRPr"):
            if def_rpr.get("sz") == "7400":
                def_rpr.set("sz", target_sz)


# =============================================================================
# Build the deck
# =============================================================================

def build():
    prs = open_template_as_pptx()
    customize_hero_for_architect(prs)
    layouts = layouts_by_name(prs)

    expected = {"Hero", "CTA", "Content / 3-Column",
                "Content / 3-Column Tall Title",
                "Content / Diagram", "Content / Diagram Compact",
                "Content / Tiles", "Content / 2-Column",
                "Section Divider", "Plain", "Plain / Compact"}
    missing = expected - set(layouts)
    if missing:
        sys.exit(f"template missing expected layouts: {missing}")

    build_slide_1_pain(prs, layouts)
    build_slide_2_cause(prs, layouts)
    build_slide_3_insight(prs, layouts)
    build_slide_4_positioning(prs, layouts)
    build_slide_5_constructor(prs, layouts)
    build_slide_6_descriptor(prs, layouts)
    build_slide_7_overview(prs, layouts)
    build_slide_8_pack(prs, layouts)
    build_slide_9_sign(prs, layouts)
    build_slide_10_transport(prs, layouts)
    build_slide_11_deploy(prs, layouts)
    build_slide_12_composition(prs, layouts)
    build_slide_14_adoption(prs, layouts)        # was 14, now slide 13
    build_slide_13_whats_sharp(prs, layouts)     # was 13, now slide 14
    build_slide_15_cta(prs, layouts)

    # Embed condensed presenter prompts into the notes pane of each slide.
    for idx, slide in enumerate(prs.slides, start=1):
        note = SPEAKER_NOTES.get(idx)
        if note:
            set_speaker_notes(slide, note)

    sanity_check(prs)
    prs.save(str(OUTPUT_PPTX))
    print(f"Wrote {OUTPUT_PPTX} ({len(prs.slides)} slides)")


# -----------------------------------------------------------------------------
# Slide builders
# -----------------------------------------------------------------------------

def build_slide_1_pain(prs, layouts):
    """1 PAIN — Hero. Two-line gradient title. Subtitle. Footer. Brand row."""
    s = prs.slides.add_slide(layouts["Hero"])
    add_banner_full_bleed(s, THEME_DIR / "OCM-Banner.png")
    set_text(s, 1, "You ship pieces.", color=C.WHITE, align_left=True)
    set_split_gradient_title(s, 2, prefix="",
                              noun="Nothing carries the release.")
    set_text(s, 3,
             "You sign the pieces. Nothing signs the release.",
             color=C.CYAN)
    set_text(s, 4,
             "Open Component Model — open source, NeoNephos Foundation.",
             color=C.WHITE)
    add_brand_row(s)


def build_slide_2_cause(prs, layouts):
    """2 CAUSE — Diagnosis. Three bullets, footer caption."""
    s = prs.slides.add_slide(layouts["Plain / Compact"])
    set_text(s, 1, "DIAGNOSIS")
    set_text(s, 2, "In every existing tool, identity is bound to location.")
    set_blue_box_bullets(s, 10, [
        "OCI image — identified by registry/repo:tag. Mirror it; every downstream reference is invalidated.",
        "Helm chart — identified by repo URL + name + version. Mirror the repo; pulls fail.",
        "SBOM — linked to its subject by file path or naming convention. Move the artifact; the link dangles.",
    ])
    # Punchline moved to speaker notes: "Cosign attestations sign each
    # piece. None of them sign the release as one named, location-
    # independent unit."


def _draw_coordinate_travel_diagram(slide, *, x_px: int, y_px: int,
                                     w_px: int, h_px: int):
    """Native-PPT visual for slide 3: one coordinate at top, three registry
    cylinders below, per-cylinder access label.

    Typography (after row-14 readability review):
      - Chip:    20pt (was 17)
      - Silos:   20pt (was 18)
      - Access:  18pt (was 13)
    Bottom 'same digest' annotation removed — redundant with the left-side
    Digest bullet on the slide.
    """
    # ---- Coordinate chip at top -----------------------------------------
    chip_w = 600
    chip_h = 64
    chip_x = x_px + (w_px - chip_w) // 2
    chip_y = y_px
    chip = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                   px(chip_x), px(chip_y),
                                   px(chip_w), px(chip_h))
    chip.fill.solid()
    chip.fill.fore_color.rgb = C.GREY_SOFT
    chip.line.color.rgb = C.BLUE
    chip.line.width = Pt(1.5)
    tf = chip.text_frame
    tf.margin_left = tf.margin_right = Emu(80000)
    tf.margin_top = tf.margin_bottom = Emu(40000)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = "github.com/acme.org/helloworld:1.0.0"
    r.font.name = "Consolas"
    r.font.size = Pt(20)
    r.font.bold = True
    r.font.color.rgb = C.BLUE

    # ---- Three registry cylinders ---------------------------------------
    cyl_w = 160
    cyl_h = 140
    gap = (w_px - 3 * cyl_w) // 4
    cyl_y = y_px + chip_h + 80
    cyls = [
        ("EU reg",    "ghcr.io/eu/..."),
        ("US reg",    "ghcr.io/us/..."),
        ("Air-gap",   "registry.local/..."),
    ]
    chip_bottom_x = chip_x + chip_w // 2
    chip_bottom_y = chip_y + chip_h
    cyl_centers_x = []
    for i, (name, access_ref) in enumerate(cyls):
        cx = x_px + gap + i * (cyl_w + gap)
        cyl_centers_x.append(cx + cyl_w // 2)
        cyl = slide.shapes.add_shape(MSO_SHAPE.CAN,
                                      px(cx), px(cyl_y),
                                      px(cyl_w), px(cyl_h))
        cyl.fill.solid()
        cyl.fill.fore_color.rgb = C.WHITE
        cyl.line.color.rgb = C.BLUE
        cyl.line.width = Pt(1.5)
        ctf = cyl.text_frame
        ctf.margin_left = ctf.margin_right = Emu(40000)
        ctf.margin_top = ctf.margin_bottom = Emu(40000)
        ctf.vertical_anchor = MSO_ANCHOR.MIDDLE
        cp = ctf.paragraphs[0]
        cp.alignment = PP_ALIGN.CENTER
        cr = cp.add_run()
        cr.text = name
        cr.font.name = "Aptos"
        cr.font.size = Pt(20)
        cr.font.bold = True
        cr.font.color.rgb = C.BLUE
        # Access reference under each cylinder
        atb, atf = add_textbox(slide, cx - 40, cyl_y + cyl_h + 16,
                                cyl_w + 80, 36)
        ap = atf.paragraphs[0]
        ap.alignment = PP_ALIGN.CENTER
        ar = ap.add_run()
        ar.text = f"access: {access_ref}"
        ar.font.name = "Consolas"
        ar.font.size = Pt(18)
        ar.font.color.rgb = C.GREY_MID

    # ---- Connector lines from chip bottom to each cylinder top ----------
    for cyl_cx in cyl_centers_x:
        line_shape = slide.shapes.add_connector(1,
            px(chip_bottom_x), px(chip_bottom_y),
            px(cyl_cx), px(cyl_y))
        line_shape.line.color.rgb = C.GREY_MID
        line_shape.line.width = Pt(1.25)


def build_slide_3_insight(prs, layouts):
    """3 INSIGHT — The Hinge. Left bullets, right ASCII diagram, footer."""
    s = prs.slides.add_slide(layouts["Plain"])
    set_text(s, 1, "THE HINGE")
    set_text(s, 2, "Identity that travels with the artifact.")
    delete_placeholder(s, 10)

    add_left_bullets(
        s, x_px=120, y_px=540, w_px=940, h_px=420,
        items=[
            "Coordinates — name and version of the component. "
            "Globally unique. Location-agnostic.",
            "Digest — every resource inside the component carries a "
            "content hash. Computed once.",
            "Access — where the resource currently lives. "
            "Rewritten on transfer. Digest stays.",
        ],
        font_size=28,
    )

    # RIGHT half: native PowerPoint visual showing coordinate-travel.
    _draw_coordinate_travel_diagram(s,
                                     x_px=1060, y_px=540,
                                     w_px=820, h_px=440)


def build_slide_4_positioning(prs, layouts):
    """4 POSITIONING — Where OCM Sits. Three columns.

    Columns named to define the 'component' noun before slides 5+ rely on it:
    a component is the (artifact-format-agnostic, location-agnostic, signed)
    wrapper around resources."""
    s = prs.slides.add_slide(layouts["Content / 3-Column Tall Title"])
    set_text(s, 1, "WHERE OCM SITS")
    set_text(s, 2, "One component wraps every artifact, signed once.")
    set_text(s, 10, "ANY FORMAT")
    set_text(s, 11, "Helm, OCI, SBOM, npm, binaries.\n"
                     "Each becomes a resource inside the component.")
    set_text(s, 12, "ANY LOCATION")
    set_text(s, 13, "Coordinates travel.\n"
                     "The component carries its name across registries.")
    set_text(s, 14, "ONE SIGNATURE")
    set_text(s, 15, "Covers every digest in the component.\n"
                     "Survives transport.")
    # Punchline moved to speaker notes: "A component is the unit you
    # sign, transport, and deploy. The next slides show how it's built."


def build_slide_5_constructor(prs, layouts):
    """5 CONSTRUCTOR — What you write.

    Pt16 YAML, ~17 lines showing the two pack-time mechanisms:
    `input:` (by value) and `access:` (by reference). componentReferences
    composition was deliberately dropped from this slide on 2026-06-24 —
    it lives on slide 8 (COMPOSE), where it gets its own visual treatment.
    Earlier iteration carried a componentReferences stanza here, but the
    slide tries to teach two mechanisms and showing a third concept
    diluted the input-vs-access distinction.
    """
    s = prs.slides.add_slide(layouts["Content / Diagram"])
    set_text(s, 1, "CONSTRUCTOR")
    set_text(s, 2, "What you write.")
    delete_placeholder(s, 10)

    K = C.BLUE_MID
    V = C.BLACK
    COM = C.GREY_MID
    yaml_lines = [
        ("components:",                                                       K),
        ("- name: github.com/acme.org/helloworld",                            V),
        ("  version: 1.0.0",                                                  V),
        ("  provider:",                                                       K),
        ("    name: acme.org",                                                V),
        ("  resources:",                                                      K),
        ("    - name: mylocalfile",                                           V),
        ("      type: blob",                                                  V),
        ("      input:                # Embed by value",                      COM),
        ("        type: File/v1",                                             V),
        ("        path: ./my-local-resource.txt",                             V),
        ("    - name: image",                                                 V),
        ("      type: ociImage",                                              V),
        ("      version: 1.0.0",                                              V),
        ("      access:               # Reference external artifact",         COM),
        ("        type: OCIImage/v1",                                         V),
        ("        imageReference: ghcr.io/stefanprodan/podinfo:6.9.1",        V),
    ]
    # 17 lines @ Pt16 @ ls 1.20 ~ 408pt ~ 544px + ~60px padding ~ 604px.
    # Box y=300, h=620 fits with comfortable bottom padding now that
    # componentReferences is gone.
    add_yaml_block(s, x_px=120, y_px=300, w_px=1180, h_px=620,
                    yaml_lines=yaml_lines, font_size=16)

    # Callouts aligned to their YAML sections.
    # Line height @ Pt16 ls 1.20 ~ 25.6px. Box top y=300 + ~30px top padding.
    # Line 9 (input:) starts at ~y=508; line 15 (access:) at ~y=662.
    add_callout(s, x_px=1340, y_px=495, w_px=460, h_px=85,
                 anchor="input:  by value",
                 body="Embed bytes at pack time.")
    add_callout(s, x_px=1340, y_px=650, w_px=460, h_px=85,
                 anchor="access:  by reference",
                 body="Resolve external artifact at pack time.")


def build_slide_6_descriptor(prs, layouts):
    """6 DESCRIPTOR — What gets signed and travels.

    Technically-correct signing semantics (per signing-and-verification-concept.md):
    - Each resource carries a content digest. Those digests are inputs to the
      canonical descriptor normalization.
    - OCM signs ONE hash: the SHA-256 of the canonicalized descriptor.
    - That single hash is what the signature value covers.
    - access fields are excluded from normalization, so signature survives transfer.

    Callouts ordered to match the descriptor flow: access first (it appears first
    in the YAML, and it is the location pointer), then digest (the content
    identity), then signature (one hash over the whole canonicalized descriptor).
    """
    s = prs.slides.add_slide(layouts["Content / Diagram"])
    set_text(s, 1, "DESCRIPTOR")
    set_text(s, 2, "What gets signed and travels.")
    delete_placeholder(s, 10)

    K = C.BLUE_MID
    V = C.BLACK
    COM = C.GREY_MID
    SIG = C.BLUE
    yaml_lines = [
        ("component:                                  # (fields trimmed)", COM),
        ("  name: github.com/acme.org/helloworld",                       V),
        ("  version: 1.0.0",                                             V),
        ("  resources:",                                                 K),
        ("    - name: image",                                            V),
        ("      type: ociImage",                                         V),
        ("      access:                                  # excluded from signature",    COM),
        ("        type: OCIImage/v1",                                    V),
        ("        imageReference: ghcr.io/.../podinfo@sha256:8fa569...", V),
        ("      digest:                                  # input to hash", COM),
        ("        hashAlgorithm: SHA-256",                               V),
        ("        value: 262578cde928d5c9eba3bce0...",                   V),
        ("    - ...                                     # more resources, references", COM),
        ("signatures:",                                                  SIG),
        ("  - name: acme-release-key",                                   V),
        ("    digest:                                  # of the descriptor", COM),
        ("      hashAlgorithm: SHA-256",                                 V),
        ("      value: a4b1c2d3e4f5...",                                 V),
        ("    signature:",                                               K),
        ("      algorithm: RSASSA-PSS",                                  V),
        ("      value: <hex-encoded signature>",                         V),
    ]
    # 21 lines @ Pt16 @ ls 1.20 ~ 540pt ~ 540px + ~60px padding ~ 600px.
    add_yaml_block(s, x_px=120, y_px=280, w_px=1180, h_px=620,
                    yaml_lines=yaml_lines, font_size=16)

    # Callouts aligned with YAML sections.
    # Line height @ Pt16 ls 1.20 ~ 25.6px. Box top y=280 + ~30px padding.
    # Line 7 (access:) at ~y=464; line 10 (digest:) at ~y=541;
    # line 14 (signatures:) at ~y=643.
    add_callout(s, x_px=1340, y_px=455, w_px=460, h_px=70,
                 anchor="access:  excluded",
                 body="Rewritten on every transfer.")
    add_callout(s, x_px=1340, y_px=530, w_px=460, h_px=70,
                 anchor="digest:  content identity",
                 body="Input to the descriptor hash.")
    add_callout(s, x_px=1340, y_px=635, w_px=460, h_px=90,
                 anchor="signature:  one hash",
                 body="Over the canonicalized descriptor.",
                 anchor_color=C.BLUE)

    # No footer caption — at 18pt it's unreadable at presentation distance.
    # Speaker delivers "Sign the descriptor hash, not the access." verbally.


def build_slide_7_overview(prs, layouts):
    """7 OVERVIEW — Pack · Sign · Transport · Deploy.

    Reuses the exec-deck SVG. The tile labels inside the SVG ("Bring your
    own GitOps", "K8s Controllers") read as exec-deck legacy in the
    architect context; the eyebrow + footer caption reframe verbally so
    the speaker doesn't have to apologise for the inherited art."""
    s = prs.slides.add_slide(layouts["Content / Diagram"])
    set_text(s, 1, "FOUR VERBS, ONE COMPONENT")
    set_text(s, 2, "Pack · Sign · Transport · Deploy.")
    diagram = (find_diagram("05-pack-sign-transport-deploy-v2.svg")
                or find_diagram("05-pack-sign-transport-deploy.svg"))
    # Shrink the diagram slightly to make room for the primitive callout
    # below — y=240 → y=940, leaving 60px for the bottom caption.
    add_diagram(s, diagram, x_px=60, y_px=240, max_w_px=1800, max_h_px=780)
    # No footer caption — the descriptor-is-an-OCI-artifact framing lives
    # in the speaker notes ("The component descriptor is itself an OCI
    # artifact, media type application/vnd.ocm.software.component-
    # descriptor.v2 — it lives in your registry.")


def build_slide_8_pack(prs, layouts):
    """8 COMPOSE — Components compose. Leaf vs product/release.

    Repurposed from Pack to introduce composition before slide 12 needs it.
    Real architecture: leaf components carry resources; product/release
    components have no resources of their own — they reference children
    by name and version. Two YAML snippets side by side show the shape.
    """
    s = prs.slides.add_slide(layouts["Content / Diagram Compact"])
    set_text(s, 1, "COMPOSE")
    set_text(s, 2, "Leaf carries resources. Product carries references.")
    delete_placeholder(s, 10)

    # Intro text aligned with title (x=120).
    intro_tb, intro_tf = add_textbox(s, 120, 280, 1680, 90)
    intro_tf.word_wrap = True
    ip = intro_tf.paragraphs[0]
    ip.alignment = PP_ALIGN.LEFT
    ip.line_spacing = 1.30
    for text, kind in [
        ("Leaf components ", "accent"),
        ("carry resources — images, charts, configs, SBOMs.\n", "normal"),
        ("A product or release component ", "accent"),
        ("composes other components by ", "normal"),
        ("name and version", "accent"),
        (". One unit, transferable, signable end-to-end.", "normal"),
    ]:
        r = ip.add_run()
        r.text = text
        r.font.name = "Aptos"
        r.font.size = Pt(22)
        if kind == "accent":
            r.font.bold = True
            r.font.color.rgb = C.BLUE
        else:
            r.font.color.rgb = C.BLACK

    K = C.BLUE_MID
    V = C.BLACK
    COM = C.GREY_MID

    leaf_yaml = [
        ("# leaf components — carry the artifacts",          COM),
        ("components:",                                      K),
        ("  - name: acme.org/sovereign/notes",               V),
        ("    version: 1.0.0",                               V),
        ("    resources:",                                   K),
        ("      - name: image       # OCI image",            V),
        ("      - name: chart       # Helm chart",           V),
        ("      - ...",                                      V),
        ("  - name: acme.org/sovereign/postgres",            V),
        ("    version: 1.0.0",                               V),
        ("    resources:",                                   K),
        ("      - name: image       # OCI image",            V),
        ("      - name: chart       # Helm chart",           V),
        ("      - ...",                                      V),
        ("# product references both, by name and version",   COM),
    ]
    product_yaml = [
        ("# product / release component",                     COM),
        ("component:",                                        K),
        ("  name: acme.org/sovereign/product",                V),
        ("  version: 1.0.0",                                  V),
        ("  componentReferences:",                            K),
        ("    - name: notes",                                 V),
        ("      componentName: acme.org/sovereign/notes",     V),
        ("      version: 1.0.0",                              V),
        ("    - name: postgres",                              V),
        ("      componentName: acme.org/sovereign/postgres",  V),
        ("      version: 1.0.0",                              V),
        ("# no resources of its own — pure composition",      COM),
    ]
    # Two side-by-side boxes, leaner widths, arrow between.
    box_w = 760
    box_h = 560
    box_y = 460
    arrow_w = 100
    arrow_h = 80
    gap = 30
    total_w = 2 * box_w + 2 * gap + arrow_w
    left_x = (SLIDE_W_PX - total_w) // 2
    right_x = left_x + box_w + gap + arrow_w + gap
    arrow_x = left_x + box_w + gap
    arrow_y = box_y + (box_h - arrow_h) // 2

    add_yaml_block(s, x_px=left_x, y_px=box_y, w_px=box_w, h_px=box_h,
                    yaml_lines=leaf_yaml, font_size=17)
    add_yaml_block(s, x_px=right_x, y_px=box_y, w_px=box_w, h_px=box_h,
                    yaml_lines=product_yaml, font_size=17)

    # Labels above each block.
    ll_tb, ll_tf = add_textbox(s, left_x, box_y - 50, box_w, 36)
    lp = ll_tf.paragraphs[0]; lp.alignment = PP_ALIGN.LEFT
    lr = lp.add_run(); lr.text = "LEAF"
    lr.font.name = "Aptos"; lr.font.size = Pt(22); lr.font.bold = True
    lr.font.color.rgb = C.GREY_MID

    rl_tb, rl_tf = add_textbox(s, right_x, box_y - 50, box_w, 36)
    rp = rl_tf.paragraphs[0]; rp.alignment = PP_ALIGN.LEFT
    rr = rp.add_run(); rr.text = "PRODUCT"
    rr.font.name = "Aptos"; rr.font.size = Pt(22); rr.font.bold = True
    rr.font.color.rgb = C.BLUE

    # Composition arrow leaf → product.
    arrow = s.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW,
                                px(arrow_x), px(arrow_y),
                                px(arrow_w), px(arrow_h))
    arrow.fill.solid()
    arrow.fill.fore_color.rgb = C.BLUE
    arrow.line.fill.background()


def build_slide_9_sign(prs, layouts):
    """9 SIGN — One signature shape. Three trust models.
    All three algorithms are GA per project guidance."""
    s = prs.slides.add_slide(layouts["Content / 3-Column"])
    set_text(s, 1, "SIGN")
    set_text(s, 2, "One signature shape. Three trust models.")
    set_text(s, 10, "RSA")
    set_text(s, 11, "Your existing PKI.\n"
                     "Keys you already rotate.")
    set_text(s, 12, "GPG")
    set_text(s, 13, "OpenPGP keys.\n"
                     "Familiar trust model, ASCII-armored.")
    set_text(s, 14, "SIGSTORE")
    set_text(s, 15, "Keyless via OIDC.\n"
                     "Identity, not long-lived keys.")
    # Punchline moved to speaker notes: "Same descriptor hash. Three
    # ways to vouch for it. Pick what your org already runs."


def build_slide_10_transport(prs, layouts):
    """10 TRANSPORT — Three patterns. One command."""
    s = prs.slides.add_slide(layouts["Content / 3-Column"])
    set_text(s, 1, "TRANSPORT")
    set_text(s, 2, "Three patterns. One command.")
    set_text(s, 10, "REGISTRY → REGISTRY")
    set_text(s, 11, "Promote across stages.\n"
                     "Source registry to target registry.")
    set_text(s, 12, "REGISTRY → CTF")
    set_text(s, 13, "Export to a local archive.\n"
                     "Hand-carry across the boundary.")
    set_text(s, 14, "CTF → REGISTRY")
    set_text(s, 15, "Air-gap import.\n"
                     "Verify on arrival. No callback to source.")
    # Punchline moved to speaker notes: "Access fields rewrite at
    # transfer. Digests don't. Signature still verifies — anywhere."


def build_slide_11_deploy(prs, layouts):
    """11 DEPLOY — Four CRs, one chain.
    Title is the architectural statement (not a recap of the cards).
    Card text is technically precise — what each CR actually contains."""
    s = prs.slides.add_slide(layouts["Plain"])
    set_text(s, 1, "DEPLOY")
    set_text(s, 2, "OCM controllers verify and apply. One mirrors.")
    delete_placeholder(s, 10)

    cr_w = 410
    cr_h = 220
    gap = 50
    total_w = 4 * cr_w + 3 * gap
    start_x = (SLIDE_W_PX - total_w) // 2
    y = 560

    crs = [
        ("Repository",  "Where component versions live."),
        ("Component",   "Pulls one version. Verifies its signature."),
        ("Resource",    "One artifact, by digest."),
        ("Deployer",    "Applies it to the cluster."),
    ]
    for i, (title, body) in enumerate(crs):
        x = start_x + i * (cr_w + gap)
        box = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                  px(x), px(y), px(cr_w), px(cr_h))
        box.fill.solid()
        box.fill.fore_color.rgb = C.GREY_SOFT
        box.line.color.rgb = C.BLUE
        box.line.width = Pt(1.5)
        tf = box.text_frame
        tf.margin_left = tf.margin_right = Emu(180000)
        tf.margin_top = tf.margin_bottom = Emu(180000)
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        tf.word_wrap = True
        p1 = tf.paragraphs[0]
        p1.alignment = PP_ALIGN.CENTER
        r1 = p1.add_run()
        r1.text = title
        r1.font.name = "Aptos"
        r1.font.size = Pt(28)
        r1.font.bold = True
        r1.font.color.rgb = C.BLUE
        for j, line in enumerate(body.split("\n")):
            p2 = tf.add_paragraph()
            p2.alignment = PP_ALIGN.CENTER
            p2.space_before = Pt(8) if j == 0 else Pt(2)
            r2 = p2.add_run()
            r2.text = line
            r2.font.name = "Aptos"
            r2.font.size = Pt(22)
            r2.font.color.rgb = C.BLACK
        if i < len(crs) - 1:
            ax = x + cr_w + 6
            ay = y + cr_h // 2 - 8
            arrow = s.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW,
                                        px(ax), px(ay), px(gap - 12), px(18))
            arrow.fill.solid()
            arrow.fill.fore_color.rgb = C.BLUE
            arrow.line.fill.background()

    # Replication — fifth controller, sits alongside the chain (not within it).
    # Per docs: "Instead of delivering content into the cluster, it transfers a
    # resolved component version from one OCM repository to another."
    rep_x = (SLIDE_W_PX - cr_w) // 2
    rep_y = y + cr_h + 60
    rep_box = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                  px(rep_x), px(rep_y), px(cr_w), px(cr_h))
    rep_box.fill.solid()
    rep_box.fill.fore_color.rgb = C.GREY_SOFT
    rep_box.line.color.rgb = C.BLUE
    rep_box.line.width = Pt(1.5)
    rtf = rep_box.text_frame
    rtf.margin_left = rtf.margin_right = Emu(180000)
    rtf.margin_top = rtf.margin_bottom = Emu(180000)
    rtf.vertical_anchor = MSO_ANCHOR.MIDDLE
    rtf.word_wrap = True
    rp1 = rtf.paragraphs[0]
    rp1.alignment = PP_ALIGN.CENTER
    rr1 = rp1.add_run()
    rr1.text = "Replication"
    rr1.font.name = "Aptos"
    rr1.font.size = Pt(28)
    rr1.font.bold = True
    rr1.font.color.rgb = C.BLUE
    rp2 = rtf.add_paragraph()
    rp2.alignment = PP_ALIGN.CENTER
    rp2.space_before = Pt(8)
    rr2 = rp2.add_run()
    rr2.text = "Mirrors a version to another repository."
    rr2.font.name = "Aptos"
    rr2.font.size = Pt(22)
    rr2.font.color.rgb = C.BLACK

    # Punchline moved to speaker notes: "Pluggable at the Deployer tier:
    # built-in for raw manifests; Flux for HelmReleases; Argo for
    # Applications."


def build_slide_12_composition(prs, layouts):
    """12 DAY 2 — Bump the product. Everything follows.

    Composition is already introduced on slide 8. This slide does ONE job:
    the day-2 upgrade mechanic. Same product, bumped version, references
    follow, signature is recomputed end-to-end.

    Layout changes 2026-06-24:
    - External DAY 1 / DAY 2 labels above each YAML block dropped, AND
      the `# day N — product X` comment lines inside each YAML are also
      dropped. The slide-level `DAY 2` eyebrow + the "bump version" arrow
      label carry the same information without YAML chrome.
    - Each YAML now ends with a 3-line `signatures:` block so the footer
      ("Every digest pinned by the signature. The cluster cannot drift.")
      is grounded in what the slide visually shows. The day-2 signature
      value is highlighted in brand blue alongside the version changes,
      so the visual diff reads three changes that tell one story: bump
      one line, the whole chain re-signs.
    - Arrow between the blocks carries the label "bump version" — the
      arrow is the operator action, the label names it.
    - Footer caption beneath both blocks delivers the differentiator
      that previously lived only in speaker notes.
    """
    s = prs.slides.add_slide(layouts["Content / Diagram Compact"])
    set_text(s, 1, "DAY 2")
    set_text(s, 2, "Bump the product version.\nEverything follows.")
    delete_placeholder(s, 10)

    K = C.BLUE_MID
    V = C.BLACK
    COM = C.GREY_MID
    HIGH = C.BLUE

    left_yaml = [
        ("component:",                                                K),
        ("  name: acme.org/sovereign/product",                        V),
        ("  version: 1.0.0",                                          V),
        ("  componentReferences:",                                    K),
        ("    - name: notes",                                         V),
        ("      version: 1.0.0",                                      V),
        ("    - name: postgres",                                      V),
        ("      version: 1.0.0",                                      V),
        ("signatures:",                                               K),
        ("  - name: acme-release-key",                                V),
        ("    value: a4b1c2d3e5f6789abc012345def04691...",            V),
    ]
    right_yaml = [
        ("component:",                                                K),
        ("  name: acme.org/sovereign/product",                        V),
        ("  version: 1.1.0",                                          HIGH),
        ("  componentReferences:",                                    K),
        ("    - name: notes",                                         V),
        ("      version: 1.1.0",                                      HIGH),
        ("    - name: postgres",                                      V),
        ("      version: 1.0.0",                                      V),
        ("signatures:",                                               K),
        ("  - name: acme-release-key",                                V),
        ("    value: 9c2af18b3e7d52914a8c6b0f1d2e8f37...",            HIGH),
    ]
    # 12 lines @ Pt22 @ ls 1.20 ~ 317pt ~ 422px + ~60px padding ~ 482px.
    # Boxes moved up to box_y=380 since external DAY 1/DAY 2 labels removed;
    # box_h grown to 520 to fit the new signatures: block with comfortable
    # bottom padding. Footer sits below at y=960.
    box_w = 720
    box_h = 520
    box_y = 380
    arrow_w = 120
    arrow_h = 100
    gap = 30
    total_w = 2 * box_w + 2 * gap + arrow_w
    left_x = (SLIDE_W_PX - total_w) // 2
    right_x = left_x + box_w + gap + arrow_w + gap
    arrow_x = left_x + box_w + gap
    arrow_y = box_y + (box_h - arrow_h) // 2

    add_yaml_block(s, x_px=left_x, y_px=box_y, w_px=box_w, h_px=box_h,
                    yaml_lines=left_yaml, font_size=22)
    add_yaml_block(s, x_px=right_x, y_px=box_y, w_px=box_w, h_px=box_h,
                    yaml_lines=right_yaml, font_size=22)

    # Arrow with "bump version" label above it. Label sits just above the
    # arrow's vertical center so the eye reads label-then-arrow as one unit.
    arrow = s.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW,
                                px(arrow_x), px(arrow_y),
                                px(arrow_w), px(arrow_h))
    arrow.fill.solid()
    arrow.fill.fore_color.rgb = C.BLUE
    arrow.line.fill.background()

    label_tb, label_tf = add_textbox(s, arrow_x - 30, arrow_y - 60,
                                       arrow_w + 60, 50)
    lp = label_tf.paragraphs[0]
    lp.alignment = PP_ALIGN.CENTER
    lr = lp.add_run()
    lr.text = "bump version"
    lr.font.name = "Aptos"
    lr.font.size = Pt(20)
    lr.font.bold = True
    lr.font.color.rgb = C.BLUE

    # Footer caption — the differentiator. Single line, centred under both
    # YAML blocks, in mid-blue so it reads as a deliberate punchline rather
    # than chrome. This sentence answers the most common architect challenge
    # to OCM ("how is this different from helm upgrade?") with a property
    # the audience can verify from the diagram above.
    footer_tb, footer_tf = add_textbox(s, 120, 960, SLIDE_W_PX - 240, 60)
    fp = footer_tf.paragraphs[0]
    fp.alignment = PP_ALIGN.CENTER
    fr = fp.add_run()
    fr.text = "Every digest pinned by the signature. The cluster cannot drift."
    fr.font.name = "Aptos"
    fr.font.size = Pt(24)
    fr.font.color.rgb = C.BLUE_MID


def build_slide_13_whats_sharp(prs, layouts):
    """13 WHAT'S SHARP — Three real edges from the docs/repo.

    All three are doc-confirmed limitations a first-time architect will hit:
      1. Helm/v1 access — not fully resolved at pack time.
         (transfer-helm-charts.md:70)
      2. transfer defaults to descriptor-only.
         (transfer-concept.md:42 — air-gap requires --copy-resources)
      3. Controllers ship as v1alpha1 — pin minor versions.
         (kubernetes/controller/api/v1alpha1)
    """
    s = prs.slides.add_slide(layouts["Plain / Compact"])
    set_text(s, 1, "WHAT'S SHARP")
    set_text(s, 2, "Two honest edges.")
    set_blue_box_bullets(s, 10, [
        "Transfer defaults — copies only the descriptor. "
        "For air-gap, pass --copy-resources so the bytes travel too.",
        "Controllers are v1alpha1 — the CRD surface can move. "
        "Pin minor versions in your platform installs.",
    ], font_size=28)
    # Punchline moved to speaker notes: "Honest now beats apologetic
    # later. Plan for the trim edge."


def build_slide_14_adoption(prs, layouts):
    """14 ADOPTION — Two paths to a first OCM component.
    Uses Plain/Compact layout with custom 2-column textboxes (the
    Content/2-Column layout has only body placeholders, no header slots)."""
    s = prs.slides.add_slide(layouts["Plain / Compact"])
    set_text(s, 1, "ADOPTION")
    set_text(s, 2, "Two paths to a first OCM component.")
    delete_placeholder(s, 10)

    # Column geometry: two equal columns under the title.
    col_y = 500
    col_h = 380
    col_w = 820
    gap = 80
    total_w = 2 * col_w + gap
    start_x = (SLIDE_W_PX - total_w) // 2  # 100 if SLIDE_W_PX=1920

    columns = [
        ("FROM ZERO — CLI",
         ["Pack one component. Sign it.",
          "Air-gap CTF round-trip.",
          "Verify on the other side.",
          "Thirty minutes. One afternoon."]),
        ("ON YOUR CLUSTER — CONTROLLERS",
         ["Helm-install the OCM controllers.",
          "Point them at your registry.",
          "Apply a Component resource — verified and reconciling.",
          "Thirty minutes. One reconciling cluster."]),
    ]
    for i, (header, lines) in enumerate(columns):
        x = start_x + i * (col_w + gap)
        # Header
        head_tb, head_tf = add_textbox(s, x, col_y, col_w, 56)
        hp = head_tf.paragraphs[0]
        hp.alignment = PP_ALIGN.LEFT
        hr = hp.add_run()
        hr.text = header
        hr.font.name = "Aptos"
        hr.font.size = Pt(22)
        hr.font.bold = True
        hr.font.color.rgb = C.BLUE
        # Thin horizontal rule under header
        rule = s.shapes.add_connector(1, px(x), px(col_y + 56),
                                       px(x + col_w), px(col_y + 56))
        rule.line.color.rgb = C.BLUE
        rule.line.width = Pt(1.25)
        # Body lines
        body_tb, body_tf = add_textbox(s, x, col_y + 72, col_w, col_h - 72)
        for j, line in enumerate(lines):
            p = body_tf.paragraphs[0] if j == 0 else body_tf.add_paragraph()
            p.alignment = PP_ALIGN.LEFT
            p.space_before = Pt(0) if j == 0 else Pt(10)
            r = p.add_run()
            r.text = line
            r.font.name = "Aptos"
            r.font.size = Pt(22)
            r.font.color.rgb = C.BLACK

    # Punchline moved to speaker notes: "Pick the path. Coexists with
    # cosign, Argo, Flux, Kyverno — OCM signs the descriptor; your
    # existing controls stay in place."


def build_slide_15_cta(prs, layouts):
    """15 CTA — Mirrors the exec-deck pattern: master layout placeholders
    only, no custom textboxes. Title is the call to action; body is the
    three doors."""
    s = prs.slides.add_slide(layouts["CTA"])
    set_text(s, 1, "Ship the release as one unit.", color=C.WHITE)
    set_action_path_lines(s, 2, [
        ("Try it",        "ocm.software"),
        ("Build with us", "github.com/open-component-model"),
        ("Talk to us",    "community channels on the website"),
    ])
    add_brand_row(s)


# -----------------------------------------------------------------------------
# Sanity check
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Slide 12 — text-above-diagram option proposals (for user review)
# -----------------------------------------------------------------------------

# Three slide-12 variants. Each renders the same composition + day-2 visual
# but introduces it with different text above the diagram. The point being
# compared is the explanatory framing — what 1-2 sentences land best as
# the architect reads the slide.

def _slide12_body(slide):
    """Render the canonical slide-12 body (two side-by-side descriptors + DAY
    labels + arrow), starting from y_body_top (caller decides where)."""
    K = C.BLUE_MID
    V = C.BLACK
    COM = C.GREY_MID
    HIGH = C.BLUE

    left_yaml = [
        ("# day 1 — product 1.0.0",                                   COM),
        ("component:",                                                K),
        ("  name: acme.org/sovereign/product",                        V),
        ("  version: 1.0.0",                                          V),
        ("  componentReferences:",                                    K),
        ("    - name: notes",                                         V),
        ("      componentName: acme.org/sovereign/notes",             V),
        ("      version: 1.0.0",                                      V),
        ("    - name: postgres",                                      V),
        ("      componentName: acme.org/sovereign/postgres",          V),
        ("      version: 1.0.0",                                      V),
    ]
    right_yaml = [
        ("# day 2 — product 1.1.0  (notes patched)",                  COM),
        ("component:",                                                K),
        ("  name: acme.org/sovereign/product",                        V),
        ("  version: 1.1.0",                                          HIGH),
        ("  componentReferences:",                                    K),
        ("    - name: notes",                                         V),
        ("      componentName: acme.org/sovereign/notes",             V),
        ("      version: 1.1.0",                                      HIGH),
        ("    - name: postgres",                                      V),
        ("      componentName: acme.org/sovereign/postgres",          V),
        ("      version: 1.0.0",                                      V),
    ]
    add_yaml_block(slide, x_px=60, y_px=480, w_px=900, h_px=460,
                    yaml_lines=left_yaml, font_size=18)
    add_yaml_block(slide, x_px=980, y_px=480, w_px=900, h_px=460,
                    yaml_lines=right_yaml, font_size=18)

    label_left_tb, label_left_tf = add_textbox(slide, 60, 440, 900, 30)
    lp = label_left_tf.paragraphs[0]; lp.alignment = PP_ALIGN.LEFT
    lr = lp.add_run(); lr.text = "DAY 1"
    lr.font.name = "Aptos"; lr.font.size = Pt(20); lr.font.bold = True
    lr.font.color.rgb = C.GREY_MID

    label_right_tb, label_right_tf = add_textbox(slide, 980, 440, 900, 30)
    rp = label_right_tf.paragraphs[0]; rp.alignment = PP_ALIGN.LEFT
    rr = rp.add_run(); rr.text = "DAY 2"
    rr.font.name = "Aptos"; rr.font.size = Pt(20); rr.font.bold = True
    rr.font.color.rgb = C.BLUE

    arrow_y = 690
    arrow = slide.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW,
                                px(950), px(arrow_y), px(40), px(40))
    arrow.fill.solid(); arrow.fill.fore_color.rgb = C.BLUE
    arrow.line.fill.background()


def _slide12_intro_text(slide, *, lines: list[tuple[str, str]]):
    """Render explanatory text above the diagram. `lines` is a list of
    (run_text, color_kind) where color_kind is 'normal' (black) or 'accent'
    (blue) — this lets the variant builders highlight key nouns."""
    tb, tf = add_textbox(slide, 60, 290, 1820, 130)
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.LEFT
    p.line_spacing = 1.30
    for text, kind in lines:
        r = p.add_run()
        r.text = text
        r.font.name = "Aptos"
        r.font.size = Pt(22)
        if kind == "accent":
            r.font.bold = True
            r.font.color.rgb = C.BLUE
        else:
            r.font.color.rgb = C.BLACK


def build_slide12_option_a(prs, layouts):
    """OPTION A — Title states the mechanic. Intro is two short sentences
    that read as the architect would say them out loud."""
    s = prs.slides.add_slide(layouts["Content / Diagram Compact"])
    set_text(s, 1, "COMPOSITION + DAY 2")
    set_text(s, 2, "Bump the product. Everything follows.")
    delete_placeholder(s, 10)
    _slide12_intro_text(s, lines=[
        ("A product component ", "normal"),
        ("references other components", "accent"),
        (" by name and version.\n", "normal"),
        ("To upgrade, raise the product version. ", "normal"),
        ("The references move with it.", "accent"),
    ])
    _slide12_body(s)
    _option_marker(s, "OPTION A — bump-the-product")


def build_slide12_option_b(prs, layouts):
    """OPTION B — Title is the canonical OCM mechanic. Intro defines
    composition once and shows the day-2 path in one sentence."""
    s = prs.slides.add_slide(layouts["Content / Diagram Compact"])
    set_text(s, 1, "COMPOSITION + DAY 2")
    set_text(s, 2, "One version bump upgrades the whole product.")
    delete_placeholder(s, 10)
    _slide12_intro_text(s, lines=[
        ("A product is a component that ", "normal"),
        ("references other components", "accent"),
        (". On day 2, the operator raises the product version — and "
         "the references update with it.", "normal"),
    ])
    _slide12_body(s)
    _option_marker(s, "OPTION B — whole-product")


def build_slide12_option_c(prs, layouts):
    """OPTION C — Title names composition as the primitive. Intro lands
    day-2 as the architect's mental model."""
    s = prs.slides.add_slide(layouts["Content / Diagram Compact"])
    set_text(s, 1, "COMPOSITION + DAY 2")
    set_text(s, 2, "Compose a product. Upgrade in one place.")
    delete_placeholder(s, 10)
    _slide12_intro_text(s, lines=[
        ("Compose a product from other components — ", "normal"),
        ("each referenced by name and version.", "accent"),
        ("\nDay 2 is a single edit on the product: bump the version, the "
         "references resolve to the new children.", "normal"),
    ])
    _slide12_body(s)
    _option_marker(s, "OPTION C — compose-and-upgrade")


def _option_marker(slide, text: str):
    """Bottom-right corner marker labelling which option this slide is."""
    tb, tf = add_textbox(slide, x_px=1340, y_px=1020, w_px=560, h_px=40)
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.RIGHT
    r = p.add_run()
    r.text = text
    r.font.name = "Aptos"
    r.font.size = Pt(12)
    r.font.italic = True
    r.font.color.rgb = C.GREY_MID


# -----------------------------------------------------------------------------

def sanity_check(prs):
    issues = []
    for i, s in enumerate(prs.slides, 1):
        if s.element.get("show") == "0":
            continue
        title_bottom_px = None
        for ph in s.placeholders:
            if ph.placeholder_format.idx == 2 and ph.top is not None:
                title_bottom_px = (ph.top + ph.height) / PX
        if title_bottom_px is None:
            continue
        for shape in s.shapes:
            if not shape.has_text_frame:
                continue
            if shape.is_placeholder:
                continue
            if shape.top is None:
                continue
            shape_top_px = shape.top / PX
            if shape_top_px < title_bottom_px - 4:
                issues.append(
                    f"slide {i}: shape top {shape_top_px:.0f}px overlaps "
                    f"title bottom {title_bottom_px:.0f}px"
                )
    if issues:
        print("WARNING: layout overlaps detected:")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("Layout sanity check passed.")


# =============================================================================
if __name__ == "__main__":
    if not shutil.which("rsvg-convert"):
        sys.exit("rsvg-convert not found; install via `brew install librsvg`")
    build()
