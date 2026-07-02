# Card Family & Typography

**Purpose.** Visual conventions the decks share. If a slide needs a card, use this pattern; don't invent another.

## Card family

The recurring visual: a rounded-rectangle card with a top stripe, an ALL-CAPS left-aligned label, and a dark-grey body. Used on:

- Slide 7 (four moves)
- Slide 11 (four-CR chain)
- Slide 13 (adoption, two cards, external and internal)
- Slide 15 (adopter proof, internal)
- Slide 17 (replication appendix, four dimmed cards + one highlighted)

### Geometry (px, 1920×1080 slide)

- Card width: 330 (four-across) or ~700 (single wide highlight) or 820 (two-across)
- Card height: ~200 (compact) to ~260 (highlight)
- Rounded corners: `adjustments[0] = 14 / min(w, h)`, proportional, so cards of different sizes have visually-matching corners
- Top stripe height: 4–5px
- Gap between cards in a row: 60–80px
- Card row y-position: ~520 (below the layout title placeholder at ~508)

### Fill & shadow

- Fill: brand-grey-soft (`#F3F4F6`)
- Line: hidden (no border)
- Outer shadow: black, alpha 30%, blur 28575 EMU, distance 28575 EMU, dir 5400000

### Top stripe

- Brand-blue (`#0F6BFF`) for highlighted cards, grey-mid (`#6B7280`) for dimmed cards.

### Label typography

- Font: Aptos, 22–30pt (22 for compact, 30 for highlight)
- Bold, ALL-CAPS
- Colour: mid-blue (`#0A3A99`) or brand-blue depending on emphasis
- Left-aligned, ~24–30px pad from card edge

### Body typography

- Font: Aptos, 16–22pt (16 for compact, 22 for architect-adoption cards)
- Regular weight
- Colour: black (or grey-mid when dimmed for de-emphasis)
- Line spacing: `space_before` 8–10pt between body lines

## Typography (deck-wide)

- **Base font:** Aptos (per OCM-Master.potx). Fall back to system sans-serif if Aptos not installed on the render environment.
- **Title (hero):** ~115pt gradient (white → cyan → brand-blue).
- **Slide title:** ~44pt bold, black or white depending on layout background.
- **Section eyebrow:** 18pt bold ALL-CAPS, brand-blue, letter-spacing +110.
- **Body:** 22pt regular black.
- **Card label:** 22–30pt bold, mid-blue or brand-blue.
- **Card body:** 16–22pt regular, black or grey-mid.
- **Footer / brand row:** 14pt grey-mid.

## Palette

```
BLUE       #0F6BFF: brand accent, primary emphasis
BLUE_MID   #0A3A99: secondary emphasis, card labels
CYAN       #5CD6FF: highlight on dark, subtitle on hero
GREY_MID   #6B7280: dimmed content, secondary text
BLUE_NIGHT #0A1530: CTA slide background (dark)
GREY_SOFT  #F3F4F6: card fill
BLACK      #000000: body text
WHITE      #FFFFFF: text on dark
```

Don't invent new colours. Every decorative colour choice must map to one of these seven.

## Diagram idioms

- **Coordinate travel diagram** (Slide 3), one chip at top, three registry cylinders below with access labels
- **Four-move cards** (Slide 7), icons + arrows + sovereign-cloud target glyph
- **Deploy chain** (Slide 11), four cards with arrows between
- **Composition diagram** (Slide 12), one product card + three service cards + upgrade arrow
- **Replication chain echo** (Slide 17), four dimmed grey cards + one highlighted brand-blue card

These are all rendered as native PowerPoint shapes, not embedded images. That's why the build script has `_draw_*` helpers and `_render_chain_cards()`. If a session wants to add a diagram, use these helpers or extend them; don't add rasterized SVGs unless it's a logo.

## Icons

Icons on Slide 7 (Pack · Sign · Transport · Deploy) are drawn as native shapes with the brand-blue stroke. Defined in `decks/exec-phase1/build-pptx/icon_strokes.py`. Consistent across all four decks.

## Layouts (from OCM-Master.potx)

The template exposes these layouts by name:

- **Hero**, full-bleed banner, title, subtitle, footer, brand row
- **CTA**, dark background, title, action-path lines, brand row
- **Content / 3-Column**, title + subtitle + three body columns
- **Content / 3-Column Tall Title**, same with a taller title area (used for Slide 4)
- **Content / Diagram**, title + subtitle + one large diagram area
- **Content / Diagram Compact**, same with less vertical space
- **Content / Tiles**, title + subtitle + tile grid
- **Content / 2-Column**, title + subtitle + two body columns
- **Section Divider**, full-bleed section-break
- **Plain**, title only, freeform body
- **Plain / Compact**, title with less top padding

When building a new slide, pick a layout by function. Don't reinvent geometry from scratch.
