# OCM PowerPoint Template — Usage Guide

`OCM-Master.potx` is a reusable PowerPoint template with the OCM brand theme (canonical website palette) and 9 named slide layouts. Open it once, "Save as" your new deck, and author from there.

## Where it lives

`docs/community/marketing/decks/exec-phase1/OCM-Master.potx`

Building / regenerating: `cd build-pptx && .venv/bin/python build_potx.py`.

## How to author a new deck

1. **Double-click `OCM-Master.potx`** in Finder. PowerPoint opens it as a new untitled deck (it does NOT modify the .potx file itself).
2. **File → Save As…** → pick a name and location. Now you have your own .pptx based on the template.
3. **Insert → New Slide → pick layout** from the dropdown:
   - **Hero** — full-bleed dark backdrop, title + subtitle + org line. Use for slide 1 of any deck.
   - **CTA** — dark backdrop with title and bulleted CTA list. Use for the closing slide.
   - **Content / 3-Column** — eyebrow + big title + three side-by-side columns (4-px Brand Blue rule above each header). Use for "why now" or "three ideas" slides.
   - **Content / Diagram** — eyebrow + big title + full-width image area. Use when a diagram is the message.
   - **Content / Tiles** — eyebrow + title + 3×2 grid of grey-soft tiles with Brand Blue top rules. Use for "what this unlocks" outcome lists.
   - **Content / 2-Column** — eyebrow + title + two side-by-side body columns. Use for comparisons or paired content.
   - **Section Divider** — solid Brand Blue background with centered large title. Use to break the deck into chapters.
   - **Plain** — eyebrow + title + free body area. Catch-all when none of the above fit.
4. **Type into the placeholders.** Click each one and replace the placeholder text. The footer line (`OPEN COMPONENT MODEL · OCM.SOFTWARE`) is part of the layout; it appears automatically on every content slide.

## Brand colors

Open the **Format → Theme Colors** picker — the OCM brand colors appear in the top row:

| Slot | Token | Hex | Use |
|---|---|---|---|
| Accent 1 | Brand Blue Dark | `#257DDC` | eyebrows, primary accents, rules |
| Accent 2 | Brand Blue Mid | `#1D65B4` | secondary blue, tile labels in some layouts |
| Accent 3 | Brand Cyan | `#4CC9F0` | hero subtitle, accent highlights |
| Accent 4 | Grey Mid | `#6B7280` | footer, secondary text |
| Accent 5 | Brand Blue Night | `#0A1530` | hero/CTA backdrops |
| Accent 6 | Grey Soft | `#F3F4F6` | tile background |
| Text/Bg Dark 1 | Black | `#000000` | body text |
| Text/Bg Light 1 | White | `#FFFFFF` | slide background |
| Hyperlink | `#257DDC` | inline links |

## Default font

The theme registers **Aptos** as both major and minor font (matches Microsoft 365 default brand font, available natively from M365 in 2024+). Falls back to Inter / Calibri on systems without Aptos.

## Known issues / hand finishing

The .potx is built programmatically; some PowerPoint-specific finishing touches couldn't be encoded into raw OOXML cleanly. Things you may want to do once after opening:

1. **Hero gradient text on "Sovereign Clouds"** — the layout supplies a default placeholder ("Sovereign Clouds" in solid cyan). To get the website-style gradient (white → cyan → brand-blue), select the operative noun → Format Text Effects → Text Fill → Gradient fill → 3 stops as in `theme/_with-banner.css`. Alternatively, derive the deck from the already-built `OCM-Sovereign-Delivery-Exec-Master.pptx` which has the gradient applied.
2. **Hero banner image** — the layout has a solid `#0A1530` backdrop. To match the "Secure Delivery" deck visual, drop in `theme/OCM-Banner.png` as a full-bleed Picture (Insert → Picture from File → 1920×1080 placement).
3. **Brand row (OCM left, NeoNephos right)** — not baked into the Hero layout to keep file size low and let other decks omit it. Add per-deck if needed.
4. **Tile icons** — Tiles layout has empty label/body placeholders but no icon slots. Add 36×36 icons by hand (Insert → Pictures → SVG, then Convert to Shape, then color stroke `#257DDC`).
5. **Tabler icon stroke recoloring** — when you import any Tabler outline SVG (lock, cloud-upload, rocket, radar, etc.), right-click → Convert to Shape, then set Line color to Accent 1 (`#257DDC`). Setting Fill does nothing — Tabler icons have `fill="none"`.

## Layout-specific notes

### Hero (Layout 1)
Backdrop is solid `#0A1530`. Drop in a banner image to match the "Secure Delivery" feel; or leave solid for sober presentations.

### Content / 3-Column (Layout 3)
Eyebrow at y=180, title at y=216, columns at y=400. Each column has a 4-px Brand Blue rule across its width, header in ALL-CAPS Brand Blue, body in 18pt black. Designed to handle 1–2 short sentences per column.

### Content / Tiles (Layout 5)
3×2 grid (six tiles) at y=400. Each tile is 570×270 with a 3-px Brand Blue top rule and grey-soft fill. Each has placeholder boxes for label + body. Add icons by hand at the top-left of each tile.

### Section Divider (Layout 7)
Solid Brand Blue (`#257DDC`) backdrop with white centered title. Use sparingly — once per major section break in long decks.

## Footer

The footer text "OPEN COMPONENT MODEL · OCM.SOFTWARE" is hard-coded into the layouts. To change it (e.g. for a non-OCM deck reusing the template), edit it in **View → Slide Master**, locate the layout, and modify the footer text shape. The change applies to all slides using that layout.
