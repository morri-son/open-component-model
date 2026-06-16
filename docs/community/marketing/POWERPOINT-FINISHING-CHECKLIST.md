# PowerPoint Finishing Checklist

After running `build-pptx/build_pptx.py`, open `OCM-Sovereign-Delivery-Exec.pptx` in PowerPoint M365 (macOS) and apply the touch-ups below. The `.potx` template + script lands roughly 95% of the deck; this list covers what python-pptx can't reliably write into OOXML and what's safer to do by eye.

Estimated time: **~10 minutes** for the full pass.

---

## 1. Slide 1 — gradient text on "Sovereign Clouds" *(usually already applied)*

The build script writes a native OOXML `<a:gradFill>` on the "Clouds" run. Open slide 1 and confirm the gradient renders left-to-right (white → cyan → brand blue) on first open. No manual step needed in normal cases.

If the gradient does not appear (older PowerPoint build, font fallback edge case), apply manually:

- Double-click into the title text box, select only the operative noun (e.g. "Clouds").
- Right-click → **Format Text Effects…** → **Text Fill** → **Gradient fill**:
  - Type: **Linear**, direction **Linear Left** (0°)
  - Stops: White `#FFFFFF` at **0%** · Cyan `#5CD6FF` at **35%** · Brand Blue `#0F6BFF` at **75%**

The other title line ("Secure Delivery for") stays solid white.

## 2. Diagrams — optional: convert SVG to editable shapes

The script embeds diagrams as PNG rasters because python-pptx can't write `<svgBlip>` cleanly. If you want editable vector shapes (recolor, resize, replace icons):

For each of slides 3, 4, 5, 6:

- Delete the current image (a raster PNG).
- **Insert → Pictures → Picture from File…** → select the matching SVG from `decks/exec-phase1/diagrams/`.
- Right-click the inserted image → **Convert to Shape**. Confirm the prompt.
- The result is a group of vector shapes you can recolor, resize, or rebuild.
- **Tabler-style stroke quirk:** if any element looks invisible after Convert to Shape, ungroup once, set **Line color** (not Fill) to `#0F6BFF`, regroup.

## 3. Tile icons — optional: recolor to Brand Blue strokes

Slide 8's six tile icons are embedded as PNG. To make them vector and recolorable:

For each tile on slide 8:

- Delete the current 36×36 raster icon.
- **Insert → Pictures → Picture from File…** → pick the SVG from `decks/exec-phase1/diagrams/icons/`.
- Right-click → **Convert to Shape**.
- Select the resulting group → **Format Shape** → **Line** → **Color** → `#0F6BFF`. (Setting Fill does nothing — Tabler outline icons have `fill="none"`.)
- Resize to 36×36 px and place at tile-x+24, tile-y+24.

Tiles, in order:

| Tile | Icon file |
|---|---|
| Code signing across stacks | `lock.svg` |
| Air-gapped delivery | `package-export.svg` |
| Kubernetes-native deployment | `rocket.svg` |
| Asynchronous security scans | `radar.svg` |
| One source of truth | `source-of-truth.svg` |
| Automated compliance reporting | `report-analytics.svg` |

## 4. Aptos availability check

Confirm Aptos is in the **Home → Font** dropdown. If it's not, M365 needs updating. The deck uses Aptos for body and **Aptos Display** for title placeholders; both come with the standard Aptos installation in M365 2024+.

## 5. Slide 9 logos — visual parity

The script sizes each logo into a 320×100 box and centres it in its slot. Walk slide 9 once and:

- Verify SAP, BwI, SAP NS2 in the top row look balanced — they have very different intrinsic aspect ratios.
- Same check on the bottom row (Gardener, Konfidence, Platform Mesh).
- If any logo looks oversized or undersized, click and resize manually; lock aspect ratio while doing so.

## 6. Save and commit

- Save with the same filename. The script will not auto-overwrite if you've made manual edits — back up first if you plan to re-run it.
- DCO sign-off when committing: `git commit -s -m "chore(marketing): update OCM exec deck"`.
- The `.pptx` is the source of truth from this point. Mirror copy changes back into `NARRATIVE.md` to keep the at-a-glance summary in sync.

---

## What the script intentionally skips

- **Per-side borders on tiles.** PowerPoint shapes don't support per-side borders, so the 3 px Brand Blue top rule is a separate rectangle.
- **SVG editable-shape conversion.** Done by hand if needed (sections 2 and 3 above).
- **Compliance Dashboard screenshot** for slide 7. Not yet sourced; flagged as a future workstream.

## When to re-run the script

If you change slide content in PowerPoint, **don't re-run the script** — that overwrites your edits. The script is for the initial build only. Subsequent edits live in the `.pptx`.

If you need to regenerate from scratch (e.g. you changed the colour palette in the script), back up the current `.pptx` first, run the script, then port your manual touch-ups across.
