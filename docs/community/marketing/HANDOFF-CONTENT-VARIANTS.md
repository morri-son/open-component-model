# Handoff — content variants for the OCM exec deck

**Repo root:** `/Users/D032990/.cline/worktrees/marketing-recovery/open-component-model`
**Working dir:** `docs/community/marketing/`
**Branch:** `marketing/spike-deck`
**Picks up from:** 2026-06-16, late evening

## What this session is about

**Content, not design.** Build multiple variant exec decks from the rework options in:

- `docs/community/marketing/EXEC-DECK-REWORK-OPTIONS.md` — 3–4 alt framings per slide (risk-led / ROI-led / peer-led / regulator-led)
- `docs/community/marketing/MARKETING-CRITIQUE-EXEC.md` — 15-issue critique + scorecard + top-5 fixes

The user wants to pit the variants against each other to pick the strongest narrative. **Design is frozen for this round** — no layout, color, font, or coordinate changes unless the user asks.

## The design rules (do not violate)

1. **Slides are EITHER text OR diagram, never both.** That's why slide 4 splits into 4a (text) + 4b (diagram), and slide 6 (Sovereign-Ready) splits into 6a (text) + 6b (diagram). When an OPTIONS variant mixes content, split the slide.
2. **Eyebrow never wraps to 2 lines.** Keep eyebrow text terse.
3. **1-line title vs 2-line title get DIFFERENT layouts.** See "Layout choice" below.

## Build state

```
decks/exec-phase1/build-pptx/
├── build_potx.py     → ../OCM-Master.potx          (9 layouts, theme, brand)
├── build_pptx.py     → ../OCM-Sovereign-Delivery-Exec.pptx (12-slide deck)
└── .venv/            (python-pptx + Pillow)
```

`rsvg-convert` (homebrew `librsvg`) needed for SVG→PNG.

```bash
cd decks/exec-phase1/build-pptx
.venv/bin/python build_potx.py     # template
.venv/bin/python build_pptx.py     # deck
```

Both must run in that order. The pptx loads layouts from the potx.

**Before rebuilding, check for `~$*.pptx` lockfiles in `decks/exec-phase1/`** — saving over an open file has corrupted state in earlier rounds. Ask the user to close PowerPoint first.

## Current 12-slide deck (the baseline)

| # | Layout | Title | Notes |
|---|---|---|---|
| 1 | Hero | "Secure Delivery for Sovereign Clouds" | line 2 full gradient white→cyan→blue, 115pt |
| 2 | 3-Column | WHY NOW | columns gutter 56 |
| 3 | Diagram | THE PAIN | 2-line title; **diagram is ugly per user — pending decision** |
| 4a | Plain / Compact | THE SHIFT — SBoD | 1-line title, blue ▪ bullets |
| 4b | Diagram | THE SHIFT — SBOM INSIDE SBoD | "Software Bill of Delivery" aligned with SBOM box |
| 5 | Diagram | OCM IN ONE PICTURE | pack/sign/transport/deploy; lock centered in cloud |
| 6a | Plain / Compact | SOVEREIGN-READY | 1-line title, blue ▪ bullets |
| 6b | Diagram | SOVEREIGN-READY — AIR-GAP | "Identity stays" moved below crossing arrow |
| 7 | Plain | SCAN — Compliance-native | **2-line title**, blue ▪ bullets, body y=580 |
| 8 | Tiles | WHAT OCM UNLOCKS | 3×2 grid |
| 9 | Plain | TRUSTED IN PRODUCTION | logo wall; body placeholder deleted; uniform-height logos |
| 10 | CTA | Start delivering with confidence. | white title + cyan action labels + white path text |

## Layout choice (1-line vs 2-line title)

The .potx has 9 layouts. Two of them differ ONLY in body Y-position to compensate for title wrap:

| Layout | Body y | Use when |
|---|---|---|
| **Plain / Compact** | 520 | Title is 1 line — body sits close under title |
| **Plain** | 580 | Title is 2 lines — body has 60px extra headroom |

When you write a new variant slide:
- Title fits on 1 line → `prs.slides.add_slide(layouts["Plain / Compact"])`
- Title wraps to 2 lines → `prs.slides.add_slide(layouts["Plain"])`

For diagram slides the **Content / Diagram** layout has body y=520, fine for 1-line titles. If a variant needs a 2-line title with a diagram, you'll need to add a **Content / Diagram (Tall)** variant — copy the pattern from `layout_plain_compact()` in `build_potx.py`.

The full layout list:
**Hero · CTA · Content / 3-Column · Content / Diagram · Content / Tiles · Content / 2-Column · Section Divider · Plain · Plain / Compact**.

## Design tokens (frozen)

Baked into `build_potx.py`. **Do not change.**

- Slide size **1920 × 1080**, 96 dpi → 1 px = 9525 EMU
- Margins x=**120**, content width **1680**
- Eyebrow y=**255**, h=48, **28pt** OCM blue (#0F6BFF), ALL CAPS, letter-spacing 1.4 — **never wrap**
- Title y=**308**, h=200, **64pt** Aptos Display, line_spacing_pct=**0.9**
- Content y=**520** (Compact / Diagram / Tiles / 2-Column / 3-Column), or **580** (Plain only)
- Footer y=**1048** — do not move
- 3-Column: gutter **56**, column header **20pt blue**, body **22pt**
- Tiles: 544 × 230, gutter 24, body 18pt
- 2-Column body 22pt, Plain body 22pt
- Hero: title 115pt both lines, line 2 gradient, subtitle 36pt cyan, org line 28pt white
- CTA: white title (no gradient); action label cyan + bold, " — path" white

## Helpers in build_pptx.py

| Helper | Purpose |
|---|---|
| `set_text(s, idx, text, color=)` | plain text into a placeholder |
| `set_blue_box_bullets(s, idx, items)` | blue ▪ + black text per item |
| `set_split_gradient_title(s, idx, prefix, noun)` | hero — prefix white, noun gradient (use prefix="" + noun=full string for whole-line gradient) |
| `set_gradient_title(s, idx, text)` | whole title gradient (currently unused — CTA reverted to plain white) |
| `set_action_path_lines(s, idx, [(action, path)])` | CTA body — action cyan, " — path" white |
| `delete_placeholder(s, idx)` | remove a layout-supplied placeholder cleanly |
| `add_diagram(s, svg, x_px, y_px, max_w_px, max_h_px)` | rasterise SVG, embed; **also auto-deletes the layout's empty pic placeholder** so the dotted "Bild einfügen" outline doesn't appear next to the picture |
| `add_tile_icon(s, tile_x, tile_y, name)` | tile icons from `diagrams/icons/` |
| `add_logo_row(s, logos, y_px, ...)` | uniform-height logo row (slide 9) |

## Building variant decks

User wants **multiple decks** from EXEC-DECK-REWORK-OPTIONS.md. Suggested structure:

```
decks/exec-phase1/
├── build-pptx/
│   ├── build_pptx.py            ← current baseline
│   ├── build_pptx_risk.py       ← risk-led variant
│   ├── build_pptx_roi.py        ← ROI-led variant
│   ├── build_pptx_peer.py       ← peer-led variant
│   └── build_pptx_regulator.py  ← regulator-led variant
└── OCM-Sovereign-Delivery-Exec-{risk,roi,peer,regulator}.pptx
```

Each script reads the same `OCM-Master.potx` and emits a different .pptx. If the helpers grow, factor `build_pptx.py` into a reusable module (e.g. `deck_helpers.py`).

**Don't write all four variants up-front.** Pick the highest-leverage 1-2 first, generate, get user feedback, then expand.

## Immediate task — slide 3 (THE PAIN)

User feedback (from earlier session):

> "Slide 3 with the pain only has a diagram and the diagram is ugly. It does not tell much."

Slide 3 also has a 2-line title which currently uses the Diagram layout (body y=520). Three open paths:

1. Drop `03-fragmented.svg`. Rewrite slide 3 as text-only on **Plain** (since title is 2-line). Pull friction language from MARKETING-CRITIQUE-EXEC.md.
2. Replace the diagram. There are no v2/v3 alternatives for slide 3 (unlike 04/05/06).
3. Defer until content variants are picked — the framing in EXEC-DECK-REWORK-OPTIONS.md may change what slide 3 *means*.

Recommend (1).

## Reference docs (don't modify unless asked)

In `docs/community/marketing/`:

- `MARKETING-CRITIQUE-EXEC.md` — strategist read; top-5 fixes is a good entry point
- `EXEC-DECK-REWORK-OPTIONS.md` — alt framings per slide (the menu)
- `TECHNICAL-DECK-OUTLINE.md` + `TECHNICAL-DECK-CONTENT.md` — practitioner deck, not built yet
- `CONTENT-OPTIONS.md` — older, more granular wording options
- `DIAGRAM-OPTIONS.md` — catalog of 7 diagram variants
- `NARRATIVE.md` + `NARRATIVE-AT-A-GLANCE.md` — locked narrative
- `decks/exec-phase1/POWERPOINT-FINISHING-CHECKLIST.md` — manual touch-ups python-pptx can't do

## What was changed this session (latest first)

1. **Two-tier Plain layout** — added `Plain / Compact` (body y=520) for 1-line titles; existing `Plain` stays at y=580 for 2-line titles. Slides 4a and 6a switched to Plain / Compact.
2. **Slide 9 (SCAN) body** — `Plain` body y=520→580 to clear the 2-line title.
3. **Slide 8 (airgap) "Identity stays" label** — moved below the crossing arrow in `06-sovereign-airgap.svg` to prevent overlap with TRUST BOUNDARY.
4. **Slide 6 cloud-lock** — lock recentered vertically inside the cloud silhouette in `05-pack-sign-transport-deploy-v2.svg`.
5. **Slide 5/6/8 dotted "Bild einfügen" outline** — `add_diagram()` now calls `delete_placeholder(s, 10)` before adding the picture, removing the empty Diagram-layout pic placeholder.
6. **Diagrams max_h 480→520** — fills the available content area below the title.
7. **Slide 11 (logo wall)** — `add_logo_row` now sizes each logo to a uniform height (max_h=80) so SAP no longer dominates; rows pushed further from labels.
8. **CTA title** — gradient removed, plain white. Action labels swapped from blue → cyan (`#5CD6FF`).
9. **Slide 2 title** — "WHY NOW — V1 · SOVEREIGNTY-LED" → "WHY NOW".
10. **Slide 2 columns** — gutter 32→56 for leaner column block.
11. **Hero gradient** — `set_split_gradient_title(s, 2, prefix="", noun="Sovereign Clouds")` so the gradient spans the full noun phrase, not just "Clouds".
12. **Title line spacing** — added `line_spacing_pct=0.9` on all title placeholders (titles wrapping to 2 lines no longer waste vertical space). Title h grew 130→200 to fit 2 lines comfortably.
13. **Eyebrow size** — 18→28pt, h 32→48.
14. **Body sizes** — column headers 16→20, column body 18→22, 2-col body 18→22, tile body 12→18.
15. **SBoD label aligned** — `04-sbom-inside-sbod.svg` "SOFTWARE BILL OF DELIVERY" x=120→140 to align with SBOM box left edge.
16. **Rocket icon redrawn** in `05-pack-sign-transport-deploy-v2.svg` (was a fountain pen-looking shape).

## What NOT to do

- **Don't** mix text + diagram on a single slide. Split into two.
- **Don't** restart from a fresh `Presentation()`. The .potx is canonical.
- **Don't** re-derive the palette. It's `#0F6BFF / #0A3A99 / #5CD6FF / #0A1530 / #6B7280 / #F3F4F6 / #000 / #FFF`.
- **Don't** change layout coordinates, token sizes, or color usage — design is frozen.
- **Don't** add new master layouts unless content forces it (e.g. a needed Tall Diagram variant for a 2-line-title diagram slide).
- **Don't** re-rasterise SVGs unless `_raster/` is missing files. Cache is mtime-keyed.
- **Don't** save over an open .pptx. Check `~$*.pptx` lockfiles first; ask user to close.

## Open questions for the new session

1. Which framing(s) from EXEC-DECK-REWORK-OPTIONS.md does the user want first?
2. Slide 3 (THE PAIN) — text-only or diagram replacement? Decision deferred to first variant work.
3. Hero subtitle and org-line copy and CTA copy — assume constant across variants unless user says otherwise.
4. Naming convention for variant `.pptx` files — confirm with user before generating.

## Build / verify cycle

```bash
cd decks/exec-phase1/build-pptx

# 1. Rebuild template (only if you changed build_potx.py)
.venv/bin/python build_potx.py

# 2. Rebuild a deck variant
.venv/bin/python build_pptx.py
# or
.venv/bin/python build_pptx_<variant>.py

# 3. Visual check in PowerPoint. Critical: hero gradient on line 2 of title;
#    bullets are blue ▪; eyebrow doesn't wrap; title doesn't wrap to 3+ lines;
#    no "Bild einfügen" prompt next to embedded diagrams.
```

If you see a `~$<name>.pptx` lockfile, ask the user to close the file first.

## Reference: the Marp dist deck

`decks/exec-phase1/dist/preview.NNN.png` are 720p previews of an older Marp render. Useful as a "does this framing tell the story?" benchmark. **Not** a layout reference — our 1080p .pptx has its own coords.
