# PowerPoint Master — Build Spec

This spec is the bridge from the Marp design reference to the PowerPoint master. Build the master once, in order, and you'll end with an editable, brand-consistent deck that you (and others) can author into directly.

**Target:** Microsoft 365 (Aptos available natively).
**Slide size:** 16:9, 1920×1080 (HD). PowerPoint default — no need to change.
**Tech check:** Confirm Aptos is showing in Home → Font dropdown before starting. If it isn't, M365 may need updating; falling back to Inter or Calibri is acceptable but the brand specifies Aptos.

---

## 1. Brand spec

**Palette** (use these exact hex values):

| Role | Hex | Use |
|---|---|---|
| Brand Blue | `#0F6BFF` | Primary brand accent: gradient endpoints, eyebrow text, accent rules, tile labels |
| Brand Blue Deep | `#0A3A99` | Subheadings, titles inside content blocks |
| Brand Blue Night | `#0A1530` | Hero/CTA backdrops |
| Accent Cyan | `#5CD6FF` | Hero subtitle, gradient mid-stop, decorative accents |
| Brand Black | `#333333` | Body text |
| Grey Mid | `#6B7280` | Footer line, secondary text |
| Grey Soft | `#F3F4F6` | Tile background, subtle fills |
| White | `#FFFFFF` | Hero/CTA text, content slide backgrounds |

**Type stack:** Aptos (with Inter as fallback if needed for export). All weights from Light to Bold.

**Type scale:**

| Element | Size (pt) | Weight | Color |
|---|---|---|---|
| Hero title | 72 | Bold | White |
| Hero subtitle | 28 | Regular | Cyan |
| Hero org line | 20 | Regular | White at 82% opacity |
| Content slide title | 40 | Bold | Brand Black |
| Content eyebrow | 14 | Semibold, ALL-CAPS, +8% letter-spacing | Brand Blue |
| Content body | 16 | Regular | Brand Black |
| Three-col header | 12 | Bold, ALL-CAPS, +8% letter-spacing | Brand Blue |
| Three-col body | 14 | Regular | Brand Black, line-height 1.45 |
| Tile label | 14 | Semibold | Brand Blue Deep |
| Tile body | 11 | Regular | Brand Black, line-height 1.45 |
| Footer line | 9 | Regular, ALL-CAPS, +6% letter-spacing | Grey Mid |
| CTA list item | 22 | Regular | White at 92% opacity, with 3px Cyan left-rule |

**Spacing rules:**
- Slide margin: 60 px top, 60 px right, 80 px bottom (footer area), 60 px left
- Hero margins: 96 px sides, vertically centred stack
- Inter-element gap inside headline groups (title→subtitle, subtitle→orgline): 8–14 px (tight; visually grouped)
- Inter-block gap (e.g., title block → diagram, eyebrow → title): 24–40 px
- Three-column gutter: 24 px
- Tile gutter: 16 px

**No-no list:**
- No page numbers anywhere
- No header logos on content slides — only hero and CTA carry the OCM/NeoNephos lockup
- No bottom gradient strips, accents, or decorations beyond what's specified
- No emoji
- Footer line is text-only ("OPEN COMPONENT MODEL · OCM.SOFTWARE")

---

## 2. Slide masters (8 layouts)

Set these up in **View → Slide Master**. Each layout below is one slide layout under the master. Naming the layouts matters — when authoring, you'll pick layouts by name.

### Master root

- Background: White (`#FFFFFF`)
- Default font: Aptos Regular, 16 pt, Brand Black
- Set the colour theme to use the 8 brand colours above (Design → Colors → Customize Colors)

### Layout 1: **Hero**

- Background: Brand Blue Night (`#0A1530`) — solid fill
- Top 60% region (1920 × 648): banner texture image. Image set to "stretch to fit," centred, opacity 100%. Asset: `theme/neonephos-banner.png`. PowerPoint will scale the 800×480 source up; this is fine for 1920×1080 export.
- Below banner: gradient overlay shape (rectangle 1920 × 432 starting at y=648) with vertical gradient from transparent (top) to Brand Blue Night (bottom). This blends the banner into the dark backdrop.
- Three text placeholders, vertically centred as a group, left-aligned at x=96:
  - **Title placeholder** ("Hero title"): 72 pt Aptos Bold, White. Two lines. The operative noun (the second line, last word/phrase) gets the gradient effect — see "Gradient text" below.
  - **Subtitle placeholder** ("Hero subtitle"): 28 pt Aptos Regular, Cyan. 8 px below title.
  - **Org line placeholder** ("Hero org line"): 20 pt Aptos Regular, White at 82% opacity. 14 px below subtitle.
- Bottom 56 px from the bottom edge: brand row.
  - OCM logo (`assets/ocm/ocm-horizontal-white.svg`): height 76 px, x=96, y=bottom-56-76
  - NeoNephos Foundation logo (`assets/neonephos/neonephos-foundation-horizontal-white.svg`): height 52 px, x=right-aligned at x=1920-96-(logo width), y=bottom-56-52

**Gradient text on operative noun:**

PowerPoint M365 supports gradient text fills via Format Shape → Text Options → Text Fill → Gradient fill. Configure as:
- Type: Linear, 0° (left to right)
- Stops:
  - 0%: White (`#FFFFFF`), 100% opacity
  - 35%: Cyan (`#5CD6FF`), 100% opacity
  - 75%: Brand Blue (`#0F6BFF`), 100% opacity

To apply: select only the operative noun (e.g. "Sovereign Clouds"), then apply the gradient. The rest of the title stays solid white.

### Layout 2: **CTA**

Mirror of Hero with these differences:
- Background: radial gradient — ellipse at 70% / 30% with Cyan @ 10% opacity fading to transparent, on top of a 135° linear gradient from Brand Blue Night to Brand Blue Deep
- Title placeholder: 56 pt Aptos Bold, White. Single line.
- List placeholder: bulleted list, custom bullet style:
  - Each line: 22 pt Aptos Regular, White at 92%, with a 3 px Cyan left-rule (border) and 32 px left padding
  - Strong (bold) text within: Cyan, weight 600
- Brand row at bottom: same as Hero (OCM left, NeoNephos right)

### Layout 3: **Content / three-column**

- Background: White
- Eyebrow placeholder ("Content eyebrow"): 14 pt Aptos Semibold ALL-CAPS, Brand Blue, top of content area at y=60
- Title placeholder ("Content title"): 40 pt Aptos Bold, Brand Black, immediately below eyebrow with 12 px gap
- Below title, three column blocks at y=180 (or wherever the title naturally ends + 40 px), full-width-divided-by-3 minus 24 px gutters:
  - **Each column**: top 4-px-thick rule in Brand Blue, with content padded 24 px below it
  - Column header (h3 placeholder): 12 pt Aptos Bold ALL-CAPS +8% letter-spacing, Brand Blue, 12 px below the rule
  - Column body (text placeholder): 14 pt Aptos Regular, Brand Black, line-height 1.45
- Footer at bottom: 9 pt Aptos Regular ALL-CAPS +6% letter-spacing, Grey Mid, content "OPEN COMPONENT MODEL · OCM.SOFTWARE", at x=80, y=1080-32

### Layout 4: **Content / diagram**

- Background: White
- Eyebrow + title same as Layout 3, but title is 28 pt (smaller because diagram needs vertical room)
- Content area below title: full-width image placeholder for the diagram SVG. Asset paths: `decks/exec-phase1/diagrams/0X-*.svg`. PowerPoint imports SVG as editable shapes — you can resize, recolour, or replace icons as needed.
- Footer same as Layout 3

**Note for Phase 2:** the four current SVG diagrams will need redrawing or replacement when the deck moves to authoritative use. Specifically `04-sbom-vs-sbod.svg` shows side-by-side composition; the locked narrative requires SBOM-inside-SBoD.

### Layout 5: **Content / tiles** (3×2 grid)

- Background: White
- Eyebrow + title same as Layout 3, title at 40 pt
- Below title at y=180: 3×2 grid of tile shapes, gutter 24 px, total width matches the slide content area (1920 - 160 = 1760 px usable; each tile = (1760 - 48) / 3 = 570 px wide)
- **Each tile shape:**
  - Background fill: Grey Soft (`#F3F4F6`)
  - Top edge: 3 px Brand Blue rule (border)
  - Padding: 24 px all sides
  - Icon placeholder at top-left: 36×36 px slot for SVG icon
  - Label below icon (12 px gap): 14 pt Aptos Semibold, Brand Blue Deep
  - Body below label (12 px gap): 11 pt Aptos Regular, Brand Black, line-height 1.45
- Footer same as Layout 3

### Layout 6: **Content / two-column** (for slide 9 adopters)

- Same eyebrow + title as Layout 3
- Body area split: top half = "Adopted by enterprises shipping into regulated environments." label + three logos in a row; bottom half = "Built into the open-source ecosystem." label + three logos in a row
- Section labels: 14 pt Aptos Semibold ALL-CAPS, Brand Blue, with 16 px gap below
- Logo row: three logos centred in the row, equal spacing, each constrained to a 250 × 80 box for visual parity. Adopter logo files (SAP, BwI, SAP NS2, Gardener, Konfidence, Platform Mesh) are not yet in `assets/adopters/` — see Open Items.
- Footer same as Layout 3

### Layout 7: **Section divider** (optional)

If you want section breaks in the deck (likely not for a 10-slide exec deck, but useful in the technical Phase 2 deck):
- Background: Brand Blue (`#0F6BFF`) solid
- Centred title placeholder: 56 pt Aptos Bold, White
- No other elements

### Layout 8: **Plain content / catch-all**

A simple layout with:
- Eyebrow + title (same as Layout 3)
- Single full-width body text area below
- Footer

For slides that don't fit any specific layout above. Useful as a fallback.

---

## 3. Slide-by-slide content map

10 slides, mapped to Layouts 1–6. Content is **verbatim** from `NARRATIVE.md`. Build the slides in this order; pick the layout from the dropdown.

### Slide 1 — Hero (Layout 1)

- Title: `Secure Delivery for Sovereign Clouds` — apply gradient to "Sovereign Clouds" only
- Subtitle: `Deliver and deploy your software securely. Anywhere, at any scale.`
- Org line: `Open Component Model — open source, NeoNephos Foundation.`

**Three opener variants exist (V1 sovereignty-led / V2 supply-chain-led / V3 fragmentation-led). Build one canonical hero, then duplicate the slide for variants if you want all three in the same deck. The hero text doesn't change between variants — only slide 2 changes.**

### Slide 2 — Why now (Layout 3)

Three column variants. **Build one canonical, then duplicate-and-edit for V2 and V3.**

**V1 — Sovereignty-led** (recommended default):
- Eyebrow: `WHY NOW`
- Title: `Sovereignty is no longer optional`
- Column 1 — header `SOVEREIGNTY PRESSURE`, body: `Wherever the law puts the boundary — by jurisdiction, sector, or air-gap — software must be deliverable, verifiable, and operable inside it.`
- Column 2 — header `REGULATION TIGHTENING`, body: `EU DORA · NIS2 · GDPR. Provable supply-chain control, not best effort.`
- Column 3 — header `SUPPLY-CHAIN ATTACKS ARE REAL`, body: `SolarWinds. xz. log4shell. Signatures must survive the journey, or compliance is theatre.`

**V2 — Supply-chain-led:** title `Trust must travel with the artifact.` Column 1 = supply-chain attacks (move to first column), Column 2 = regulation, Column 3 = sovereignty. Body texts as in NARRATIVE.md slide 2.

**V3 — Fragmentation-led:** title `Compliance retrofits don't scale.` Column 1 = `SOFTWARE DELIVERY IS FRAGMENTED` with body `Many teams, many stacks. Signatures break between them. SBOMs were never built for delivery.` Columns 2 & 3 = regulation + sovereignty.

### Slide 3 — The pain (Layout 4 + diagram, OR Layout 3 with text columns)

- Eyebrow: `THE PAIN`
- Title: `Software delivery is fragmented. Compliance retrofits don't scale.`
- Body / diagram: insert `decks/exec-phase1/diagrams/03-fragmented.svg` if using Layout 4. If using Layout 3 with text, write the body as: `Many teams, many stacks. Signatures break in transit. SBOMs were never built for delivery — they were built for inventory. Each compliance regime adds its own bolt-on. None of it composes.`

### Slide 4 — The shift, SBoD (Layout 4 OR Layout 8 with custom illustration)

- Eyebrow: `THE SHIFT`
- Title: `SBOM lists. SBoD delivers.`
- Body: `An SBOM tells you what's in your software. It was built for inventory.\nA Software Bill of Delivery (SBoD) tells you what you delivered, how to verify it, how to transport it, and how to operate it. It was built for delivery.\nThe SBoD contains the SBOM. OCM doesn't replace your SBOM tooling — it gives the SBOM an envelope that's compliance-native, signed once, and travels intact across any boundary.`
- **Diagram:** `decks/exec-phase1/diagrams/04-sbom-vs-sbod.svg` is provisional (shows side-by-side; spec wants SBOM-inside-SBoD). Either: (a) use the existing SVG with a known-stale flag, (b) redraw in PowerPoint as nested concentric shapes (SBoD outer, SBOM inner), or (c) use Layout 8 with text only and skip the diagram on this slide. **My recommendation: option b — draw it in PowerPoint as two concentric rounded-rect shapes labelled SBoD (outer, brand-blue stroke) and SBOM (inner, grey fill). Quick, and it lands the composition message.**

### Slide 5 — OCM in one picture (Layout 4)

- Eyebrow: `OCM IN ONE PICTURE`
- Title: `Pack · Sign · Transport · Deploy`
- Diagram: `decks/exec-phase1/diagrams/05-pack-sign-transport-deploy.svg` (provisional; renders small in Marp due to internal SVG layout. In PowerPoint, the SVG imports as editable shapes — you can rebuild this as four-card row using the tile pattern from Layout 5, with the Pack/Sign/Transport/Deploy/Sovereign Cloud cards as native PowerPoint shapes. ~10 min in PowerPoint, gives you a full-width clean diagram.)

### Slide 6 — Sovereign-ready (Layout 4)

- Eyebrow: `SOVEREIGN-READY`
- Title: `Trust, but verify.`
- Body: `Identity is location-independent. Signatures are location-independent. Day-2 ops happen inside the boundary. On transfer into a sovereign environment, a component can carry every artifact it needs along with it.`
- Diagram: `decks/exec-phase1/diagrams/06-sovereign-airgap.svg`

### Slide 7 — Compliance-native (Layout 3 OR Layout 8)

- Eyebrow: `COMPLIANCE-NATIVE — OPEN DELIVERY GEAR`
- Title: `Compliance as a system property — not a quarterly project.`
- Body bullets:
  - `Open Delivery Gear (ODG) is OCM's compliance automation engine.`
  - `The Compliance Dashboard is your entry point: every component, every finding, every signature in one view.`
  - `Continuous scans run asynchronously — even after release.`
  - `Findings get rescored against contextual risk, so your team patches what actually matters.`
  - `Every compliance signal correlates by component identity. Auditors get evidence, not spreadsheets.`

**Note for speaker:** the project's UI is named "Delivery Dashboard"; we frame it as "Compliance Dashboard" for exec language.

### Slide 8 — What OCM unlocks (Layout 5, tiles)

- Eyebrow: `WHAT OCM UNLOCKS`
- Title: `One model unlocks all of this.`
- Six tiles (icon, label, body):

| # | Icon (SVG) | Label | Body |
|---|---|---|---|
| 1 | `diagrams/icons/lock.svg` | Code signing across stacks | Sign once at source; verify everywhere, with no per-stack tooling. |
| 2 | `diagrams/icons/cloud-upload.svg` | Air-gapped delivery | Walk a complete component across an air gap; verify at destination. |
| 3 | `diagrams/icons/rocket.svg` | Kubernetes-native deployment | OCM controllers deploy components directly into clusters. |
| 4 | `diagrams/icons/radar.svg` | Asynchronous security scans | Continuous scanning, even after release; findings tied to component identity. |
| 5 | `diagrams/icons/adjustments-horizontal.svg` | Contextual CVE rescoring | Patch what matters in your context, not what a generic feed says. |
| 6 | `diagrams/icons/report-analytics.svg` | Automated compliance reporting | Reports composed from SBoD metadata — no spreadsheet drift. |

Icons are Tabler outline SVGs. PowerPoint imports them as editable line shapes. Apply Brand Blue stroke colour after pasting.

### Slide 9 — Open and governed (Layout 6, two-column)

- Eyebrow: `TRUSTED IN PRODUCTION`
- Title: `Aligned with NeoNephos.`
- Top section: label `ADOPTED BY ENTERPRISES SHIPPING INTO REGULATED ENVIRONMENTS`. Three logos: SAP · BwI · SAP NS2.
- Bottom section: label `BUILT INTO THE OPEN-SOURCE ECOSYSTEM`. Three logos: Gardener · Konfidence · Platform Mesh.
- Proof point (under the logos): `An open standard, neutrally governed — your stack stays portable, your dependencies stay yours.`

**Note: adopter logos are not in `assets/adopters/` yet.** SAP and BwI logos can be sourced from Wikimedia Commons (public-domain trademark per usage guidelines). SAP NS2 logo from sapns2.com. Gardener, Konfidence, Platform Mesh logos from `github.com/neonephos/artwork/projects/`. Pulling them is the next step before authoring this slide.

### Slide 10 — Call to action (Layout 2)

- Title: `Start delivering with confidence.`
- List items:
  - `**Try it** — ocm.software`
  - `**Build with us** — github.com/open-component-model`
  - `**Talk to us** — community channels on the website`
- Brand row: OCM left, NeoNephos right (same as hero)

---

## 4. Asset reference

All assets live in `docs/community/marketing/assets/` and `docs/community/marketing/decks/exec-phase1/`. Repo-relative paths used here.

**Logos (committed):**
- `assets/ocm/ocm-horizontal-color.svg` — OCM, color version (use on light backgrounds)
- `assets/ocm/ocm-horizontal-white.svg` — OCM, white version (use on dark backgrounds: hero, CTA)
- `assets/neonephos/neonephos-foundation-horizontal-color.svg` — NeoNephos Foundation, color
- `assets/neonephos/neonephos-foundation-horizontal-white.svg` — NeoNephos Foundation, white

**Diagrams (committed, all SVG, all editable on import):**
- `decks/exec-phase1/diagrams/03-fragmented.svg`
- `decks/exec-phase1/diagrams/04-sbom-vs-sbod.svg` *(known-stale per locked narrative; redraw recommended in PowerPoint)*
- `decks/exec-phase1/diagrams/05-pack-sign-transport-deploy.svg` *(small in Marp; rebuild as native PowerPoint cards recommended)*
- `decks/exec-phase1/diagrams/06-sovereign-airgap.svg`

**Tile icons (committed, Tabler MIT):**
- `decks/exec-phase1/diagrams/icons/lock.svg`
- `decks/exec-phase1/diagrams/icons/cloud-upload.svg`
- `decks/exec-phase1/diagrams/icons/rocket.svg`
- `decks/exec-phase1/diagrams/icons/radar.svg`
- `decks/exec-phase1/diagrams/icons/adjustments-horizontal.svg`
- `decks/exec-phase1/diagrams/icons/report-analytics.svg`
- `signature.svg` is committed but unused.

**Banner texture (committed):**
- `decks/exec-phase1/theme/neonephos-banner.png` — 800×480, ~420 KB. Cropped from the LinkedIn banner SVG. Use as hero backdrop image, "stretch to fit" the top 60% region.

**Adopter logos (NOT YET COMMITTED — fetch before authoring slide 9):**
- SAP logo
- BwI logo
- SAP NS2 logo
- Gardener logo (`github.com/neonephos/artwork/projects/gardener/horizontal/color/`)
- Konfidence logo (need source)
- Platform Mesh logo (need source — likely `github.com/neonephos/artwork/projects/platform-mesh/`)

---

## 5. Build order (suggested)

Don't try to do everything at once. Build the master in this order so you can validate visual fidelity early:

1. **Set up theme** (5 min)
   - Design → Variants → Colors → Customize Colors → set the 8 brand colours
   - Confirm Aptos in font dropdown
   - Save the theme as "OCM-NeoNephos"

2. **Build Layout 1 — Hero** (15 min)
   - This is the most visually distinctive slide; getting it right validates the design language
   - Place banner backdrop, title placeholder, subtitle, org line, both logos
   - Apply gradient text to the operative noun
   - Save and review

3. **Build Layout 3 — Three-column content** (10 min)
   - Most-used content layout
   - Eyebrow, title, three column blocks with top rules, footer line
   - Save and review

4. **Build Layouts 4, 5, 6 in parallel** (15 min)
   - Layout 4 — Diagram (eyebrow + title + image area + footer)
   - Layout 5 — Tiles 3×2 grid
   - Layout 6 — Two-column logo wall

5. **Build Layout 2 — CTA** (10 min)
   - Mirror of Hero with list-of-three styling

6. **Author content slides** (45 min)
   - Apply layouts to ten slides per the content map in section 3
   - Paste assets from the file paths in section 4

7. **Refinement pass** (15 min)
   - Look at the 10 slides end-to-end
   - Tighten spacing where needed
   - Confirm gradient looks right in Powerpoint preview *and* on actual PowerPoint export to PDF

Estimated total: ~2 hours. The first slide is slow; the rest accelerate as the masters take shape.

---

## 6. Open items / decisions remaining

- **Adopter logos** — need to fetch SAP, BwI, SAP NS2, Gardener, Konfidence, Platform Mesh before slide 9 can be authored. Likely a 20-min asset hunt. Want me to do this in the next iteration?
- **Slide 4 SBoD diagram** — narrative locks "SBOM inside SBoD" composition; current SVG shows side-by-side. Recommendation: draw in PowerPoint as nested rounded rectangles. Alternative: redraw the SVG, keep file-based.
- **Slide 5 Pack/Sign/Transport/Deploy** — current SVG is wide/short and renders small. Recommendation: rebuild as 5 PowerPoint cards (4 steps + sovereign cloud target) using the tile pattern from Layout 5.
- **Slide 7 ODG icon / illustration** — narrative is text-heavy; consider whether a single illustrative element (Compliance Dashboard mockup, or a simple "data flow" graphic) would land. Currently no asset exists for this slide; bullets-only is also a valid choice.
- **Slide 10 contact line** — "community channels on the website" is the placeholder. If you have a specific channel (Slack, GitHub Discussions URL), substitute it.
- **Hero gradient anchor** — currently applied to "Sovereign Clouds." Confirmed in the Marp design reference; confirm it still feels right in PowerPoint master.
- **Slide order** — current 10-slide order is the master narrative. If your team gives feedback that suggests reordering (e.g., move the diagram-heavy slides together), the master accommodates it without rebuild.

---

## 7. Once the master is built

- Save as `OCM-Sovereign-Delivery-Exec-Master.pptx` in `docs/community/marketing/decks/exec-phase1/`. Or wherever you'd like.
- Commit the .pptx to the repo (DCO sign-off, push to fork).
- The `.pptx` becomes the source of truth from this point forward. NARRATIVE.md remains the canonical content spec; if you change copy in PowerPoint, mirror the change back into NARRATIVE.md so the at-a-glance summary stays in sync.
- The Marp source (`slides.md`, `theme/`, `build.sh`) becomes reference material; no further development.

---

**Spec version:** v0.1 — initial transfer from Marp design reference.
