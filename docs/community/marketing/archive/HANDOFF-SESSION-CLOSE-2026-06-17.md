# Handover — Phase 1 Closing Notes

**Repo root:** `/Users/D032990/.cline/worktrees/marketing-recovery/open-component-model`
**Working dir:** `docs/community/marketing/`
**Branch:** `marketing/spike-deck`
**Closing:** 2026-06-17, late-night
**Status:** Two rendered decks ready for stakeholder review. 11 modified files awaiting commit.

This is a session-close handoff, not a Phase-2 plan. The Phase-2 plan is unchanged from `archive/HANDOFF-PHASE2.md`. This document captures what was done in the last working session and what someone picking up the branch needs to know to continue.

---

## What state the deck is in right now

Two brand-correct PPTX files are rendered and ready:

- **`decks/exec-phase1/OCM-Sovereign-Delivery-Exec.pptx`** — external (cold-room canonical), 13 physical slides
- **`decks/exec-phase1/OCM-Sovereign-Delivery-Internal-Sponsor.pptx`** — internal-sponsor variant, 14 physical slides

Both use the same `OCM-Master.potx` template (also in this folder), 20"×11.25" slide size, brand-correct (white-on-blue hero, Aptos Display, three-column rules, soft tile backgrounds, etc.).

**11 modified files are uncommitted** at the time this doc is written. They are listed at the bottom under "Open commit." Run a `git status` to see the current set; everything in scope is documented below.

---

## What changed in this last session (post-recovery commit `8d9cf6b66`)

The recovery commit landed all the major edits from earlier in the day. After that, the user reviewed both decks in PowerPoint and a series of targeted fixes were applied:

### External hero
- Title `"Your supply chain has blind spots."` + gradient on `"blind spots."`
- Subtitle: `"Three minutes from now, you'll know what they are."`
- Two-line layout, 115pt, `Hero` (the `Hero / 3-Line` layout was abandoned earlier and is removed from `LAYOUTS` — the layout function remains as commented documentation in `build_potx.py`).
- **Convention written into `build_potx.py` doc-comment, into `NARRATIVE.md`, and into `README.md`:** hero titles are at most TWO lines, never three.

### Internal hero
- Title `"Every LoB rebuilds the same delivery stack."` (gradient on `"the same delivery stack."`)
- Subtitle: `"OCM is the shared standard. Each LoB still ships — but on the same model."`
- Org-line: `"Open Component Model — open source, NeoNephos Foundation. Stewarded by SAP."`
- Hero is observation-led, not loss-led. The user clarified: each LoB still builds and ships its own artifacts; what changes with OCM is the shared *concept / vocabulary / mechanics*, not a shared build. Subtitle is worded accordingly — *"Each LoB still ships — but on the same model."*

### Slide 2 (Why now)
- **External:** unchanged (sovereignty pressure / regulation tightening / supply-chain attacks). Regulation column says *"EU DORA · NIS2 · CRA"* (GDPR was dropped earlier as off-thesis).
- **Internal:** col 1 *"Ecosystem velocity is real"* (OCM-shaped abstractions in adjacent OSS projects), col 2 *"THE WINDOW IS CLOSING"* (NeoNephos governance, CRA enforcement, sovereign-cloud market formation — *"the rails are being laid now"*), col 3 *"Disinvestment has a cost"* (each LoB rebuilding pays the cost OCM was supposed to amortize).

### Slide 5 (How OCM composes — comparator slide)
Reframed in this session from a signing-only comparator to a **three-axis comparator**: signing / transport / compliance. Each column says *what existing tools do* and *what OCM adds*. Title: *"OCM doesn't replace your tools. It gives them an envelope to compose around."*

### Slide 7b (SOVEREIGN-READY — AIR-GAP) diagram
Substantial redesign in this session:
- **Source-component box widened** (240→290px) so `github.com/acme/webshop` no longer overflows.
- **Mid-flight component glyph removed.** Replaced with an *identical copy of the source component* inside the air-gapped zone, so the visual reads "same artifact, different location."
- **Curved Bezier arrow** ties the two component boxes directly (source-right-edge → landing-left-edge), explicitly crossing the trust boundary.
- Arrow is rendered as the **last layer** of the SVG so it draws on top of the air-gapped container's dashed border (otherwise the dashed border would z-overlap and visually break the connection).
- **Trust-boundary line centred** between the two side panels (x=650 instead of 780; midpoint between source-box-right and air-gap-box-left). Extended to the full bottom of the air-gap container (y=720).
- **`"Identity stays / signature stays"` caption** moved from the arrow midpoint to *next to* the landing component, inside the air-gapped zone. Two lines (no `·` separator needed since it's stacked).
- **`"SAME SIGNATURE · ANY LOCATION"` background rect widened** (240→320px, x=140) so the letter-spaced caption has visible padding on both sides.
- ViewBox bumped from 700 to 760 to fit the new air-gap container height (380→480px).
- Diagram repositioned in both build scripts: 40.22 × 17.6 cm at x=3.72cm, y=10.25cm (pixel: 1519×665 at x=141, y=387).

### Slide 4b (SBoD diagram-only)
Diagram repositioned per user spec: 39.09 × 17.59 cm at x=5.15cm, y=10.99cm (pixel: 1478×665 at x=195, y=415).

### Slide 3 (Meet OCM hub-and-spoke)
Diagram repositioned per user spec: 50.02 × 15.93 cm at x=-2.4cm (slight bleed left), y=11.65cm (pixel: 1890×602 at x=-91, y=440). SVG `viewBox` previously bumped 540→560 for footer-line clearance.

### Slide 6 (Pack/Sign/Transport/Deploy diagram)
SVG card font enlarged: body 18pt → 26pt, label 30pt → 34pt. Lines rewrapped to fit 290px text-region (32px symmetric margins inside 360px-wide cards). All four step-cards (PACK, SIGN, TRANSPORT, DEPLOY) plus the SOVEREIGN CLOUD target re-formatted accordingly. Drop-shadow filter on cards remains.

### PowerPoint auto-underline cleanup
PowerPoint's grammar checker auto-underlines possessive apostrophes on technical acronyms (renders as a faint double-underline on `OCM's`, `SAP's`). The persistence is *interactive*, not in the saved XML — but visually it's a problem in the rendered file every time someone opens it. Workaround: rephrase to drop the apostrophe.

Two hits found and fixed:
- *"OCM's compliance automation engine"* → *"the OCM compliance automation engine"* (slide 8 in both decks, plus `NARRATIVE.md` and `README.md` glossary)
- *"SAP's"* in two places in the internal deck (slide 2 col 3 ending, slide 10a Kyma description) → reformulated to drop the apostrophe.

This is a recurring failure mode. **For Phase 2: avoid possessive apostrophes on `OCM`, `SAP`, `BwI`, etc. anywhere on slides.** They will render with the double-underline artifact.

### Layout-level changes in `build_potx.py`
- `Hero` layout title-box geometry tightened (y=180/370 with h=160) to give descenders (`y`, `p`, `q`) room — earlier h=140 caused descender bleed into Title Line 2.
- `Hero / 3-Line` layout was kept removed from `LAYOUTS`. The function remains as commented documentation explaining why it exists and why it was abandoned.
- 3-Column `Col Body` y-offset stayed at `+84` (compact) per the *"column headers stay 1-line"* convention. This convention is what unblocked Slide 5 from being inconsistent with Slide 2.

### Narrative + at-a-glance + handoff sync
Every text change above propagated to:
- `narratives/NARRATIVE.md` (external locked master narrative)
- `narratives/NARRATIVE-INTERNAL-SPONSOR.md` (internal-sponsor sibling)
- `narratives/NARRATIVE-AT-A-GLANCE.md` (one-page external summary)
- `narratives/NARRATIVE-INTERNAL-SPONSOR-AT-A-GLANCE.md` (one-page internal summary)
- `README.md` (folder navigator)

The `archive/HANDOFF-PHASE2.md` was *not* re-touched in this last session — it still describes the Phase-2 plan correctly (build remaining external variants: cold-room is the existing `build_pptx.py`, plus regulator-led FSI-EU and peer-led conference). The hero-copy line in HANDOFF-PHASE2 was already updated in the recovery commit.

---

## How to rebuild

From `decks/exec-phase1/build-pptx/`:

```bash
python3 build_potx.py                    # regenerates OCM-Master.potx
python3 build_pptx.py                    # regenerates external deck
python3 build_pptx_internal_sponsor.py   # regenerates internal deck
```

All three exit clean. Outputs land in `decks/exec-phase1/`. Slide size is 18288000×10287000 EMU (= 50.8 × 28.575 cm = 20" × 11.25") and matches the `.potx` exactly.

Dependencies: `python-pptx`, `Pillow`, `lxml` (all pip-installable; `requirements.txt` lists the first two — `lxml` was added later but isn't pinned).

External system dependency: `rsvg-convert` (used to rasterize SVG diagrams to PNG before embedding). Available via Homebrew (`brew install librsvg`).

---

## How a colleague should review the deck

For a meeting / discussion (15-min prep), open in this order:

1. `narratives/NARRATIVE-AT-A-GLANCE.md` (~5 min) — external one-pager.
2. `narratives/NARRATIVE-INTERNAL-SPONSOR-AT-A-GLANCE.md` (~5 min) — internal one-pager.
3. The two rendered PPTX files in `decks/exec-phase1/`.

For deeper context:
- `narratives/NARRATIVE.md` — locked external master narrative
- `narratives/NARRATIVE-INTERNAL-SPONSOR.md` — internal sibling narrative
- `archive/MARKETING-PEER-REVIEW.md` — second-chief peer review (process artifact)
- `archive/HANDOFF-PHASE2.md` — Phase-2 plan (variant authoring path)

---

## Open commit

11 files modified, awaiting commit at session close:

- `README.md` (hero copy + ODG glossary line)
- `narratives/NARRATIVE.md` (external hero copy + ODG bullet)
- `narratives/NARRATIVE-INTERNAL-SPONSOR.md` (internal hero, slide 2 col 2/3, slide 8, slide 10a Kyma)
- `narratives/NARRATIVE-INTERNAL-SPONSOR-AT-A-GLANCE.md` (matching internal at-a-glance)
- `narratives/NARRATIVE-AT-A-GLANCE.md` (matching external at-a-glance)
- `decks/exec-phase1/build-pptx/build_potx.py` (Hero geometry, 3-Line layout removed)
- `decks/exec-phase1/build-pptx/build_pptx.py` (external hero, slide 3/4b/7b positions, slide 5 three-axis, slide 8 OCM apostrophe fix)
- `decks/exec-phase1/build-pptx/build_pptx_internal_sponsor.py` (internal hero, slide 2 col 2/3, slide 5 three-axis, slide 7b position, slide 8 apostrophe fix, slide 10a Kyma)
- `decks/exec-phase1/diagrams/06-sovereign-airgap.svg` (full redesign)
- `decks/exec-phase1/OCM-Master.potx`, `OCM-Sovereign-Delivery-Exec.pptx`, `OCM-Sovereign-Delivery-Internal-Sponsor.pptx` (rebuilt artifacts)

Suggested commit message:

```
chore(marketing): post-review polish — hero copy, three-axis comparator, slide 7b redesign

- External hero locked: "Your supply chain has blind spots." + subtitle
  "Three minutes from now, you'll know what they are."
- Internal hero locked: "Every LoB rebuilds the same delivery stack." + subtitle
  "OCM is the shared standard. Each LoB still ships — but on the same model."
- Slide 5 (How OCM composes) reframed to three-axis comparator:
  signing / transport / compliance.
- Slide 7b (Air-Gap) SVG redesigned: identical component glyphs both sides,
  curved arrow connects them directly, trust boundary centred and
  extended to full air-gap height. SAME SIGNATURE accent rect widened.
- Slide 3 / 4b / 7b diagram positions per user spec (cm-precise).
- Slide 6 cards: 26pt body / 34pt label, lines rewrapped.
- Hero / 3-Line layout dropped — convention: max 2 hero lines, never 3.
- 3-Column body offset back to +84 (compact); convention: column
  headers stay 1-line.
- Apostrophe sweep: OCM's / SAP's reformulated to avoid PowerPoint
  auto-grammar-underline rendering artifact.
- Narratives, at-a-glance, README synced.
```

The user has been doing the actual `git push` themselves throughout this session.

---

## What's still open for Phase 2

Unchanged from `archive/HANDOFF-PHASE2.md` §"What's still open." Briefly:

1. External concession line wording — pick one of three candidates in `archive/MARKETING-PEER-REVIEW.md` §4.2.
2. External CTA wording — current "Try it / Build with us / Talk to us" vs. first chief's escalation-tier proposal.
3. Build the three remaining external Phase-2 variants when ready: regulator-led FSI-EU, peer-led conference. (Cold-room canonical *is* the current `build_pptx.py` already.)

ROI-led variant remains permanently deferred (no real numbers).

---

*Generated 2026-06-17, session close.*
