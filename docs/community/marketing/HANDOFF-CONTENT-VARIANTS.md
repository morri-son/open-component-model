# Handoff — peer review of OCM exec-deck content options

**Repo root:** `/Users/D032990/.cline/worktrees/marketing-recovery/open-component-model`
**Working dir:** `docs/community/marketing/`
**Branch:** `marketing/spike-deck`
**Picks up from:** 2026-06-17, late morning

## What this session is about

You are stepping in as a **second marketing chief reviewing what the first one produced.** The first round generated narrative + critique + content/diagram option menus. The user wants a fresh, independent set of eyes on that material *before* any new deck variants get built.

**Phase 1 — peer review (do this first).** Read the existing artifacts, push back, surface gaps, sharpen weak framings. Output is feedback, not a rewrite.

**Phase 2 — variants (only after the user agrees Phase 1 has converged).** Build multiple deck variants in Marp, one `.md` per audience/framing, so they can be compared side by side. **Including a new variant the first chief did not consider:** internal-sponsor exec (see below).

The user is the project owner. They want sharp critique, not validation theatre.

## Phase 1: artifacts to review (read these in order)

All in `docs/community/marketing/`:

1. **`NARRATIVE.md`** (201 lines) — locked narrative. The thesis the deck must serve. Treat as ground truth unless review surfaces a tension.
2. **`NARRATIVE-AT-A-GLANCE.md`** (47 lines) — one-page version. Sanity-check the long form against this.
3. **`MARKETING-CRITIQUE-EXEC.md`** (240 lines) — first chief's critique of the v1 deck: 15-issue list, scorecard, top-5 fixes. Is the critique itself sharp, or is it polite?
4. **`EXEC-DECK-REWORK-OPTIONS.md`** (478 lines) — alt framings per slide: risk-led / ROI-led / peer-led / regulator-led. The menu the variants will be picked from. **Highest-leverage doc to review.** Are these four the right axes? Are any framings weak? What's missing?
5. **`CONTENT-OPTIONS.md`** (371 lines) — older, more granular wording options. Still useful?
6. **`DIAGRAM-OPTIONS.md`** (121 lines) — catalog of 7 diagram variants. Per the user, design is frozen for this round, but if a diagram is named in critique it matters.

Read everything once before commenting. Do not edit any of them in Phase 1 — produce a review document.

## What "peer review" means concretely

You are not a yes-person. Push hard on:

- **Audience clarity.** Who is each framing actually for? "Exec" is too coarse. CTO ≠ CISO ≠ Head of Platform ≠ Procurement.
- **Proof asymmetry.** Where do claims outrun evidence? Where is evidence buried?
- **The "so what" gap.** When a slide tells the audience something true, does it tell them what to *do* with it?
- **Competitive framing.** Where does the deck assume the audience already wants OCM vs. selling against status quo?
- **Honest weaknesses.** Where would a hostile reviewer (a competitor, a skeptical CIO, an open-source skeptic) attack? Are those addressed or dodged?
- **Cross-doc coherence.** Does `EXEC-DECK-REWORK-OPTIONS.md`'s framing actually serve `NARRATIVE.md`'s thesis, or do they pull in different directions?
- **Missing axes.** The four axes in REWORK-OPTIONS (risk / ROI / peer / regulator) are framings the *first chief saw*. What did they miss?

The first chief's critique is in `MARKETING-CRITIQUE-EXEC.md` — read it, then ask: what did they *not* say?

## The new variant the first chief did not consider

The first chief's `EXEC-DECK-REWORK-OPTIONS.md` implicitly assumes **external audience** — execs at companies considering adoption.

The user is a senior engineer at OCM's **main corporate sponsor** (SAP). They need a deck for **internal-sponsor execs** — the people inside the sponsoring company who decide whether to keep funding, expand, or scale OCM investment.

Different audience, even if both are "execs":

| | External exec | Internal-sponsor exec |
|---|---|---|
| Decision | adopt / evaluate / sponsor | keep funding / expand / scale |
| Wants to hear | "this is safe to bet on" | "this is paying off / this is strategic" |
| Proof points | peer logos, regulator pressure, ROI | internal traction, ecosystem leverage, strategic fit (sovereignty agenda, NeoNephos), customer wins enabled by OCM |
| Competitive framing | OCM vs. status quo / vs. proprietary | what we lose if we walk away, what competitors gain |
| Risk language | "risk of inaction" | "risk of disinvestment / loss of position" |

Treat **internal-sponsor exec** as a fifth framing axis to compare against the first chief's four. The peer review should land an opinion: is this axis distinct enough to deserve its own variant deck, or is it close enough to one of the existing four that a small overlay suffices?

## Phase 1 deliverable

Write `MARKETING-PEER-REVIEW.md` in `docs/community/marketing/` containing:

1. **Cross-doc coherence read** — do narrative / critique / options pull together or apart?
2. **Per-framing critique** of REWORK-OPTIONS (risk / ROI / peer / regulator) — strengths, weaknesses, audience fit.
3. **Internal-sponsor framing** — proposed scope, key proof points, what's distinct from the four existing.
4. **Gaps the first chief missed** — framings, proof points, audiences, objections.
5. **Top-5 sharpening recommendations** — concrete edits to REWORK-OPTIONS or NARRATIVE before variants are built.

Then **stop and discuss with the user.** Do not start Phase 2 until they agree Phase 1 has landed.

## Phase 2 (only after Phase 1 converges): build variants in Marp

The Marp content playground is fully wired up:

```
docs/community/marketing/decks/exec-phase1/marp/
├── .marprc.yml
├── build.sh             ./build.sh [slides.md] [norender|noserve]
├── theme/ocm-master.css 1920×1080, tokens aligned with OCM-Master.potx
├── slides.md            baseline 10-slide deck (mirrors current build_pptx.py)
└── README.md
```

Build cycle:

```bash
cd docs/community/marketing/decks/exec-phase1/marp
./build.sh                       # renders slides.md, serves on :8080, opens browser
./build.sh slides-roi.md         # renders a variant
./build.sh slides.md noserve     # render only
```

Render output is `marp/slides.html` (next to `slides.md`, not in `dist/` — paths break otherwise). Server is at repo root so `../../../assets/...` resolves.

**Per-variant pattern:** `slides-risk.md`, `slides-roi.md`, `slides-peer.md`, `slides-regulator.md`, `slides-internal-sponsor.md`. Same theme, same canvas, same layouts; only copy + slide order change.

**Don't write all variants up-front.** Pick the highest-leverage 1–2 from Phase 1's recommendations, generate, get user feedback, then expand.

**Marp is iteration only.** The brand-correct PPTX is built by `decks/exec-phase1/build-pptx/build_pptx.py` against `OCM-Master.potx` — not by Marp's pptx export. When copy is locked, port to python-pptx.

## Constraints (do not violate)

- **Slides are EITHER text OR diagram, never both.** That's why slide 4/6 split into 4a+4b and 6a+6b. Mixing forces a split.
- **Eyebrow never wraps to 2 lines.** Keep eyebrow text terse.
- **1-line vs 2-line title use different layouts** (Plain / Compact at body y=520 vs Plain at y=580). The Marp theme handles this via `_class:` directives.
- **Design is frozen.** No layout, color, font, or coordinate changes. If a variant truly needs a new layout, ask the user first.

## Build state

| File | Purpose |
|---|---|
| `decks/exec-phase1/build-pptx/build_potx.py` | emits `OCM-Master.potx` (9 layouts, brand theme) |
| `decks/exec-phase1/build-pptx/build_pptx.py` | emits the brand-correct `OCM-Sovereign-Delivery-Exec.pptx` from the .potx |
| `decks/exec-phase1/marp/` | Marp content playground (this session works here in Phase 2) |
| `decks/exec-phase1/POWERPOINT-FINISHING-CHECKLIST.md` | manual touch-ups python-pptx can't do |

**Do not modify** `build_potx.py` or `build_pptx.py` in this session — they are downstream.

## What was settled in the previous session

- Marp setup retargeted to 1920×1080, tokens aligned with `build_potx.py`.
- `slides.md` mirrors the 10-slide baseline as authored by `build_pptx.py`.
- HTML render works, server resolves images correctly.
- Marp's pptx export is **not** used. Final pptx always comes from python-pptx + .potx.

Don't redo any of this. Don't second-guess the Marp setup; if a variant breaks, the fix is content, not pipeline.

## Suggested skills for the new session

- **`grill-with-docs`** — stress-test the existing options against `NARRATIVE.md` and the docs the first chief produced. Best fit for Phase 1.
- **`grill-me`** — if the user wants to be interviewed about audience/positioning before you review, run this first to extract their priors.
- **`double-check`** — after writing `MARKETING-PEER-REVIEW.md`, run this against it to catch hand-waving and unjustified assertions.

## Open questions to confirm with the user before Phase 2

1. Audience for the **internal-sponsor** variant — SAP exec board, line-of-business heads, OCC steering, all of the above?
2. Naming convention for variant `.pptx` files when Phase 2 produces them.
3. Hero subtitle, org-line copy, and CTA copy — assume constant across variants unless user says otherwise.
4. Is the locked `NARRATIVE.md` actually locked, or open to revision if peer review surfaces a problem?
