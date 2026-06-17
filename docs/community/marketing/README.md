# OCM Marketing — Phase 1 Working Folder

**Status:** Phase 1 complete (narrative + first deck variant). Phase 2 (additional variants) handed off to a fresh agent — see `archive/HANDOFF-PHASE2.md`.

This folder holds the work product of designing OCM exec deck content for both **external** and **internal-sponsor** audiences. It is a **discussion folder**, not a build pipeline. The build pipeline lives in `decks/exec-phase1/`.

---

## For a meeting / discussion (15-minute prep)

Read in this order:

1. **`narratives/NARRATIVE-AT-A-GLANCE.md`** (~5 min) — one-page summary of the deck. Beat-by-beat punchlines.
2. **`narratives/NARRATIVE.md`** (~10 min) — the locked external master narrative. The thesis, the audience model, the 11-beat skeleton with body and proof points per beat.
3. **`narratives/NARRATIVE-INTERNAL-SPONSOR.md`** (~10 min) — sibling for the internal-sponsor audience (SAP LoB heads + chief architects). Lead axis is loss-frame; CTA is sponsor / scale / standardize. Twelve-slide skeleton including a comparator slide.

Then, optionally, open the actual deck variant rendered as a brand-correct PPTX in `decks/exec-phase1/dist/` (PowerPoint-editable; uses the `OCM-Master.potx` layouts directly).

---

## Folder structure

```
marketing/
├── README.md                          ← this file
├── narratives/                        ← discussion canon (read these for the meeting)
│   ├── NARRATIVE.md                       external locked
│   ├── NARRATIVE-INTERNAL-SPONSOR.md      internal-sponsor sibling
│   └── NARRATIVE-AT-A-GLANCE.md           one-page summary
├── decks/
│   └── exec-phase1/                   ← build pipeline + outputs (python-pptx + .potx)
│       ├── build-pptx/                    one Python script per variant; .potx-based, brand-correct
│       ├── diagrams/                      SVG diagrams + primitives library
│       ├── theme/                         brand assets (banner, master fonts)
│       ├── dist/                          rendered .pptx outputs (PowerPoint-editable)
│       ├── OCM-Master.potx                brand template (9 layouts)
│       ├── OCM-Sovereign-Delivery-Exec.pptx   current build (NOTE: structurally outdated; see Phase-2 handoff)
│       ├── POWERPOINT-FINISHING-CHECKLIST.md  manual touch-ups python-pptx can't do
│       └── TEMPLATE-USAGE.md
├── assets/                            ← shared logo and brand assets
├── archive/                           ← process artifacts; not meeting-relevant
│   ├── MARKETING-CRITIQUE-EXEC.md         first chief's deck critique
│   ├── MARKETING-PEER-REVIEW.md           second-chief peer review (substance + open items)
│   ├── EXEC-DECK-REWORK-OPTIONS.md        first chief's options menu (mostly resolved into NARRATIVE)
│   ├── CONTENT-OPTIONS.md                 wording-level options (older)
│   ├── DIAGRAM-OPTIONS.md                 diagram catalog
│   ├── HANDOFF-CONTENT-VARIANTS.md        original Phase-1 handoff
│   ├── HANDOFF-PHASE2.md                  handoff to fresh agent for Phase 2
│   └── marp-iteration-attempt/            abandoned Marp playground (kept as reference; not active)
└── phase-2-technical/                 ← future scope: technical-cut deck (architects, security)
    ├── TECHNICAL-DECK-CONTENT.md
    └── TECHNICAL-DECK-OUTLINE.md
```

---

## What's locked vs still open

**Locked (decisions reached during Phase 1 grilling, applied to the narratives):**

- Lead-axis: external = compliance + sovereignty pressure; internal-sponsor = strategic-fit + ecosystem leverage (loss-frame).
- Hero: *"Your supply chain has blind spots."* + subtitle *"Three minutes from now, you'll know what they are."* (Earlier draft used the longer 11-word *"Three minutes from now…"* as the entire title — abandoned because three lines at 115pt reads as overwhelming. **Convention: hero titles are at most 2 lines, never 3.**)
- Slide 3 reframed: *"Meet OCM. One identity, every boundary."* (Hub-and-spoke diagram landed.)
- Slide 5 added: comparator slide *"How OCM composes — OCM doesn't replace your tools."*
- Regulatory regimes: DORA, NIS2, CRA (Cyber Resilience Act). GDPR dropped. Footer names FedRAMP/FISMA, BSI C5, SecNumCloud.
- Internal-sponsor slide 9 outcomes: four adoption examples — Hyperspace, Gardener, CSI, Konfidence.
- Internal-sponsor slide 10 ecosystem: split into open peers (CSI, Gardener, Kyma, Konfidence, OCP) + internal SAP (Hyperspace, RBSC) + upstream contributions (kro, ESO).
- Internal-sponsor slide 11 CTA: SAP Slack `#sap-tech-ocm` only. No Zulip on the internal deck.
- ROI-led variant deferred (no real numbers available).

**Still open** (carried into Phase 2 — see `archive/HANDOFF-PHASE2.md`):

- External concession line wording (3 candidates in `archive/MARKETING-PEER-REVIEW.md` §4.2).
- External CTA wording (first chief's Option A vs the current).
- Specific SAP LoB names beyond the four already chosen (e.g., for slide 9 dotted-line examples).
- Wiring the new `03-meet-ocm-hub-and-spoke.svg` into `build_pptx.py`.

---

## Where the slide deck artifacts live

- **Source-of-truth narratives:** `narratives/`.
- **Build path:** **python-pptx** scripts in `decks/exec-phase1/build-pptx/`. Each variant deck has its own script (`build_pptx.py` for the external base, `build_pptx_internal_sponsor.py` for the internal cut, etc.) that constructs slides against the `OCM-Master.potx` layouts directly. Output is a brand-correct, PowerPoint-editable `.pptx` in `decks/exec-phase1/dist/`.
- **No Marp.** An earlier iteration tried Marp for content authoring; it was archived (`archive/marp-iteration-attempt/`) because Marp's pptx output flattens layouts and drifts from the `.potx` brand template. python-pptx is the single build path.
- **Current PPTX in `decks/exec-phase1/OCM-Sovereign-Delivery-Exec.pptx` is structurally outdated** — predates the Phase-1 narrative changes. Regenerate via `build_pptx.py` to pick up the new structure.

---

## Glossary

- **SBoD** = Software Bill of Delivery. The category claim OCM owns. Contains the SBOM as one payload item.
- **OCM Coordinates** = globally unique, location-agnostic component identity.
- **ODG** = Open Delivery Gear. OCM's compliance-automation engine; reads SBoD metadata directly.
- **NeoNephos** = Linux Foundation Europe foundation under which OCM is governed.
- **CRA** = Cyber Resilience Act (EU). Mandates SBOMs, vulnerability management, supply-chain accountability. Sept 2026 enforcement begins.

---

*Last updated: 2026-06-17. Phase 1 closed; Phase 2 handover written.*
