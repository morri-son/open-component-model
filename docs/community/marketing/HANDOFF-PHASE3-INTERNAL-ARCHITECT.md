# Handoff — Phase 3: Internal-Architect Deck Variant

## What this next session is for

**Subject.** Fork the external architect deck into an internal-architect variant for SAP-internal audiences.

The external architect deck (`docs/community/marketing/decks/architect-phase2a/`) was built for architects encountering OCM cold — from CNCF events, customer architectural reviews, public talks. The persona-pass + Phase 2B cleanup finished it. **It is the canonical source of truth for the technical spine.** Don't refactor it; fork it.

The internal-architect variant is for SAP architects who:
- have already heard the OCM name (through Hyperspace mandates, SLC-29 framing, the exec-internal sponsor deck, OpenControlPlane discussions),
- are evaluating OCM against SAP-internal tooling, not against cosign/SLSA/in-toto,
- want SAP-specific adoption shapes (Hyperspace integration / RBSC ingest / openMCP delivery), not "30-min laptop demo,"
- want adopter proof — the SAP teams already running OCM, not OSS-foundation positioning.

The mechanic, descriptor, signing, transport, composition, day-2 — unchanged. The audience-shaped framing slides — reworked.

## Why this is a fork, not an edit

The exec deck pair (`exec-phase1/`) ships two PPTX files from one build directory:
- `OCM-Sovereign-Delivery-Exec.pptx` — external
- `OCM-Sovereign-Delivery-Internal-Sponsor.pptx` — internal

Same template, same build scripts, ~50% shared middle. The architect deck should follow the same pattern: one folder, two outputs.

Don't create a separate `architect-phase3-internal/` folder. The internal-architect variant lives **inside `architect-phase2a/`** as a second build target with a second output file. Folder name keeps the `phase2a` tag for filesystem stability; the variant is a build artifact, not a separate project.

## Scope: what changes vs the external deck

Of 16 main-arc slides + 2 appendices, **5–6 slides need audience-shaped rework**. The rest are byte-identical or near-identical.

| Slide | Status | What changes |
|---|---|---|
| 1 PAIN | **Rework** | Cold open assumes the audience hasn't heard the name. Internal audience has. Reframe opener — acknowledge the inbound context, position THIS talk as "the architecture-track depth behind the conversation you've been having." Pain remains universal; the framing shifts. |
| 2 DIAGNOSIS | Keep | The technical diagnosis ("digest pins the bytes, nothing pins the release") works for both audiences. |
| 3 HINGE | Keep | Conceptual fulcrum. Same regardless of audience. |
| 4 POSITIONING | **Minor retune** | "Wraps every artifact" works as-is. Speaker notes should drop the OCI/Helm/cosign Q&A backup (internal architects ask different "what does this replace?" questions — SAP-internal tooling, not CNCF) and add SAP-stack equivalents. SBOD vocabulary footnote stays. |
| 5 CONSTRUCTOR | Keep | YAML is YAML. |
| 6 DESCRIPTOR | Keep | YAML is YAML. |
| 7 FOUR MOVES | Keep | Pack·Sign·Transport·Deploy is universal. Slide 7 is byte-identical across all three existing decks for this reason. |
| 8 COMPOSE | Keep | Composition mechanic is universal. |
| 9 TRANSPORT | Keep | Three patterns, one command — universal. |
| 10 SIGN | Keep | Three signing options — universal. |
| 11 DEPLOY | Keep | Four-CR chain — universal. |
| 12 DAY 2 | Keep | Bump-version mechanic — universal. |
| 13 ADOPTION | **REWORK — biggest change** | External deck: "Two paths in 30 minutes — CLI laptop / Helm controllers." Internal deck: SAP-specific adoption shapes — likely Hyperspace integration, RBSC ingest, openMCP delivery. Match the project's actual Adoption Plan (`~/dies-und-das/OCM/OCM-Adoption Plan.pdf`). The 30-min CLI path can stay as a "first hands-on" subset of one card; the cluster path is replaced by SAP-platform-shaped paths. |
| 14 WHAT'S SHARP | Keep | Three honest edges. Universal honesty. |
| 15 CTA | **REWORK** | External: Evaluate · Pilot · Engage. Internal needs different verbs — internal architects don't *evaluate OCM as a standard*, they *pilot it within an SAP product context*. Candidates: **Pilot · Standardize · Steward** (pilot one product, standardize via SLC-29, steward the SAP-side roadmap). Or mirror the exec-internal deck's Sponsor·Scale·Standardize verbs at architect level. Decision needed in session. |
| **NEW slide (optional)** | **Add?** | Adopter proof — five SAP teams (Hyperspace, RBSC, CSI, Steampunk, Greenhouse) as a card-family or logo lockup. Mirrors what the exec-internal deck does on slide 13. Decision needed: does the architect-track audience need this, or is it implicit from the rest of the framing? My read: yes, add it — internal architects' "is this real?" test is adopter proof, not OSS-foundation positioning. |
| 16 APPENDIX REPLICATION | Keep | Universal. |
| 18 APPENDIX COMPARE | **Replace or drop** | External: cosign / SLSA / SBOM / OCM matrix. Internal architects asking "what does this replace?" mean SAP-internal tooling — Hyperspace's existing signing, RBSC's existing transport, etc. The CNCF comparison doesn't land. Either: (a) drop this appendix from the internal variant entirely, or (b) replace with an SAP-internal-tooling comparison. Option (b) is riskier — depends on what's still in play internally and may be politically sensitive. My recommendation: drop it from the internal variant. The hostile internal architect's "why not just use our existing X?" is answered better in speaker-notes Q&A backups than on a slide. |

**Net:** ~3 reworked slides + 1 new + 1 dropped. ~75% of the deck is byte-identical to the external; ~25% is audience-shaped.

## What was already decided in Phase 2B — out of scope to re-litigate

These are settled. Apply them to both variants identically; don't reopen:

- Slide 2 bullets use the Option B wording (digest concedes, release gap names).
- Slide 4 keeps "SBOMs, npm, maven" in the noun list; speaker notes carry the npm/maven access-binding nuance.
- Slide 7 stays between 5/6 and 8–11. "THE FOUR MOVES" eyebrow.
- Slide 9 = Transport, slide 10 = Sign in the rendered PDF order (PowerPoint reorder vs build-script numbering — see below).
- Slide 10 column header is "OpenPGP" (not "GPG"). Body says GPG-as-implementation in speaker notes.
- Slide 11 deploy chain stays four cards; verification-opt-in disclosure lives in speaker notes.
- Slide 12 day-2 highlights are brand-blue (changed values).
- Slide 13 dropped the "Thirty minutes" closing lines from both cards on the external deck. **Internal deck doesn't need to copy this** — slide 13 is being reworked anyway.
- Slide 14 third bullet: "Helm-deploy adds kro + Flux or Argo CD — the OCM controllers don't ship them. Bring your existing GitOps engine."
- "Component identity" is the agreed term (not "Coordinates").
- The comparison appendix slide ("How OCM compares") is slide 18 in the external deck, NOT in the main arc. Slide-18 stays in the external deck; for the internal deck it's dropped (see above).
- Replication is appendix slide 16. Universal.

## Where the truth references live

### Templates and existing decks

- **External architect deck (canonical source):** `docs/community/marketing/decks/architect-phase2a/`
  - `OCM-Story-Architect-External.pptx` — main deck
  - `OCM-Story-Architect-External-Slide-4b.pptx` — slide-18 appendix (post-CTA Q&A backup)
  - `build-pptx/build_pptx_architect_external.py` — main build script
  - `build-pptx/build_slide_4b_compare.py` — slide-18 generator
  - `build-pptx/speaker_notes.py` — condensed notes (the dict embedded in the .pptx)
  - `notes/SPEAKER-NOTES-ARCHITECT-EXTERNAL.md` — long-form speaker notes
  - `notes/PHASE2B-CHANGE-SUMMARY.md` — what changed in Phase 2B and why
  - `notes/PHASE2B-SPEAKER-NOTES-COPY-PASTE.md` — paste-ready notes by slide

- **Exec deck pair (fork pattern to mirror):** `docs/community/marketing/decks/exec-phase1/`
  - `OCM-Sovereign-Delivery-Exec.pptx` — external
  - `OCM-Sovereign-Delivery-Internal-Sponsor.pptx` — internal — **read this carefully**, it's the closest existing analog for internal-tone framing
  - `build-pptx/` — same build directory ships both PPTX files

- **PDF copies of all three current decks (read these first):** `~/Downloads/OCM/`
  - `OCM-Story-Architect-External.pdf` — what you're forking
  - `OCM-Story-Exec-External.pdf` — exec external (for cross-deck consistency)
  - `OCM-Story-Exec-Internal-Sponsor.pdf` — exec internal (for tone reference — same audience genus as the new deck, different role)

### Project context (the canonical adoption story)

- **`~/dies-und-das/OCM/OCM-Adoption Plan.pdf`** — **critical for the slide-13 rework.** The project's own adoption strategy. Names Hyperspace, RBSC, CSI, SLC-29. Slide 13 of the internal deck should be calibrated against this document.
- **`~/dies-und-das/OCM/whitepaper.pdf`** — canonical OCM whitepaper. Same alignment notes as Phase 2B.
- **`~/dies-und-das/OCM/20250327 IPCEI-CIS GA OCM-ODG – Kopie.pdf`** — NeoNephos / sovereign-cloud / IPCEI framing.
- **`~/dies-und-das/OCM/2024-05-28_OCM_Delivery_and_Compliance_Automation.pdf`** — older Delivery & Compliance Automation framing (May 2024). Useful for checking that internal-deck framing hasn't drifted from earlier internal positioning.

### Code / spec references (only needed for technical fact-checks)

- `bindings/go/...` — the v2 implementation
- `/Users/D032990/github/github.com/morri-son/ocm-spec/doc/` — the canonical spec
- `website/content/docs/` — the website docs

Don't re-verify Phase 2B technical claims (those were verified in the persona pass). Only verify *new* claims the internal deck introduces.

## Slide-numbering trap — read this before editing

**The external deck has a subtle slide-order swap that matters:**

- The Python build script (`build_pptx_architect_external.py`) builds slides in this order: 9=SIGN, 10=TRANSPORT.
- The rendered PDF has them swapped: slide 9=TRANSPORT, slide 10=SIGN.
- This is because the user manually reordered the slides in PowerPoint after the build script ran.
- The `speaker_notes.py` dict uses the **build-script numbering** (9=SIGN, 10=TRANSPORT).
- The Phase 2B hand-edit summaries use the **PDF numbering** (9=TRANSPORT, 10=SIGN).

When working on the internal deck:
- If you edit the build script, you're using build-script numbering.
- If you describe changes to the user for PowerPoint hand-editing, use PDF numbering.
- If you regenerate from scratch and don't reorder, the new internal deck will have 9=SIGN, 10=TRANSPORT — which may or may not match the external deck the audience has seen. Decide early which order the internal variant ships with.

## Suggested session sequence

1. **Read this handoff document end-to-end.** Confirm `~/Downloads/OCM/` and `~/dies-und-das/OCM/` still resolve (user-local paths).
2. **Read all four artifact PDFs** in `~/Downloads/OCM/` to refresh on what's settled. Pay special attention to the Internal-Sponsor exec deck — it's the closest tonal analog and shares some load-bearing slides (Pack·Sign·Transport·Deploy, sovereign-cloud framing).
3. **Read `OCM-Adoption Plan.pdf` carefully.** This is the canonical reference for slide 13's rework. If the deck's adoption framing doesn't match the project's actual adoption thinking, an internal architect will notice immediately.
4. **Decide the scope upfront with the user:**
   - Single new slide vs full fork-and-rebuild?
   - 5 reworked slides or 6 (does the adopter-proof slide get added)?
   - SAP-internal-tooling comparison or drop it?
   - CTA verbs: Evaluate·Pilot·Engage / Pilot·Standardize·Steward / something else?
5. **Spawn a persona pass if needed** — a single SAP-internal-architect persona is probably enough (not the full three-persona pass; the technical spine is already vetted). Use the same haiku-for-search / opus-for-thinking pattern. Look at the prompt for "Persona 3 — Hostile Senior Architect" in Phase 2B for the template, but reshape it for an internal-SAP audience who's been pre-briefed.
6. **Apply changes** in this order:
   - Speaker notes first (`.py` + `.md`) — lowest-risk, easy to iterate
   - Slide text changes — once the user signs off on wording
   - Any new slide(s) — last, after the rest is settled
7. **Produce a hand-edit guide** like `PHASE2B-CHANGE-SUMMARY.md` and `PHASE2B-SPEAKER-NOTES-COPY-PASTE.md` so the user can apply the changes against the SharePoint copy of the deck.

## What success looks like

A second PPTX in `architect-phase2a/` — call it `OCM-Story-Architect-Internal.pptx` — that:

- shares the technical spine with the external deck verbatim (slides 2–12, 14, 16),
- has audience-shaped slides 1, 4-notes, 13, 15, and possibly a new adopter-proof slide,
- drops the comparison appendix from the external deck (or replaces with an SAP-internal-tooling version, if user wants that),
- references the same OCM-Master template,
- has speaker notes calibrated for an internal audience (different Q&A, different cross-deck callouts, no "in earlier presentations" SBOD framing — assume they've seen it),
- ships through a parallel build script (or a `--variant=internal` flag on the existing one — pick the cleaner pattern after looking at how exec-phase1 does it).

## A note on workload

Phase 2B took ~3-4 hours of focused work plus three persona reports. The internal-architect variant is probably **2-3 hours** of focused work — less audit, more focused rework. The persona pass is optional (one fresh persona is enough; the technical claims are already vetted).

Don't manufacture findings. Don't redesign visuals. Don't re-litigate Phase 2B decisions. The deck's voice, typography, palette, card-design, and arc shape are all locked. The variant is about *audience-shaped meaning*, not *craft*.

## Final note for the next session

The external deck is in a strong state. The internal variant should inherit that strength, not try to improve on it. If a finding wants to change something the external deck already settled, push back — the consistency across the two decks is itself load-bearing for a buyer who sees both. The variant is for an audience that's been pre-briefed, not a competing source of truth.
