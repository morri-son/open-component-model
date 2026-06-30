# Phase 3 — Internal-Architect Deck Change Summary

**What this is.** Per-slide diff between the external architect deck (canonical source) and the new internal-architect variant (`OCM-Story-Architect-Internal.pptx`). Use this to apply the changes against a SharePoint copy if the build pipeline is unavailable.

**Source of truth.** `decks/architect-phase2a/build-pptx/build_pptx_architect_internal.py` produces the canonical PPTX. The text below is paste-ready for slide-text and speaker-notes panes.

---

## What changed at a glance

| Slide | External | Internal |
|---|---|---|
| 1 PAIN | Cold opener ("You ship pieces / Nothing carries the release") | Architecture question on two lines ("What's a release / as one signed unit?") + three-beat trailer. Eyebrow dropped. |
| 2–3 | unchanged | byte-identical |
| 4 POSITIONING | slide text + CNCF Q&A in notes | slide text **unchanged**; notes drop CNCF Q&A, add SAP-stack Q&A |
| 5–12 | unchanged | byte-identical (slide 9 = SIGN, slide 10 = TRANSPORT — canonical order, see slide-order fix elsewhere) |
| 13 ADOPTION | "FROM ZERO — CLI / ON YOUR CLUSTER — CONTROLLERS" | "PACK & SHIP / DEPLOY & OPERATE" — SAP-shaped paths |
| 14 WHAT'S SHARP | unchanged | byte-identical |
| **15 ADOPTER PROOF** | (does not exist) | **NEW** — two-column slide; open-source projects + SAP-internal teams |
| 16 CTA | "Evaluate · Pilot · Engage" | "Pilot · Standardize · Steward" |
| 17 (was 16) REPLICATION APPENDIX | unchanged | byte-identical |
| **18 GLOSSARY** | (does not exist) | **NEW** — acronym appendix mirroring exec-internal slide 15 |
| External slide 18 (comparison matrix) | cosign/SLSA/SBOM/OCM matrix | **DROPPED** entirely |

Total: 17 main-arc slides + 2 appendices = **18 slides** (external = 16 + 1 appendix = 17 slides + separate slide-4b compare).

---

## SLIDE 1 (PAIN) — reframe opener

### ★ Slide-text change

Hero placeholders:

| Placeholder | External text | Internal text |
|---|---|---|
| Eyebrow | `You ship pieces.` | **deleted — no eyebrow** |
| Title (line 1, white) | (none) | `What's a release` |
| Title (line 2, white→cyan gradient) | `Nothing carries the release.` | `as one signed unit?` |
| Subtitle | `You sign the pieces. Nothing signs the release.` | `The model. The mechanic. The honest edges.` |
| Footer | (unchanged) | `Open Component Model — open source, NeoNephos Foundation.` |

Notes for hand-editing:
- The build script calls `delete_placeholder(s, 1)` to remove the eyebrow textbox entirely. In PowerPoint, delete the upper-left eyebrow label, don't just blank its text.
- The title breaks across two lines via an `<a:br/>` element between the two runs (white prefix + gradient noun). In PowerPoint, insert a hard line break (Shift+Enter) between "What's a release" and "as one signed unit?" — not a paragraph break.

### ★ Speaker notes — full replacement

```
Open with the question, not the noun. Internal architects in the first 60 seconds are silently asking: 'what's a release, as one signed unit?' Stating that question on the slide instead of pitching OCM gives both groups in the room the same starting point — the briefed half recognises the question they've been working on; the un-briefed half gets handed the frame they'll need anyway.
The subtitle trails the three concrete content beats this hour delivers: the model (descriptor, component identity, composition — slides 2-8), the mechanic (signature, transport, deploy, day-2 ops — slides 9-12), and the honest edges (what's still sharp — slide 14). That's the deck. Don't promise more.
Specifically don't promise 'the SAP stack' or 'where it fits in your pipeline.' OCM + ODG + OCP exist; an OCM-based SAP delivery stack does not yet. Saying it would land as overclaim. Slide 13 names two SAP-shaped adoption paths; slide 15 names the teams running OCM. That's the honest scope.
One sentence to land: 'For the next 30 minutes we're walking the model behind one signed unit — what it is, how it travels, and what's still sharp.' Then slide 2.
```

---

## SLIDE 4 (POSITIONING) — notes only

**Slide text:** No change. SBOMs, npm, maven still in the noun list.

### ★ Speaker notes — full replacement

```
OCM does NOT replace OCI, Helm, cosign, sigstore, your SBOM tooling. It WRAPS them — adds one envelope signature over the whole release.
• Any format - any artifact you produce becomes a resource. OCI, Helm, configs, SBOMs, npm, maven, binaries.
• Any location - identity is location-independent; the same component travels across registries unchanged.
• One signature - covers every digest in the component. The whole release is one signed unit.
Q&A backup on SAP-stack equivalents (the question this room actually asks): RBSC ships products; OCM describes the product so RBSC can ship it consistently. Hyperspace builds artifacts; OCM is the metadata wrapper added on top — the existing Piper steps stay. Open Delivery Gear (formerly OCM Gear) handles compliance automation on top of OCM components. None of these are replaced. OCM is the shared primitive they all align on.
Q&A backup on SBOMs (still relevant): SBOMs go INTO the component as resources. OCM does not generate SBOMs — it carries them, signs them as part of the release, and lets compliance tools query 'every SBOM in every shipped product' via the OCM coordinate system.
A component is the unit you sign, transport, and deploy. Hold the noun.
```

---

## SLIDE 13 (ADOPTION) — full rework

### ★ Slide-text changes

Title: `ADOPTION` (unchanged)
Subtitle: was `Two paths to a first OCM component.` → now `Two SAP-shaped paths to a first OCM component.`

Two columns (same geometry, full content swap):

| Column header | Body lines |
|---|---|
| `PACK & SHIP` | OCM CLI v2 — pack one product. Sign it.<br>RBSC integration — ship via the shipment channel.<br>Air-gap-safe by construction. No callbacks.<br>Start hands-on: pack locally in 30 minutes. |
| `DEPLOY & OPERATE` | Open Delivery Gear — OCM compliance automation.<br>Open Control Plane — declarative deploy runtime.<br>Sovereign-cloud-ready. Verify at the destination.<br>Day-2 ops on the same primitive. |

### ★ Speaker notes — full replacement

```
Two SAP-shaped paths. The external deck offers 'CLI laptop / Helm controllers' for an audience evaluating OCM from zero. This room is not at zero.
PACK & SHIP: OCM CLI v2 produces component descriptors. RBSC integration with the v2 CLI is live — the existing OCM RBSC plugin works against v2. The 30-minute laptop hands-on is the first half of this card; the production shape is wiring it into the team's release pipeline.
DEPLOY & OPERATE: Open Delivery Gear runs the compliance automation engine on the OCM coordinate system. Open Control Plane (the open-source successor to Managed Control Plane / MCP) is the declarative deployment runtime — the long-term replacement for Landscaper.
Q&A backup on Landscaper sunset (Sovereign Cloud audience will ask): Landscaper deploys type-A services (IAS, Audit Log) today in Sovereign Cloud. The migration to Open Control Plane is planned for end-of-year / early next year. OCM components are the SAME on both sides of the migration — only the runtime changes. That is the whole point of the model.
Q&A backup on Hyperspace Piper step (someone will ask if it's not on the slide): Hyperspace integration exists today on OCM v1. The v2 migration is on the 2026 roadmap, not started yet. Internally, Hyperspace already uses OCM for SBOM aggregation. This is why it's on the adopter-proof slide but not as an adoption path — the path is still being built.
Q&A backup on the renames: OCM Gear → Open Delivery Gear (ODG), now inside the OCM GitHub org. Managed Control Plane → Open Control Plane, also open source. We hardened the naming when we hardened the projects.
```

---

## SLIDE 15 (ADOPTER PROOF) — new slide

### ★ Slide-text

Title: `ADOPTER PROOF`
Subtitle: `Open ecosystem on the left. SAP teams on the right.`

**Left column (logo grid, 2×2 — no descriptive captions; icon-only logos carry their project name below):**

| Logo | URL | Below logo |
|---|---|---|
| Gardener (wordmark) | gardener.cloud | — |
| Kyma (icon) | kyma-project.io | `Kyma` |
| Open Control Plane (icon) | open-control-plane.io | `OpenControlPlane` |
| Konfidence (wordmark) | konfidence.cloud | — |

Header: `SAP OPEN-SOURCE PROJECTS`

Note: earlier drafts had descriptive captions (`Managed Kubernetes` / `Cloud-native runtime` / `Control-plane framework` / `Reproducible delivery`). Those were dropped — the deck's spoken context carries the description, and the captions duplicated content the glossary would otherwise repeat.

**Right column (bullet list):**

- Hyperspace — internal Dev Portal & product delivery.
- RBSC — Release-Based Shipment Channel.
- CSI — Common Service Infrastructure.
- Steampunk — ABAP Development PaaS.
- Sovereign Services & Delivery — sovereign-market operations.

Header: `SAP-INTERNAL TEAMS`

### ★ Speaker notes — full replacement

```
Adopter proof, two columns. The exec-internal deck splits this across two slides; we combine into one for the architect-track audience.
LEFT — four SAP-internal projects that are also open source: Gardener (managed Kubernetes), Kyma (cloud-native runtime), Open Control Plane (control-plane framework), Konfidence (reproducible delivery). All aligned with the NeoNephos Foundation. These are not just adopters — they are part of the open ecosystem OCM is building with.
RIGHT — five SAP-internal teams running on OCM: Hyperspace, RBSC, CSI, Steampunk, Sovereign Services & Delivery. These are SAP-only; no public logos.
Hyperspace caveat (audience WILL ask): Hyperspace integration today runs on OCM v1. The v2 migration is on the 2026 roadmap. Internally, Hyperspace ALREADY uses OCM for SBOM aggregation — that is in production. The Piper-step v2 integration is the in-flight piece.
Sovereign Services & Delivery operates SAP products in sovereign markets — the Sovereign Cloud delivery use case is the cleanest current OCM end-to-end story (pack, sign, ship via Landscaper today, will move to Open Control Plane).
Q&A backup on conspicuous absences: ACD, Hana Cloud / SGSC traceability — these were in the 2024 plan but have not made the same progress. We don't claim them as adopters; we claim them as 'considering / in conversation.' Better to under-claim than over-claim.
```

---

## SLIDE 16 (CTA) — was slide 15, full rework

### ★ Slide-text change

Title: was `Ship the release as one unit.` → now `Pilot. Standardize. Steward.`

Three action lines:

| Verb | Action line |
|---|---|
| Pilot | `Pack one product as an OCM component in your team this quarter.` |
| Standardize | `Make OCM the default for component delivery in your LoB.` |
| Steward | `Bring your LoB into the OCM steering conversation — SAP Slack #sap-tech-ocm.` |

### ★ Speaker notes — full replacement

```
Pilot. Standardize. Steward. Three verbs, three concrete next-quarter actions for an architect in this room.
PILOT: Pack one product as an OCM component, in your team, this quarter. Not a laptop demo — a real product, in your existing pipeline. RBSC is the cleanest first wire-up if you ship via RBSC today.
STANDARDIZE: Make OCM the default for component delivery IN YOUR LoB. This is the key reframe: we are NOT mandating OCM via SLC-29 or via a top-down product standard. The 2024 plan named that path; the 2026 strategy is different. We invest in the CLI quality so that OCM becomes the standard because it's the best tool for the job — bottom-up. The Elton Mathias support from Product Standards Lifecycle is still on the table for future inclusion, but it's not the lever we're pulling first.
STEWARD: Bring your LoB into the OCM steering conversation. Slack #sap-tech-ocm. We meet every two weeks; cross-LoB design decisions land there. If your LoB has a stake in component-delivery architecture, you should be in the room.
Final stop-sentence rhythm: 'One primitive. Your stack. Your call.' Then pause. Don't trail into the appendix.
```

---

## SLIDE 18 (GLOSSARY) — new appendix

### ★ Slide-text

Title: `APPENDIX · ABBREVIATIONS`
Subtitle: `Quick reference for terms used in this deck.`

Two-column layout, six entries each, alphabetical. **Discipline: every entry on this slide also appears in the slide text of an earlier slide.** Terms that live only in speaker notes (ODG, OCP, SBOD, NIS2, CRA, DORA, SLC-29, SPDX, SWID, SecNumCloud, TG, PEM, RSA-PSS, Hyperspace, Steampunk) were intentionally dropped — they don't reach the audience on a slide, so they don't need a glossary entry. Speaker notes carry the gloss for Q&A.

**Left column:** CSI · Helm · LoB · NeoNephos · OCI · OCM
**Right column:** OpenPGP · RBSC · RSA · SBOM · Sigstore · SS&D

Each entry: term in brand blue, dash, gloss in black. See `build_slide_18_appendix_glossary` in the build script for the exact gloss text per entry.

### ★ Speaker notes — full replacement

```
Appendix only. Pull on demand if the audience stalls on a term. Don't narrate.
Scope discipline: every entry on this slide also appears in the slide text of an earlier slide. If someone asks about a term that's NOT on this glossary (ODG, OCP, SBOD, NIS2, CRA, DORA, SLC-29, SPDX, SWID, SecNumCloud, TG, …), it lives in the speaker notes — answer from there.
Spot-checks worth knowing: OCM = Open Component Model (the spec). RBSC = Release-Based Shipment Channel. CSI = Common Service Infrastructure. SS&D = Sovereign Services & Delivery. NeoNephos = the foundation, hosted under Linux Foundation Europe.
```

---

## Dropped from internal variant

**External slide 18 (compare-appendix, cosign/SLSA/SBOM/OCM matrix)** — not built by the internal script. The "what does this replace?" question is answered in speaker notes (slide 4) with SAP-stack equivalents instead of CNCF comparisons.

---

## Quick reference — locked decisions

- Two scripts side by side (no `--variant` flag). Both fully self-contained, helpers duplicated. Mirrors the exec-phase1 pattern.
- Adopter slide is **one combined slide, two columns** — not two separate slides like the exec deck.
- CTA verb 2 is **Standardize**, reframed in notes from "SLC-29 mandate" to "bottom-up team standard." Strategy explicitly changed since the 2024 adoption plan.
- Hyperspace stays on the adopter slide despite the v1/v2 gap. Caveat in notes, not on slide.
- Landscaper-sunset story stays in notes only (per user preference).
- Slide 9 = SIGN, slide 10 = TRANSPORT (canonical, matches slide-7 mnemonic Pack · Sign · Transport · Deploy).

---

## Files

- `decks/architect-phase2a/build-pptx/build_pptx_architect_internal.py` — main build script (forked from external)
- `decks/architect-phase2a/build-pptx/speaker_notes_internal.py` — note overrides for slides 1, 4, 13, 15, 16, 18
- `decks/architect-phase2a/OCM-Story-Architect-Internal.pptx` — output (18 slides, ~2.1 MB)

Rebuild: `cd decks/architect-phase2a/build-pptx && python3 build_pptx_architect_internal.py`
