# OCM Marketing Deck — Internal-Sponsor Narrative (v0.1 draft)

**Status:** v0.1 draft for review
**Audience:** SAP LoB heads (primary) + chief architects (secondary, objection-handling inline)
**Sibling to:** `NARRATIVE.md` (external audiences) — read that first; this doc only describes the *departures*.
**Status of NARRATIVE.md:** locked for external variants. This doc replaces only what changes for the internal-sponsor cut.

---

## Deck thesis (one sentence)

> **OCM is SAP's leverage point in the open-source supply-chain ecosystem — and the standardization window is closing. Compounding the leverage costs less than retrofitting it later.**

Compare to external thesis: "Modern software delivery faces two non-negotiables: prove compliance continuously, and operate on your own terms. OCM is the open standard that resolves both at once." The external thesis is *demand + constraint → answer*. The internal thesis is *strategic position → leverage compounds or migrates*.

---

## Audience model — who this deck is for

| Audience | Role | What they're deciding |
|---|---|---|
| **Primary** | SAP LoB heads (which LoBs: TBD with stakeholders) | Should my product line standardize on OCM for regulated delivery, or roll my own / pick a vendor / wait? |
| **Secondary** | SAP chief architects | Is OCM the right architectural primitive for this domain? *(Objections handled inline on the same slides.)* |
| **Out of scope** | SAP board / CTO office | Already have context, or politics don't run through this deck. |

The LoB head decides. The architect's questions are answered as objection-handling, not as separate framings.

---

## Lead axis — loss-frame, not pressure-frame

External `NARRATIVE.md` leads with *compliance + sovereignty pressure*. The internal-sponsor LoB head already accepts both as table-stakes constraints. The live question is not *"do we need to comply?"* — it's *"is OCM the right SAP-wide answer, and what happens if we walk away?"*

Therefore the lead axis is **strategic fit + ecosystem leverage**, framed as **what we lose by not compounding** rather than **what we gain by adopting**:

- **OCM has compounded leverage over years.** SAP investment has shaped the open standard, the foundation governance, and the ecosystem of peer projects (Gardener, Kyma, Konfidence, OCP, Hyperspace, RBSC, CSI).
- **The standardization window is closing, not opening.** Late entrants pay migration cost; early stewards keep optionality.
- **Walking away forfeits the leverage.** What we lose: ecosystem stewardship, NeoNephos positioning, EU competitiveness alignment, internal velocity from a shared primitive across LoBs.
- **Compliance + sovereignty are *given*.** The deck does not relitigate them. They appear as constraints the LoB head already operates under, not as the slide-1 lead.

---

## What this deck does not show

> **This deck argues OCM strategically, not transactionally.**
> **OCM's value is strategic — ecosystem leverage, sovereignty positioning, standardization. The transactional case is built per-LoB, with your team.**

This single concession line lives on slide 5 as a footer (or on the new slide-9 ecosystem beat). Its purpose: name what the deck *cannot* show, so the deck *can* be trusted on what it *does* show. Without this concession, a chief architect reads the deck as marketing rather than engineering. With it, the deck converts the absence of per-LoB ROI numbers from a vulnerability into a position.

---

## 14-slide skeleton — internal-sponsor cut

The deck has 14 physical slides — 1, 2, 3, 4a, 4b, 5, 6, 7a, 7b, 8, 9, 10a, 10b, 11. The **structural changes from prior versions:** slide 3 is now "Meet OCM" rather than "The pain" (Option 3 reframe); slide 5 is the new comparator slide ("How OCM composes"); slide 10 split into 10a (open peers) + 10b (internal SAP) to fix layout overflow and drop the factually-wrong upstream-contributions section; the "compliance retrofits don't scale" framing relocates to slide 8 where it has body text to anchor it.

Each slide carries: **External (NARRATIVE.md) — what this slide says externally. Internal-sponsor — what changes for this audience.**

---

### 1. Hero

**External (cold-room canonical):** *Three minutes from now, you'll know what your supply chain doesn't.* Subtitle: *A new model for delivering software the auditor can verify, the operator can run, and the regulator already requires.*

**Internal-sponsor:**
- **Title:** *Why OCM matters more now — and what we lose by walking away.*
- **Subtitle:** *Compounding strategic position in the open standard for regulated delivery.*
- **Org line:** *Open Component Model — open source, NeoNephos Foundation. Stewarded by SAP.*

The hero names the loss-frame directly. The subtitle is an asset claim. The org line adds *Stewarded by SAP* — a line the external deck cannot make.

---

### 2. Why now — three columns, internal lens

**External:** sovereignty pressure / regulation tightening / supply-chain attacks.

**Internal-sponsor:**

- **Eyebrow:** *WHY NOW — INTERNAL*
- **Title:** *Compliance and sovereignty are given. The strategic position is not.*

Three columns:

1. **Ecosystem velocity is real.** OCM-shaped abstractions are landing in adjacent OSS projects. NeoNephos is operationalizing. The peer ecosystem (Gardener, Kyma, Konfidence, OCP, Hyperspace, RBSC, CSI) shares the primitive.
2. **The standardization window is closing.** Adoption is consolidating. Late entrants pay migration cost; early stewards keep optionality.
3. **Disinvestment has a cost.** Walking away costs more than staying. Each LoB that builds its own retrofit pays the cost OCM was supposed to amortize. Competitors who keep investing get the standard built around their preferences, not SAP's.

This slide is text-only (3-column layout), no diagram.

---

### 3. Meet OCM — one identity, every boundary

**This is the new slide structure** (per Option 3 agreed with stakeholder). The "pain" beat from external slide 3 is dissolved into slide 2 column 3; slide 3 becomes the *answer*.

- **Eyebrow:** *THE ANSWER*
- **Title:** *Meet OCM. One identity, every boundary.*
- **Diagram:** hub-and-spoke. OCM in the centre. Spokes to artifact types (OCI, Helm, npm, Binary, Config, *…* — any artifact type), to regulatory regimes (DORA, NIS2, **CRA** — Cyber Resilience Act), to deployment boundaries (EU, US, Sovereign Cloud). Footer line below the diagram: *"plus FedRAMP/FISMA, BSI C5, SecNumCloud — and the regimes specific to your sector."*
- **Diagram status (2026-06-17):** new SVG in production at `decks/exec-phase1/diagrams/03-meet-ocm-hub-and-spoke.svg` (subagent task in flight). Variant deck may ship with placeholder until landed.

This slide is diagram-only (no body text — eyebrow + 1-line subtitle is the navigational frame). The diagram carries the message.

The internal-sponsor cut and the external cut both use this structure; the diagram is shared. Only context differs (external audience reads it as "OCM is the answer to the pressures"; internal audience reads it as "OCM is the primitive we already invested in, here's what it bridges").

---

### 4a. The shift — SBoD (text-only)

**External:** *SBOM lists. SBoD delivers.*

**Internal-sponsor — same content, reframed positioning:**

- **Eyebrow:** *THE SHIFT*
- **Title:** *SBOM lists. SBoD delivers.*
- **Body:** Same three bullets as external, but with a footer line:
  > *SBoD is the category SAP led the definition of — now standardised through NeoNephos governance.*

This footer is the strategic-positioning beat. Externally it would read as boasting; internally it grounds the LoB head in *why this is SAP's vocabulary*.

---

### 4b. The shift — SBoD diagram

**External and internal-sponsor are identical here.** Same SVG (`04-sbom-inside-sbod.svg` or v3 nested-rings variant per `DIAGRAM-OPTIONS.md`). Diagram-only slide. The mechanic is audience-independent.

---

### 5. How OCM composes — comparator slide

**External and internal-sponsor are identical here.** New slide added to the deck per Phase 1 peer review (disarms the *"we already have this"* objection from chief architects + skeptical CIOs).

- **Eyebrow:** *HOW OCM COMPOSES*
- **Title:** *OCM doesn't replace your tools. It gives them something to sign together.*
- **Three columns:**
  - **Keyless (Sigstore) / key-based (your PKI)** — *only signs one artifact.* OCM gives them the complete SBoD to sign. **One signature, covering every artifact in the delivery, by digest.** Your existing keys still work.
  - **Your SBOM tool or format** (Syft, CycloneDX, SPDX) — *lists what's in your software.* The SBoD contains or references it. Your SBOM tool is unchanged; the SBOM now travels with the signature.
  - **A bit of OCI + Sigstore + your own scripts** — *can almost get you there, in pieces.* OCM is the standardised version, openly governed, with conformance tests and the SBoD vocabulary your auditors are starting to expect.

For the internal-sponsor audience, this slide carries a load-bearing job: it *survives the chief architect's first objection* on the page, freeing the LoB-head conversation in the room to focus on strategic-fit rather than feature-comparison.

---

### 6. OCM in one picture — Pack · Sign · Transport · Deploy

**External:** *One model. One flow. Any artifact, any registry, any boundary.*

**Internal-sponsor:** identical. The mechanic is audience-independent. **Diagram-only slide.**

**Concession line lives here as a footer** (per stakeholder decision):

> *This deck argues OCM strategically. OCM's value is ecosystem leverage, sovereignty positioning, standardization. The transactional case is built per-LoB, with your team.*

---

### 7a. Sovereign-ready (text-only)

**External and internal-sponsor are identical.** The four bullets land the same for both audiences. The mechanic is the mechanic.

The *proof point* may shift between cuts — external cites the open-source sovereign conformance scenario; internal additionally cites BwI / SAP NS2 production deployments. Both true; both useful; pick by audience.

---

### 7b. Sovereign-ready — air-gap diagram

**External and internal-sponsor are identical.** Same SVG. Diagram-only slide.

---

### 8. Scan — compliance-native with Open Delivery Gear

**External:** *Compliance as a system property — not a quarterly project.*

**Internal-sponsor — same content, reframed:**

- **Eyebrow:** *SCAN — COMPLIANCE-NATIVE*
- **Title:** *Compliance as a system property — not a quarterly retrofit.* *(reframed from "project" to "retrofit" — picks up the relocated framing from old slide 3)*
- **Body bullets:** same five as external, but with a sub-bullet:
  > *Every SAP LoB gets compliance correlation by component identity, without each LoB building its own retrofit.*

This sub-bullet is the *internal* leverage claim: ODG isn't just "compliance for OCM users" — it's "compliance leverage SAP doesn't pay N times across N LoBs."

---

### 9. What OCM unlocks — six tiles, internal-sponsor outcomes

**External:** generic outcome tiles (audit prep, sovereign delivery, K8s-native, async scans, source of truth, automated compliance).

**Internal-sponsor — same six tile slots, reworked outcomes for SAP product lines:**

- **Eyebrow:** *WHAT OCM UNLOCKS FOR SAP*
- **Title:** *Six outcomes from one shared primitive.*

| Tile | Outcome (internal-sponsor framing) |
|---|---|
| **Faster sovereign delivery** | Pack a complete component once. From source into a regulated sovereign environment — every operator, every region, every air-gap. |
| **Compliance leverage across LoBs** | Each LoB gets DORA-aligned reporting from one shared primitive — not built N times. |
| **Integration after acquisition** | Acquired teams' signing schemes converge on one mechanism. The retire-list shrinks every quarter. |
| **Cross-LoB security correlation** | An incident's blast radius is one query — *"which deployments contain OCM component X?"* — across every LoB on OCM. |
| **One source of truth** | One signed descriptor per delivery. Rebuild any landscape. Audit prep is composition, not archaeology. |
| **Ecosystem stewardship** | SAP investment in OCM compounds with the open-peer ecosystem (Gardener, Konfidence, OCP, NeoNephos). |

These are outcome claims, not metric claims. No numbers asserted. **The transactional ROI lives one level down**, with the LoB team — per concession line.

**Note on what was dropped from an earlier draft:** italicized per-tile project pointers (*"Hyperspace + Gardener"*, *"CSI + Konfidence"*) were attached to each tile as adoption-example markers. They read as quoted attribution / AI slop. Named projects belong on slide 10a/10b, not on this slide.

---

### 10a. Where OCM is shipping — open ecosystem

**External:** Adopters in two tiers — regulated enterprises (SAP / BwI / SAP NS2) + open-source ecosystem (Gardener / Konfidence / Platform Mesh).

**Internal-sponsor — open-peer wall.** First of two slides on traction (split decision: too much content for one slide; logo-positioning was overlapping the title).

- **Eyebrow:** *WHERE OCM IS SHIPPING — OPEN ECOSYSTEM*
- **Title:** *Peer in the open ecosystem.*
- **Body — open peer projects** (no metrics):
  - **Gardener** — Kubernetes-as-a-service, open ecosystem.
  - **Kyma** — SAP's open-source Kubernetes-based runtime.
  - **Konfidence** — a development and delivery framework (SAP-originated, now open source).
  - **Open Control Plane (OCP)** — a platform that lets you create and manage Kubernetes-based ControlPlanes for your teams.
- **Forward-looking footer:** *And forthcoming: every NeoNephos foundation project as it lands.*

This is the *external-facing leverage* claim: OCM stands among open projects shaping regulated delivery. (CSI moved to slide 10b — internal-services footprint reads more accurately as internal SAP traction than external open-ecosystem peer.)

---

### 10b. Where OCM is shipping — internal SAP

**Internal-sponsor — internal-traction wall.** Second of the two split slides.

- **Eyebrow:** *WHERE OCM IS SHIPPING — INTERNAL SAP*
- **Title:** *Backbone of internal SAP delivery.*
- **Body — internal-only delivery infrastructure converging on OCM (5 projects, no metrics):**
  - **Hyperspace** — hosts the internal Dev Portal, lifecycle processes, and the shipment / delivery of SAP products. Direct OCM consumer.
  - **Release-Based Shipment Channel (RBSC)** — internal SAP delivery infrastructure converging on OCM.
  - **Common Service Infrastructure (CSI)** — the largest internal-services footprint shared across SAP.
  - **Greenhouse** — a cloud operations platform that streamlines management of large-scale, distributed infrastructure.
  - **Steampunk** — internal name for SAP BTP ABAP Environment (PaaS within SAP BTP); large user of OCM and ODG.
- **Closing manifesto (centred italic caption, visually separated from the bullet list — not a bulleted item):**
  > *Stewardship is leverage. Disinvestment forfeits it. The window for shaping the open standard for regulated delivery is closing — what compounds for SAP today migrates elsewhere if we step back.*

This is the *internal-traction* claim: major internal SAP delivery infrastructure is converging on OCM. Combined with 10a, the two slides land two distinct claims (external-facing leverage + internal-facing traction) without conflating them.

**Note on what was dropped:** an earlier draft included a "Section 3 — OCM contributes upstream to kro and ESO." This was factually wrong and has been removed. *OCM does not contribute to kro or ESO as a project — individual OCM contributors happen to also be maintainers in those adjacent OSS projects, which is cross-pollination, not an OCM-project upstream contribution.* The ecosystem-leverage claim stands on the open peer projects (10a) + the internal SAP traction (10b) alone.

---

### 11. CTA — sponsor / scale / standardize

**External:** *Try it / Build with us / Talk to us.* (Or first chief's Option A: 30-min reading / 2-hour PoC / white-glove. External CTAs may name Zulip `open-component-model`.)

**Internal-sponsor — different shape, named asks. Internal channels only — no Zulip on this deck:**

- **Title:** *Sponsor. Scale. Standardize.*

Three escalation tiers, each with a specific ask the LoB head can act on:

1. **Sponsor** — Allocate engineering capacity to OCM stewardship in your LoB. *Specific: name the engineer who owns the OCM relationship for your LoB.*
2. **Scale** — Pick one regulated component delivery your LoB ships and pack it as an OCM component this quarter. *We'll help.*
3. **Standardize** — Bring your LoB's signing / compliance / delivery patterns into the OCM steering conversation. *Channel: SAP Slack `#sap-tech-ocm`.*

Each tier names a *concrete action this week*, not a URL. The transactional case (per concession line) is built one level down — these CTAs are how the LoB head triggers that conversation.

---

## What this deck does NOT do

(Honesty section. Read alongside the concession line on slide 6.)

- It does not publish per-LoB ROI numbers. Those vary too much to land in a deck.
- It does not present competitive benchmarks against proprietary signing/SBOM stacks. The argument is strategic-fit, not feature-comparison.
- It does not relitigate compliance or sovereignty as live questions. The audience already operates under them.
- It names adoption examples (Hyperspace, Gardener, CSI, Konfidence on slide 9) without per-project metric claims. The transactional ROI lives one level down.

