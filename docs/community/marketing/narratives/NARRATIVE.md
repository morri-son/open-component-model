# OCM Marketing Deck — Master Narrative (v0.1 draft)

**Status:** v0.1 draft for review

---

## Deck thesis (one sentence)

> **Modern software delivery faces two non-negotiables: prove compliance continuously, and operate on your own terms. OCM is the open standard that resolves both at once — a Software Bill of Delivery you can sign, ship, and run anywhere, including behind your air gap.**

---

## Audience model — one narrative, three target groups

This file is the **master narrative**. From it, we can cut various versions of the deck for different audiences. 

| Cut | Depth | Audience | Slides |
|---|---|---|---|
| **A — Boardroom** | Outcome-only, terse | C-level, sovereign-cloud buyers | 9–11 |
| **B — Mixed-audience** | Outcome + one proof point per beat | Foundation events, partner workshops, mid-management with technical staff in the room | 9–11 |
| **C — Phase 2 technical** | Same beats, deeper drilldowns | Architects, security engineers, platform teams | longer (separate plan) |

---

## Lead axis — two-fold opener

**Compliance + sovereignty, together.**

- **Compliance is the demand.** EU DORA (Digital Operational Resilience Act, in force Jan 2025), NIS2, the Cyber Resilience Act (CRA, enforcement rolling out Sept 2026), supply-chain attacks (SolarWinds, xz, log4shell). Regulators and adversaries both raised the bar on what enterprises must prove about their software.
- **Sovereignty is the constraint.** Data residency, regulated jurisdictions, air-gapped environments — software must be deliverable, verifiable, and operable on the customer's own terms, inside their own boundary.
- **OCM resolves both.** The same architectural property — signed, location-independent, self-contained SBoD — answers both pressures at once. Compliance-native by design; location-independent by construction.

Sovereignty is **not** the slide-1 lead. It lands as the *proof beat* on slide 6 — the model holds even under the hardest constraint. This lets a regulated enterprise without an air-gap requirement still see themselves in slides 1–4, and meet sovereignty as the credibility multiplier rather than the entry ticket.

---

## Step-count framing — 4-step core, 5-step lifecycle

The OCM project uses **two** step-counts depending on context, and this deck uses both, in different registers:

- **4-step (core mechanics) — Pack · Sign · Transport · Deploy.** What every OCM user does on day 1. Lives on slide 6 as the canonical OCM diagram. This is what OCM *is*.
- **5-step (full lifecycle) — Pack · Scan · Ship · Deploy · Scale Out.** What OCM *enables* as you mature: scanning via Open Delivery Gear (slide 8), and scale-out through subscription-based, multi-region delivery (slide 7 day-2 bullet). Lives on slide 9 as a header strip above the outcome tiles, framing the tiles as the harvest of the full lifecycle.

The 4-step is the mechanic; the 5-step is the lifecycle picture. Slide 8 is renamed *"Scan — Compliance-native with Open Delivery Gear"* to invoke the 5-step's second step explicitly. *Scale Out* is not given its own beat — its semantics (multi-region, subscription-based, continuous ops) are absorbed into slide 7's day-2 bullet, where they strengthen the sovereignty story.

---

## Three opener variants for slides 1–2 (A/B testing)

Same beats 3–10. Variants change only the voice of slides 1 and 2.

- **V1 — Sovereignty-led.** Slide 1 hero stays, slide 2 leads with sovereignty pressure: "*Sovereignty is no longer optional. Wherever the law puts the boundary — by jurisdiction, sector, or air-gap — software must be deliverable, verifiable, and operable inside it.*" Then compliance and supply-chain follow as twin pressures.
- **V2 — Supply-chain-led.** Slide 2 leads with supply-chain attacks: "*Trust must travel with the artifact. SolarWinds, xz, log4shell — when signatures break in transit, you lose the chain of custody.*" Then sovereignty and compliance follow.
- **V3 — Fragmentation-led.** Slide 2 leads with operational pain: "*Modern software delivery is fragmented. Many teams, many stacks, signatures break between them. Compliance retrofits don't scale.*" Then sovereignty and compliance follow as the regulatory consequence.

---

# 10-beat skeleton

Each beat below carries:
- **Punchline** — what the slide says (boardroom-cut headline).
- **Body** — what the speaker fills in (mixed-audience-cut copy).
- **Proof point** — concrete capability (mixed-audience cut sub-bullet).

---

## 1. Hero

**Title:** Three minutes from now, you'll know what your supply chain doesn't.
**Subtitle:** A new model for delivering software the auditor can verify, the operator can run, and the regulator already requires.
**Lockup:** Open Component Model — open source, NeoNephos Foundation.
---

## 2. Why now — two pressures, one answer

**Punchline:** *Compliance is rising. Sovereignty makes it harder. Trust must travel with the artifact.*

**Body:** Three columns, each one beat:
- **Regulation tightening.** EU DORA · NIS2 · CRA. Provable supply-chain control, not best effort.
- **Supply-chain attacks are real.** SolarWinds. xz. log4shell. Signatures must survive the journey, or compliance is theatre.
- **Sovereignty pressure.** Wherever the law puts the boundary — by jurisdiction, sector, or air-gap — software must be deliverable, verifiable, and operable inside it.

**Proof point (mixed cut):** OCM separates artifact identity from artifact location, so trust travels with the signature, not with the registry.

---

## 3. The pain — fragmentation

**Punchline:** *Software delivery is fragmented. Compliance retrofits don't scale.*

**Body:** Many teams, many stacks. Signatures break in transit. SBOMs were never built for delivery — they were built for inventory. Each compliance regime adds its own bolt-on. None of it composes.

**Proof point (mixed cut):** OCM gives every component a globally unique, technology- and location-agnostic identity — its **OCM Coordinates**. One identity, one signature, one audit trail.

---

## 4. The shift — SBoD

**Punchline:** *SBOM lists. SBoD delivers.*

**Body:**
- An SBOM tells you *what's in your software*. It was built for inventory.
- A **Software Bill of Delivery (SBoD)** tells you *what you delivered, how to verify it, how to transport it, and how to operate it*. It was built for delivery.
- **The SBoD contains the SBOM.** OCM doesn't replace your SBOM tooling — it gives the SBOM an envelope that's compliance-native, signed once, and travels intact across any boundary.

**Proof point (mixed cut):** SBoD is an OCM concept defined in `docs/overview/benefits.md` — a signed, machine-readable record of every artifact a deployment needs, including images, charts, configs, binaries, and how to access them.

---

## 5. How OCM composes — comparator slide

**Punchline:** *OCM doesn't replace your tools. It gives them something to sign together.*

**Body:** Three columns, each one beat:

- **Keyless (Sigstore) / key-based (your PKI).** *Only signs one artifact.* OCM gives them the complete SBoD to sign. **One signature, covering every artifact in the delivery, by digest.** Your existing keys still work.
- **Your SBOM tool or format** (Syft, CycloneDX, SPDX). *Lists what's in your software.* The SBoD contains or references it. Your SBOM tool is unchanged; the SBOM now travels with the signature.
- **A bit of OCI + Sigstore + your own scripts.** *Can almost get you there, in pieces.* OCM is the standardised version, openly governed, with conformance tests and the SBoD vocabulary your auditors are starting to expect.

**Why this slide exists:** disarms the *"we already have this"* objection on the page, not in the speaker's head. Locked into the deck after Phase 1 peer review surfaced that the cold-room hero (slide 1) creates a comparator-objection debt the deck must repay before the mechanic walkthrough.

---

## 6. OCM in one picture — Pack · Sign · Transport · Deploy

**Punchline:** *One model. One flow. Any artifact, any registry, any boundary.*

**Body:** OCM gives you a single, standard way to handle the whole journey:
- **Pack** your software into a component descriptor — one operational source of truth for an entire landscape.
- **Sign** the descriptor (one signature covers every artifact, by digest). Supports RSA-based signing (your existing PKI), GPG/OpenPGP, and Sigstore keyless signing.
- **Transport** across any boundary — registry to registry, or registry to archive.
- **Deploy** at the target — bring your own GitOps (Argo, Flux, KRO) or use OCM's Kubernetes controllers. OCM walks the component and applies it.

**Proof point (mixed cut):** Works with what you already ship — OCI, Helm, npm, GitHub, S3. OCM doesn't replace your registries; it gives them one signed envelope. No lock-in: your existing tooling reads the artifacts as-is.

---

## 7. Sovereign-ready — trust, but verify

**Punchline:** *Trust, but verify. Anywhere — including behind the air gap.*

**Body:**
- Identity is location-independent. A component carries its name regardless of which registry it lives in.
- Signatures are location-independent. Sign once at the source; verify at the destination, or at any hop in between, with no callback upstream.
- Day-2 ops happen inside the boundary. Subscribe to the component and pull upgrades on your schedule, scale across regions, all without reaching back upstream.
- On transfer into a sovereign environment, a component can carry every artifact it needs along with it. The destination needs nothing more.

**Proof point (mixed cut):** Sign once at the source, transport across the boundary, verify at the destination — same signature, same public key, no callback upstream. Validated end-to-end in the project's conformance scenario.

---

## 8. Scan — Compliance-native with Open Delivery Gear (NEW BEAT)

**Punchline:** *Compliance as a system property — not a quarterly project.*

**Body:**
- Open Delivery Gear (ODG) is OCM's compliance automation engine.
- The Compliance Dashboard is your entry point: every component, every finding, every signature in one view.
- Continuous scans run asynchronously — even after release.
- Findings get rescored against contextual risk, so your team patches what actually matters.
- Every compliance signal correlates by component identity. Auditors get evidence, not spreadsheets.

**Proof point (mixed cut):** ODG is open source and reads OCM SBoD metadata directly. Compliance is a system output of the model, not bolted on.

---

## 9. What OCM unlocks — six tiles

**Punchline:** *One model unlocks all of this.*

**Header strip (above the tiles):** *The full lifecycle: **Pack · Scan · Ship · Deploy · Scale Out** — one model, end to end.*

3×2 grid, one line each:

| Tile | Outcome |
|---|---|
| **Code signing across stacks** | Sign once at source; verify everywhere, with no per-stack tooling. |
| **Air-gapped delivery** | Walk a complete component across an air gap; verify at destination. |
| **Kubernetes-native deployment** | OCM controllers deploy components directly into clusters. |
| **Asynchronous security scans** | Continuous scanning, even after release; findings tied to component identity. |
| **One source of truth** | Rebuild any landscape from a single signed descriptor. |
| **Automated compliance reporting** | Reports composed from SBoD metadata — no spreadsheet drift. |

---

## 10. Open and governed

**Punchline:** *Trusted in production. Aligned with NeoNephos.*

**Body:**

OCM is stewarded as open building blocks for sovereign delivery — interoperable, portable, federable, neutrally governed under NeoNephos Foundation (Linux Foundation Europe).

**Two-tier adopter wall:**

> **Adopted by enterprises shipping into regulated environments**
>
> SAP &nbsp; · &nbsp; BwI &nbsp; · &nbsp; SAP NS2

> **Built into the open-source ecosystem**
>
> Gardener &nbsp; · &nbsp; Konfidence &nbsp; · &nbsp; Platform Mesh

**Proof point (mixed cut):** An open standard, neutrally governed — your stack stays portable, your dependencies stay yours.

---

## 11. Call to action

**Punchline:** *Start delivering with confidence.*

**Body:**
- **Try it** — `ocm.software`
- **Build with us** — `github.com/open-component-model`
- **Talk to us** — community channels on the website (Slack / GitHub Discussions)
