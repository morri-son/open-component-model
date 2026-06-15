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
| **A — Boardroom** | Outcome-only, terse | C-level, sovereign-cloud buyers | 8–10 |
| **B — Mixed-audience** | Outcome + one proof point per beat | Foundation events, partner workshops, mid-management with technical staff in the room | 8–10 |
| **C — Phase 2 technical** | Same beats, deeper drilldowns | Architects, security engineers, platform teams | longer (separate plan) |

---

## Lead axis — two-fold opener

**Compliance + sovereignty, together.**

- **Compliance is the demand.** EU DORA (Digital Operational Resilience Act, in force Jan 2025), NIS2, GDPR, supply-chain attacks (SolarWinds, xz, log4shell). Regulators and adversaries both raised the bar on what enterprises must prove about their software.
- **Sovereignty is the constraint.** Data residency, regulated jurisdictions, air-gapped environments — software must be deliverable, verifiable, and operable on the customer's own terms, inside their own boundary.
- **OCM resolves both.** The same architectural property — signed, location-independent, self-contained SBoD — answers both pressures at once. Compliance-native by design; location-independent by construction.

Sovereignty is **not** the slide-1 lead. It lands as the *proof beat* on slide 6 — the model holds even under the hardest constraint. This lets a regulated enterprise without an air-gap requirement still see themselves in slides 1–4, and meet sovereignty as the credibility multiplier rather than the entry ticket.

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

**Title:** Secure Delivery for Sovereign Clouds
**Subtitle:** Deliver and deploy your software securely. Anywhere, at any scale.
**Lockup:** Open Component Model — open source, NeoNephos Foundation.
---

## 2. Why now — two pressures, one answer

**Punchline:** *Compliance is rising. Sovereignty makes it harder. Trust must travel with the artifact.*

**Body:** Three columns, each one beat:
- **Regulation tightening.** EU DORA · NIS2 · GDPR. Provable supply-chain control, not best effort.
- **Supply-chain attacks are real.** SolarWinds. xz. log4shell. Signatures must survive the journey, or compliance is theatre.
- **Sovereignty pressure.** Wherever the law puts the boundary — by jurisdiction, sector, or air-gap — software must be deliverable, verifiable, and operable inside it.

**Proof point (mixed cut):** OCM separates artifact identity from artifact location, so trust travels with the signature, not with the registry.

---

## 3. The pain — fragmentation

**Punchline:** *Software delivery is fragmented. Compliance retrofits don't scale.*

**Body:** Many teams, many stacks. Signatures break in transit. SBOMs were never built for delivery — they were built for inventory. Each compliance regime adds its own bolt-on. None of it composes.

**Proof point (mixed cut):** OCM gives every component a globally unique, technology-agnostic, location-agnostic identity. One identity, one signature, one audit trail.

---

## 4. The shift — SBoD

**Punchline:** *SBOM lists. SBoD delivers.*

**Body:**
- An SBOM tells you *what's in your software*. It was built for inventory.
- A **Software Bill of Delivery (SBoD)** tells you *what you delivered, how to verify it, how to transport it, and how to operate it*. It was built for delivery.
- **The SBoD contains the SBOM.** OCM doesn't replace your SBOM tooling — it gives the SBOM an envelope that's compliance-native, signed once, and travels intact across any boundary.

**Proof point (mixed cut):** SBoD is an OCM concept defined in `docs/overview/benefits.md` — a signed, machine-readable record of every artifact a deployment needs, including images, charts, configs, binaries, and how to access them.

---

## 5. OCM in one picture — Pack · Sign · Transport · Deploy

**Punchline:** *One model. One flow. Any artifact, any registry, any boundary.*

**Body:** OCM gives you a single, standard way to handle the whole journey:
- **Pack** your software into a component descriptor.
- **Sign** the descriptor (one signature covers every artifact, by digest).
- **Transport** across any boundary — registry to registry, or registry to archive.
- **Deploy** at the target — OCM's Kubernetes controllers walk the component and apply it.

**Proof point (mixed cut):** OCM stores component versions in standard OCI registries — and the artifacts inside (container images, Helm charts) remain native OCI artifacts. No lock-in: your existing OCI tooling reads them as-is.

---

## 6. Sovereign-ready — trust, but verify

**Punchline:** *Trust, but verify. Anywhere — including behind the air gap.*

**Body:**
- Identity is location-independent. A component carries its name regardless of which registry it lives in.
- Signatures are location-independent. Sign once at the source; verify at the destination, with no callback upstream.
- Day-2 ops happen inside the boundary. Upgrades, config changes, migrations — all without reaching back upstream.
- On transfer into a sovereign environment, a component can carry every artifact it needs along with it. The destination needs nothing more.

**Proof point (mixed cut):** Sign once at the source, transport across the boundary, verify at the destination — same signature, same public key, no callback upstream. Validated end-to-end in the project's conformance scenario.

---

## 7. Compliance-native — Open Delivery Gear (NEW BEAT)

**Punchline:** *Compliance as a system property — not a quarterly project.*

**Body:**
- Open Delivery Gear (ODG) is OCM's compliance automation engine.
- The Compliance Dashboard is your entry point: every component, every finding, every signature in one view.
- Continuous scans run asynchronously — even after release.
- Findings get rescored against contextual risk, so your team patches what actually matters.
- Every compliance signal correlates by component identity. Auditors get evidence, not spreadsheets.

**Proof point (mixed cut):** ODG is open source and reads OCM SBoD metadata directly. Compliance is a system output of the model, not bolted on.

---

## 8. What OCM unlocks — six tiles

**Punchline:** *One model unlocks all of this.*

3×2 grid, one line each:

| Tile | Outcome |
|---|---|
| **Code signing across stacks** | Sign once at source; verify everywhere, with no per-stack tooling. |
| **Air-gapped delivery** | Walk a complete component across an air gap; verify at destination. |
| **Kubernetes-native deployment** | OCM controllers deploy components directly into clusters. |
| **Asynchronous security scans** | Continuous scanning, even after release; findings tied to component identity. |
| **Contextual CVE rescoring** | Patch what matters in your context, not what a generic feed says. |
| **Automated compliance reporting** | Reports composed from SBoD metadata — no spreadsheet drift. |

---

## 9. Open and governed

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

## 10. Call to action

**Punchline:** *Start delivering with confidence.*

**Body:**
- **Try it** — `ocm.software`
- **Build with us** — `github.com/open-component-model`
- **Talk to us** — community channels on the website (Slack / GitHub Discussions)
