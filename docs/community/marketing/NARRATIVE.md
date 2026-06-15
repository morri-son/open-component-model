# OCM Marketing Deck — Master Narrative (v0.1 draft)

**Status:** v0.1 draft for review. Not locked.
**Replaces:** previous narrative (which conflated EU DORA with DORA Metrics, led on sovereignty alone, and treated SBoD as adversarial to SBOM).

---

## Deck thesis (one sentence)

> **Modern software delivery faces two non-negotiables: prove compliance continuously, and operate on your own terms. OCM is the open standard that resolves both at once — a Software Bill of Delivery you can sign, ship, and run anywhere, including behind your air gap.**

---

## Audience model — one narrative, three depths

This file is the **master narrative**. From it, three deck cuts are produced:

| Cut | Depth | Audience | Slides |
|---|---|---|---|
| **A — Boardroom** | Outcome-only, terse | C-level, sovereign-cloud buyers | 8–10 |
| **B — Mixed-audience** | Outcome + one proof point per beat | Foundation events, partner workshops, mid-management with technical staff in the room | 8–10 |
| **C — Phase 2 technical** | Same beats, deeper drilldowns | Architects, security engineers, platform teams | longer (separate plan) |

Same skeleton. Three depths. Updates to this master ripple to all cuts.

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

Pick the variant that matches the room. The body of the deck does not change.

---

# The 10-beat skeleton

Each beat below carries:
- **Punchline** — what the slide says (boardroom-cut headline).
- **Body** — what the speaker fills in (mixed-audience-cut copy).
- **Proof point** — concrete capability (mixed-audience cut sub-bullet).
- **Source** — published OCM material the claim is grounded in.

---

## 1. Hero

**Title:** Secure Delivery for Sovereign Clouds
**Subtitle:** Deliver and deploy your software securely. Anywhere, at any scale.
**Lockup:** Open Component Model — open source, NeoNephos Foundation.
**Source:** project tagline (used on `docs/overview/_index.md`: *"a model and toolkit for a secure delivery for sovereign clouds"*).

---

## 2. Why now — two pressures, one answer

**Punchline:** *Compliance is rising. Sovereignty makes it harder. Trust must travel with the artifact.*

**Body:** Three columns, each one beat:
- **Regulation tightening.** EU DORA · NIS2 · GDPR. Provable supply-chain control, not best effort.
- **Supply-chain attacks are real.** SolarWinds. xz. log4shell. Signatures must survive the journey, or compliance is theatre.
- **Sovereignty pressure.** Wherever the law puts the boundary — by jurisdiction, sector, or air-gap — software must be deliverable, verifiable, and operable inside it.

**Proof point (mixed cut):** OCM separates artifact identity from artifact location, so trust travels with the signature, not with the registry.

**Source:**
- EU DORA — Regulation (EU) 2022/2554, in force 17 Jan 2025; financial-sector ICT third-party risk management.
- NIS2 — Directive (EU) 2022/2555.
- GDPR — Regulation (EU) 2016/679.
- "Trust must travel with the artifact" — paraphrase of `signing-and-verification-concept.md`: *"The digest remains stable because it depends only on what the artifacts contain, not where they are stored."*

---

## 3. The pain — fragmentation

**Punchline:** *Software delivery is fragmented. Compliance retrofits don't scale.*

**Body:** Many teams, many stacks. Signatures break in transit. SBOMs were never built for delivery — they were built for inventory. Each compliance regime adds its own bolt-on. None of it composes.

**Proof point (mixed cut):** OCM gives every component a globally unique, technology-agnostic, location-agnostic identity. One identity, one signature, one audit trail.

**Source:**
- `core-model.md`: *"Modern software is assembled from many different artifacts… stored across many different registries and repositories. There is no standard way to describe, version, sign, or transport a complete delivery as a single unit."*
- OCM whitepaper (Krüger, p. 4): *"A globally unique, technology-agnostic, and location agnostic naming scheme."*

---

## 4. The shift — SBoD

**Punchline:** *SBOM lists. SBoD delivers.*

**Body:**
- An SBOM tells you *what's in your software*. It was built for inventory.
- A **Software Bill of Delivery (SBoD)** tells you *what you delivered, how to verify it, how to transport it, and how to operate it*. It was built for delivery.
- **The SBoD contains the SBOM.** OCM doesn't replace your SBOM tooling — it gives the SBOM an envelope that's compliance-native, signed once, and travels intact across any boundary.

**Proof point (mixed cut):** SBoD is an OCM concept defined in `docs/overview/benefits.md` — a signed, machine-readable record of every artifact a deployment needs, including images, charts, configs, binaries, and how to access them.

**Source:**
- `benefits.md`, *"Create a Software Bill of Delivery"*: *"Unlike a Software Bill of Materials (SBOM), which lists all components inside an application, a Software Bill of Delivery focuses on everything you need for a successful deployment — including container images, Helm charts, configuration files, and binaries. It is a complete, verifiable record of all deliverables and how to access them."*
- `how-ocm-works.md`: *"This creates a Software Bill of Delivery (SBoD): a signed, verifiable record of exactly what was shipped."*
- OCM v2 announcement: *"OCM already provides the foundation for a true Software Bill of Delivery (SBOD)."*

**Visual note for Phase B:** the existing `04-sbom-vs-sbod.svg` shows SBOM and SBoD side-by-side with an arrow. That's the wrong relationship. The redrawn diagram must show **SBOM inside SBoD** — composition, not replacement.

---

## 5. OCM in one picture — Pack · Sign · Transport · Deploy

**Punchline:** *One model. One flow. Any artifact, any registry, any boundary.*

**Body:** OCM gives you a single, standard way to handle the whole journey:
- **Pack** your software into a component descriptor.
- **Sign** the descriptor (one signature covers every artifact, by digest).
- **Transport** across any boundary — registry to registry, or registry to archive.
- **Deploy** at the target — OCM's Kubernetes controllers walk the component and apply it.

**Proof point (mixed cut):** OCM stores component versions in standard OCI registries — and the artifacts inside (container images, Helm charts) remain native OCI artifacts. No lock-in: your existing OCI tooling reads them as-is.

**Source:**
- `how-ocm-works.md`: *"OCM gives you a single, standard way to handle that journey: Pack your software, Sign it for integrity, Transport it across any boundary, and Deploy it at the target."*
- OCM v2 announcement on OCI-native: *"Every component version is stored as a standard OCI Image Index, pushable to and pullable from any spec-compliant registry without OCM-specific extensions."*

---

## 6. Sovereign-ready — trust, but verify

**Punchline:** *Trust, but verify. Anywhere — including behind the air gap.*

**Body:**
- Identity is location-independent. A component carries its name regardless of which registry it lives in.
- Signatures are location-independent. Sign once at the source; verify at the destination, with no callback upstream.
- Day-2 ops happen inside the boundary. Upgrades, config changes, migrations — all without reaching back upstream.
- On transfer into a sovereign environment, a component can carry every artifact it needs along with it. The destination needs nothing more.

**Proof point (mixed cut):** Sign once at the source, transport across the boundary, verify at the destination — same signature, same public key, no callback upstream. Validated end-to-end in the project's conformance scenario.

**Source:**
- `how-ocm-works.md` (callout): *"Sovereign means more than air-gapped. It means the target environment can receive, verify, deploy, and upgrade software completely on its own. Components carry everything needed for the full lifecycle."*
- `transfer-concept.md`: *"At no point does the signature leave the component descriptor. The verification in the target environment uses the same public key and produces the same result as if verified against the original source."*
- OCM v2 announcement (conformance): *"validating that signatures, resources, and references survive the entire journey intact."*

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

**Source:**
- ODG README: *"Open Delivery Gear (ODG) is a production-ready compliance automation engine built for software components modelled with the Open Component Model… ODG implements a trust-but-verify solution for public and sovereign clouds."*
- IPCEI / Adoption-Plan-derived: *"Continuous scanning of all components gives full transparency about security and compliance. Rescoring CVEs based on Contextual Assessment allows to push patch due dates into the future."*
- (Note for speaker: project's own UI is named "Delivery Dashboard"; we frame it as "Compliance Dashboard" to match exec language.)

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

**Source:** All six are sourced from `benefits.md`, the v2 announcement, the controllers blog post, and ODG's framing. (Drops "DORA Metrics" — that was the DevOps metric, not the EU regulation we're naming. Drops "Inbound OSS consumption" — too developer-experience-focused for this audience.)

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

**Source:**
- OCM v2 announcement: lists Gardener, Konfidence, Platform Mesh as production users.
- BwI (Bundeswehr IT) and SAP NS2 are public adopters in regulated/sovereign environments.
- `open-component-model.org` / NeoNephos governance.

---

## 10. Call to action

**Punchline:** *Start delivering with confidence.*

**Body:**
- **Try it** — `ocm.software`
- **Build with us** — `github.com/open-component-model`
- **Talk to us** — community channels on the website (Slack / GitHub Discussions)

**Brand lockup:** OCM mark left, NeoNephos / LF Europe lockup right. (Mirrors the hero.)

---

# Cross-cutting rules for slide copy

These rules apply to every cut and every beat. Phase B (visual design) inherits them:

1. **DORA = EU regulation, every time.** Never DORA Metrics. If the DevOps concept is needed in some other context, write it out: "DevOps deployment metrics."
2. **No CLI flags. No `--copy-artifacts`. No "transfer modes."** The fact that a transfer can either keep references or pull artifacts in is a behaviour of the tool, not a concept the audience needs. Slide 6 expresses it as plain English ("a component can carry every artifact it needs along with it").
3. **No internal SAP terminology.** Hyperspace, Piper, RBSC, ACD, IAS, SLC-29, Landscaper, etc. — out.
4. **Pack · Sign · Transport · Deploy is the official 4-step.** Do not mix with the IPCEI 5-step (*Pack · Scan · Ship · Deploy · Scale*) — that's the European partner doc's framing, not the project's published voice.
5. **SBoD contains SBOM.** Never "SBoD vs SBOM." Always composition, never replacement.
6. **Compliance Dashboard is the user-facing name on the slide.** Project's actual UI is "Delivery Dashboard." Don't rename the project; just frame it for execs.
7. **Three opener variants exist; everything else is shared.** Do not let an opener variant ripple into slides 3–10.

---

# Open items

- **Specific community-channel name on slide 10.** "Slack / GitHub Discussions" is the placeholder; finalise when we know which is canonical.
- **Tagline on slide 9** — "Trusted in production. Aligned with NeoNephos." Could be sharper. Alternatives welcome.
- **Hero subtitle gradient** — "Sovereign Clouds" was the gradient anchor in the previous design; with the new lead axis, "Secure Delivery" might be the better gradient anchor. Decide in Phase B.

---

# Provenance index

Every claim in this narrative is grounded in one of these sources:

- `website/content/docs/overview/_index.md`
- `website/content/docs/overview/benefits.md`
- `website/content/docs/overview/core-model.md`
- `website/content/docs/overview/how-ocm-works.md`
- `website/content/docs/concepts/signing-and-verification-concept.md`
- `website/content/docs/concepts/transfer-concept.md`
- `website/content/blog/ocm_v2_announcement.md`
- `website/content/blog/2026-03-16-ocm-controllers-differences.md`
- OCM whitepaper (Krüger, SAP SE, internal reference)
- OCM Adoption Plan (Morrison/Braun, SAP, internal reference — used for context only, internal terminology stripped)
- IPCEI-CIS / GA-OCM-ODG document (partner-only reference, framing only)
- Open Delivery Gear README (`open-component-model/open-delivery-gear`)

A reader of this narrative file alone can recreate the storyline without reading any of the source material.
