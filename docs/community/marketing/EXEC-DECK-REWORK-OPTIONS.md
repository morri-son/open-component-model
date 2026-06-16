# Exec Deck — Rework Options

For each slide where the marketing critique flagged an issue, this doc gives 3–4 alternative framings. Variants differ in **angle**, not just wording — risk-led, ROI-led, peer-led, regulator-led, etc.

Read alongside `MARKETING-CRITIQUE-EXEC.md` (the diagnosis) and `CONTENT-OPTIONS.md` (the wording-only options). This doc focuses on **structural and angle-level rework**.

Nothing here is applied yet. Mark up what you like; we'll converge.

---

## Slide 1 — Hero / opener

The current hero is a brand promise ("Secure Delivery for Sovereign Clouds"). Marketers know that opening with a brand promise loses 60% of the room in the first 8 seconds. Below: 4 alt openers, each with a different audience-targeting strategy.

### Option A — Stake-led / risk-frame (recommended for first-time exec audience)

> **Title:** Three minutes from now, you'll know what your supply chain doesn't.
> **Subtitle:** A new model for delivering software the auditor can verify, the operator can run, and the regulator already requires.
> **Org line:** Open Component Model — open source, NeoNephos Foundation.

Rationale: time-bound stake ("three minutes from now"), personal address ("you'll"), implication ("there's something you don't know"). This is the most marketing-mature opener.

### Option B — Regulator-led / DORA-frame (for European financial services)

> **Title:** DORA is in force. Is your software delivery audit-ready?
> **Subtitle:** Provable supply-chain control. Built once. Verified everywhere. By construction.
> **Org line:** Open Component Model — open source, NeoNephos Foundation.

Rationale: opens with a known regulatory hook, makes the buyer feel personally accountable. Strongest with CISO / risk officers.

### Option C — Peer-led / category-claim (for buyers who want to know "what's everyone else doing")

> **Title:** SAP, BwI, Gardener — and now you?
> **Subtitle:** Open Component Model is how regulated industries already deliver software into sovereign clouds.
> **Org line:** Open standard, neutrally governed by NeoNephos Foundation.

Rationale: social proof in the title. The shorter and more pointed, the better. "And now you" is the hook.

### Option D — Outcome-led / ROI-frame (for CFO-adjacent audiences)

> **Title:** From audit-as-fire-drill to audit-as-property.
> **Subtitle:** OCM turns compliance from a quarterly project into a system property — by binding signing, scanning, and delivery to one identity.
> **Org line:** Open Component Model — open source, NeoNephos Foundation.

Rationale: "fire drill → property" is a quotable, vivid contrast. Translates the deck's whole thesis into a single line.

### Option E — Current, kept for reference

> **Title:** Secure Delivery for Sovereign Clouds (with "Sovereign Clouds" gradient)
> **Subtitle:** Deliver and deploy your software securely. Anywhere, at any scale.
> **Org line:** Open Component Model — open source, NeoNephos Foundation.

Rationale: brand promise. Strongest if the audience already knows OCM and you're cementing the positioning.

**My recommendation:** Use **A** as the canonical exec hero, keep **C** for peer-validation contexts (industry events with named adopters in the room), keep **B** as the financial-services variant, keep **E** when the deck is a brand-cement asset (e.g., distributed at a conference where attendees pre-read).

---

## Slide 2 + 3 — Diagnosis (currently two slides, options to collapse)

The critique: these two slides cover the same fire from two angles. Below: 4 options — two collapse-into-one, two restructure-the-arc.

### Option A — Collapse into one slide: "The pressure"

Single slide. Three columns. New title:

> **Eyebrow:** WHY NOW
> **Title:** The boundary moved. Your software delivery hasn't.
> **Column 1 — Sovereignty:** Wherever the law sets the boundary — by jurisdiction, sector, or air-gap — software must be deliverable, verifiable, and operable inside it.
> **Column 2 — Regulation:** DORA in force from January 2025. NIS2 transposed across the EU. Provable supply-chain control, not best effort.
> **Column 3 — Fragmentation:** Many teams, many stacks. Signatures break in transit. SBOMs were built for inventory, not delivery. Compliance retrofits don't compose.

Reframes diagnosis as one **multi-pressure system** (3 fronts) instead of two slides. Slide 3 (current pain) becomes redundant — repurpose its slot.

### Option B — Collapse + repurpose slide 3 as "OCM enters the story"

After Option A's collapsed pressure slide, the freed slot becomes:

> **Eyebrow:** THE ANSWER
> **Title:** OCM is the model that crosses every boundary.
> **Body:** One identity per component. One signature per delivery. One audit trail across every regime. Across every registry. Across every sovereign environment.
> **Proof / mini-diagram:** OCM blob in the centre, arrows out to OCI/Helm/npm/Binary/Config + arrows out to DORA/NIS2/GDPR + arrows out to EU/US/Sovereign Cloud.

This compresses the diagnosis-to-answer arc by one slide and front-loads "OCM is the answer" before slide 5's mechanism walkthrough.

### Option C — Restructure: keep two slides, but reframe the second as "OCM enters"

> **Slide 2 stays as-is (V1 sovereignty-led, current).**
> **Slide 3 becomes:** "Meet OCM. One identity, every boundary."
>
> Body: Three short paragraphs anchored to the columns from slide 2:
> - "Sovereignty? OCM Coordinates carry the same identity into any registry, any region, any air-gap."
> - "Regulation? OCM gives auditors evidence — not spreadsheets — by component identity."
> - "Fragmentation? OCM doesn't replace your stacks. It gives them one signed envelope across all of them."

This is the cleanest "diagnosis → answer" pivot. Slide 2 ends with a question, slide 3 answers it directly.

### Option D — Three-pillar structure (different layout altogether)

Replace slides 2 + 3 with a single slide titled **"Three things that broke. One thing that fixes them."** Two-column layout: left column lists the breakage (sovereignty, regulation, fragmentation), right column lists the OCM property that addresses each (location-independent identity, by-construction compliance, one envelope across all stacks).

Most "marketing-deck-y" of the four. Highest density. Risk: feels formulaic.

**My recommendation:** **C** (cleanest diagnosis-to-answer flow, retains current structure). **A** if the deck needs to come down to 9 slides. **B** if you want to front-load "OCM is the answer" hardest. **D** for a different stylistic register.

---

## Slide 4 — SBoD vs SBOM (category claim)

Critique: SBoD is a category name OCM literally owns. The current slide treats it like a definition. Should treat it like a *category claim*. Below: 4 reworks.

### Option A — Three-beat repetition (marketing classic)

> **Eyebrow:** THE SHIFT
> **Title:** SBOM lists. SBoD delivers.
> **Body:**
> - SBOM = ingredients. SBoD = the delivery.
> - SBOM = inventory. SBoD = the audit trail.
> - SBOM lives inside the SBoD. The SBoD lives inside the signed envelope.
>
> *Pull quote:* "Built. Signed. Transported. Deployed. Your SBOM tooling is unchanged. OCM gives it the envelope that travels intact."

Three contrasts in three lines. Each is a memorable bumper-sticker. The body forces the audience to think about SBoD vs SBOM three different ways.

### Option B — Analogy-led ("a new word for a thing you already understand")

> **Eyebrow:** A NEW CATEGORY
> **Title:** A Software Bill of Delivery — like a shipping manifest, for software.
> **Body:** Your SBOM is the ingredients label on the box. Your SBoD is the manifest on the shipping container — what was loaded, by whom, signed by whom, en route to where, verified at which checkpoints. The SBOM lives inside.
> *Proof line:* OCM was the first to name this. It's now the foundation for OCM v2 and the conformance scenario.

Analogies hit hard with execs. The shipping manifest is universally understood. Repositions SBoD as the natural extension of an idea the audience already accepts.

### Option C — Verb-chain led (matches v2 announcement language)

> **Eyebrow:** WHAT YOU ACTUALLY DELIVER
> **Title:** Built. Signed. Transported. Deployed.
> **Body:** A Software Bill of Delivery records all four — not what's in the artifact, but what was *done* to it. The SBOM is one chapter inside. OCM gives every component an SBoD; auditors get evidence; ops teams get a deployable record; security teams get a chain of custody.

Verb-chain-led titles are the strongest "this slide is about what we did" framing. Doubles down on the v2 announcement's wording.

### Option D — Visual-led (the diagram does the talking)

Slide title: **"SBoD ⊃ SBOM"** (set-theoretic notation; signals technical seriousness).
Body is just one line: *"Your inventory list, inside a signed delivery record."*
Bulk of the slide is the v3 nested-rings diagram (SBoD → Payload → SBOM, three concentric layers).

Highest "memorable single image" potential. Risk: looks too clever for some audiences.

**My recommendation:** **A** for canonical exec deck (most repeatable), **B** for board / non-technical audiences (analogy lands), **C** when paired with v2 announcement context.

---

## Slide 5 — Pack · Sign · Transport · Deploy (canonical mechanism)

Don't break this slide. The verb chain is the deck's strongest single beat. Just **enrich** it. Three options to add depth without changing structure.

### Option A — Add native-OCI proof-line + Sigstore beat (subagent rec, lift-and-shift)

Keep the four bullets. Replace the existing proof line:

> **Old:** "Works with what you already ship — OCI, Helm, npm, GitHub, S3. OCM doesn't replace your registries; it gives them one signed envelope. No lock-in: your existing tooling reads the artifacts as-is."
>
> **New:** "Native OCI. Native Helm. Native npm. Pull components with the tools you already use. RSA, GPG, or Sigstore keyless signing — your choice."

### Option B — Add the "and a fifth: scale out" footer line

Below the four bullets:

> "Plus: the same model handles day-2 ops and multi-region scale-out. One mechanism, full lifecycle."

This sets up slide 8's tile grid + 5-step framing; resolves the bridge problem without contortion.

### Option C — Make Sign the hero bullet

Restructure the four bullets so Sign gets a sub-bullet:

> **Pack** — your software into a component descriptor.
> **Sign** — one signature covers every artifact, by digest.
> &nbsp;&nbsp;&nbsp;&nbsp;Bring your existing PKI (RSA), your team's GPG keys, or go keyless with Sigstore. No long-lived secrets.
> **Transport** — across any boundary. Registry to registry, archive to air-gap.
> **Deploy** — your existing GitOps stack (Argo, Flux, KRO) — or use OCM's Kubernetes controllers.

Sign is the slide's biggest IP claim ("one signature covers every artifact, by digest"). Currently equal-weighted with the others.

**My recommendation:** **A + C combined**. **B** if you want to fix the slide-8 bridge directly here.

---

## Slide 6 — Sovereign-ready (mechanism + proof)

Critique: bullets are dense (4 × 25 words), conformance-scenario proof is missing.

### Option A — Tighten to 3 bullets + add conformance proof (subagent rec)

> **Title:** Trust, but verify.
> **Bullets:**
> 1. **Identity travels.** A component's name is the same in every registry, every region.
> 2. **Signatures travel with it.** Sign at source; verify at destination, or any hop in between. No upstream callback.
> 3. **Day-2 ops stay inside the boundary.** Subscribe. Upgrade. Scale across regions. The destination needs nothing more.
>
> *Proof:* Validated end-to-end in OCM's open-source sovereign conformance scenario — exercised on every release.

### Option B — Reorder, no rewrite (lowest cost)

Same four bullets, but promote "Day-2 ops" to second position. This is the strongest beat after location-independent identity and is currently buried.

### Option C — Single big sentence + diagram

> **Title:** One identity. One signature. One closed-loop.
> **Body:** A signed component crosses any boundary you have — verified at the destination, with no callback to upstream — and runs in a closed-loop inside.
>
> *Diagram:* the v3 concentric circles diagram (open world → sovereign zone, with closed-loop arrow inside).
>
> *Proof line:* "Validated in the sovereign conformance scenario."

Most visual. Lowest text density. Best for boards / non-technical execs.

### Option D — "Three properties" structural rewrite

> **Title:** Sovereign-ready by three properties.
> **Three columns:**
> 1. **Location-independent identity.** Coordinates carry the name.
> 2. **Location-independent signatures.** Verified at any hop.
> 3. **Closed-loop day-2.** Subscribe, scale, no upstream callback.
>
> *Proof:* OCM's open-source sovereign conformance scenario.

Cleanest structural framing. Mirrors slide 2's three-column rhythm if Option A from slide-2 rework is also picked.

**My recommendation:** **A** for canonical, **D** for structural mirror of slide 2.

---

## Slide 7 — ODG / Compliance Dashboard

Critique: zero visual evidence. Bullets duplicate.

### Option A — Tighten 5 bullets to 4 + add Compliance Dashboard thumbnail

Bullets:
1. Open Delivery Gear (ODG) is OCM's compliance automation engine.
2. Compliance Dashboard: every component, every finding, every signature in one view.
3. Continuous async scans — even after release. Findings rescore against contextual risk.
4. **All signals correlate by OCM Coordinates.** Auditors get evidence, not spreadsheets.

Right side: dashboard thumbnail (sourced from IPCEI deck slides 5–6, sanitised).

### Option B — DORA-aligned title + bullets

> **Title:** DORA-aligned by construction.
> **Body:**
> - ODG turns compliance into a system property, not a release-time gate.
> - Compliance Dashboard correlates findings, signatures, and deployments by OCM Coordinates.
> - Per-component DORA metrics: built-in, not bolted-on.
> - Auditors get evidence; ops teams get DORA fields without a separate pipeline.

Strongest for financial-services exec audiences. Names the regulation directly.

### Option C — "Show the dashboard" minimal text

Title: "Compliance, by component identity."
Body: one paragraph (~30 words).
80% of the slide: a hero-sized dashboard screenshot.

Risk: depends entirely on the screenshot quality. Reward: highest "this is real" credibility.

### Option D — "Before / after" format

Left: "How compliance worked." (Quarterly project, audit-as-fire-drill, spreadsheets, per-stack findings.)
Right: "How compliance works with ODG." (Continuous, auto-correlated, evidence-by-component.)

Visual contrast. Marketing-classic.

**My recommendation:** **A** for canonical, **B** for FSI audiences, **C** if a sanitised dashboard screenshot is available, **D** for the rework into a tighter category claim.

---

## Slide 8 — What OCM unlocks (tile grid)

Critique: tiles describe **mechanisms**, not **outcomes**. Below: four total reworks of the tile content.

### Option A — Outcome-language reframing (each tile reworded as a buyer-language outcome)

| # | Eyebrow / Label | Body |
|---|---|---|
| 1 | Cut audit prep from weeks to hours | One signed envelope. Every signature. Every artifact. Auditors stop chasing evidence. |
| 2 | Ship into sovereign regions next quarter, not next year | Pack a complete component once. It carries everything the destination needs. |
| 3 | Eliminate per-stack signing-tool sprawl | One signing model across OCI, Helm, npm, binaries. Your security team stops chasing tooling. |
| 4 | Patch what matters, not what trends | Async scans run after release. Findings rescore by your contextual risk, not raw CVE count. |
| 5 | Rebuild any landscape, on demand | One signed descriptor = the spec for the whole environment. Lose the cluster, restore from the descriptor. |
| 6 | Make compliance a property, not a project | DORA-aligned reporting flows from SBoD metadata. No spreadsheet drift between releases. |

Same icons, same tile geometry. Just the words change. **Highest-impact, lowest-risk rework.**

### Option B — ROI-quantified tiles (where numbers exist or are defensible)

Each tile has a hard claim:

| # | Label | Body |
|---|---|---|
| 1 | Code signing across stacks | Sign once, verify everywhere. **Cuts per-stack signing tooling by N tools.** |
| 2 | Air-gapped delivery | One mechanism for every sovereign target. **Months of bespoke tooling → reuses your existing pipeline.** |
| 3 | Kubernetes-native deployment | OCM controllers deploy directly. **Eliminates the GitOps-to-OCI translation layer.** |
| 4 | Asynchronous security scans | Continuous post-release. **Patches are scoped by context, not CVE count.** |
| 5 | One source of truth | One descriptor per delivery. **Audit prep from weeks to hours.** |
| 6 | Automated compliance reporting | DORA fields by construction. **Spreadsheet drift: 0.** |

Risk: hard claims need to be defensible. Reward: most exec-resonant.

### Option C — Three buckets (split the 6 tiles into 2 rows of 3)

Top row label: **"For your security team"** — code signing, async scans, evidence by identity.
Bottom row label: **"For your operations team"** — air-gapped delivery, K8s deployment, one source of truth.

Adds a layer of audience-mapping. Helps execs decide "which department buys in first."

### Option D — Drop the lifecycle frame entirely (cleanest fix to step-count problem)

Replace the 5-step header strip with a single line:

> **"What changes for the people running your software."**

The tiles speak for themselves. No bridge needed between slides 5 and 8.

**My recommendation:** **A** for the deck's canonical version (highest leverage, easy switch). **B** if you can defend the numbers. **D** if you want the cleanest slide-8 / slide-5 alignment.

---

## NEW Slide — "What's at risk if you don't" (cost-of-inaction)

Currently absent from the deck. Insert between slide 7 and slide 8.

### Option A — Three-pillar risk slide

> **Eyebrow:** THE COST OF NOT MOVING
> **Title:** What you're betting against the next audit cycle.
> **Three columns:**
> 1. **Regulatory:** DORA fines up to 2% of group revenue. NIS2 personal liability for executives. GDPR + supply-chain regimes converging.
> 2. **Operational:** Per-stack signing tools compound annually. Each acquisition adds a new signing scheme to retire.
> 3. **Strategic:** Sovereign cloud markets (BSI C5, ENS, FedRAMP) require provable supply-chain control. Without it, market access is locked.

### Option B — "Three things that break first" risk slide

> **Eyebrow:** SIGNALS YOUR ORG IS UNDER-PREPARED
> **Title:** The first three things that break.
> **Body:**
> 1. **Audit prep takes weeks of evidence-chasing.** When auditors ask "show me the chain of custody for this release," your team builds a spreadsheet.
> 2. **A new sovereign region requires bespoke tooling.** Each one. Every project.
> 3. **An incident's blast radius is unknown.** "Which deployments contain library X?" is not a one-query answer.

More empathetic. Lands as "I've felt this." Better with engineering-led exec audiences (CTO, head of platform).

### Option C — Quoted regulator line + one sentence

> **Title:** "Provable supply-chain control. Not best effort."
> *(Attribution: paraphrased EU DORA framing.)*
>
> **Body:** Without an identity that travels, signatures don't compose. Without composing signatures, you're still chasing evidence at audit time.

Single-idea slide. Less verbose. Highest "feels like a moment" potential.

**My recommendation:** **A** for full executive deck. **C** if you want the deck to stay 10 slides total.

---

## Slide 9 — Adopters (credibility)

Critique: logos without proof are wallpaper.

### Option A — Per-logo one-liner

Below each logo:

> SAP — *"OCM packages our regulated cloud services across DORA-aligned releases."*
> BwI — *"Bundeswehr-grade air-gapped deliveries; OCM is the supply chain backbone."*
> SAP NS2 — *"US public-sector deliveries; OCM provides the chain of custody."*
> Gardener — *"Component graph and lifecycle, end-to-end."*
> Konfidence — *"Open-source compliance dashboard built on OCM."*
> Platform Mesh — *"Multi-cloud platform composition, by component identity."*

(Verify each line with the relevant team before publishing externally.)

### Option B — One quote, big

Drop the logo wall to half-size; use the other half for a single, big-type quote:

> *"OCM gave us a single mechanism for compliance, signing, and delivery — across SAP's regulated cloud services, by component identity."*
> — *Engineering leader, SAP* (or actual person if attributed)

Risk: requires a real attributable quote. Reward: most credible single-slide play.

### Option C — Scale numbers

Below the logo wall:

> "Components delivered: N+ in production. Sovereign deployments: M+. Regions: K. Releases per month: J."

Numbers anchor "this is real" without requiring quotes. Even directional numbers help.

### Option D — Combine: logos + 1 quote + 1 scale number

Top: logo wall (current).
Middle: one big quote.
Bottom: a single scale number ("N+ components in production across regulated industries").

Densest. Highest credibility per slide-inch.

**My recommendation:** **D**. Logos alone aren't enough; a quote is best; numbers anchor the claim.

---

## Slide 10 — CTA

Critique: three competing CTAs, none specific.

### Option A — Single specific ask, three escalation tiers

> **Title:** Pick one component this sprint. Pack it. We'll help.
> **Three lines:**
> 1. **30-min reading** — `ocm.software/start`
> 2. **2-hour PoC** — `github.com/open-component-model/poc-template`
> 3. **White-glove** — Zulip channel `open-component-model`

Lowest-friction, highest-converging CTA structure.

### Option B — Peer-pressure CTA

> **Title:** Join the cohort already running OCM in production.
> **Body:** SAP. BwI. Gardener. Konfidence. Platform Mesh. The next wave of regulated-industry adopters is forming now.
> **One link:** `github.com/open-component-model/adopters`

Single ask: become part of the peer group.

### Option C — Question-frame CTA

> **Title:** Three questions to take to your team this week.
> **Body:**
> 1. Which of our regulated components has the most fragmented supply chain?
> 2. Could we run an OCM PoC on it before next quarter's audit?
> 3. Who in our security and platform team should own the evaluation?
> **One link:** `ocm.software/start`

Educator-CTA. Hands the audience an action plan, not a URL.

### Option D — Current ("Try it / Build with us / Talk to us"), kept for reference.

**My recommendation:** **A** for action-oriented audiences, **C** for board / non-implementing audiences. Both name Zulip.

---

## Optional: per-vertical hero variants

If the deck travels to multiple audiences, having 3–4 hero variants pre-built saves time and lifts conversion. Suggested set:

| Variant | Audience | Hero title |
|---|---|---|
| Default | Mixed exec | "Three minutes from now, you'll know what your supply chain doesn't." |
| Financial services | CISO / risk officer | "DORA is in force. Is your software delivery audit-ready?" |
| Public sector / defense | Procurement / sovereignty buyer | "Software that crosses every boundary you have." |
| Platform / SaaS | Head of platform | "One model. Every stack. End to end." |
| Industry conference | Crowd | "SAP, BwI, Gardener — and now you?" |

---

## What to do with this doc

Browse, mark up, comment. There are too many options here to apply all of them — you'll converge to ~1 variant per slide once you've sat with them.

When you're ready, I'll:
- Apply your selected variants to the layout content (`build_pptx.py`)
- Rebuild the deck
- Update `NARRATIVE.md` to mirror the chosen wording
- Sweep the .potx layouts for any styling changes the new structure needs

The .potx template stays unchanged regardless of which content variants you pick — these are all wording / structural reframings, not visual changes.

*Generated 2026-06-16. Companion to `MARKETING-CRITIQUE-EXEC.md`.*
