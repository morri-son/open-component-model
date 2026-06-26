# Speaker Notes — External Exec Deck (`OCM-Sovereign-Delivery-Exec.pptx`)

**Audience.** External decision-makers — CIOs, CTOs, heads of platform engineering, security or compliance leads at customers, partners, regulated-industry buyers. People who decide whether their organisation invests time in OCM, not the engineers who'll implement it.

**Talk length.** ~13 minutes. Q&A is its own thing — keep the talk tight so questions have room.

**Tone.** Honest, grounded, not preachy. You believe the thing because it's been built and used; that confidence carries — you don't need to oversell. Treat the audience as smart peers; never explain the obvious. No marketing inflation ("revolutionary", "industry-leading"). State what's true; let it land.

**Open with energy, close with an ask.** The middle is allowed to be a calm explanation.

**Slide count.** 14 presented slides + appendix glossary + 2 hidden trademark slides (not presented).

---

## SLIDE 1 — HERO  (00:00 — 00:45, ~45 sec)

**On screen.** "Your supply chain has / blind spots." (Gradient on "blind spots".) Subtitle: "Three minutes from now, you'll know what they are."

**Speaker notes.**

Open with the observation, not the company. People are tired of being sold to.

> "Software stopped being a thing you build and started being a thing you transport. Across registries, across borders, across air gaps. And every boundary it crosses, somebody asks: is this still the artifact you signed?"

Pause. Let that land.

> "I'm here for fifteen minutes to show you what we've built so that question has a clean answer. It's called OCM — the Open Component Model. It's open source, governed by the NeoNephos Foundation. SAP stewards it; we're not selling it."

Move on. Don't dwell on the brand row.

---

## SLIDE 2 — THREE BLIND SPOTS  (00:45 — 01:45, ~60 sec)

**On screen.** Three columns: IDENTITY DRIFT / NO RELEASE ENVELOPE / UNVERIFIED ARRIVAL. Subtitle: "Where today's delivery model can't see."

**Speaker notes.**

Discharge the contract you just made on slide 1. Three picturable failures the audience can recognise in their own delivery chain. The slide is intentionally sparse — let the audience read; you fill in the colour.

> "Three blind spots. Each one is a place the current model literally cannot see."

**Column 1 — Identity drift.** "You signed an artifact at source. Then it moved — to a mirror, to a customer's registry, into an air gap. Each of those transfers changed its reference, because location is part of the name. Downstream verifies a reference you never signed — and most chains don't notice."

**Column 2 — No release envelope.** "A release is twelve things — images, charts, configs, manifests, an SBOM. Today, those get signed separately, if at all. So when a regulator asks for proof that *the release* is what you said it is, you hand them twelve signatures and an explanation."

**Column 3 — Unverified arrival.** "Sovereign-cloud and regulated environments forbid upstream traffic. So either verification ships with the release, or it doesn't happen. In most chains, it doesn't — and the gap shows up at audit time."

> "Those are the blind spots. Now — why now."

Hand off to slide 3.

---

## SLIDE 3 — WHY NOW  (01:45 — 03:15, ~90 sec)

**On screen.** Three columns: SOVEREIGNTY PRESSURE / REGULATION TIGHTENING / SUPPLY-CHAIN ATTACKS ARE REAL. Subtitle: "Sovereignty is no longer optional."

**Speaker notes.**

Don't read the columns. Frame them. The audience has just been shown what is broken; now name why it matters this quarter, not next year.

> "Three things are converging right now, and they're not going away."

**Column 1 — Sovereignty pressure.** "The law draws boundaries — by jurisdiction, by sector, by air-gap.
Software must be deliverable inside each one. If your delivery model can't survive 'no callback to source' inside
a regulated environment, you're not in those markets anymore."

**Column 2 — Regulation tightening.** "EU DORA, NIS2, CRA — all want provable supply-chain control.
Not 'best effort'. Provable. Machine-readable evidence, at the artifact level, traceable end-to-end."

**Column 3 — Supply-chain attacks.** "SolarWinds. xz. log4shell.
These weren't theoretical risks — they were live in production.
The lesson the industry took: signatures must survive the journey, or compliance is theatre."

> "This is what's pushing the industry toward something different. Not faster pipelines. Different mechanics."

---

## SLIDE 4 — THE ANSWER  (03:15 — 04:30, ~75 sec)

**On screen.** Hub-and-spoke diagram. OCM in the centre. Artifacts on the left (OCI / Helm / npm / Binary / Config / any artifact type). Boundaries on the right (EU / US / Sovereign Cloud). Compliance frameworks at the bottom (DORA / NIS2 / CRA).

**Speaker notes.**

Wait two seconds before talking. Let people read the diagram.

> "OCM is one model that ties three things together — your artifacts, your deployment boundaries, and the regulations you're delivering against."

> "On the left: every artifact type. Container images, Helm charts, configuration files, binaries. OCM doesn't care what shape your software comes in."

> "On the right: every boundary. EU, US, sovereign cloud, customer-owned. Same identity, same signature, regardless of where the component lives."

> "And underneath: every compliance regime. DORA, NIS2, CRA — plus the sector-specific ones. OCM gives you the evidence model the regulators are asking for."

> "Meet OCM. One identity, every boundary."

That's the headline. Move on.

---

## SLIDE 5 — THE SHIFT  (04:30 — 05:30, ~60 sec)

**On screen.** Title: THE SHIFT. Subtitle: "SBOM lists. SBOD delivers." Three bullets.

**Speaker notes.**

This slide does the conceptual work the rest of the deck builds on. Slow down here.

> "There's a category shift happening in how we think about delivery. SBOMs — Software Bills of Materials — were designed for inventory. They tell you what's inside a piece of software. That's useful, but it's not enough."

> "A Software Bill of Delivery — SBOD — tells you what you actually delivered. How to verify it, how to transport it, how to operate it. The container images, the Helm chart, the configuration, the manifest of how to deploy."

> "An SBOM lists. An SBOD delivers. The SBOM lives inside the SBOD."

Read the third bullet only if the audience is reading it. Otherwise paraphrase:

> "The point is: OCM doesn't replace your SBOM tooling. It gives the SBOM an envelope."

---

## SLIDE 6 — THE SHIFT, SBOM INSIDE SBOD  (05:30 — 06:00, ~30 sec)

**On screen.** SBOD diagram: artifact list (Docker images, Helm charts, K8s manifests, config files, SBOM) on the left, signature bracket on the right with "One digest covers all." Component identity (`github.com/acme/webshop:v1.0.0`) at the top.

**Speaker notes.**

The diagram is the point. Don't talk over it.

> "Visually: this is what an SBOD contains. Container images, charts, manifests, configs, the SBOM itself. One signed envelope. One identity at the top. Everything you delivered."

Pause. Let people look.

> "If you take one thing from this talk, take this picture."

---

## SLIDE 7 — HOW OCM COMPOSES  (06:00 — 07:30, ~90 sec)

**On screen.** Three columns: SIGNING / TRANSPORT / COMPLIANCE. Each is two lines — "what you have today" then "what OCM adds".

**Speaker notes.**

This is the objection-handling slide. Almost everyone in the room is thinking "we already have signing / registries / scanners". Address that head-on.

> "I want to disarm something. You probably hear me say 'OCM' and think — we already have signing. We have registries. We have scanners. Why do I need another thing?"

> "OCM doesn't replace any of that. OCM composes around what you already have."

**Walk through the columns. One sentence each. The slide gives you setup; you deliver the punchline.**

> "Signing: you sign artifacts today. OCM signs the release as a whole — one signature, every digest. So the signature you check at the destination is one check, not twelve."

> "Transport: your registries differ — by vendor, by location, sometimes air-gapped archives. OCM moves the release across all of them. The identity stays."

> "Compliance: your scanners look at one artifact at a time. OCM correlates findings to the release. Compliance becomes continuous — not a project that starts every quarter."

> "Same tools. New connective tissue."

---

## SLIDE 8 — OCM IN ONE PICTURE  (07:30 — 09:00, ~90 sec)

**On screen.** Pack · Sign · Transport · Deploy → Sovereign Cloud diagram.

**Speaker notes.**

Big diagram, four verbs, this is the demo replacement.

> "Here's the whole flow on one slide. Four verbs."

**Point at PACK.** "Pack. You bundle whatever your software actually needs — the image, the chart, the config — into one named, versioned component. One source of truth."

**Point at SIGN.** "Sign. One signature covers every artifact in the bundle. By digest. So if anything changes, the signature breaks."

**Point at TRANSPORT.** "Transport. The component moves across registry boundaries. Cloud to cloud, region to region, even into an air-gapped archive — without the signature breaking."

**Point at DEPLOY.** "Deploy. At the destination, the receiver verifies the signature, unpacks the bundle, deploys it. GitOps or OCM K8s controllers — your choice. No callback upstream."

> "Pack, sign, transport, deploy. That's OCM in operation."

---

## SLIDE 9 — SOVEREIGN-READY  (09:00 — 10:00, ~60 sec)

**On screen.** Title: SOVEREIGN-READY. Subtitle: "Trust, but verify." Four bullets, each anchor + characterisation + consequence.

**Speaker notes.**

This is the slide for the regulator-and-CISO conversation.

> "Sovereign-ready isn't a checkbox. It's a property of the delivery model. Four things have to be true."

**Bullet 1 — Identity.** "Location-independent. The component carries its name regardless of registry. Same identity in your dev cluster and in a customer's air-gapped data centre."

**Bullet 2 — Signatures.** "Location-independent. Sign once at source, verify anywhere downstream. No callback upstream."

**Bullet 3 — Day-2 ops.** "Inside the boundary. Once a component is in the sovereign environment, subscribe to it, pull upgrades, scale across regions. Still no callback."

**Bullet 4 — Transfer.** "Self-contained. Every artifact travels with the component. The destination needs nothing more."

> "Trust, but verify. The component is the trust boundary — not the registry, not the network."

---

## SLIDE 10 — SOVEREIGN-READY — AIR-GAP  (10:00 — 11:00, ~60 sec)

**On screen.** Air-gap diagram. Source side (left), trust boundary (middle), sovereign target (right). Local registry / K8s cluster / Auditor as three green checks on the destination side.

**Speaker notes.**

Reinforce the previous slide visually.

> "On the left: source side. You pack and sign. Public registry, your dev environment, doesn't matter."

> "Down the middle: the trust boundary. This is the air gap, the sovereign cloud edge, the regulated network perimeter. No traffic crosses it without explicit transfer."

> "On the right: sovereign target. The component lands. The local registry receives it. Verification happens locally — same signature, same identity, no upstream traffic. The K8s cluster pulls from the local registry. Auditor signs off based on the component's own evidence."

> "Same identity. Same signature. Any location. That's the property."

---

## SLIDE 11 — SCAN  (11:00 — 11:45, ~45 sec)

**On screen.** Title: SCAN. Subtitle: "Compliance as a system property — not a quarterly retrofit." Five bullets, the first introduces ODG.

**Speaker notes.**

Brief stop here. Don't go deep — this is the "and there's tooling around it" slide.

> "There's an open-source compliance engine that runs on top of OCM. It's called Open Delivery Gear — ODG. Built on the same primitives as the rest of OCM."

> "ODG scans every component continuously, even after release, and correlates findings by component identity. Auditors get evidence, not spreadsheets."

> "What that means in practice: when CVE-something-2026 drops at 11pm, you don't ask 'which of our products is affected'. You query the OCM coordinate system, you get a list, and you see the rescored risk for each one — patch what matters, not the noise."

> "Compliance becomes a property of the system. Not a Q3 deliverable."

---

## SLIDE 12 — WHAT OCM UNLOCKS  (11:45 — 12:30, ~45 sec)

**On screen.** Six tiles: Code signing across stacks · Air-gapped delivery · K8s-native deployment · Async security scans · One source of truth · Automated compliance reporting.

**Speaker notes.**

Don't read the tiles. The audience can read.

> "Six things you get from one shared model. Code signing across the whole stack, not per-tool. Air-gapped delivery as a built-in, not a workaround. Kubernetes-native deployment via OCM controllers. Continuous async security scans. A single signed source of truth you can rebuild any landscape from. And compliance reporting that flows from the SBOD itself — no spreadsheets."

> "All from one model. That's the point."

---

## SLIDE 13 — TRUSTED IN PRODUCTION  (12:30 — 13:00, ~30 sec)

**On screen.** Title: "SAP stewards. NeoNephos governs. / Production-grade. Sovereign-ready." Two-tier logo wall: top row BWI + SAP NS2 (production adopters), bottom row Gardener + Kyma + OpenControlPlane + Platform Mesh (peer projects). NeoNephos logo at the footer with "Aligned with".

**Speaker notes.**

Ground the credibility. Be honest about scale; don't oversell. The title carries four claims — let it speak; you fill in the colour.

> "OCM isn't a research project. SAP stewards the engineering investment. NeoNephos — the foundation — governs the standard. The result is in production today."

**Point at the top row.** "BWI is Germany's federal IT service. SAP NS2 handles regulated US workloads. Both run on OCM. That's the production proof."

**Point at the bottom row.** "And a peer ecosystem has converged around the model. Gardener — SAP's open-source Kubernetes orchestrator, in production for over five years. Kyma. OpenControlPlane. Platform Mesh. Each does something different; each builds on the OCM primitive."

> "Aligned with NeoNephos. Open source. Production-grade."

---

## SLIDE 14 — CTA  (13:00 — 13:45, ~45 sec)

**On screen.** Title: "Pilot. Evaluate. Engage." Three action lines: Pilot / Evaluate / Engage.

**Speaker notes.**

Close with the ask. Plain language. The asks are exec-shaped — pilot a delivery, hear back from the team that ran it, bring your delivery problem to the standard while it's being shaped. The CLI and the GitHub repo are still in the footer for any platform lead in the room, but they are not the headline.

> "Three asks."

> "Pilot. Pick one regulated delivery you're already shipping. Pack it as an OCM component this quarter. Not a proof of concept in a sandbox — something real, something that's already going through compliance friction. That's where the early payoff is."

> "Evaluate. Have your platform-engineering and security leads brief you on what they found. The signal is in their faces, not in the slides. If the model fits your delivery, they'll come back saying so without prompting."

> "Engage. Bring your delivery problem to the steering conversation. The standard is open and being shaped right now. The reality of what you ship is the input we need. ocm.software for the entry point — github dot com slash open-component-model for the code — community Slack and steering meetings linked from the website."

> "Pilot. Evaluate. Engage. That's the ask. Thank you."

(Then: take questions.)

---

## TIMING TOTAL

| Slide | Topic | Duration |
|---|---|---|
| 1 | Hero — Your supply chain has blind spots | 0:45 |
| 2 | THREE BLIND SPOTS | 1:00 |
| 3 | WHY NOW | 1:30 |
| 4 | THE ANSWER — hub-and-spoke | 1:15 |
| 5 | THE SHIFT (bullets) | 1:00 |
| 6 | SBOM INSIDE SBOD (diagram) | 0:30 |
| 7 | HOW OCM COMPOSES | 1:30 |
| 8 | OCM IN ONE PICTURE | 1:30 |
| 9 | SOVEREIGN-READY (bullets) | 1:00 |
| 10 | AIR-GAP (diagram) | 1:00 |
| 11 | SCAN | 0:45 |
| 12 | WHAT OCM UNLOCKS | 0:45 |
| 13 | TRUSTED IN PRODUCTION | 0:30 |
| 14 | CTA | 0:45 |
| **Total** | | **13:45** |

Buffer: ~75 seconds inside a 15-minute slot. If the audience is engaged, slides 7 and 8 absorb extra time naturally. The two appendix slides (glossary, trademarks) don't run in the show.

---

## Q&A PREP — questions that come up

- **"Is this another SBOM standard?"** → No. OCM is about delivery. SBOMs are inputs to it. SPDX, CycloneDX — both fit inside an OCM component. (slide 5)
- **"Do I throw away my container registry?"** → No. OCM sits on top. Your OCI registry stores the same images. (slide 7)
- **"Is it Sigstore-compatible?"** → Yes. Sigstore is a first-class signing backend. Classical RSA also supported. (slide 7 / 8)
- **"Who pays for it?"** → It's open source under NeoNephos governance. SAP funds the core engineering. Production use is free. (slide 13)
- **"What's the lock-in?"** → Open standard, open spec, open implementation. Nothing proprietary. The point of standardising is to *prevent* lock-in. (slide 13 / 14)
- **"How does this compare to [Tanzu Application Catalog / Backstage / etc.]?"** → Different layer. OCM is the delivery format; tools like that are catalogs and developer portals on top. They can — and do — read OCM components. (no slide; off-prompt)
- **"How long to adopt?"** → A team can pack one component in an afternoon. Org-wide standardisation is a quarter to a year, depending on scope. (slide 14)

---

## NOTE — what to leave OUT of this deck even if asked

- **Tool names like Sigstore, Trivy, Grype, S3, OCI registries.** They're in the architect deck. For execs, generic categories ("your scanner", "your registry") land cleaner.
- **Spec details.** Component descriptors, resource access types, plugin system. Architect material.
- **Code.** Not in this deck.
- **Roadmap dates.** Unless asked. The deck makes the case for OCM today; promises about Q3 next year are a different conversation.

---

## DELIVERY NOTES

- **The four-claim title on slide 13 is your credibility moment.** "SAP stewards. NeoNephos governs. Production-grade. Sovereign-ready." — four stop-sentences, each carrying one of the four credibility axes the slide proves. Let the slide speak for two seconds before you fill in the colour with BWI / SAP NS2 / Gardener.
- **Slide 2 (THREE BLIND SPOTS) discharges the slide 1 contract.** Slide 1 promised the audience three minutes to know what the blind spots are. Slide 2 names them in their own vocabulary — identity drift, no release envelope, no callback verification. Without this slide, slide 4 (THE ANSWER) reads as a vendor outcome line, not as the answer to a question the audience has been asked.
- **Slide 5 (THE SHIFT) is the conceptual fulcrum.** If you only have five minutes total, deliver slide 1, slide 2, slide 5, slide 8, and slide 14. Skip everything else. The SBOM-vs-SBOD distinction is the new vocabulary OCM introduces; without it, the rest of the deck doesn't pay off.
- **Slide 7 (HOW OCM COMPOSES) carries the objection-handling.** Pre-empt "we already have this" before the Q&A — slide 7 is built for it.
- **Stop-sentence rhythm.** Hero, slide 13 title, CTA — all use the "stop. stop. stop." stop-sentence rhythm. Honour the pauses; don't rush them.
