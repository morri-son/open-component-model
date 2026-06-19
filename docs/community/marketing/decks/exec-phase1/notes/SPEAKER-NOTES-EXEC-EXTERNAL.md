# Speaker Notes — External Exec Deck (`OCM-Sovereign-Delivery-Exec.pptx`)

**Audience.** External decision-makers — CIOs, CTOs, heads of platform engineering, security or compliance leads at customers, partners, regulated-industry buyers. People who decide whether their organisation invests time in OCM, not the engineers who'll implement it.

**Talk length.** ~13 minutes. Q&A is its own thing — keep the talk tight so questions have room.

**Tone.** Honest, grounded, not preachy. You believe the thing because it's been built and used; that confidence carries — you don't need to oversell. Treat the audience as smart peers; never explain the obvious. No marketing inflation ("revolutionary", "industry-leading"). State what's true; let it land.

**Open with energy, close with an ask.** The middle is allowed to be a calm explanation.

**Cuts.** Slides marked `(NATIVE)`, `(NATIVE A)`, `(NATIVE B)` are PowerPoint-native versions of the same content as their preceding diagram slide — for hand-edit comfort, not for the talk. Pick **one** of each pair and hide the others before presenting. The cadence below assumes you keep one diagram slide per topic.

---

## SLIDE 1 — HERO  (00:00 — 00:45, ~45 sec)

**On screen.** "Your supply chain has Sovereign Clouds." (or whatever the noun-line resolves to in your build).

**Speaker notes.**

Open with the observation, not the company. People are tired of being sold to.

> "Software stopped being a thing you build and started being a thing you transport. Across registries, across borders, across air gaps. And every boundary it crosses, somebody asks: is this still the artifact you signed?"

Pause. Let that land.

> "I'm here for fifteen minutes to show you what we've built so that question has a clean answer. It's called OCM — the Open Component Model. It's open source, governed by the NeoNephos Foundation. SAP stewards it; we're not selling it."

Move on. Don't dwell on the brand row.

---

## SLIDE 2 — WHY NOW  (00:45 — 02:15, ~90 sec)

**On screen.** Three columns: Sovereignty pressure / Compliance is operational / Air-gap is the new normal. (Adjust to whatever your final WHY NOW columns say.)

**Speaker notes.**

Don't read the columns. Frame them.

> "Three things are converging right now, and they're not going away."

**Point at column 1.** Sovereignty.

> "Sovereign-cloud isn't a marketing term anymore. DORA, NIS2, the EU sovereign-cloud rules — these are operational requirements with deadlines. If your software can't be delivered into a regulated environment with an audit trail, you have a 2027 problem, not a 2030 one."

**Point at column 2.** Compliance.

> "Compliance used to be a quarterly project — a team of people producing reports for auditors. That model is breaking. Auditors want continuous evidence now, machine-readable, at the artifact level. Spreadsheets don't scale to that."

**Point at column 3.** Air-gap.

> "And air-gapped delivery — sovereign environments, regulated industries, defence — used to be an edge case. It's the centre of gravity in the markets we work in now. If your delivery model can't survive 'no callback to source', you're not in those markets."

> "This is what's pushing the industry toward something different. Not faster pipelines. Different mechanics."

---

## SLIDE 3 — THE ANSWER  (02:15 — 03:30, ~75 sec)

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

## SLIDE 4a — THE SHIFT  (03:30 — 04:30, ~60 sec)

**On screen.** Title: THE SHIFT. Subtitle: "SBOM lists. SBOD delivers."

**Speaker notes.**

This slide does the conceptual work the rest of the deck builds on. Slow down here.

> "There's a category shift happening in how we think about delivery. SBOMs — Software Bills of Materials — were designed for inventory. They tell you what's inside a piece of software. That's useful, but it's not enough."

> "What you actually deliver is everything around the SBOM — the container images, the Helm chart, the configuration, the manifest of how to deploy it. We call that the SBOD. Software Bill of Delivery."

> "An SBOM lists. An SBOD delivers. The SBOM lives inside the SBOD."

Read the bullets only if the audience is reading them. Otherwise paraphrase the through-line:

> "The point is: OCM doesn't replace your SBOM tooling. It gives the SBOM an envelope — signed once, transports intact, audit-ready at every hop."

---

## SLIDE 4b — THE SHIFT, SBOM INSIDE SBOD  (04:30 — 05:00, ~30 sec)

**On screen.** SBOM-inside-SBOD diagram. Pick **one** of: original SVG, NATIVE A, or NATIVE B variant — depending on what reads best in your room.

**Speaker notes.**

The diagram is the point. Don't talk over it.

> "Visually: this is what an SBOD contains. The container image, the chart, the config files, the SBOM itself. One signed envelope. One identity. Everything you delivered."

Pause. Let people look.

> "If you take one thing from this talk, take this picture."

---

## SLIDE 5 — HOW OCM COMPOSES  (05:00 — 06:30, ~90 sec)

**On screen.** Three columns: SIGNING / TRANSPORT / COMPLIANCE. Each says "your tools today" then "what OCM adds".

**Speaker notes.**

This is the objection-handling slide. Almost everyone in the room is thinking "we already have signing / registries / scanners". Address that head-on.

> "I want to disarm something. You probably hear me say 'OCM' and think — we already have signing. We have registries. We have scanners. Why do I need another thing?"

> "OCM doesn't replace any of that. OCM composes around what you already have."

**Walk through the columns. One sentence each.**

> "Signing: your tools sign individual artifacts. OCM signs the whole release. One signature, every digest. So the signature you check at the destination is one check, not twelve."

> "Transport: your registries are heterogeneous — different vendors, different locations, sometimes air-gapped archives. OCM moves the release across all of them. The identity stays."

> "Compliance: your scanners look at one artifact at a time. OCM correlates findings to the release as a whole. Compliance becomes continuous — not a project that starts every quarter."

> "Same tools. New connective tissue."

---

## SLIDE 6 — OCM IN ONE PICTURE  (06:30 — 08:00, ~90 sec)

**On screen.** Pack · Sign · Transport · Deploy → Sovereign Cloud diagram. Pick the SVG variant or the NATIVE variant — only present one.

**Speaker notes.**

Big diagram, four verbs, this is the demo replacement.

> "Here's the whole flow on one slide. Four verbs."

**Point at PACK.** "Pack. You bundle whatever your software actually needs — the image, the chart, the config — into one named, versioned component. We call this the SBOD."

**Point at SIGN.** "Sign. One signature covers every artifact in the bundle. By digest. So if anything changes, the signature breaks."

**Point at TRANSPORT.** "Transport. The component moves across registry boundaries. Cloud to cloud, region to region, even into an air-gapped archive — without the signature breaking."

**Point at DEPLOY.** "Deploy. At the destination, the receiver verifies the signature, unpacks the bundle, deploys it. No callback upstream. No phone-home. Self-contained."

> "Pack, sign, transport, deploy. That's OCM in operation."

---

## SLIDE 7a — SOVEREIGN-READY  (08:00 — 09:00, ~60 sec)

**On screen.** Title: SOVEREIGN-READY. Subtitle: "Trust, but verify." Four bullets about identity / signature / day-2 / self-contained.

**Speaker notes.**

This is the slide for the regulator-and-CISO conversation.

> "Sovereign-ready isn't a checkbox. It's a property of the delivery model. Four things have to be true."

**Bullet 1.** "Identity is location-independent. The component carries its name regardless of where it lives. Same identity in your dev cluster and in a customer's air-gapped data centre."

**Bullet 2.** "Signatures are location-independent. Sign once at source, verify at every hop down to the destination. No callback upstream."

**Bullet 3.** "Day-2 ops happen inside the boundary. Once a component is in the sovereign environment, you subscribe to it and pull upgrades when needed — still no callback upstream."

**Bullet 4.** "On transfer, the component carries every artifact it needs. Completely self-contained."

> "Trust, but verify. The component is the trust boundary — not the registry, not the network."

---

## SLIDE 7b — SOVEREIGN-READY — AIR-GAP  (09:00 — 10:00, ~60 sec)

**On screen.** Air-gap diagram with source side, trust boundary, target side, transport arrow.

**Speaker notes.**

Reinforce the previous slide visually.

> "On the left: source side. You pack and sign. Public registry, your dev environment, doesn't matter."

> "Down the middle: the trust boundary. This is the air gap, the sovereign cloud edge, the regulated network perimeter. No traffic crosses it without explicit transfer."

> "On the right: sovereign target. The component lands. The local registry receives it. Verification happens locally — same signature, same identity, no upstream traffic. The K8s cluster pulls from the local registry. Auditor signs off based on the component's own evidence."

> "Same identity. Same signature. Any location. That's the property."

---

## SLIDE 8 — SCAN — COMPLIANCE-NATIVE WITH OPEN DELIVERY GEAR  (10:00 — 10:45, ~45 sec)

**On screen.** Title: SCAN. Subtitle: "Compliance as a system property — not a quarterly retrofit." Bullets about Open Delivery Gear, the dashboard, continuous scans, contextual rescoring, evidence by component identity.

**Speaker notes.**

Brief stop here. Don't go deep — this is the "and there's tooling around it" slide.

> "There's an open-source compliance engine that runs on top of OCM. It's called Open Delivery Gear. It scans every component continuously, even after release, and correlates findings by component identity."

> "What that means in practice: when CVE-something-2026 drops at 11pm, you don't ask 'which of our products is affected'. You query the OCM coordinate system, you get a list, and you see the rescored risk for each one."

> "Compliance becomes a property of the system. Not a Q3 deliverable."

---

## SLIDE 9 — WHAT OCM UNLOCKS  (10:45 — 11:30, ~45 sec)

**On screen.** Six tiles: Code signing across stacks · Air-gapped delivery · K8s-native deployment · Async security scans · One source of truth · Automated compliance reporting.

**Speaker notes.**

Don't read the tiles. The audience can read.

> "Six things you get from one shared model. Code signing across the whole stack, not per-tool. Air-gapped delivery as a built-in, not a workaround. Kubernetes-native deployment via OCM controllers. Continuous async security scans. A single signed source of truth you can rebuild any landscape from. And compliance reporting that flows from the SBOD itself — no spreadsheets."

> "All from one model. That's the point."

---

## SLIDE 10 — TRUSTED IN PRODUCTION  (11:30 — 12:00, ~30 sec)

**On screen.** Adopter logos: NeoNephos, SAP, BWI, SAP NS2, Gardener, Konfidence, OpenControlPlane, Platform Mesh.

**Speaker notes.**

Ground the credibility. Be honest about scale; don't oversell.

> "OCM isn't a research project. Gardener — SAP's open-source Kubernetes orchestrator — has used OCM in production for over five years. It's how Gardener delivers landscape components across cloud providers and into sovereign environments."

> "It's been adopted by SAP, by BWI — Germany's federal IT service — by SAP NS2 for regulated US workloads, and by a growing peer ecosystem: Konfidence, OpenControlPlane, Platform Mesh. Aligned with the NeoNephos Foundation, which now governs it."

> "Open source. Production-grade. Industry-aligned."

---

## SLIDE 11 — CTA  (12:00 — 12:45, ~45 sec)

**On screen.** "Start delivering with confidence." Three action lines: Try it / Build with us / Talk to us.

**Speaker notes.**

Close with an ask. Plain language.

> "Three ways forward."

> "Try it. Go to ocm.software, install the CLI, pack one of your existing components into an OCM component. It takes maybe twenty minutes. You'll know within an hour whether this fits your delivery."

> "Build with us. Github dot com slash open-component-model. The code is there, the discussions are there, the roadmap is in the open."

> "Talk to us. There's a community Slack, mailing list, and steering meetings — all linked from the website. If your organisation is at the regulatory pressure point I described at the start, we want to hear about your delivery problem in your words. We're not selling. We're building the standard. The more voices in the room while it's being shaped, the better the standard gets."

> "That's it. Thank you."

(Then: take questions.)

---

## TIMING TOTAL

| Slide | Duration |
|---|---|
| 1 — Hero | 0:45 |
| 2 — WHY NOW | 1:30 |
| 3 — THE ANSWER | 1:15 |
| 4a — THE SHIFT | 1:00 |
| 4b — SBOM IN SBOD | 0:30 |
| 5 — HOW OCM COMPOSES | 1:30 |
| 6 — OCM IN ONE PICTURE | 1:30 |
| 7a — SOVEREIGN-READY | 1:00 |
| 7b — AIR-GAP | 1:00 |
| 8 — SCAN | 0:45 |
| 9 — WHAT OCM UNLOCKS | 0:45 |
| 10 — TRUSTED IN PRODUCTION | 0:30 |
| 11 — CTA | 0:45 |
| **Total** | **12:45** |

Buffer: 15-20 seconds you can spend on a question or pause; if the audience is engaged, slides 5 and 6 absorb extra time naturally.

---

## Q&A PREP — questions that come up

- **"Is this another SBOM standard?"** → No. OCM is about delivery. SBOMs are inputs to it. SPDX, CycloneDX — both fit inside an OCM component. (slide 4a)
- **"Do I throw away my container registry?"** → No. OCM sits on top. Your OCI registry stores the same images. (slide 5)
- **"Is it Sigstore-compatible?"** → Yes. Sigstore is a first-class signing backend. Classical RSA also supported. (slide 5 / 6)
- **"Who pays for it?"** → It's open source under NeoNephos governance. SAP funds the core engineering. Production use is free. (slide 10)
- **"What's the lock-in?"** → Open standard, open spec, open implementation. Nothing proprietary. The point of standardising is to *prevent* lock-in. (slide 10 / 11)
- **"How does this compare to [Tanzu Application Catalog / Backstage / etc.]?"** → Different layer. OCM is the delivery format; tools like that are catalogs and developer portals on top. They can — and do — read OCM components. (no slide; off-prompt)
- **"How long to adopt?"** → A team can pack one component in an afternoon. Org-wide standardisation is a quarter to a year, depending on scope. (slide 11)

---

## NOTE — what to leave OUT of this deck even if asked

- **Tool names like Sigstore, Trivy, Grype, S3, OCI registries.** They're in the architect deck. For execs, generic categories ("your scanner", "your registry") land cleaner.
- **Spec details.** Component descriptors, resource access types, plugin system. Architect material.
- **Code.** Not in this deck.
- **Roadmap dates.** Unless asked. The deck makes the case for OCM today; promises about Q3 next year are a different conversation.
