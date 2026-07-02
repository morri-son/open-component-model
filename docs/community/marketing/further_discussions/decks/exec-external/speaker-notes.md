# Speaker Notes

## Slide 1: Your supply chain has

(no notes)

## Slide 2: THREE BLIND SPOTS

Deliver on the promise from slide 1. Three picturable failures the audience can recognise in their own delivery chain. The slide is intentionally sparse - let the audience read; you fill in the colour.
> "Three blind spots. Each one is a place the current model literally cannot see."

**Column 1 - Identity drift.** "You signed an artifact at source. Then it moved - to a mirror, to a customer's registry, into an air gap. Each of those transfers changed its reference, because location is part of the name. Downstream verifies a reference you never signed - and most chains don't notice."

**Column 2 - No release envelope.** "A release is twelve things - images, charts, configs, manifests, an SBOM. Today, those get signed separately, if at all. So when a regulator asks for proof that *the release* is what you said it is, you hand them twelve signatures and an explanation."

**Column 3 - Unverified arrival.** "Sovereign-cloud and regulated environments forbid upstream traffic. So either verification ships with the release, or it doesn't happen. In most chains, it doesn't - and the gap shows up at audit time."

> "Those are the blind spots. Now - why now."

Hand off to slide 3.

## Slide 3: WHY NOW

Don't read the columns. Frame them. The audience has just been shown what is broken; now name why it matters this quarter, not next year.

> "Three things are converging right now, and they're not going away."

- Column 1 - Sovereignty pressure. "The law draws boundaries - by jurisdiction, by sector, by air-gap.
Software must be deliverable inside each one. If your delivery model can't survive 'no callback to source' inside
a regulated environment, you're not in those markets anymore."

- Column 2 - Regulation tightening. "EU DORA, NIS2, CRA - all want provable supply-chain control.
Not 'best effort'. Provable. Machine-readable evidence, at the artifact level, traceable end-to-end."

- Column 3 - Supply-chain attacks. "SolarWinds. xz. log4shell.
These weren't theoretical risks - they were live in production.
The lesson the industry took: signatures must survive the journey, or compliance is theatre."

> "This is what's pushing the industry toward something different. Not faster pipelines. Different mechanics."

## Slide 4: THE ANSWER

Wait two seconds before talking. Let people read the diagram.

> "OCM is one model that ties three things together - your artifacts, your deployment boundaries, and the regulations you're delivering against."

> "On the left: every artifact type. Container images, Helm charts, configuration files, binaries. OCM doesn't care what shape your software comes in."

> "On the right: every boundary. EU, US, sovereign cloud, customer-owned. Same identity, same signature, regardless of where the component lives."

> "And underneath: every compliance regime. DORA, NIS2, CRA - plus the sector-specific ones. OCM gives you the evidence model the regulators are asking for."

> "Meet OCM. One identity, every boundary."

That's the headline. Move on.

## Slide 5: THE SHIFT

This slide does the conceptual work the rest of the deck builds on. Slow down here.

> "There's a category shift happening in how we think about delivery. SBOMs - Software Bills of Materials - were designed for inventory. They tell you what's inside a piece of software. That's useful, but it's not enough."

> "A Software Bill of Delivery - SBOD - tells you what you actually delivered. How to verify it, how to transport it, how to operate it. The container images, the Helm chart, the configuration, the manifest of how to deploy."

> "An SBOM lists. An SBOD delivers. The SBOM lives inside the SBOD."

Read the third bullet only if the audience is reading it. Otherwise paraphrase:

> "The point is: OCM doesn't replace your SBOM tooling. It gives the SBOM an envelope."

## Slide 6: THE SHIFT - SBOM INSIDE SBOD

The diagram is the point. Don't talk over it.

> "Visually: this is what an SBOD contains. Container images, charts, manifests, configs, the SBOM itself. One signed envelope. One identity at the top. Everything you delivered."

Pause. Let people look.

> "If you take one thing from this talk, take this picture."

## Slide 7: HOW OCM COMPOSES

This is the objection-handling slide. Almost everyone in the room is thinking "we already have signing / registries / scanners". Address that head-on.

> "Disarm something first. You probably hear me say 'OCM' and think - we already have signing. We have registries. We have scanners. Why do I need another thing?"

> "OCM doesn't replace any of that. OCM composes around what you already have."

Walk through the columns. One sentence each. The slide gives you setup; you deliver the punchline.

> "Signing: you sign artifacts today. OCM signs the release as a whole - one signature, every digest. So the signature you check at the destination is one check, not twelve."

> "Transport: your registries differ - by vendor, by location, sometimes air-gapped archives. OCM moves the release across all of them. The identity stays."

> "Compliance: your scanners look at one artifact at a time. OCM correlates findings to the release. Compliance becomes continuous - not a project that starts every quarter."

> "Same tools. New connective tissue."

## Slide 8: OCM IN ONE PICTURE

Big diagram, four verbs, this is the demo replacement.

> "Here's the whole flow on one slide. Four verbs."

**Point at PACK.** "Pack. You bundle whatever your software actually needs - the image, the chart, the config - into one named, versioned component. One source of truth."

**Point at SIGN.** "Sign. One signature covers every artifact in the bundle. By digest. So if anything changes, the signature breaks."

**Point at TRANSPORT.** "Transport. The component moves across registry boundaries. Cloud to cloud, region to region, even into an air-gapped archive - without the signature breaking."

**Point at DEPLOY.** "Deploy. At the destination, the receiver verifies the signature, unpacks the bundle, deploys it. GitOps or OCM K8s controllers - your choice. No callback upstream."

> "Pack, sign, transport, deploy. That's OCM in operation."

## Slide 9: SOVEREIGN-READY

This is the slide for the regulator-and-CISO conversation.

> "Sovereign-ready isn't a checkbox. It's a property of the delivery model. Four things have to be true."

**Bullet 1 - Identity.** "Location-independent. The component carries its name regardless of registry. Same identity in your dev cluster and in a customer's air-gapped data centre."

**Bullet 2 - Signatures.** "Location-independent. Sign once at source, verify anywhere downstream. No callback upstream."

**Bullet 3 - Day-2 ops.** "Inside the boundary. Once a component is in the sovereign environment, subscribe to it, pull upgrades, scale across regions. Still no callback."

**Bullet 4 - Transfer.** "Self-contained. Every artifact travels with the component. The destination needs nothing more."

> "Trust, but verify. The component is the trust boundary - not the registry, not the network."

## Slide 10: SOVEREIGN-READY - AIR-GAP

Reinforce the previous slide visually.

> "On the left: source side. You pack and sign. Public registry, your dev environment, doesn't matter."

> "Down the middle: the trust boundary. This is the air gap, the sovereign cloud edge, the regulated network perimeter. No traffic crosses it without explicit transfer."

> "On the right: sovereign target. The component lands. The local registry receives it. Verification happens locally - same signature, same identity, no upstream traffic. The K8s cluster pulls from the local registry. Auditor signs off based on the component's own evidence."

> "Same identity. Same signature. Any location. That's the property."

## Slide 11: SCAN

Brief stop here. Don't go deep - this is the "and there's tooling around it" slide.

> "There's an open-source compliance engine that runs on top of OCM. It's called Open Delivery Gear - ODG. Built on the same primitives as the rest of OCM."

> "ODG scans every component continuously, even after release, and correlates findings by component identity. Auditors get evidence, not spreadsheets."

> "What that means in practice: when CVE-something-2026 drops at 11pm, you don't ask 'which of our products is affected'. You query the OCM coordinate system, you get a list, and you see the rescored risk for each one - patch what matters, not the noise."

> "Compliance becomes a property of the system. Not a Q3 deliverable."

## Slide 12: WHAT YOU GET

Pause. Let them read the tiles. Two seconds. They will read them whether you talk or not.Then one line to frame:"Six outcomes. All of them coming from the same model. That's the point of the slide. Not that OCM does six things, but that all six come out of one primitive."Now walk the tiles. One concretising sentence each. Not the tile title again. What the tile title doesn't say.- Artifact signing across stacks. "Today you have cosign for images, package signatures for charts, something else for SBOMs. Every tool signs a different thing, no two verify the same way. With OCM the whole release is signed once and every downstream verifier does the same check."- Air-gapped delivery. "Regulated customers don't just want signatures. They want to run the verification themselves, offline, on their own hardware. OCM was designed for that from day one. Nothing in the verify path calls upstream."- Kubernetes-native deployment. "The OCM K8s controllers verify and apply components directly. No shell scripts around your Helm install to bolt on integrity. The check is the deploy path."- Asynchronous security scans. "A CVE dropping two months after release used to mean 'rebuild the world'. With OCM the finding attaches to the component identity, so you know exactly which shipped release is affected and where it went. You patch the affected components, not the fleet."- One source of truth. "When a landscape has to be rebuilt, from scratch, in a new region, or after a compliance decision, today it's manual archaeology across tickets and configs. With OCM: one signed descriptor per delivery, and the landscape rebuilds from that."- Automated compliance reporting. "Auditors ask for SBOMs, VEX, provenance, attestations. Today those live in spreadsheets that go stale the moment they're produced. With OCM the reports are composed from the SBOD metadata itself, so they don't drift from what actually shipped."Land it:"Six outcomes. One model. That's what OCM unlocks."

## Slide 13: TRUSTED IN PRODUCTION

Ground the credibility. Be honest about scale; don't oversell. The title carries four claims - let it speak; you fill in the colour.

> "OCM isn't a research project. SAP stewards the engineering investment. NeoNephos - the foundation - governs the standard. The result is in production today."

**Point at the top row.** "BWI is Germany's federal IT service. SAP NS2 handles regulated US workloads. Both run on OCM. That's the production proof."

**Point at the bottom row.** "And a peer ecosystem has converged around the model. Gardener - SAP's open-source Kubernetes orchestrator, in production for over five years. Kyma. OpenControlPlane. Platform Mesh. Each does something different; each builds on the OCM primitive."

> "Aligned with NeoNephos. Open source. Production-grade."

## Slide 14: Start delivering with confidence.

Close with the ask. Plain language. The asks are exec-shaped - pilot a delivery, hear back from the team that ran it, bring your delivery problem to the standard while it's being shaped. The CLI and the GitHub repo are still in the footer for any platform lead in the room, but they are not the headline.

> "Three asks."

> "Pilot. Pick one regulated delivery you're already shipping. Pack it as an OCM component this quarter. Not a proof of concept in a sandbox - something real, something that's already going through compliance friction. That's where the early payoff is."

> "Evaluate. Have your platform-engineering and security leads brief you on what they found. If the model fits your delivery, they'll come back saying so without prompting.."

> "Engage. Bring your delivery problem to the steering conversation. The standard is open and being shaped right now. The reality of what you ship is the input we need. ocm.software for the entry point - github dot com slash open-component-model for the code - community Slack and steering meetings linked from the website."

> "Pilot. Evaluate. Engage. That's the ask. Thank you – Time for questions

## Slide 15: APPENDIX - ABBREVIATIONS

(no notes slide)

## Slide 16: TRADEMARK & LICENSE NOTICES (1/2)

(no notes slide)

## Slide 17: TRADEMARK & LICENSE NOTICES (2/2)

(no notes)

