# Speaker Notes

## Slide 1: Every LoB ships

Open with the observation. No preamble."Every line of business at SAP ships its own delivery. Signing. Transport. Sovereign-cloud readiness. Compliance reporting. Each LoB built its own version of all of that. Each one operates it independently."Pause. Let it land. If the room nods, you have the next ten minutes."OCM is the shared standard for that work. Open source, governed by NeoNephos, stewarded by SAP. Each LoB still ships its own products. What changes is that they ship on the same model. Same vocabulary. Same signing primitive. Same transport story. Same compliance evidence.""Today: why that matters now, where we already are, and what the choice in front of us is."Move on.

## Slide 2: WHY NOW

Don't read the columns. Frame the choice."The subtitle is the whole pitch in one line: compliance and sovereignty are given. We're not arguing about whether DORA, NIS2, sovereign-cloud delivery are real. They are. Table stakes for the markets we serve. The strategic question is what shape SAP shows up in."Column 1, Ecosystem Velocity. "The peer ecosystem is converging. Gardener, Kyma, OpenControlPlane, Konfidence, Platform Mesh. All aligned around the OCM primitive. SAP is currently the biggest contributor, by a comfortable margin. The biggest contributor shapes the standard. That's true today. It'll be true in two years about whoever the biggest contributor is then."Column 2, The Window. "The rails are being laid right now. NeoNephos governance is forming. CRA enforcement starts. The sovereign-cloud market is taking shape. Late entrants pay migration cost. Early stewards keep optionality and shape the standard around their use cases."Column 3, Disinvestment. "Walking away costs more than staying. Each LoB that builds its own retrofit pays the cost OCM was supposed to amortise. The standard gets shaped without us. Competitors who keep investing get the standard built around their preferences.""The choice isn't 'should we adopt OCM'. We already did. The choice is whether we keep the steering position or hand it over."

## Slide 3: THE ANSWER

Brief. Refresh, not introduction. The audience knows what OCM is."What OCM ties together. Left: every artifact type. Images, charts, npm, binaries, config. Right: every deployment boundary. EU, US, sovereign cloud, customer-owned. Below: every compliance regime. DORA, NIS2, CRA.""One identity. Every boundary. That's the model."Move on.

## Slide 4: THE SHIFT

Bullets first, diagram on the next slide."There's a category shift. SBOMs were built for inventory. What's-in-the-software. SBODs, Software Bill of Delivery, are built for delivery. What-was-shipped-where-and-how-to-verify. The SBOD contains the SBOM."Bullet 4 specifically, the political one. "SBOD is the category SAP defined. Now standardised through NeoNephos. That's the position the disinvestment slide was talking about. A place where SAP is the one defining the vocabulary, and the industry adopts it. That position has value. It's worth protecting.""OCM doesn't replace your SBOM tooling. It gives the SBOM an envelope. Signed once, transports intact, audit-ready at every hop."

## Slide 5: THE SHIFT - SBOM INSIDE SBOD

Show the picture. The explanation happened on the previous slide."Visually: the SBOD. Container image, chart, manifests, config, the SBOM itself. One signed envelope. One identity at the top: `github.com/acme/webshop:v1.0.0`. Everything that was delivered, with one signature covering all of it."Pause."Internally, this picture is what every LoB needs. Today, every LoB has its own version of it. With OCM, they share the picture."

## Slide 6: HOW OCM COMPOSES

Internal twist. This isn't competing with what LoBs already have. It's the connective tissue."Whenever I show this internally, the first reaction is 'we already have signing, we already have registries, we already have scanners.' Right. Of course you do. OCM doesn't replace any of that. OCM composes around what each LoB already has."Walk the columns. Slide gives setup. You deliver the punchlines."Signing: you sign artifacts. OCM signs the release as a whole. One signature, every digest. When audit shows up, you don't track twelve signatures across twelve artifacts. You track one.""Transport: your registries differ. By type, by location, by LoB. OCM moves the release across them all. Same identity. Same signature.""Compliance: your scanners see one artifact at a time. OCM correlates findings to the release. Compliance becomes continuous, not a quarterly project each LoB runs separately.""What this means for SAP: instead of every LoB owning its own signing-transport-compliance pipeline, every LoB plugs into the same primitive. Investment compounds across LoBs. That's the leverage."

## Slide 7: OCM IN ONE PICTURE

"The whole flow on one slide. Four verbs."- PACK. "Bundle every artifact your software needs into one named, versioned component. One source of truth."- SIGN. "One signature covers every artifact in the bundle by digest."- TRANSPORT. "Move the bundle across registry boundaries. Cloud to cloud, region to region, into an air-gapped archive. Without breaking the signature."- DEPLOY. "At the destination, verify the signature, unpack, deploy. GitOps or OCM K8s controllers, your team's call. No callback upstream.""Every LoB at SAP has built some version of this. Some are mature, some are partial, some are still spreadsheets. With OCM, they're all on the same picture. The work to mature one LoB's version helps every other LoB."

## Slide 8: SOVEREIGN-READY

"Sovereign-ready isn't a checkbox. It's a property of the delivery model. Four things have to be true."- Identity. "Location-independent. The component carries its name regardless of registry."- Signatures. "Location-independent. Sign once at source, verify anywhere downstream. No callback upstream."- Transfer. "Self-contained. Every artifact travels with the component."- Day-2 ops. "Happen inside the boundary. Subscribe to the component, pull upgrades, scale across regions. Still no callback.""Several SAP LoBs are already shipping into sovereign environments today. Those four properties are how they get away with it."

## Slide 9: SOVEREIGN-READY - AIR-GAP

Reinforce visually."Source side, left. Pack and sign. Public registry or your dev environment, doesn't matter.""Trust boundary, middle. The air gap. The sovereign-cloud edge. The regulated network perimeter.""Sovereign target, right. Component lands. Local registry receives it. Verification happens locally. Same signature, same identity. K8s cluster pulls from local. Auditor signs off based on the component's own evidence.""Same identity. Same signature. Any location."

## Slide 10: SCAN

Brief stop. Internally everyone should now know the OCM Gear / ODG. You don't need to introduce it. If you see eybrows raising, stop and explain more on the first bullet point."Open Delivery Gear is the OCM-native compliance engine. ODG dashboard is the entry point. Every component, every finding, one view. Continuous scans run asynchronously, even after release. Findings get rescored against contextual risk. The team only patches what actually matters, not the noise. Every signal correlates by component identity. Auditors get answers, not spreadsheets.""Internally: when a CVE drops, the question 'which SAP product is affected' isn't a fire drill across LoBs. It's a query. The OCM coordinate system answers it."

## Slide 11: WHAT SAP GETS

Pause. Let them read the six tiles. Two seconds. They will read them whether you talk or not.Then one line to frame:"Six outcomes. All of them cross-LoB by construction. The point isn't that OCM does six things. The point is that all six come from the same primitive, so the investment compounds."Now walk the tiles. One concretising sentence each. NOT THE TILE TITLE AGAIN !!! What the tile title doesn't say.- Faster sovereign delivery. "Today every LoB negotiates its own air-gap procedure with the customer. With OCM they don't. The customer verifies once, at the destination, the same way for every SAP product."- Compliance leverage across LoBs. "Right now, when a regulator asks for the security posture of SAP, they get eight different answers from eight LoBs. With OCM, they get one query against one coordinate system. Same regulator, same auditors, dramatically less work."- Integration after acquisition. "When SAP acquires, the new company almost never ships the way we do. Twelve months of retrofit. With OCM, both sides publish components in the same shape and the integration starts at day one instead of month twelve."- Cross-LoB security correlation. "Log4Shell dropped on a Friday night. The question 'which SAP product is affected' cost weeks. With OCM that's a query against the coordinate system, answered in an afternoon."- One source of truth. "If a datacenter has to be rebuilt because of a regional failure or a compliance decision, today it's a manual reconstruction from tickets and Slack. With OCM, one signed descriptor per delivery, and the landscape rebuilds from the descriptor."- Ecosystem stewardship. "This is where the sponsor question becomes an investment question. SAP funds the standard, the ecosystem shapes around SAP's use cases. Walk away and the standard shapes around whoever fills the seat."Land it:"Six outcomes. One model. Cross-LoB by construction."

## Slide 12: WHERE OCM IS SHIPPING - OPEN ECOSYSTEM

Quick tour. Don't dwell."Outside SAP, here's where OCM is shipping. Gardener, in production for over five years, the managed Kubernetes layer. Kyma, the cloud-native runtime. OpenControlPlane, the control-plane framework. Konfidence, reproducible delivery. All aligned with NeoNephos, which now governs the standard.""This is the velocity I mentioned at the start. It's real, and it's accelerating."

## Slide 13: WHERE OCM IS SHIPPING - SAP

Internal evidence. Be specific."Inside SAP: five pieces of delivery infrastructure already on OCM.""Hyperspace, internal Dev Portal and product delivery. RBSC, the Release-Based Shipment Channel, customer shipments. CSI, Common Service Infrastructure, the shared internal services platform. Steampunk for ABAP development. Sovereign Services and Delivery, operating SAP products inside sovereign clouds.""This isn't theoretical. SAP is already running on it. The question is whether SAP keeps stewarding the standard or hands the steering wheel over."

## Slide 14: Sponsor. Scale. Standardize.

Close with the actual ask. Plain, no posturing."Three asks.""Sponsor. Allocate engineering capacity to OCM stewardship in your LoB. Concretely: name a person, name the percentage, write it into the next quarter's plan.""Scale. Pack one regulated component as an OCM component this quarter. Pick something that's already going through compliance friction. That's where the early payoff is.""Standardize. Bring your LoB into the OCM steering conversation. SAP Slack, channel #sap-tech-ocm. The earlier your LoB's voice is in the room, the more the standard reflects your delivery reality.""Sponsor. Scale. Standardize. That's the ask.""Thank you."Take questions.

## Slide 15: APPENDIX - ABBREVIATIONS

Appendix only. Pull on demand if the audience stalls on a term. Don't narrate.Quick spot-checks worth knowing without reading: SBOD is the OCM component descriptor, the category SAP defined and NeoNephos governs. ODG is Open Delivery Gear, the OCM-native compliance engine. DORA, NIS2, CRA are the EU regulatory anchors most sponsors already know. Restate only if asked.

## Slide 16: TRADEMARK & LICENSE NOTICES (1/2)

(no notes slide)

## Slide 17: TRADEMARK & LICENSE NOTICES (2/2)

(no notes slide)

