# Speaker Notes

## Slide 1: Your supply chain has

The words "blind spots" on the slide are the whole payload. Don't read the slide.

Say roughly: "Your supply chain has blind spots. In the next fifteen minutes I'll show you three of them, and the model that closes them."

Don't preview the answer. Slide 2 discharges the promise.


## Slide 2: THREE BLIND SPOTS

Discharge the promise from slide 1. Three concrete failure modes in the delivery chain the audience is already running.

Frame: signed at source, broken by the time it lands. Three places that happens.

Identity drift. Every artifact reference carries its location. Push the image to a mirror, to a customer's registry, into an air-gapped archive, and the reference changes at each hop. The signature was on the old reference. Downstream verifies the new reference, and either the check fails or, more commonly, silently trusts a reference that was never signed. Most chains never notice, because nothing checks end-to-end.

No release envelope. A release is twelve things: images, charts, config, manifests, an SBOM, sometimes a database migration. Today those get signed individually, when they get signed at all. A regulator asks "prove this release is what you shipped" and the honest answer is twelve signatures and a spreadsheet.

Unverified arrival. Sovereign zones, air-gapped estates, regulated financial environments forbid callbacks upstream. If verification depends on reaching Rekor, Fulcio, an internal PKI, or the source registry, verification does not happen inside the boundary. Either the release travels with everything needed to verify itself, or the audit catches the gap.

Land: those are the blind spots. Now why they matter this quarter.

Q&A:
"Doesn't cosign solve identity drift?" No. Cosign signs by digest but the reference still includes registry. OCM signs the canonical descriptor, which is location-independent.
"Isn't in-toto a release envelope?" In-toto attests to build-pipeline steps. OCM signs the delivered artifact set. Compatible layers, different jobs.


## Slide 3: WHY NOW

Time-pressure. Not sequential, converging.

Frame: three forces. All of them push toward the same decision, and none of them are going away.

Sovereignty pressure. The law draws boundaries by jurisdiction (EU, US, national), by sector (finance, defence, health), and physical (air-gap). If the delivery model cannot survive "no callback to source" inside one of those boundaries, the release does not ship into those markets. Already true for federal work in Germany and France. Becomes true for most regulated EU customers through 2026 and 2027.

Regulation tightening. DORA is in force. NIS2 transposition is landing across member states. CRA obligations phase in through 2027. All three demand provable supply-chain control at the artifact level. Machine-readable evidence, traceable end-to-end. Most delivery chains produce spreadsheets, not evidence.

Supply-chain attacks. SolarWinds, xz, log4shell. All three signed. Signatures did nothing because verification never ran at the destination. The lesson: signatures must survive the journey and be verified where the software lands, or destination verification fails.

Land: not faster pipelines. Different mechanics.

Q&A:
"Does CRA mandate SBOMs?" Yes for products with digital elements from 2027. The bigger obligation is provable due diligence on components across the lifecycle. OCM covers both.
"NIS2 vs DORA?" NIS2 is horizontal cybersecurity baseline for essential entities. DORA is finance-sector-specific with more prescriptive obligations. OCM's evidence model satisfies the technical parts of both.


## Slide 4: THE ANSWER

Pivot from problem to solution. The diagram carries the slide.

Left: every artifact type. OCI images, Helm charts, npm packages, binaries, config. OCM does not care about the shape.

Right: every deployment boundary. EU, US, sovereign, customer-owned. Same identity in each.

Bottom: every compliance framework. DORA, NIS2, CRA today. FedRAMP, BSI C5, SecNumCloud tomorrow. Same evidence model, whichever regime applies.

Bottom-right: v1.0.0. Released, in production. Not a research paper.

Land: one identity, every boundary.

Q&A:
"Is OCM a registry?" No. OCM is a specification and tooling above the registry. Any OCI-compliant registry stores an OCM component.
"Is this SAP-only?" No. OCM is at NeoNephos Foundation under Linux Foundation Europe. Vendor-neutral. SAP is the largest contributor.


## Slide 5: THE SHIFT

Conceptual pivot the rest of Act 2 depends on. Slow down here.

SBOM. Software Bill of Materials. Designed for inventory: what is inside a piece of software. Useful for vulnerability lookup, licence compliance, provenance. Not designed to describe delivery.

SBOD. Software Bill of Delivery. What you delivered, how to verify it, how to transport it, how to operate it. Designed for delivery, not just inventory.

The SBOM lives inside the SBOD. OCM does not replace SBOM tooling. It wraps it. That's the disarm: keep saying that until someone in the room visibly relaxes.

Land the stop-line: "Your SBOM still runs. Now it travels with a name and a signature." Pause. Slide 6 shows what that looks like.

Q&A:
"Is SBOD a standard?" It's the marketing-facing name. On the wire it's the OCM component descriptor. Same object. Defined in the spec at ocm.software.
"Does the SBOM live literally inside the descriptor?" Yes. As a resource with a defined type (SPDX or CycloneDX). One digest of the descriptor covers the SBOM plus everything else in the bundle.


## Slide 6: THE SHIFT - SBOM INSIDE SBOD

The diagram is the answer to "what does the SBOD actually contain?": container images, Helm charts, deployment manifests, configuration, the SBOM. One envelope, one identity at the top, one signature on the right.

The identity line matters: github.com/acme/app:v1.0.0. Same reference in the dev registry, in a customer's cloud registry, in an air-gapped archive. That is location-independent. This becomes load-bearing on slide 9.

If they take one picture home, this is it.

Q&A:
"5 GB Helm chart?" OCM stores by digest in an OCI registry. Blob deduplication works normally. Size is a registry concern.
"Signature format?" Default is RSASSA-PSS over the canonical descriptor. OpenPGP and Sigstore in the CLI. K8s controller v1alpha1 is RSA-only. OpenPGP and Sigstore on the controller roadmap.


## Slide 7: HOW OCM COMPOSES

Objection-handling. Everyone is thinking: we already sign, we have registries, we run scanners. Address it head-on.

OCM does not replace any of that. OCM composes around what is there.

Signing. Cosign for images, package signatures for charts, GPG for tarballs. Every tool signs a different thing. No two verifiers do the same check. OCM signs the release as one unit. Every downstream verifier does the same check whatever the artifact mix.

Transport. Registries differ: cloud vendor, on-prem, air-gapped archive. Moving a release today means re-tagging, re-signing, re-referencing. OCM moves the descriptor plus every referenced blob in one operation. Identity stays the same at every stop.

Compliance. Scanners look at one artifact at a time. OCM correlates findings to the release, because every artifact carries the release identity. The question shifts from "which images are affected" to "which shipped releases contain an affected artifact."

Land: same tools. OCM sits between them and gives the release one name.

Q&A:
"Does OCM replace cosign?" No. Cosign remains valid for per-artifact signing. OCM adds a release-level signature over the descriptor.
"Policy engines (Kyverno, Gatekeeper)?" OCM ships no admission webhook. Global enforcement is BYO: Kyverno, Gatekeeper, or custom, verifying the OCM signature at admission. Some SAP-internal teams already run this in production.


## Slide 8: OCM IN ONE PICTURE

Payoff of Act 2. Four verbs, one arrow.

Pack. Bundle whatever the release needs. Image, chart, config, manifest. Into one named, versioned component. One source of truth.

Sign. One signature covers every artifact in the bundle, by digest. If anything changes, the signature breaks.

Transport. The component moves across registry boundaries. Cloud to cloud, region to region, air-gapped archive. Signature intact throughout.

Deploy. At the destination, the receiver verifies the signature, unpacks the bundle, deploys. GitOps or OCM K8s controllers. No callback upstream.

Land: pack, sign, transport, deploy. That's the whole model.

This slide is byte-identical across all four OCM decks. The most portable asset in the whole talk.

Q&A:
"Which controller?" ocm-k8s-toolkit, v1alpha1. Reconciles Component resources by verifying and deploying referenced artifacts. RSA today.
"Must I use the K8s controllers?" No. Flux and Argo CD both consume OCM components with community adapters. The CLI does the same job scripted.


## Slide 9: SOVEREIGN-READY

Regulator and CISO slide. They are deciding whether the model survives inside their compliance perimeter.

The title is the claim. The two bullets prove it. Land the title first, pause, then walk the bullets.

Bullet 1: the release lands as one unit. Identity (the name, not a URL, so it doesn't encode a registry), signature (one hash over every artifact in the bundle), artifacts (images, charts, config, SBOM), and day-2 metadata. Everything the destination needs arrives together.

Bullet 2: the consequence. Verification runs locally against the signature and the pinned public key. The K8s controller verifies without callbacks to Rekor, Fulcio, or an internal PKI, provided the trusted-root file has been delivered once, out of band. Upgrades, patches, and horizontal scale all run against the local registry. The boundary is never crossed after initial delivery.

The refrain: nothing reaches back upstream. Say it after each bullet if the room is a regulated-industry one.

Slide 10 shows the same story as a diagram. Don't pre-explain the diagram here; let it land on its own.

Q&A:
"Can't cosign do this?" cosign verifies one image. What's missing is one signature over the complete set: this image, this chart, this config, this SBOM, as the intended release. OCM signs the bundle. cosign signs the piece.
"What about the trusted-root for Sigstore air-gap?" Works offline once the trusted-root file (Fulcio CA plus Rekor public key) has been distributed to the destination out of band. After that, no callback. RSA and OpenPGP need only the pinned public key, no trusted-root file.

Land: the component is the trust boundary. Not the registry, not the network, not the certificate chain.

Q&A:
"Bring our own KMS?" RSA today. OpenPGP and Sigstore in the CLI. K8s controller v1alpha1 is RSA-only. Other schemes on the controller roadmap for v1alpha2.
"Air-gap Sigstore verify?" Works offline once the trusted-root file (Fulcio CA plus Rekor public key for your OIDC issuer) has been delivered once.
"Different digest algorithm at destination?" Doesn't matter. OCM signs the canonical descriptor, not the storage form.
"Global enforcement?" No admission webhook ships with OCM. BYO with Kyverno or Gatekeeper.


## Slide 10: SOVEREIGN-READY - AIR-GAP

Visual proof of the previous slide.

Left, source. Public registry, dev registry, doesn't matter. Where the release is packed and signed. Upstream-connected, normal operation.

Middle, the trust boundary. Air gap, sovereign cloud edge, regulated network perimeter. No traffic crosses this without explicit transfer. The transfer is deliberate, auditable, one-time.

Right, sovereign target. The component lands in a local registry inside the boundary. Verification runs locally against the trusted-root file already present. The K8s cluster pulls from the local registry, not from outside. The auditor signs off based on the component's own evidence, which travelled with the release.

Land: same identity, same signature, any location. That is the property.

If asked about customers: BWI runs this pattern for German federal workloads. SAP NS2 for regulated US workloads. Both in production.

Q&A:
"Trusted-root delivery?" One-time, out of band. Same way a root CA gets delivered today. Once inside the boundary, no update path needed until roots rotate.
"Fully offline target?" Same model. ocm transfer produces a signed self-contained archive that crosses the air gap on physical media. Verified and unpacked at destination.


## Slide 11: SCAN

Tooling slide. Brief.

There is an open-source compliance engine on top of OCM: Open Delivery Gear (ODG). Same primitives as the rest of OCM.

Continuous scanning of every OCM component in the landscape. Findings correlate by component identity, not artifact path. Rescoring picks up context: is this artifact actually deployed, is it network-facing, is a patch already committed. Important findings surface. The dashboard is one view across every release.

The scenario that makes this concrete: a CVE lands at 11pm with CVSS 9.8. Instead of asking "which of our products contains this library", query the OCM component graph. Get a list of shipped releases affected. Rescored priority on each. Patch what matters. Not the fleet.

Land: continuous compliance. Not quarterly audits.

Q&A:
"Must I run ODG?" No. OCM works standalone. ODG is complementary, using OCM as substrate.
"Where does ODG live?" GitHub, at open-component-model. Apache-2.0.
"How does rescoring work?" ODG combines vulnerability data, deployment reachability, and configurable business context. Rules are declarative, versioned in the same repo as the OCM components.


## Slide 12: WHAT YOU GET

Payoff. Six tiles. All fall out of the same signed descriptor. Not six features bolted together, one primitive doing six jobs.

Artifact signing across stacks. Cosign for images, package signatures for charts, something separate for SBOMs. Every tool signs a different thing. OCM signs the release once; every downstream verifier does the same check.

Air-gapped delivery. Regulated customers do not just want signatures. They want to run the verify themselves, offline, on their hardware. OCM was designed for that from day one. Nothing in the verify path calls upstream.

Kubernetes-native deployment. The OCM K8s controllers verify and apply components directly. No shell scripts wrapped around Helm install to bolt on integrity. The check is the deploy path.

Asynchronous security scans. A CVE dropping two months after release used to mean "rebuild the world". With OCM the finding attaches to the component identity. The affected shipped release is known, and where it went. Patch the affected components, not the fleet.

One source of truth. Rebuilding a landscape (new region, compliance decision, incident recovery) is manual archaeology across tickets and configs today. With OCM: one signed descriptor per delivery. The landscape rebuilds from that.

Automated compliance reporting. Auditors ask for SBOMs, VEX, provenance, attestations. Those live in spreadsheets that go stale the moment they are produced. With OCM the reports compose from the SBOD metadata itself. They cannot drift from what actually shipped.

Land: six outcomes. All from one signed descriptor.

Q&A:
"VEX?" VEX documents can be resources inside the OCM component, signed with the rest. Auditors verify VEX and artifact together, from one signature.
"Does OCM produce the compliance report?" No. OCM provides the metadata. ODG composes reports on top. Teams also plug in their own reporting layer.


## Slide 13: TRUSTED IN PRODUCTION

Credibility. Specificity is the credibility, not scale claims.

OCM is not a research project. SAP stewards the engineering. NeoNephos governs the standard. Real teams run this in production.

Top row:

BWI. Germany's federal IT service provider. Runs OCM for regulated workloads inside the Bundeswehr estate. Air-gapped, sovereign, verified locally, no callback upstream.

SAP NS2. Handles regulated US workloads under FedRAMP-adjacent frameworks. Same model as BWI, different jurisdiction.

Bottom row:

Gardener. SAP's open-source Kubernetes orchestrator. Five years in production, thousands of clusters. Consumes OCM for release delivery.

Kyma. SAP-originated open-source runtime for Kubernetes extensions. On OCM.

OpenControlPlane. Open-source control plane. Replaces Landscaper for Sovereign Cloud deployment through 2027. On OCM.

Platform Mesh. Federated multi-runtime platform. Same open ecosystem.

Land: aligned with NeoNephos. Open source. Production-grade.

Q&A:
"How many components in production?" BWI and NS2 do not publish counts. SAP-internal OCM usage is in hundreds of components across five internal teams. Growing quarter over quarter.
"Kubernetes required?" No. OCM works for anything that ships as artifacts. Kubernetes is the dominant target, not the only one.
"Spec governance?" NeoNephos Foundation, hosted under Linux Foundation Europe. Spec changes go through open steering. SAP contributes; SAP does not decide alone.


## Slide 14: STRATEGIC POSITION

The credibility-and-sustainability slide. Answers the question "why isn't this going to disappear in two years?"

Apeiro is short for ApeiroRA, the Apeiro Reference Architecture. EU-funded blueprint for the sovereign cloud-edge continuum. Part of IPCEI-CIS, Important Projects of Common European Interest on Cyber and Information Security. NextGenerationEU funds it. Germany's BMWK co-funds it. Seventeen open-source projects across three layers.

OCM sits in the Cloud OS layer. Alongside Gardener, OpenControlPlane, and Platform Mesh, three of the peer projects from the previous slide. Not coincidence. Slide 13 named the peers; this slide names their umbrella. They are pieces of the same reference architecture.

Governance sits in NeoNephos, Linux Foundation Europe. Neutral by design. Long-term sustainability requires that flagship projects outlive any single funding cycle.

Land: this is an EU strategic asset, not a vendor tool.

Q&A:
"Is Apeiro time-limited?" IPCEI-CIS is the funding vehicle, time-bound. The flagship projects live in NeoNephos exactly so they outlive the funding.
"Who runs the consortium?" Multiple European vendors and research partners. SAP is the lead partner but does not decide alone; NeoNephos governance is open.
"Can I contribute?" Yes. Every project is open source. Community channels are on the project sites.


## Slide 15: Start delivering with confidence.

Close. Three asks, all small, all this quarter.

Pilot. Pick one regulated delivery already shipping. Something already grinding through compliance friction. Pack it as an OCM component this quarter. Not a sandbox proof-of-concept. Something real, where the payoff is visible in one review cycle.

Evaluate. Platform-engineering and security leads brief back on what they found. If the model fits the delivery, they come back saying so without prompting. If it does not, that is useful too. Answer within eight weeks.

Engage. The standard is open and being shaped right now. Bring the delivery problem to the steering conversation. The reality of what ships is the input the working group needs.

Entry points on the slide: ocm.software for the site. github.com/open-component-model for the code. Community channels linked from both.

Land: pilot, evaluate, engage. That is the ask.

Q&A:
"Timeline for controller v1?" Controller is v1alpha1 today. RSA path stable. OpenPGP and Sigstore paths targeted for v1alpha2 within 2026. No date commitments in the room; refer to the roadmap on GitHub.
"Cost model?" Open source. No licence fees. Adoption cost is engineering time to pack existing releases and wire verify into the deploy path. Typical pilot is two to four engineers, four to eight weeks.
"Vendor lock-in?" OCM is at NeoNephos Foundation. Spec is open. Multiple implementations. Adoption does not tie the customer to SAP tooling.


## Slide 16: APPENDIX - ABBREVIATIONS

(no notes; reference slide)


## Slide 17: TRADEMARK & LICENSE NOTICES (1/2)

(no notes; reference slide)


## Slide 18: TRADEMARK & LICENSE NOTICES (2/2)

(no notes; reference slide)
