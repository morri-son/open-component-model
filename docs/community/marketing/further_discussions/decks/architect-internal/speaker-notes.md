# Speaker Notes

## Slide 1: You ship pieces

Open with the observation, not the noun OCM.

The already-briefed half of the room recognises the frame; the un-briefed half gets handed it. Either way, the release is the one thing they ship that isn't an object they can point at: images, charts, configs, SBOMs all have names; the release doesn't. The deck's job is to walk the model that makes it one: what it is, how it travels, and what's still sharp.

One sentence to land before advancing: for the next 30 minutes we're walking the model behind one signed unit. Then slide 2.

Pacing for the whole deck: this is a 30-minute talk, and not every slide gets equal time. Most slides you walk in full: point at each element, land the closing line, pause. Two you deliberately skim, Slide 9 (signing schemes) and Slide 11 (the deploy chain), because they carry breadth the argument doesn't need in one pass. On those two, name the structure, say one framing sentence, and move on; the detail is in the notes as backup for when someone in the room asks. When a note says "skim this slide," that is what it means.


## Slide 2: DIAGNOSIS

Existing toolbox doesn't compose. Every tool names one artifact well. None of them names the release.

OCI. The digest identifies the image's bytes. Nothing in that digest says which release the image belongs to.

Helm. The version identifies the chart. Nothing says which release the chart is part of, which image and config ship with it.

SBOMs and signatures. In OCI they attach through the 1.1 Referrers API: the artifact names one manifest digest as its subject. So an SBOM refers to one image, a signature covers one artifact. A release is not a single digest, it's a set of them, so there is no subject a single referrer can point the whole release at.

Calibration for a cosign audience: cosign updates the digest after an explicit "cosign copy". Keeps signing each piece. What's missing is a name for the release as one unit, signable, verifiable in a sovereign zone with no callback.

Name the cost before advancing. No name for the release means three failures the audience has lived: a deployment breaks because one artifact shipped mismatched or missing, and nothing said the four belonged together. An audit stalls because no single record says what "release 1.4" actually contained. An air-gap transfer carries the descriptor but leaves the bytes behind, and nothing checked the set arrived whole. This is the stop-line on the slide: you can't sign, ship, or audit what you can't name.

Diagnosis in one line: the release has no identity of its own. Slide 3 gives it one.


## Slide 3: THE HINGE

Fulcrum slide.

OCM separates three things the existing tools fuse into one.

Identity. A DNS-style name plus a SemVer version. Globally unique, no registry in the name.

Digest. SHA-256 over each resource, computed at pack time. This is what gets signed.

Access. The type plus fetch fields: OCIImage/v1, Helm/v1, LocalBlob/v1. Where the bytes currently sit.

Promote across environments: EU to US, dev to staging to prod, registry to CTF to air-gapped registry. Identity stays. Digest stays. Access is rewritten. Signature still verifies.

Land the seven-word version: move the artifact, the digest stays, only the access changes.

Q&A:
"Globally unique?" Uniqueness is inherited from DNS-prefix naming. Same model as Go import paths. OCM does not run a registry that arbitrates conflicts; DNS does. Two parties claiming acme.org/helloworld is prevented the same way as two parties claiming acme.org.
"Squatting?" Trust is per-component. The verifier knows which anchor to apply to the descriptor in front of it. A regulated environment relies on (a) controlling which registry the controllers pull from and (b) per-component verifier config. Per-name-prefix trust-anchor binding is not in the spec or the controllers today.


## Slide 4: WHERE OCM SITS

OCM does NOT replace OCI, Helm, cosign, Sigstore, SBOM tooling. It WRAPS them. One envelope signature over the whole release.

Any format. Any artifact produced becomes a resource. OCI, Helm, configs, SBOMs, npm, maven, binaries.

Any location. Identity is location-independent; the same component travels across registries unchanged.

One signature. Covers every digest in the component. The whole release is one signed unit.

Q&A on SAP-stack equivalents (internal audience will map to their own stack):
RBSC ships products; OCM describes the product so RBSC can ship it consistently.
Hyperspace builds artifacts; OCM is the metadata wrapper added on top. The existing Piper steps stay.
Open Delivery Gear runs on top of OCM components: SBOM aggregation, compliance signal rollup, policy hooks.
None of these are replaced. OCM is the shared primitive they all align on.

Q&A if asked about SBOD: external-facing name for the component descriptor. Same object, different word.

The one-liner for the "why not just compose what we already run?" reflex: RBSC, Hyperspace, cosign, each ships or signs an artifact; OCM names the release they can't name as a unit. Different unit of analysis. The SAP-stack mapping above is the answer set; walk it if the room presses. There is no compare-table slide in this deck by design: internal's question is "where does OCM sit relative to RBSC / Hyperspace / ODG?", a layering question answered by "OCM is the primitive underneath, those tools ride on top", not a feature-parity table. This Q&A carries the whole comparison.

Land: a component is the unit you sign, transport, and deploy.


## Slide 5: CONSTRUCTOR

First YAML in the deck. Eighteen lines, hand-written. Walk it.

components. List, usually one. Name is DNS-style; version is SemVer.

provider. Metadata, required.

resources. Every artifact in the release. Two ways in:
input: by value. Constructor reads the file at pack time, embeds the bytes. Travels in the archive.
access: by reference. Records a pointer (e.g. ghcr.io/.../podinfo:6.9.1), resolves digest now, copies bytes later.

Local files and configs tend to be input; big images tend to be access. Mix freely.

CLI if asked: ocm add cv against this file, default output a CTF archive.


## Slide 6: DESCRIPTOR

Clarify first: the descriptor is generated by ocm add cv. Nobody hand-edits it. This is what travels.

One resource shown (the image) to keep focus on the mechanism. Real components carry many resources and can reference other components; the ellipsis stands in for that.

access is OCIImage/v1 with the imageReference pinned to a digest. Kills the repoint-the-tag attack class. Excluded from the canonical form on purpose, because transport rewrites it.

digest is SHA-256 over the resource bytes, computed at pack time. It feeds the descriptor hash.

signatures is a list. Each entry signs one hash: the SHA-256 of the canonicalized descriptor. That single hash covers every resource digest. Multiple signatures allowed. Dual-sign RSA plus Sigstore, verifiers pick.

The seven-word version: sign the descriptor hash, not the access. Signed: the descriptor hash. One signature covers every artifact. Not signed: the access fields, so transport can rewrite them freely. The signature still verifies, anywhere.

Q&A:
"Trust model?" One per scheme, all configurable. RSA-PSS: operator pins the public key. Sigstore: operator pins the OIDC issuer; Fulcio issues short-lived certs; Rekor logs. GPG: operator pins the OpenPGP fingerprint. Algorithm is configurable per signature; the signed object is the canonicalized descriptor regardless.
"Composition?" The signature transitively pins componentReferences (defined on slide 8). The product signature covers every reference's descriptor digest. Re-signing or re-publishing a referenced component breaks the product signature. Verifier policy is per-component: at deploy time each referenced component is verified against its own trust anchor.


## Slide 7: OCM IN ONE PICTURE

Big diagram. Four verbs. This IS the demo. No live tooling.

Pack. Everything the software needs (image, chart, config) bundled into one named, versioned component. One artifact carries the release.

Sign. One signature covers every artifact in the bundle, by digest. If anything changes, verification breaks.

Transport. The component moves across registry boundaries. Cloud to cloud, region to region, into an air-gapped CTF. Signature doesn't care.

Deploy. At the destination, the receiver verifies the signature, unpacks, deploys. GitOps or OCM K8s controllers, operator's call. No callback upstream.

Land: pack, sign, transport, deploy. That's the whole model.


## Slide 8: COMPOSE

Services carry resources: images, charts, configs, SBOMs. Walk the LEFT box: acme.org/sovereign/notes and acme.org/sovereign/postgres, each with its image and/or chart. Real service components usually carry more (configs, SBOMs, provenance).

A product component composes services via componentReferences. Name plus version, normally no resources of its own. Walk the RIGHT box: acme.org/sovereign/product references notes and postgres by name and version. That's it.

Each service is independently versioned, signed, transferable. The product is a component that points at them.

Real releases are not one big component. They are one product referencing several services. Slide 12 (day 2) operates on this shape.

Q&A:
"Transitive trust?" componentReferences are pinned by the referenced descriptor's digest. The product signature covers each reference digest, so re-signing a referenced component breaks the product signature.
"Verifier policy at deploy time?" Each component is checked against its own trust anchor: notes against the notes team's anchor, postgres against the postgres team's anchor, product against the product team's anchor. With no explicit per-component policy, the controller applies whatever anchor was configured on the Component CR for that name.


## Slide 9: SIGN

Skim this slide in a 30-minute talk, don't walk it. Point at the three column headers, say "one signed object, three ways to prove the key, pick what your org already runs," and advance. The per-scheme detail below is depth-on-demand for when a security architect engages. Teaching all three schemes in the main pass spends attention the argument doesn't need; the mnemonic on Slide 7 already carried "Sign."

Same signed object across all three schemes: the canonical descriptor digest. What varies is how the key is proven. All three schemes are stable in the CLI on the v1alpha1 API surface today.

RSA / RSASSA-PSS. Bare public-key pinning. The key already rotated in ops. No PKI required.

OpenPGP. OpenPGP key material, same trust model as RSA (key pinning), different key format. Fits orgs already running web-of-trust keyrings. Header says OpenPGP; GPG is one implementation, Sequoia and RNP produce compatible signatures.

Sigstore. Keyless via OIDC plus a Rekor transparency log; trust anchor is the OIDC issuer. Fits CI workloads and any signer that can present an OIDC identity.

Land: verifiers can require multiple in parallel. RSA from the release team plus Sigstore from CI. Pick what the org already runs.

Q&A:
"Verifier policy on the Kubernetes Component CR?" Optional verify field, list of {signature-name, public-key} pairs. Verification is opt-in: with no entries the controller resolves and pulls but doesn't check signatures. With entries the controller looks for those signature names in the descriptor and verifies. No scheme pinning on the CR; the scheme is read from the signature's algorithm field.
Honest scope note. The v1alpha1 controller today implements RSA (RSASSA-PSS, RSASSA-PKCS1V15) only. OpenPGP and Sigstore verification work in the CLI; the three columns on this slide are the CLI surface. The controller rejects a non-RSA signature with an "unsupported signature algorithm" error rather than falling through silently, so the safety property holds. Practical answer for teams running the controllers in production today: RSA on the CR, CLI for the broader scheme set, OpenPGP and Sigstore controller support on the roadmap.
"Global enforcement?" No admission webhook ships with the OCM controllers. Verification policy lives on each Component CR. Production installs that want global enforcement bring their own admission policy: Kyverno, Gatekeeper, or a custom webhook against the Component resource.
"PEM / cert chains?" A fourth option exists: RSA with X.509 chain, PEM encoded. Still experimental. The CLI prints "experimental" on every sign and verify. Watch the docs; promotion follows encoding stability.


## Slide 10: TRANSPORT

One mechanic, three shapes.

Registry to registry. Promotion across dev/staging/prod, or cross-cloud (GHCR to ECR). Same digests. Every access rewritten.

Registry to CTF. Common Transport Format, a local archive of blobs plus index. Hand-carry across the boundary.

CTF to registry. The air-gap import. Archive arrives, ocm transfer uploads, access rewrites to the local registry, signature verifies locally. No traffic to source.

Same command in all three: ocm transfer cv <src> <dst>. Access changes; digests don't. The signature covers digests, so it survives every hop. Verification is purely local at the destination. That's the air-gap property.

Q&A:
"Air-gap default footgun?" Default ocm transfer copies only the descriptor; the access fields still point back at the source registry. For air-gap (CTF to registry) you MUST pass --copy-resources so the bytes travel with the descriptor. Slide 14 names this as one of the three honest edges. Worth catching in a CI step the first time someone runs an air-gap export.
"Sigstore air-gap specifically?" Works offline IF the trusted-root file (Fulcio CA plus Rekor public key for the configured issuer) has been distributed to the destination once, out of band. After that, ocm verify cv runs without contacting Rekor or Fulcio. RSA and OpenPGP need only their pinned public keys, no trusted-root file.


## Slide 11: DEPLOY

Skim this slide in a 30-minute talk, don't walk it. Name the chain and land the one property that matters: Repository to Component to Resource to Deployer, and the controllers verify before they apply. The per-CR walk below is depth-on-demand for a Kubernetes-platform architect who leans in. Two things stay in the main pass even when skimming: the verification-opt-in disclosure on the Component card, and the BYO-GitOps dependency, because Slide 14 pays both off.

Four CRs, one chain. The controllers verify and apply the component.

Repository. Names where component versions live. OCI registry, mounted CTF, S3, local FS.

Component. Names a specific component version. Pulls the descriptor and verifies its signature against the trust anchor configured on the Component CR. Verification is opt-in: without a verify entry the controller resolves and pulls but doesn't check signatures. Production installs should require verification via admission policy.

Resource. Picks one artifact from the component, by digest. Helm chart, OCI image, raw manifest, blob. The digest is the content hash written into the descriptor at pack time, the same one the component signature covers. On fetch the Resource controller recomputes the hash over the actual bytes and compares. A match confirms the content is exactly what the signature vouched for. This is the last link in the chain: the Component card proves the descriptor is trusted; the Resource card proves the bytes match the descriptor.

Deployer. Applies the resource to the cluster. Resolves image refs and other deploy-time pointers from the verified descriptor at apply time. This is where localization happens in v2.

Say the dependency out loud now, so slide 14 doesn't feel retroactive: the four-card chain on its own deploys raw Kubernetes manifests. For Helm-deploy, the chain feeds a ResourceGraphDefinition that kro reconciles, with Flux or Argo CD applying the resulting HelmRelease. OCM controllers don't ship kro, Flux, or Argo CD. BYO.

Q&A:
"Is the resource check always on?" verificationPolicy defaults to Always, so yes by default; Never turns it off. Two honest edges though. It is best-effort per access type: the check needs a digest processor plugin for that access type, and where none exists yet the controller logs and moves on without verifying. And a matching digest only means trusted content if the Component signature was actually verified upstream, which is opt-in. The signature check and the digest check are independent switches.
"Controller-shaped ocm transfer?" Yes. There's a Replication CR for in-cluster repo-to-repo mirroring. Appendix slide 17.


## Slide 12: DAY 2

Composition was defined on slide 8. This slide does one job: show the day-2 mechanic.

Product is acme.org/sovereign/product. Day 1: references notes 1.0.0 and postgres 1.0.0, each pinned by its descriptor digest. Notes team ships a patch (1.0.0 to 1.1.0). Platform team raises the product to 1.1.0, updates the notes reference. Its version AND its digest, because the new notes descriptor hashes differently. Postgres stays: same version, same digest.

Commit. The controller pulls the new product descriptor, verifies the signature, resolves the new digests, applies. Notes rolls forward. Postgres untouched.

For security architects: OCM is a release-level envelope. helm upgrade upgrades one chart; cosign signs one image. The OCM signature covers the whole release as one unit. Every digest in every resource of every referenced component pinned by the one parent signature. Drift breaks that signature.

Q&A:
"Forged descriptors?" Nothing OCM-specific stops a malicious operator from committing a forged descriptor with bumped versions, an attacker's image references, and a re-signed signature using a stolen key. Same threat model as any signed-release system. Rotate keys, dual-sign, audit.

Land: one signature to audit instead of N. Bump the product. The references follow. The cluster can't drift without breaking the envelope.


## Slide 13: ADOPTION

Two paths to a first OCM component. Both tested in conformance on every release.

From zero, CLI-only. No cluster. Install the CLI, write a constructor for one component, pack, sign with RSA, export as CTF, carry to a second machine, import, verify. Cold-start budget: about thirty minutes. The helloworld pack/sign/verify tutorial on the website walks it end-to-end.

On your cluster, controllers. Spin up a kind cluster. Helm-install the OCM controllers, plus kro, plus Flux or Argo CD. Point them at your registry. Apply a Component resource, verified and reconciling. Cold-start budget: an afternoon, including bootstrap (kind + controllers + kro + Flux or Argo CD) and a Helm-deploy of the simple component in the getting-started tutorial.

Both paths coexist with cosign, Argo CD, Flux, Kyverno, whatever is already running. OCM signs the descriptor; existing controls stay in place.

Q&A the internal audience will bring in on this slide:
RBSC integration with the CLI is live. Wiring the CLI into a team's RBSC-facing release pipeline is the production shape of "FROM ZERO".
Hyperspace Piper step integration exists today on OCM v1. The v2 migration is on the 2026 roadmap, not started yet. Internally, Hyperspace already uses OCM for SBOM aggregation.
Open Delivery Gear (ODG) runs compliance and SBOM rollup using the OCM coordinate system. Open Control Plane (OCP) is the declarative deployment runtime, long-term replacement for Landscaper.
Landscaper sunset (Sovereign Cloud audience will ask): Landscaper deploys type-A services (IAS, Audit Log) today in Sovereign Cloud. Migration to Open Control Plane is planned for end-of-year / early next year. OCM components are the SAME on both sides of the migration; only the runtime changes. That is the point of the model.
Renames: OCM Gear became Open Delivery Gear (ODG), now inside the OCM GitHub org. Managed Control Plane became Open Control Plane, also open source. Naming hardened when the projects hardened.


## Slide 14: WHAT'S SHARP

Trust slide. Deliver straight.

Transfer defaults copy only the descriptor. For air-gap, pass --copy-resources so the artifacts travel too. Worth catching in a CI step the first time someone runs an air-gap export.

Controllers are v1alpha1. CRD shapes for Repository, Component, Resource, Deployer, Replication are stabilizing but still v1alpha1. Pin to specific release tags in platform installs.

Helm-deploy adds kro plus Flux or Argo CD. The OCM controllers don't ship them. Bring an existing GitOps solution.

Nuance for Q&A: kro is required for ALL documented deploy paths. It reconciles the ResourceGraphDefinition the Deployer feeds it, not only Helm-deploy. The GitOps engine (Flux or Argo CD) is the Helm-deploy-specific add. Three installs total for Helm-deploy.

Land: if any edge is a deal-breaker, tell us early.


## Slide 15: ADOPTER PROOF

Adopter proof, two columns.

Left. Four SAP-internal projects that are also open source: Gardener (managed Kubernetes), Kyma (cloud-native runtime), Open Control Plane, Konfidence (aka DWC, Deploy with Confidence). All aligned under NeoNephos Foundation governance, co-developing the surrounding open ecosystem.

Right. Five SAP-internal teams running on OCM: Hyperspace, RBSC, CSI, Steampunk, Sovereign Services & Delivery. These are SAP-only, no public logos.

Hyperspace caveat (audience WILL ask): Hyperspace integration with Piper today runs on OCM v1. The v2 migration is on the 2026 roadmap. Internally, Hyperspace ALREADY uses OCM for SBOM aggregation. The Piper-step v2 integration is the in-flight piece.

Sovereign Services & Delivery operates SAP products in sovereign markets. Sovereign Cloud delivery is the cleanest current OCM end-to-end story (pack, sign, ship via Landscaper today, will move to Open Control Plane).

Q&A on conspicuous absences: ACD, Hana Cloud / SGSC traceability were in the 2024 plan but have not made the same progress. We don't claim adopters we don't have. Better honest than complete.


## Slide 16: Ship the release as one unit.

Close with the ask. Three verbs, three concrete next-quarter actions for an internal architect in this room.

Pilot. Pack one product as an OCM component, in your team, this quarter. Not a laptop demo, a real product in an existing pipeline. RBSC is the cleanest first wire-up if the LoB ships via RBSC today.

Standardize. Make OCM the default for component delivery IN YOUR LoB. Key reframe: we are NOT mandating OCM via SLC-29 or a top-down product standard. The 2024 plan named that path; the 2026 strategy is different. We invest in the CLI and toolkit quality so OCM becomes the standard because it is the best tool for the job. Bottom-up.

Steward. Bring the LoB into the OCM steering conversation. Slack #sap-tech-ocm. Steering meets every four weeks; cross-LoB design decisions land there. If the LoB has a stake in component-delivery architecture, the LoB should be in the room.

Land: one primitive. Your stack. Your call.


## Slide 17: APPENDIX · REPLICATION

Appendix. Pull only if asked about cluster-side component transfer, or "how do I get a version from one repo into another without running the CLI?"

A fifth controller, Replication, sits alongside the four-card chain, not within it. The chain delivers content into the cluster; Replication transfers a resolved component version from one OCM repository to another. Same descriptor, same digests, fresh access fields.

References a source Component CR and a target Repository CR. When the resolved version of a source changes, Replication transfers that version with its full reference graph into the target. Mirrors ocm transfer cv on the CLI. Records status.lastTransferredDigest after each successful run; a later reconciliation on the same digest is a no-op.

Use cases: delivery pipelines, promotion between environments.

Kept off the main deck because the four-card chain is the load-bearing story for a 30-minute talk. This is the answer to a specific question, not part of the arc.


## Slide 18: APPENDIX · ABBREVIATIONS

(no notes)
