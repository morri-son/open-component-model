"""Per-slide condensed speaker notes embedded into the .pptx via python-pptx.

The canonical, fully-elaborated speaker notes (with timers, stage directions,
Q&A prep) live in ../notes/SPEAKER-NOTES-ARCHITECT-EXTERNAL.md. This file is
the trimmed presenter prompt shipped INSIDE the deck.
"""

SPEAKER_NOTES: dict[int, str] = {
    1: (
        "Open with the observation, not the product 'OCM'.\n"
        "Any release in the last six months: images, charts, configs, SBOMs - each named differently, each signed differently, if at all.\n"
        "You shipped pieces. Nothing carried the release.\n"
        "Thread the arc: by the end of the deck you'll have a thirty-minute path to your first OCM component on a laptop - and an afternoon to one running on a cluster. Until then, here's why that matters.\n"
        "No brand pitch yet - the deck does that at the end."
    ),
    2: (
        "Why the existing toolbox does not compose. Three artifact types, three identity shapes:\n"
        "• OCI image - digest pins the bytes. Nothing pins the release the image belongs to.\n"
        "• Helm chart - version pins the chart. Nothing pins it to the image, config, and SBOM it ships with.\n"
        "• SBOM - referrer attaches to one digest. No referrer spans the whole release.\n"
        "Calibration for COSIGN (which can update the digest after explicit `cosign copy`): keep signing each piece. What is missing is a name for the release as one unit, signable, verifiable in a sovereign zone with no callback.\n"
        "Diagnosis: identity is bound to location."
    ),
    3: (
        "The conceptual fulcrum. Let it breathe. OCM separates three things the existing tools fuse:\n"
        "• Component identity - DNS-style name plus SemVer. Globally unique, location-agnostic. No registry in the name.\n"
        "• Digest - SHA-256 over each resource. Computed at pack time. This is what we sign.\n"
        "• Access - type plus fetch fields (`OCIImage/v1`, `Helm/v1`, `LocalBlob/v1`). Where the bytes currently live.\n"
        "Promote EU -> US -> air-gapped CTF and DEV -> STAGING -> PROD : identity stays, digest stays, only access is rewritten. Signature still verifies - anywhere.\n"
        "Move the artifact. The digest stays. Only the access changes. That is the whole trick.\n"
        "Q&A backup on 'globally unique': inherits from DNS-prefix naming - same model as Go import paths. We don't run a registry that arbitrates conflicts; uniqueness is delegated to DNS. Two parties claiming `acme.org/helloworld` is prevented the same way two parties claiming `acme.org` is prevented.\n"
        "Q&A backup on squatting: trust is per-component - the verifier knows what trust anchor to apply to the descriptor in front of it. A regulated environment relies on (a) controlling which registry the controllers are configured to pull from, and (b) per-component verifier config. Per-name-prefix trust-anchor binding is not in the spec or the controllers today."
    ),
    4: (
        "Two jobs: pre-empt 'what does this replace?' and define the noun 'COMPONENT' the rest of the deck rests on.\n"
        "OCM is not a replacement for OCI, Helm, cosign, sigstore, or your SBOM tooling. It WRAPS them — adds one envelope signature over the whole release, sitting on top of whatever signatures the individual artifacts already carried.\n"
        "• Any format - Helm stays Helm, OCI stays OCI, configs stay configs. The artifact `type:` is free-form, so an OCM component already carries SBOMs, npm packages, maven artifacts and anything else your team produces today - access is via `File/v1` or `LocalBlob/v1`. Dedicated `NPM/v1` and `Maven/v1` access types are roadmap (Maven epic ocm-project#836; NPM targeted before first GA at end of 2026).\n"
        "• Any location - name and version do not encode a registry. Move it; the name stays.\n"
        "• One signature - covers every digest in the component. The whole release is one signed unit.\n"
        "Q&A backup on cosign / sigstore / OCI 1.1 referrers: We don't replace per-artifact signatures - they travel inside the component. OCM adds a release-level envelope: one signature over the canonicalized component descriptor that covers the digests of every resource. If you cosign-sign every image and ship a sigstore bundle per chart today, keep doing that - OCM signs the wrapper above them.\n"
        "Q&A backup on SBOD vocabulary: if the audience knows OCM at all, they may have heard 'Software Bill of Delivery' - SBOD - in earlier presentations or on the website. It's our positioning term against SBOM. Technically an SBOD is the same object architects call the component descriptor - the serialized form of an OCM component version. Different words, one object.\n"
        "A component is the unit you sign, transport, and deploy. Hold the noun."
    ),
    5: (
        "First YAML the audience sees. Walk it like you would for a colleague - eighteen lines, hand-written.\n"
        "• `components` - list, usually one. Name is DNS-style; version is SemVer.\n"
        "• `provider` - metadata, required.\n"
        "• `resources` - every artifact in the release. Two ways in:\n"
        "  ▪ `input:` - by value. Constructor reads the file at pack time, embeds the bytes. Travels in the archive.\n"
        "  ▪ `access:` - by reference. Records a pointer (e.g. `ghcr.io/.../podinfo:6.9.1`), resolves digest now, copies bytes later.\n"
        "Local files and configs tend to be input; big images tend to be access. Mix freely.\n"
        "CLI if asked: `ocm add cv` against this file, default output a CTF archive."
    ),
    6: (
        "Clarify first: this is generated by `ocm add cv`. You do not hand-edit it. This is what travels.\n"
        "We show one resource - the image - to keep focus on the mechanism. Real components carry many resources and may reference other components; the '...' line stands in for that.\n"
        "• `access` - `OCIImage/v1` with the imageReference pinned to a digest. Kills the repoint-the-tag attack class. Excluded from the canonical form on purpose - transport rewrites it.\n"
        "• `digest` - SHA-256 over the resource bytes. Computed at pack time. Input to the descriptor hash.\n"
        "• `signatures:` - list. Each entry signs ONE hash: the SHA-256 of the canonicalized descriptor. That single hash covers every resource digest. Multiple signatures allowed - dual-sign RSA + Sigstore, verifiers pick.\n"
        "Three things to land. Signed: the descriptor hash - so one signature covers every artifact in the component. Not signed: the access fields - so transport can rewrite them freely. The signature still verifies, anywhere.\n"
        "Sign the descriptor hash, not the access. Seven words; whole transport story.\n"
        "Q&A backup on the trust model (one per scheme, all configurable): RSA-PSS uses bare public-key pinning - operator pins the public key. Sigstore uses OIDC issuer + Fulcio short-lived cert + Rekor transparency log - operator pins the issuer. GPG uses an OpenPGP keyring - operator pins the key fingerprint. Algorithm is configurable per signature; the signed object is the canonicalized descriptor regardless of algorithm.\n"
        "Q&A backup on composition: the signature transitively pins `componentReferences` (introduced on slide 8). The product signature covers every reference's descriptor digest - so re-signing or re-publishing a referenced component breaks the product signature. Verifier policy is per-component: a referenced component is verified against its own trust anchor at deploy time; the product is verified against the product's anchor.\n"
        "Q&A backup on canonicalization: the canonical form of the descriptor is spec'd at `ocm-spec/04-extensions/01-artifact-types/`. Signatures are over canonical bytes - so JSON/YAML field ordering and whitespace can't break verification."
    ),
    7: (
        "Bridge from noun to verb. On slides 5 and 6 you saw the static artifact - what you write and what travels. Now four moves on that artifact.\n"
        "We've covered the first half of two of them already: the constructor (slide 5) is the input to Pack; the descriptor (slide 6) is the output of Pack, the target of Sign, and the unit of Transport.\n"
        "Name the primitive: the signed descriptor is itself an OCI artifact - media type `application/vnd.ocm.software.component-descriptor.v2`. Lives in your registry next to the images. No new infrastructure.\n"
        "Four moves, same flow, every component:\n"
        "• Pack - bundle once, name once.\n"
        "• Sign - one signature covers every digest.\n"
        "• Transport - registry ↔ registry ↔ tarball. Signature survives every hop.\n"
        "• Deploy - controller verifies, resolves digests, applies. No callback upstream.\n"
        "These are lifecycle moves, not CLI verbs. The CLI you'll type is `ocm add cv`, `ocm sign cv`, `ocm transfer cv`, then `kubectl apply` against the Deployer CR. Same four moves, slightly different names. Sovereign cloud, air-gap, customer cluster. Next four slides are the mechanics."
    ),
    8: (
        "Composition is the architectural fact that makes day-2 work.\n"
        "• Service components carry resources - images, charts, configs, SBOMs. Walk the LEFT box: `acme.org/sovereign/notes` and `acme.org/sovereign/postgres`, each with image + chart + `...` (real components carry more - configs, SBOMs - the `...` stands for that).\n"
        "• A product component composes services via `componentReferences:` - name + version, no resources of its own. Walk the RIGHT box: `acme.org/sovereign/product` references both notes and postgres by name and version. Nothing else.\n"
        "• Each service is independently versioned, signed, transferable. The product is a small descriptor that points at them.\n"
        "Real releases are not one big component - they are one product component referencing several services. This is the shape day-2 (slide 12) operates on.\n"
        "Q&A backup on transitive trust: `componentReferences` are pinned by the digest of the referenced component's descriptor. The product signature covers each reference's digest - re-signing a referenced component breaks the product signature. At deploy time the verifier checks each component against its own trust anchor: notes against the notes team's anchor, postgres against the postgres team's anchor, product against the product team's anchor. Without an explicit per-component policy, the controller applies whatever trust anchor was configured on the Component CR for that name."
    ),
    9: (
        "Same signed object - the canonical descriptor digest - in all three. How you prove the key is what varies. All three are stable on the v1alpha1 API surface today:\n"
        "• RSA / RSASSA-PSS - bare public-key pinning. The key you already rotate. No PKI required. Trust model: key pinning.\n"
        "• OpenPGP - OpenPGP key material; trust model is the same as RSA Plain (key pinning), just with a different key format. Fits orgs already running web-of-trust keyrings. (Slide header says 'OpenPGP' - GPG is one implementation; Sequoia and RNP produce compatible signatures.)\n"
        "• Sigstore - keyless via OIDC + Rekor transparency log; trust anchor is your OIDC issuer. Fits CI workloads and any signer that can present an OIDC identity.\n"
        "Three things to land. Same signed object - the canonical descriptor digest. Verifiers can require multiple in parallel (RSA from release team + Sigstore from CI). Pick what your org already runs.\n"
        "Q&A backup on verifier policy floor (the security architect's hardest question): all three schemes resolve against standard trust anchors - RSA against pinned public keys, OpenPGP against an OpenPGP keyring, Sigstore against a Fulcio root plus Rekor verifier. Verifier policy is per-component: an operator pins 'this product accepts only scheme X with anchor Y' on the Component CR. Without explicit policy, the controller accepts any signature whose anchor matches the configured `verify:` entries on that Component CR. Production installs SHOULD pin policy via admission. There's no implicit fall-through to a weakest scheme.\n"
        "Q&A backup on PEM / cert chains: A fourth option exists - RSA with X.509 certificate chain, PEM encoding. Still experimental: the CLI prints `experimental` warnings on every sign and verify. Watch the docs; we'll promote it when the encoding stabilizes.\n"
        "CLI: `ocm sign cv ./archive//github.com/acme/widget:v1.4.2 --signature acme-release-key --private-key ./release-key.pem`. Idempotent."
    ),
    10: (
        "One mechanic, three patterns - covers every delivery topology you will see.\n"
        "• Registry -> Registry - promotion across dev/staging/prod, or cross-cloud GHCR -> ECR. Same digests, every access rewritten.\n"
        "• Registry -> CTF - Common Transport Format. A local archive of blobs + index. Hand-carry across the boundary.\n"
        "• CTF -> Registry - the air-gap import. Archive arrives, `ocm transfer` uploads, access rewrites to local registry, signature verifies locally. No traffic to source.\n"
        "Same command in all three: `ocm transfer cv <src> <dst>`. Access changes; digests do not. Signature covers digests, so it survives every hop. Verification is purely local at the destination - that is the air-gap property.\n"
        "Q&A backup on the air-gap default footgun: default `ocm transfer` copies only the component descriptor - the access fields still point back at the source registry. For air-gap (CTF -> Registry) you MUST pass `--copy-resources` so the bytes travel with the descriptor. Slide 14 names this as one of the three honest edges. Worth catching in a CI step the first time someone runs an air-gap export.\n"
        "Q&A backup on Sigstore air-gap specifically: Sigstore verification at the destination is offline IF the trusted-root file (Fulcio CA + Rekor public key for the configured issuer) has been distributed into the destination once, out of band. After that, `ocm verify cv` runs without contacting Rekor or Fulcio. RSA and OpenPGP need only their pinned public keys - no trusted-root file."
    ),
    11: (
        "Four CRs, one chain. The controllers verify and apply the component.\n"
        "• Repository - names where component versions live. OCI registry, mounted CTF, S3, local FS.\n"
        "• Component - names a specific component version. Pulls the descriptor and verifies its signature against the trust anchor configured on the Component CR. Verification is OPT-IN: without a `verify:` entry referencing a key/secret, the controller resolves and pulls but does not check signatures. Production installs should require verification via admission policy.\n"
        "• Resource - picks one artifact from the verified component, by digest: Helm chart, OCI image, raw manifest, blob.\n"
        "• Deployer - applies the resource to the cluster. Resolves image refs and other deploy-time pointers from the verified component descriptor at apply time - that is where localization happens in v2.\n"
        "Foreshadow the dependency now so slide 14 doesn't feel retroactive: the four-card chain on its own deploys raw Kubernetes manifests. For the Helm-deploy reference flow, the chain feeds a `ResourceGraphDefinition` that kro reconciles, with Flux (or Argo CD) applying the resulting `HelmRelease`. The OCM controllers DON'T ship kro, Flux, or Argo CD - bring your own. Slide 14 names this as one of the three honest edges.\n"
        "Q&A backup on Argo CD: tabs for Argo CD are landing in the website how-tos before the deck ships. Until then, the documented Helm-deploy path is kro + Flux; the Argo CD path is symmetrical.\n"
        "Q&A backup on the controller-shaped `ocm transfer`: yes, there's a `Replication` CR for in-cluster repo-to-repo mirroring. Appendix slide 16 covers it."
    ),
    12: (
        "Composition was just defined on slide 8. This slide does ONE job: the day-2 mechanic.\n"
        "The product is `acme.org/sovereign/product`. Day 1 references notes 1.0.0 and postgres 1.0.0, each with its descriptor digest pinned. The notes team ships a patch (1.0.0 -> 1.1.0). The platform team raises the product to 1.1.0 and updates the notes reference (its version AND its digest, because the new notes descriptor hashes differently). Postgres stays - same version, same digest.\n"
        "Commit. The controller pulls the new product descriptor, verifies the signature, resolves the new digests, applies. Notes rolls forward; postgres is untouched.\n"
        "Differentiator framing for security architects: OCM is a release-level envelope. `helm upgrade` upgrades one chart; cosign signs one image. The OCM signature covers the whole release as one unit - every digest in every resource of every referenced component is pinned by the one parent signature. Drift would mean breaking that signature.\n"
        "Q&A backup on forged descriptors: nothing OCM-specific stops a malicious operator from committing a forged descriptor with bumped versions, an attacker's image references, and a re-signed signature using a stolen key. Same threat model as any signed-release system: rotate keys, dual-sign, audit. What OCM gives you is one signature to audit instead of N.\n"
        "Bump the product. The references follow. The cluster cannot drift without breaking the envelope."
    ),
    13: (
        "Two paths to a first OCM component. Both tested in conformance on every release.\n"
        "• From zero - CLI. No cluster needed. Install CLI. Write a constructor for one component. Pack. Sign with RSA. Export as CTF. Carry to a second machine. Import. Verify. Cold-start budget: about thirty minutes - CLI install plus the simple `helloworld` pack/sign/verify walked in the website tutorial. Recommend this path first.\n"
        "• On your cluster - controllers. Spin up a kind cluster. Helm-install the OCM controllers, plus kro, plus your deployer of choice (Flux or Argo CD). Point them at your registry. Apply a Component resource - verified and reconciling. Cold-start budget: an afternoon - includes the bootstrap (kind + controllers + kro + Flux/Argo CD) and a Helm-deploy of the simple component documented in the getting-started tutorial.\n"
        "On the slide: no marketing minutes. The honest numbers live here so the speaker can land them when asked.\n"
        "Both paths coexist with what you already run - cosign, Argo CD, Flux, Kyverno. OCM signs the descriptor; your existing controls stay in place."
    ),
    14: (
        "The slide that earns trust. Deliver straight; do not soften.\n"
        "• Transfer defaults - copies only the descriptor. For air-gap, pass --copy-resources so the bytes travel too. Worth catching in a CI step the first time someone runs an air-gap export.\n"
        "• Controllers v1alpha1 - CRD shapes for Repository/Component/Resource/Deployer are stabilising but still v1alpha1. Pin to specific release tags in your platform installs.\n"
        "• Helm-deploy adds kro + Flux or Argo CD - the OCM controllers don't ship them. Bring your existing GitOps engine. Nuance for Q&A: kro is required for ALL documented deploy paths (it reconciles the ResourceGraphDefinition the Deployer feeds it), not only Helm-deploy. The GitOps engine - Flux today, Argo CD path landing in the docs before this deck ships - is the Helm-deploy-specific add. Three installs total for Helm-deploy.\n"
        "Honest now beats apologetic later. If any edge is a deal-breaker, tell us early."
    ),
    15: (
        "Close with the ask. Three doors, architect-shaped.\n"
        "• Evaluate - `ocm.software`. Read the spec, run the conformance scenario at `conformance/scenarios/sovereign`, judge fit. You will know within an afternoon if OCM fits.\n"
        "• Pilot - `github.com/open-component-model`. Take one product, one team, scoped scope of work. Spec, implementation, conformance suite, roadmap - all in the open.\n"
        "• Engage - community channels on the website. We're stewarding a standard under NeoNephos Foundation governance. The more voices while it's being shaped, the better the standard gets.\n"
        "Not selling OCM. Stewarding it as a multi-vendor standard. Ship the release as one unit. Thank you - questions."
    ),
    16: (
        "APPENDIX — pull only if asked about cluster-side mirroring or 'how do I get a version from one repo into another without running the CLI?'.\n"
        "A fifth controller, `Replication`, sits alongside the four-card chain - not within it. Where the chain delivers content INTO the cluster, Replication transfers a resolved component version FROM one OCM repository TO another. Same descriptor, same digests, fresh access fields.\n"
        "References a source `Component` CR and a target `Repository` CR. When the source's resolved version changes, transfers that version with its full reference graph into the target.\n"
        "Mirrors the behavior of `ocm transfer cv` on the OCM CLI. Records `status.lastTransferredDigest` after each successful run; a later reconciliation seeing the same digest is a no-op.\n"
        "Use cases: delivery pipelines, promotion between environments, air-gap mirroring kept in-cluster rather than on a workstation.\n"
        "Not on the main deck because the four-card chain is the load-bearing story for a 30-minute architect talk. This is the answer to a specific question, not part of the arc."
    ),
    # Slide 17 reserved if a future appendix slide is added between Replication
    # and the comparison backup. Keep the dict gap-free by skipping 17 here.
    18: (
        "APPENDIX / Q&A BACKUP — pull only if a hostile architect asks 'why not just compose cosign + in-toto + OCI 1.1 referrers + Flux?'. Not in the main 30-minute flow.\n"
        "Each tool in the room operates on a different unit; OCM operates one level up.\n"
        "• cosign / sigstore - signs one OCI artifact. Strong per-image trust. Doesn't bundle. Doesn't travel across registries without re-sign or `cosign copy`. OCM uses Sigstore as one of its signing schemes for the component descriptor.\n"
        "• SLSA / in-toto - attests the build that produced one artifact. Provenance, not bundling. Not natively air-gap; needs a separate transport story. OCM carries SLSA/in-toto attestations as resources inside the component.\n"
        "• SBOM / OCI 1.1 referrers - inventories one artifact's contents and attaches it to that artifact's digest. Discovery, not bundling. Doesn't span a multi-artifact release. OCM carries SBOMs as resources; the descriptor names which SBOM belongs to which artifact.\n"
        "• OCM - signs THE COMPONENT, a named versioned bundle of artifacts plus access paths. One signature covers every digest. Location-independent: access fields rewritten on transfer; signature still verifies. Air-gap native: CTF round-trip with no callback to source.\n"
        "The 'partial' cells are calibrated honesty - SLSA attestations CAN travel with their subject if you choose to, OCI 1.1 referrers ARE digest-addressable so partially location-independent. We don't overclaim.\n"
        "Close with the band line: 'OCM rides on top. It doesn't replace the per-artifact tools - it adds the release-level envelope they don't.'"
    ),
}


