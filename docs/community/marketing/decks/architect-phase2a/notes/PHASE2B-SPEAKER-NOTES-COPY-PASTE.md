# Speaker Notes — Copy-Paste Source for SharePoint PPTX

**How to use this file.** Each section below is one PDF slide. Click into the slide's Notes pane in PowerPoint, **select all existing text and replace** with the block under that section. Slide numbers below match the rendered PDF order you see in SharePoint.

**Slide-order note.** In the rendered deck, slide 9 = TRANSPORT and slide 10 = SIGN. That's the opposite of the Python build script's internal numbering (the script has SIGN=9, TRANSPORT=10) — but the speaker notes below are indexed by what you see in the PDF, so paste them where the visible slide titles match.

**No main-arc renumbering.** The "How OCM compares" slide is a post-CTA Q&A backup at slide 18. Main-arc slides (1–16) keep their current numbering.

---

## SLIDE 1 — PAIN ("You ship pieces. Nothing carries the release.")

```
Open with the observation, not the product 'OCM'.
Any release in the last six months: images, charts, configs, SBOMs - each named differently, each signed differently, if at all.
You shipped pieces. Nothing carried the release.
Thread the arc: by the end of the deck you'll have a thirty-minute path to your first OCM component on a laptop - and an afternoon to one running on a cluster. Until then, here's why that matters.
No brand pitch yet - the deck does that at the end.
```

---

## SLIDE 2 — DIAGNOSIS ("In every existing tool, identity is bound to location.")

```
Why the existing toolbox does not compose. Three artifact types, three identity shapes:
• OCI image - digest pins the bytes. Nothing pins the release the image belongs to.
• Helm chart - version pins the chart. Nothing pins it to the image, config, and SBOM it ships with.
• SBOM - referrer attaches to one digest. No referrer spans the whole release.
Calibration for COSIGN (which can update the digest after explicit `cosign copy`): keep signing each piece. What is missing is a name for the release as one unit, signable, verifiable in a sovereign zone with no callback.
Diagnosis: identity is bound to location.
```

---

## SLIDE 3 — THE HINGE ("Identity that travels with the artifact.")

```
The conceptual fulcrum. Let it breathe. OCM separates three things the existing tools fuse:
• Component identity - DNS-style name plus SemVer. Globally unique, location-agnostic. No registry in the name.
• Digest - SHA-256 over each resource. Computed at pack time. This is what we sign.
• Access - type plus fetch fields (`OCIImage/v1`, `Helm/v1`, `LocalBlob/v1`). Where the bytes currently live.
Promote EU -> US -> air-gapped CTF and DEV -> STAGING -> PROD : identity stays, digest stays, only access is rewritten. Signature still verifies - anywhere.
Move the artifact. The digest stays. Only the access changes. That is the whole trick.
Q&A backup on 'globally unique': inherits from DNS-prefix naming - same model as Go import paths. We don't run a registry that arbitrates conflicts; uniqueness is delegated to DNS. Two parties claiming `acme.org/helloworld` is prevented the same way two parties claiming `acme.org` is prevented.
Q&A backup on squatting: trust is per-component - the verifier knows what trust anchor to apply to the descriptor in front of it. A regulated environment relies on (a) controlling which registry the controllers are configured to pull from, and (b) per-component verifier config. Per-name-prefix trust-anchor binding is not in the spec or the controllers today.
```

---

## SLIDE 4 — POSITIONING ("Wraps every artifact. Signs the whole release.")

```
Two jobs: pre-empt 'what does this replace?' and define the noun 'COMPONENT' the rest of the deck rests on.
OCM is not a replacement for OCI, Helm, cosign, sigstore, or your SBOM tooling. It WRAPS them — adds one envelope signature over the whole release, sitting on top of whatever signatures the individual artifacts already carried.
• Any format - Helm stays Helm, OCI stays OCI, configs stay configs. The artifact `type:` is free-form, so an OCM component already carries SBOMs, npm packages, maven artifacts and anything else your team produces today - access is via `File/v1` or `LocalBlob/v1`. Dedicated `NPM/v1` and `Maven/v1` access types are roadmap (Maven epic ocm-project#836; NPM targeted before first GA at end of 2026).
• Any location - name and version do not encode a registry. Move it; the name stays.
• One signature - covers every digest in the component. The whole release is one signed unit.
Q&A backup on cosign / sigstore / OCI 1.1 referrers: We don't replace per-artifact signatures - they travel inside the component. OCM adds a release-level envelope: one signature over the canonicalized component descriptor that covers the digests of every resource. If you cosign-sign every image and ship a sigstore bundle per chart today, keep doing that - OCM signs the wrapper above them.
Q&A backup on SBOD vocabulary: if the audience knows OCM at all, they may have heard 'Software Bill of Delivery' - SBOD - in earlier presentations or on the website. It's our positioning term against SBOM. Technically an SBOD is the same object architects call the component descriptor - the serialized form of an OCM component version. Different words, one object.
A component is the unit you sign, transport, and deploy. Hold the noun.
```

---

## SLIDE 5 — CONSTRUCTOR ("What you write.")

No change to speaker notes. Existing text stands as-is.

```
First YAML the audience sees. Walk it like you would for a colleague - eighteen lines, hand-written.
• `components` - list, usually one. Name is DNS-style; version is SemVer.
• `provider` - metadata, required.
• `resources` - every artifact in the release. Two ways in:
  ▪ `input:` - by value. Constructor reads the file at pack time, embeds the bytes. Travels in the archive.
  ▪ `access:` - by reference. Records a pointer (e.g. `ghcr.io/.../podinfo:6.9.1`), resolves digest now, copies bytes later.
Local files and configs tend to be input; big images tend to be access. Mix freely.
CLI if asked: `ocm add cv` against this file, default output a CTF archive.
```

---

## SLIDE 6 — DESCRIPTOR ("What gets signed and travels.")

```
Clarify first: this is generated by `ocm add cv`. You do not hand-edit it. This is what travels.
We show one resource - the image - to keep focus on the mechanism. Real components carry many resources and may reference other components; the '...' line stands in for that.
• `access` - `OCIImage/v1` with the imageReference pinned to a digest. Kills the repoint-the-tag attack class. Excluded from the canonical form on purpose - transport rewrites it.
• `digest` - SHA-256 over the resource bytes. Computed at pack time. Input to the descriptor hash.
• `signatures:` - list. Each entry signs ONE hash: the SHA-256 of the canonicalized descriptor. That single hash covers every resource digest. Multiple signatures allowed - dual-sign RSA + Sigstore, verifiers pick.
Three things to land. Signed: the descriptor hash - so one signature covers every artifact in the component. Not signed: the access fields - so transport can rewrite them freely. The signature still verifies, anywhere.
Sign the descriptor hash, not the access. Seven words; whole transport story.
Q&A backup on the trust model (one per scheme, all configurable): RSA-PSS uses bare public-key pinning - operator pins the public key. Sigstore uses OIDC issuer + Fulcio short-lived cert + Rekor transparency log - operator pins the issuer. GPG uses an OpenPGP keyring - operator pins the key fingerprint. Algorithm is configurable per signature; the signed object is the canonicalized descriptor regardless of algorithm.
Q&A backup on composition: the signature transitively pins `componentReferences` (introduced on slide 8). The product signature covers every reference's descriptor digest - so re-signing or re-publishing a referenced component breaks the product signature. Verifier policy is per-component: a referenced component is verified against its own trust anchor at deploy time; the product is verified against the product's anchor.
Q&A backup on canonicalization: the canonical form of the descriptor is spec'd at `ocm-spec/04-extensions/01-artifact-types/`. Signatures are over canonical bytes - so JSON/YAML field ordering and whitespace can't break verification.
```

---

## SLIDE 7 — THE FOUR MOVES ("Pack · Sign · Transport · Deploy")

No change to speaker notes. Existing text stands as-is.

```
Bridge from noun to verb. On slides 5 and 6 you saw the static artifact - what you write and what travels. Now four moves on that artifact.
We've covered the first half of two of them already: the constructor (slide 5) is the input to Pack; the descriptor (slide 6) is the output of Pack, the target of Sign, and the unit of Transport.
Name the primitive: the signed descriptor is itself an OCI artifact - media type `application/vnd.ocm.software.component-descriptor.v2`. Lives in your registry next to the images. No new infrastructure.
Four moves, same flow, every component:
• Pack - bundle once, name once.
• Sign - one signature covers every digest.
• Transport - registry ↔ registry ↔ tarball. Signature survives every hop.
• Deploy - controller verifies, resolves digests, applies. No callback upstream.
These are lifecycle moves, not CLI verbs. The CLI you'll type is `ocm add cv`, `ocm sign cv`, `ocm transfer cv`, then `kubectl apply` against the Deployer CR. Same four moves, slightly different names. Sovereign cloud, air-gap, customer cluster. Next four slides are the mechanics.
```

---

## SLIDE 8 — COMPOSE ("Service carries resources. Product carries references.")

```
Composition is the architectural fact that makes day-2 work.
• Service components carry resources - images, charts, configs, SBOMs. Walk the LEFT box: `acme.org/sovereign/notes` and `acme.org/sovereign/postgres`, each with image + chart + `...` (real components carry more - configs, SBOMs - the `...` stands for that).
• A product component composes services via `componentReferences:` - name + version, no resources of its own. Walk the RIGHT box: `acme.org/sovereign/product` references both notes and postgres by name and version. Nothing else.
• Each service is independently versioned, signed, transferable. The product is a small descriptor that points at them.
Real releases are not one big component - they are one product component referencing several services. This is the shape day-2 (slide 12) operates on.
Q&A backup on transitive trust: `componentReferences` are pinned by the digest of the referenced component's descriptor. The product signature covers each reference's digest - re-signing a referenced component breaks the product signature. At deploy time the verifier checks each component against its own trust anchor: notes against the notes team's anchor, postgres against the postgres team's anchor, product against the product team's anchor. Without an explicit per-component policy, the controller applies whatever trust anchor was configured on the Component CR for that name.
```

---

## SLIDE 9 — TRANSPORT ("Three patterns. One command.")

```
One mechanic, three patterns - covers every delivery topology you will see.
• Registry -> Registry - promotion across dev/staging/prod, or cross-cloud GHCR -> ECR. Same digests, every access rewritten.
• Registry -> CTF - Common Transport Format. A local archive of blobs + index. Hand-carry across the boundary.
• CTF -> Registry - the air-gap import. Archive arrives, `ocm transfer` uploads, access rewrites to local registry, signature verifies locally. No traffic to source.
Same command in all three: `ocm transfer cv <src> <dst>`. Access changes; digests do not. Signature covers digests, so it survives every hop. Verification is purely local at the destination - that is the air-gap property.
Q&A backup on the air-gap default footgun: default `ocm transfer` copies only the component descriptor - the access fields still point back at the source registry. For air-gap (CTF -> Registry) you MUST pass `--copy-resources` so the bytes travel with the descriptor. Slide 14 names this as one of the three honest edges. Worth catching in a CI step the first time someone runs an air-gap export.
Q&A backup on Sigstore air-gap specifically: Sigstore verification at the destination is offline IF the trusted-root file (Fulcio CA + Rekor public key for the configured issuer) has been distributed into the destination once, out of band. After that, `ocm verify cv` runs without contacting Rekor or Fulcio. RSA and OpenPGP need only their pinned public keys - no trusted-root file.
```

---

## SLIDE 10 — SIGN ("Same signed object. Three signing options.")

**Slide text change first:** middle column header `GPG` → `OpenPGP`.

```
Same signed object - the canonical descriptor digest - in all three. How you prove the key is what varies. All three are stable on the v1alpha1 API surface today:
• RSA / RSASSA-PSS - bare public-key pinning. The key you already rotate. No PKI required. Trust model: key pinning.
• OpenPGP - OpenPGP key material; trust model is the same as RSA Plain (key pinning), just with a different key format. Fits orgs already running web-of-trust keyrings. (Slide header says 'OpenPGP' - GPG is one implementation; Sequoia and RNP produce compatible signatures.)
• Sigstore - keyless via OIDC + Rekor transparency log; trust anchor is your OIDC issuer. Fits CI workloads and any signer that can present an OIDC identity.
Three things to land. Same signed object - the canonical descriptor digest. Verifiers can require multiple in parallel (RSA from release team + Sigstore from CI). Pick what your org already runs.
Q&A backup on verifier policy floor (the security architect's hardest question): all three schemes resolve against standard trust anchors - RSA against pinned public keys, OpenPGP against an OpenPGP keyring, Sigstore against a Fulcio root plus Rekor verifier. Verifier policy is per-component: an operator pins 'this product accepts only scheme X with anchor Y' on the Component CR. Without explicit policy, the controller accepts any signature whose anchor matches the configured `verify:` entries on that Component CR. Production installs SHOULD pin policy via admission. There's no implicit fall-through to a weakest scheme.
Q&A backup on PEM / cert chains: A fourth option exists - RSA with X.509 certificate chain, PEM encoding. Still experimental: the CLI prints `experimental` warnings on every sign and verify. Watch the docs; we'll promote it when the encoding stabilizes.
CLI: `ocm sign cv ./archive//github.com/acme/widget:v1.4.2 --signature acme-release-key --private-key ./release-key.pem`. Idempotent.
```

---

## SLIDE 11 — DEPLOY ("OCM controllers verify and apply.")

```
Four CRs, one chain. The controllers verify and apply the component.
• Repository - names where component versions live. OCI registry, mounted CTF, S3, local FS.
• Component - names a specific component version. Pulls the descriptor and verifies its signature against the trust anchor configured on the Component CR. Verification is OPT-IN: without a `verify:` entry referencing a key/secret, the controller resolves and pulls but does not check signatures. Production installs should require verification via admission policy.
• Resource - picks one artifact from the verified component, by digest: Helm chart, OCI image, raw manifest, blob.
• Deployer - applies the resource to the cluster. Resolves image refs and other deploy-time pointers from the verified component descriptor at apply time - that is where localization happens in v2.
Foreshadow the dependency now so slide 14 doesn't feel retroactive: the four-card chain on its own deploys raw Kubernetes manifests. For the Helm-deploy reference flow, the chain feeds a `ResourceGraphDefinition` that kro reconciles, with Flux (or Argo CD) applying the resulting `HelmRelease`. The OCM controllers DON'T ship kro, Flux, or Argo CD - bring your own. Slide 14 names this as one of the three honest edges.
Q&A backup on Argo CD: tabs for Argo CD are landing in the website how-tos before the deck ships. Until then, the documented Helm-deploy path is kro + Flux; the Argo CD path is symmetrical.
Q&A backup on the controller-shaped `ocm transfer`: yes, there's a `Replication` CR for in-cluster repo-to-repo mirroring. Appendix slide 16 covers it.
```

---

## SLIDE 12 — DAY 2 ("Bump the product version. Everything follows.")

No change to speaker notes. Existing text stands as-is.

```
Composition was just defined on slide 8. This slide does ONE job: the day-2 mechanic.
The product is `acme.org/sovereign/product`. Day 1 references notes 1.0.0 and postgres 1.0.0, each with its descriptor digest pinned. The notes team ships a patch (1.0.0 -> 1.1.0). The platform team raises the product to 1.1.0 and updates the notes reference (its version AND its digest, because the new notes descriptor hashes differently). Postgres stays - same version, same digest.
Commit. The controller pulls the new product descriptor, verifies the signature, resolves the new digests, applies. Notes rolls forward; postgres is untouched.
Differentiator framing for security architects: OCM is a release-level envelope. `helm upgrade` upgrades one chart; cosign signs one image. The OCM signature covers the whole release as one unit - every digest in every resource of every referenced component is pinned by the one parent signature. Drift would mean breaking that signature.
Q&A backup on forged descriptors: nothing OCM-specific stops a malicious operator from committing a forged descriptor with bumped versions, an attacker's image references, and a re-signed signature using a stolen key. Same threat model as any signed-release system: rotate keys, dual-sign, audit. What OCM gives you is one signature to audit instead of N.
Bump the product. The references follow. The cluster cannot drift without breaking the envelope.
```

---

## SLIDE 13 — ADOPTION ("Two paths to a first OCM component.")

**Slide text change first:** delete the "Thirty minutes on a laptop" and "Thirty minutes on any cluster" closing lines from both cards. The cards now end on "Verify on the other side." and "Deploy a component." respectively.

```
Two paths to a first OCM component. Both tested in conformance on every release.
• From zero - CLI. No cluster needed. Install CLI. Write a constructor for one component. Pack. Sign with RSA. Export as CTF. Carry to a second machine. Import. Verify. Cold-start budget: about thirty minutes - CLI install plus the simple `helloworld` pack/sign/verify walked in the website tutorial. Recommend this path first.
• On your cluster - controllers. Spin up a kind cluster. Helm-install the OCM controllers, plus kro, plus your deployer of choice (Flux or Argo CD). Point them at your registry. Apply a Component resource - verified and reconciling. Cold-start budget: an afternoon - includes the bootstrap (kind + controllers + kro + Flux/Argo CD) and a Helm-deploy of the simple component documented in the getting-started tutorial.
On the slide: no marketing minutes. The honest numbers live here so the speaker can land them when asked.
Both paths coexist with what you already run - cosign, Argo CD, Flux, Kyverno. OCM signs the descriptor; your existing controls stay in place.
```

---

## SLIDE 14 — WHAT'S SHARP ("Three honest edges.")

**Slide text change first:** third bullet changes from "Helm-deploy adds kro + Flux — the OCM controllers don't ship them. Bring your existing GitOps engine." to "Helm-deploy adds kro + Flux or Argo CD — the OCM controllers don't ship them. Bring your existing GitOps engine."

```
The slide that earns trust. Deliver straight; do not soften.
• Transfer defaults - copies only the descriptor. For air-gap, pass --copy-resources so the bytes travel too. Worth catching in a CI step the first time someone runs an air-gap export.
• Controllers v1alpha1 - CRD shapes for Repository/Component/Resource/Deployer are stabilising but still v1alpha1. Pin to specific release tags in your platform installs.
• Helm-deploy adds kro + Flux or Argo CD - the OCM controllers don't ship them. Bring your existing GitOps engine. Nuance for Q&A: kro is required for ALL documented deploy paths (it reconciles the ResourceGraphDefinition the Deployer feeds it), not only Helm-deploy. The GitOps engine - Flux today, Argo CD path landing in the docs before this deck ships - is the Helm-deploy-specific add. Three installs total for Helm-deploy.
Honest now beats apologetic later. If any edge is a deal-breaker, tell us early.
```

---

## SLIDE 15 — CTA ("Ship the release as one unit — Evaluate / Pilot / Engage.")

No change to speaker notes. Existing text stands as-is.

```
Close with the ask. Three doors, architect-shaped.
• Evaluate - `ocm.software`. Read the spec, run the conformance scenario at `conformance/scenarios/sovereign`, judge fit. You will know within an afternoon if OCM fits.
• Pilot - `github.com/open-component-model`. Take one product, one team, scoped scope of work. Spec, implementation, conformance suite, roadmap - all in the open.
• Engage - community channels on the website. We're stewarding a standard under NeoNephos Foundation governance. The more voices while it's being shaped, the better the standard gets.
Not selling OCM. Stewarding it as a multi-vendor standard. Ship the release as one unit. Thank you - questions.
```

---

## SLIDE 16 — APPENDIX · REPLICATION

No change to speaker notes. Existing text stands as-is.

```
APPENDIX — pull only if asked about cluster-side mirroring or 'how do I get a version from one repo into another without running the CLI?'.
A fifth controller, `Replication`, sits alongside the four-card chain - not within it. Where the chain delivers content INTO the cluster, Replication transfers a resolved component version FROM one OCM repository TO another. Same descriptor, same digests, fresh access fields.
References a source `Component` CR and a target `Repository` CR. When the source's resolved version changes, transfers that version with its full reference graph into the target.
Mirrors the behavior of `ocm transfer cv` on the OCM CLI. Records `status.lastTransferredDigest` after each successful run; a later reconciliation seeing the same digest is a no-op.
Use cases: delivery pipelines, promotion between environments, air-gap mirroring kept in-cluster rather than on a workstation.
Not on the main deck because the four-card chain is the load-bearing story for a 30-minute architect talk. This is the answer to a specific question, not part of the arc.
```

---

## ★ SLIDE 18 — APPENDIX · HOW OCM COMPARES (Q&A backup)

Speaker notes are already embedded in `OCM-Story-Architect-External-Slide-4b.pptx`. Reference text below in case you need to paste manually:

```
APPENDIX / Q&A BACKUP — pull only if a hostile architect asks 'why not just compose cosign + in-toto + OCI 1.1 referrers + Flux?'. Not in the main 30-minute flow.
Each tool in the room operates on a different unit; OCM operates one level up.
• cosign / sigstore - signs one OCI artifact. Strong per-image trust. Doesn't bundle. Doesn't travel across registries without re-sign or `cosign copy`. OCM uses Sigstore as one of its signing schemes for the component descriptor.
• SLSA / in-toto - attests the build that produced one artifact. Provenance, not bundling. Not natively air-gap; needs a separate transport story. OCM carries SLSA/in-toto attestations as resources inside the component.
• SBOM / OCI 1.1 referrers - inventories one artifact's contents and attaches it to that artifact's digest. Discovery, not bundling. Doesn't span a multi-artifact release. OCM carries SBOMs as resources; the descriptor names which SBOM belongs to which artifact.
• OCM - signs THE COMPONENT, a named versioned bundle of artifacts plus access paths. One signature covers every digest. Location-independent: access fields rewritten on transfer; signature still verifies. Air-gap native: CTF round-trip with no callback to source.
The 'partial' cells are calibrated honesty - SLSA attestations CAN travel with their subject if you choose to, OCI 1.1 referrers ARE digest-addressable so partially location-independent. We don't overclaim.
Close with the band line: 'OCM rides on top. It doesn't replace the per-artifact tools - it adds the release-level envelope they don't.'
```

---

## What to apply on the slides themselves (not in notes)

Three slide-text changes plus one appendix slide. See `PHASE2B-CHANGE-SUMMARY.md` for the full per-slide rationale; the short list:

1. **Slide 2** — replace the three bullets with the new Option-B wording (see slide-text in PHASE2B-CHANGE-SUMMARY.md, "SLIDE 2 — DIAGNOSIS" section).
2. **Slide 10 (SIGN)** — middle column header `GPG` → `OpenPGP`.
3. **Slide 13 (ADOPTION)** — delete the two "Thirty minutes …" closing lines from both cards.
4. **Slide 14 (WHAT'S SHARP)** — third bullet rewrite (see above section).
5. **Slide 18 (appendix)** — drag-insert `OCM-Story-Architect-External-Slide-4b.pptx` AFTER slide 16 in the deck. Pulled on demand in Q&A; not in the main 30-min flow.
