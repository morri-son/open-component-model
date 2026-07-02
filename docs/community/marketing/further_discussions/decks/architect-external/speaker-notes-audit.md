# Speaker-Notes Audit — Architect External Deck

**Purpose.** Identify AI-slop patterns in the current speaker notes and propose rewrites in the voice defined at `design-principles/voice-guide.md`. User approves before any actual rewrite happens.

**Audit method.** Every slide reviewed against the banned-list in the voice guide plus the "what this voice does NOT do" section. When a pattern is found, the offending phrase is quoted and the pattern named. When multiple patterns cluster on one slide, they are grouped by impact.

**How to use this file.** Read the "AI-slop patterns" and "Impact" sections per slide first. Where the impact is real, accept or edit the proposed rewrite. Where the impact is trivial, skip. When a rewrite is approved, apply it to the source PPTX (SharePoint) speaker notes pane.

---

## Slide 1 — You ship pieces.

**AI-slop patterns found:** None significant. The notes read like a human wrote them. "You shipped pieces. Nothing carried the release." is exactly the target rhythm — short, load-bearing, no filler. The "no brand pitch yet" self-instruction is a stage direction, which is fine.

Minor: the em-dashes rendered as hyphens (`-`) throughout the file are a typographical issue, not a voice issue. Flag for later cleanup, not for this audit.

---

## Slide 2 — DIAGNOSIS

**AI-slop patterns found:**
- Enumeration with over-perfect parallel structure: three bullets, each `<Artifact> - <verb> pins <X>. Nothing pins <Y>.` The shape is too clean. The last bullet strains to fit the template — SBOMs and "referrer attaches" doesn't sit in the same shape as digest/version pinning.
- Consulting rhythm: `Three artifact types, three identity shapes:` — reads like a slide title, not a spoken note.
- Slight preamble: `Why the existing toolbox does not compose.` — states the topic before saying the thing.

**Impact:** Moderate. The parallel structure makes the diagnosis feel constructed rather than observed. The point (identity bound to location) survives; the delivery flattens it.

**Proposed rewrite:**

> Existing toolbox doesn't compose. OCI: the digest pins bytes; nothing pins the release those bytes belong to. Helm: the chart version pins the chart; nothing binds it to the image, config, and SBOM shipped alongside. SBOMs and OCI 1.1 referrers: attach to one digest — no referrer spans the whole release.
>
> Calibration for the cosign audience: cosign updates the digest after an explicit `cosign copy`. Keep signing each piece. What's missing is a name for the release as one unit — signable, verifiable in a sovereign zone with no callback.
>
> Diagnosis in one line: identity is bound to location.

---

## Slide 3 — THE HINGE

**AI-slop patterns found:**
- Consulting rhythm: `The conceptual fulcrum. Let it breathe.` — stage direction that describes what the slide is rather than what to say.
- Enumeration with over-perfect parallel structure: the three-bullet `Component identity / Digest / Access` block has identical shape and length. Same template-generated feel as Slide 2.
- Meta-scaffolding: `That is the whole trick.` — the note announces its own punchline instead of letting the mechanism do it.
- Q&A backups run together into one paragraph with no line breaks between them — makes them hard to find on stage.

**Impact:** Moderate on the main block, low on the Q&A backups (content is fine, formatting is bad). The three-bullet stack is the load-bearing slide of the entire deck. It should not read like a template.

**Proposed rewrite:**

> Fulcrum slide. Let it breathe.
>
> OCM separates three things the existing tools fuse into one. Identity is a DNS-style name plus a SemVer version — globally unique, no registry in the name. Digest is SHA-256 over each resource, computed at pack time; this is what we sign. Access is the type plus fetch fields — `OCIImage/v1`, `Helm/v1`, `LocalBlob/v1` — where the bytes currently sit.
>
> Promote across environments — EU to US, dev to staging to prod, registry to CTF to air-gapped registry. Identity stays. Digest stays. Access is rewritten. Signature still verifies.
>
> Land the seven-word version: move the artifact, the digest stays, only the access changes.
>
> Q&A — "globally unique?" Uniqueness is inherited from DNS-prefix naming. Same model as Go import paths. We don't run a registry that arbitrates conflicts; DNS does. Two parties claiming `acme.org/helloworld` is prevented the same way as two parties claiming `acme.org`.
>
> Q&A — squatting. Trust is per-component. The verifier knows which anchor to apply to the descriptor in front of it. A regulated environment relies on (a) controlling which registry the controllers pull from and (b) per-component verifier config. Per-name-prefix trust-anchor binding is not in the spec or the controllers today.

---

## Slide 4 — WHERE OCM SITS

**AI-slop patterns found:**
- Consulting rhythm: `Two jobs: pre-empt 'what does this replace?' and define the noun 'COMPONENT'…` — meta-scaffolding announcing what the slide does.
- Enumeration with over-perfect parallel structure: `Any format / Any location / One signature` — three bullets, each starting `Any …` or `One …`, sales-bullet shape.
- Filler-as-filler: the parenthetical `(Maven epic ocm-project#836; NPM targeted before first GA at end of 2026)` reads like it was pasted in from a status update, not delivered aloud.
- Meta-scaffolding: `Hold the noun COMPONENT.` — describes what the speaker should do rather than saying the thing.

**Impact:** Moderate. The `Any format / Any location / One signature` template is a marketing shape masquerading as an architect note. The Q&A backup on cosign/sigstore is good — keep it.

**Proposed rewrite:**

> Two jobs on this slide. Pre-empt "what does OCM replace?" and define the noun COMPONENT that the rest of the deck rests on.
>
> OCM doesn't replace OCI, Helm, cosign, Sigstore, or SBOM tooling. It wraps them — one envelope signature over the whole release, sitting on top of whatever signatures the individual artifacts already carry.
>
> Format is free. Helm stays Helm; OCI stays OCI; configs stay configs. `type:` on a resource is a free-form string, so an OCM component already carries SBOMs, npm packages, Maven artifacts, whatever your team produces — access via `File/v1` or `LocalBlob/v1`. Dedicated `NPM/v1` and `Maven/v1` access types are on the roadmap (Maven: epic ocm-project#836; NPM targeted before first GA, end of 2026).
>
> Location is free. Name and version don't encode a registry. Move it — the name stays.
>
> One signature covers every digest in the component.
>
> Q&A — cosign, Sigstore, OCI 1.1 referrers. We don't replace per-artifact signatures; they travel inside the component. OCM adds a release-level envelope: one signature over the canonicalized descriptor that covers every resource digest. If you cosign-sign every image and ship a Sigstore bundle per chart today, keep doing that. OCM signs the wrapper above them.
>
> Q&A — the term SBOD. If the audience has heard SBOM they may have heard SBOD — Software Bill of Delivery — in earlier OCM material or on the website. Same object architects call the component descriptor. Different word for the same serialized OCM component version.
>
> Land: a component is the unit you sign, transport, and deploy.

---

## Slide 5 — CONSTRUCTOR

**AI-slop patterns found:** None significant. The note walks the YAML like a colleague. "Local files and configs tend to be input; big images tend to be access. Mix freely." is exactly the target voice — observation with a concrete verb, no filler.

Minor: "First YAML the audience sees. Walk it like you would for a colleague - eighteen lines, hand-written." is a good stage direction. Keep.

---

## Slide 6 — DESCRIPTOR

**AI-slop patterns found:**
- Consulting rhythm: `Three things to land ->` — explicit "here come three things" scaffolding.
- Enumeration with over-perfect parallel structure: the `access / digest / signatures:` bullets are again three balanced bullets. The content is good; the shape is repetitive across slides 2, 3, 4, 6.
- Meta-scaffolding: `Seven words; whole transport story.` — announces the punchline instead of letting it land.
- Q&A backups collapsed into a wall of prose.

**Impact:** Low-to-moderate. Content is technically strong. Delivery-wise, the "three things to land" trope repeats across the deck and starts to feel like a tic.

**Proposed rewrite:**

> Clarify first: the descriptor is generated by `ocm add cv`. Nobody hand-edits it. This is what travels.
>
> One resource shown — the image — to keep focus on the mechanism. Real components carry many resources and can reference other components; the `...` stands in for that.
>
> `access:` is `OCIImage/v1` with the imageReference pinned to a digest. Kills the repoint-the-tag attack class. Excluded from the canonical form on purpose, because transport rewrites it.
>
> `digest:` is SHA-256 over the resource bytes, computed at pack time. It feeds the descriptor hash.
>
> `signatures:` is a list. Each entry signs one hash — the SHA-256 of the canonicalized descriptor. That single hash covers every resource digest. Multiple signatures allowed: dual-sign RSA plus Sigstore, verifiers pick.
>
> The seven-word version: sign the descriptor hash, not the access. Signed: the descriptor hash — one signature covers every artifact. Not signed: the access fields — so transport can rewrite them freely. The signature still verifies, anywhere.
>
> Q&A — trust model, one per scheme, all configurable. RSA-PSS: operator pins the public key. Sigstore: operator pins the OIDC issuer; Fulcio issues short-lived certs; Rekor logs. GPG: operator pins the OpenPGP fingerprint. Algorithm is configurable per signature; the signed object is the canonicalized descriptor regardless.
>
> Q&A — composition. The signature transitively pins `componentReferences` (defined on slide 8). The product signature covers every reference's descriptor digest — re-signing or re-publishing a referenced component breaks the product signature. Verifier policy is per-component: at deploy time each referenced component is verified against its own trust anchor.

---

## Slide 7 — OCM IN ONE PICTURE

**AI-slop patterns found:**
- Meta-scaffolding / preamble: `Big diagram, four verbs, this is the demo replacement.` — stage direction.
- Consulting rhythm: `"Here's the whole flow on one slide. Four verbs."` — announces the structure before delivering it.
- Filler-as-filler / meta-scaffolding: `"Pack, sign, transport, deploy. That's OCM in operation."` — closes by naming what was just done. Redundant.
- The quoted spoken lines have a mild hyperbole streak: `"One source of truth."`, `"So if anything changes, the signature breaks."` — the first is a marketing cliché, the second is fine.

**Impact:** Moderate. The slide is the demo replacement, so the notes are spoken almost verbatim. The template-y quotes will sound like a script when read aloud.

**Proposed rewrite:**

> Big diagram. Four verbs. This IS the demo — no live tooling.
>
> Point at PACK. Everything the software needs — image, chart, config — bundled into one named, versioned component. One artifact carries the release.
>
> Point at SIGN. One signature covers every artifact in the bundle, by digest. If anything changes, verification breaks.
>
> Point at TRANSPORT. The component moves across registry boundaries. Cloud to cloud, region to region, into an air-gapped CTF. Signature doesn't care.
>
> Point at DEPLOY. At the destination, the receiver verifies the signature, unpacks, deploys. GitOps or OCM K8s controllers — operator's call. No callback upstream.
>
> Land: pack, sign, transport, deploy — advance.

---

## Slide 8 — COMPOSE

**AI-slop patterns found:**
- Enumeration with over-perfect parallel structure: three bullets, each starting `• Service components / A product component / Each service`. Same template shape as slides 2, 3, 4, 6.
- Consulting rhythm: `This is the shape day-2 (slide 12) operates on.` — announces cross-reference in a stiff way.
- Q&A backup collapses two paragraphs of trust-model detail into one block that's hard to find under pressure.

**Impact:** Low. The mechanism (services vs. product, `componentReferences`) is the point of the slide and the note delivers it. The parallel-bullet tic keeps showing up.

**Proposed rewrite:**

> Services carry resources — images, charts, configs, SBOMs. Walk the LEFT box: `acme.org/sovereign/notes` and `acme.org/sovereign/postgres`, each with its image and/or chart. Real service components usually carry more (configs, SBOMs, provenance).
>
> A product component composes services via `componentReferences:` — name plus version, normally no resources of its own. Walk the RIGHT box: `acme.org/sovereign/product` references notes and postgres by name and version. That's it.
>
> Each service is independently versioned, signed, transferable. The product is a component that points at them.
>
> Real releases are not one big component. They're one product referencing several services. Slide 12 (day 2) operates on this shape.
>
> Q&A — transitive trust. `componentReferences` are pinned by the referenced descriptor's digest. The product signature covers each reference digest, so re-signing a referenced component breaks the product signature.
>
> Q&A — verifier policy at deploy time. Each component is checked against its own trust anchor: notes against the notes team's anchor, postgres against the postgres team's anchor, product against the product team's anchor. With no explicit per-component policy, the controller applies whatever anchor was configured on the Component CR for that name.

---

## Slide 9 — SIGN

**AI-slop patterns found:**
- Enumeration with over-perfect parallel structure: three bullets — RSA / OpenPGP / Sigstore — each in the shape `<name> - <mechanism>. <trust model>. <fit>.` Very template.
- Consulting rhythm: `Three things to land.` — same tic as slide 6.
- Hyperbole nearly avoided: `The controller will reject a non-RSA signature with an 'unsupported signature algorithm' error rather than fall through silently, so the safety property holds` — this one is actually good, concrete, keep.
- The "Honest scope note" paragraph is one of the strongest passages in the deck — do not touch. Reads like a person owning the trim edge.

**Impact:** Low. The signing slide carries a lot of technical weight and the note is largely accurate and specific. The template bullets are the only real weakness.

**Proposed rewrite:**

> Same signed object across all three schemes — the canonical descriptor digest. What varies is how you prove the key. All three schemes are stable in the CLI on the v1alpha1 API surface today.
>
> RSA / RSASSA-PSS: bare public-key pinning. The key you already rotate. No PKI required.
>
> OpenPGP: OpenPGP key material, same trust model as RSA (key pinning), different key format. Fits orgs already running web-of-trust keyrings. Header says OpenPGP; GPG is one implementation, Sequoia and RNP produce compatible signatures.
>
> Sigstore: keyless via OIDC plus a Rekor transparency log; trust anchor is your OIDC issuer. Fits CI workloads and any signer that can present an OIDC identity.
>
> Land: verifiers can require multiple in parallel — RSA from the release team plus Sigstore from CI. Pick what your org already runs.
>
> Q&A — verifier policy on the Kubernetes Component CR. Optional `verify:` field, list of {signature-name, public-key} pairs. Verification is opt-in: with no entries the controller resolves and pulls but doesn't check signatures. With entries the controller looks for those signature names in the descriptor and verifies. No scheme pinning on the CR; the scheme is read from the signature's algorithm field.
>
> Honest scope note — the v1alpha1 controller today implements RSA (RSASSA-PSS, RSASSA-PKCS1V15) only. OpenPGP and Sigstore verification work in the CLI — the three columns on this slide are the CLI surface. The controller rejects a non-RSA signature with an "unsupported signature algorithm" error rather than falling through silently, so the safety property holds. Practical answer for teams running the controllers in production today: RSA on the CR, CLI for the broader scheme set, OpenPGP and Sigstore controller support on the roadmap.
>
> Q&A — global enforcement. No admission webhook ships with the OCM controllers. Verification policy lives on each Component CR. Production installs that want global enforcement bring their own admission policy — Kyverno, Gatekeeper, or a custom webhook against the Component resource.
>
> Q&A — PEM / cert chains. A fourth option exists: RSA with X.509 chain, PEM encoded. Still experimental — the CLI prints `experimental` on every sign and verify. Watch the docs; we'll promote it when the encoding stabilizes.

---

## Slide 10 — TRANSPORT

**AI-slop patterns found:**
- Enumeration with over-perfect parallel structure: three bullets `Registry -> Registry / Registry -> CTF / CTF -> Registry`. Content is fine, but shape repeats the deck's tic.
- Meta-scaffolding: `covers every delivery topology you will see.` — announces coverage.
- Q&A backup on air-gap default footgun is one of the strongest passages in the deck. Do not touch.

**Impact:** Low. The slide is a mechanic-in-three-shapes and the three-shape enumeration is legitimate — this is one of the few places where the balanced list matches the content. Barely audit-worthy.

**Proposed rewrite:** Optional. The current note is close enough to voice. If tightening:

> One mechanic, three shapes.
>
> Registry to registry — promotion across dev/staging/prod, or cross-cloud (GHCR to ECR). Same digests. Every access rewritten.
>
> Registry to CTF — Common Transport Format, a local archive of blobs plus index. Hand-carry across the boundary.
>
> CTF to registry — the air-gap import. Archive arrives, `ocm transfer` uploads, access rewrites to the local registry, signature verifies locally. No traffic to source.
>
> Same command in all three: `ocm transfer cv <src> <dst>`. Access changes; digests don't. The signature covers digests, so it survives every hop. Verification is purely local at the destination — that's the air-gap property.
>
> Q&A — air-gap default footgun. Default `ocm transfer` copies only the descriptor; the access fields still point back at the source registry. For air-gap (CTF to registry) you MUST pass `--copy-resources` so the bytes travel with the descriptor. Slide 14 names this as one of the three honest edges. Worth catching in a CI step the first time someone runs an air-gap export.
>
> Q&A — Sigstore air-gap specifically. Works offline IF the trusted-root file — Fulcio CA plus Rekor public key for the configured issuer — has been distributed to the destination once, out of band. After that, `ocm verify cv` runs without contacting Rekor or Fulcio. RSA and OpenPGP need only their pinned public keys — no trusted-root file.

---

## Slide 11 — DEPLOY

**AI-slop patterns found:**
- Enumeration with over-perfect parallel structure: four bullets — Repository / Component / Resource / Deployer — each starting with the CR name, dash, mechanism. Consistent with the deck's tic.
- Consulting rhythm: `Foreshadow the dependency now so slide 14 doesn't feel retroactive:` — meta-scaffolding announcing what the note is doing.
- Q&A backup uses the same run-together format that hurts findability on stage.

**Impact:** Low. The CR chain is inherently four-shaped, so the parallel bullets are earned here. The foreshadowing sentence is the only real fix.

**Proposed rewrite:**

> Four CRs, one chain. The controllers verify and apply the component.
>
> Repository — names where component versions live. OCI registry, mounted CTF, S3, local FS.
>
> Component — names a specific component version. Pulls the descriptor and verifies its signature against the trust anchor configured on the Component CR. Verification is opt-in: without a `verify:` entry the controller resolves and pulls but doesn't check signatures. Production installs should require verification via admission policy.
>
> Resource — picks one artifact from the verified component, by digest. Helm chart, OCI image, raw manifest, blob.
>
> Deployer — applies the resource to the cluster. Resolves image refs and other deploy-time pointers from the verified descriptor at apply time. This is where localization happens in v2.
>
> Say the dependency out loud now, so slide 14 doesn't feel retroactive: the four-card chain on its own deploys raw Kubernetes manifests. For Helm-deploy, the chain feeds a `ResourceGraphDefinition` that kro reconciles, with Flux or Argo CD applying the resulting `HelmRelease`. OCM controllers don't ship kro, Flux, or Argo CD. Bring your own.
>
> Q&A — controller-shaped `ocm transfer`. Yes, there's a `Replication` CR for in-cluster repo-to-repo mirroring. Appendix slide 16.

---

## Slide 12 — DAY 2

**AI-slop patterns found:**
- Consulting rhythm: `This slide does ONE job: the day-2 mechanic.` — meta-scaffolding.
- Meta-scaffolding: `Differentiator framing for security architects:` — announces the framing rather than delivering it.
- Filler-as-filler: `What OCM gives you is one signature to audit instead of N.` — the "what X gives you is Y" shape is a mild sales cadence, though the content is honest.
- Enumeration ends with a sentence-fragment closer `Bump the product. The references follow. The cluster cannot drift without breaking the envelope.` This one is actually target voice — keep it.

**Impact:** Low-to-moderate. The mechanism (bump product, references follow, digest math forces re-sign) is delivered well. The framing lines around it are the weak part.

**Proposed rewrite:**

> Composition was defined on slide 8. This slide does one job: show the day-2 mechanic.
>
> Product is `acme.org/sovereign/product`. Day 1: references notes 1.0.0 and postgres 1.0.0, each pinned by its descriptor digest. Notes team ships a patch (1.0.0 to 1.1.0). Platform team raises the product to 1.1.0, updates the notes reference — its version AND its digest, because the new notes descriptor hashes differently. Postgres stays: same version, same digest.
>
> Commit. The controller pulls the new product descriptor, verifies the signature, resolves the new digests, applies. Notes rolls forward. Postgres untouched.
>
> For security architects: OCM is a release-level envelope. `helm upgrade` upgrades one chart; cosign signs one image. The OCM signature covers the whole release as one unit — every digest in every resource of every referenced component pinned by the one parent signature. Drift breaks that signature.
>
> Q&A — forged descriptors. Nothing OCM-specific stops a malicious operator from committing a forged descriptor with bumped versions, an attacker's image references, and a re-signed signature using a stolen key. Same threat model as any signed-release system. Rotate keys, dual-sign, audit.
>
> Land: one signature to audit instead of N. Bump the product. The references follow. The cluster can't drift without breaking the envelope.

---

## Slide 13 — ADOPTION

**AI-slop patterns found:**
- Enumeration with over-perfect parallel structure: two bullets — "From zero - CLI" and "On your cluster - controllers" — each with cold-start budget as the closer. Content is fine; shape is template.
- Filler-as-filler: `Both paths coexist with what you already run - cosign, Argo CD, Flux, Kyverno.` — the "coexist with X" phrasing is mild sales cadence, though it delivers a real point.
- The concrete times ("thirty minutes", "an afternoon") are exactly the specificity the voice guide asks for. Keep.

**Impact:** Low. This is the call-to-action slide and the two paths ARE parallel by content. Barely worth a rewrite.

**Proposed rewrite:** Optional tightening only.

> Two paths to a first OCM component. Both tested in conformance on every release.
>
> From zero, CLI-only. No cluster. Install CLI, write a constructor for one component, pack, sign with RSA, export as CTF, carry to a second machine, import, verify. Cold-start budget: about thirty minutes — CLI install plus the `helloworld` pack/sign/verify from the website tutorial. Recommend this path first.
>
> On your cluster, controllers. Spin up a kind cluster. Helm-install the OCM controllers, plus kro, plus Flux or Argo CD. Point them at your registry. Apply a Component resource — verified and reconciling. Cold-start budget: an afternoon, including bootstrap (kind + controllers + kro + Flux or Argo CD) and a Helm-deploy of the simple component in the getting-started tutorial.
>
> Both paths coexist with cosign, Argo CD, Flux, Kyverno — whatever you already run. OCM signs the descriptor; existing controls stay in place.

---

## Slide 14 — WHAT'S SHARP

**AI-slop patterns found:**
- Consulting rhythm: `The slide that earns trust. Deliver straight; do not soften.` — meta-scaffolding announcing the slide's job. Ironic, given the slide's job is to be direct.
- Enumeration with parallel structure — three bullets — but this one is legitimate: the slide IS three sharp edges. Shape matches content.
- The final line `"If any edge is a deal-breaker, tell us early.` has an orphaned opening quote and is grammatically awkward.
- Formatting: the "Nuance for Q&A" block runs into the third bullet without a break.

**Impact:** Low content-wise, moderate formatting-wise. This slide is the trust slide and the notes are already in target voice. The delivery instruction at the top is a tic; the content is fine.

**Proposed rewrite:**

> The trust slide. Deliver straight. Don't soften.
>
> Transfer defaults copy only the descriptor. For air-gap, pass `--copy-resources` so the artifacts travel too. Worth catching in a CI step the first time someone runs an air-gap export.
>
> Controllers are v1alpha1. CRD shapes for Repository, Component, Resource, Deployer, Replication are stabilizing but still v1alpha1. Pin to specific release tags in platform installs.
>
> Helm-deploy adds kro plus Flux or Argo CD. The OCM controllers don't ship them. Bring your existing solution for delivery.
>
> Nuance for Q&A: kro is required for ALL documented deploy paths — it reconciles the ResourceGraphDefinition the Deployer feeds it, not only Helm-deploy. The GitOps engine (Flux or Argo CD) is the Helm-deploy-specific add. Three installs total for Helm-deploy.
>
> Land: if any edge is a deal-breaker, tell us early.

---

## Slide 15 — Ship the release as one unit.

**AI-slop patterns found:**
- Enumeration with over-perfect parallel structure: three bullets — Evaluate / Pilot / Engage — each URL-plus-verb-plus-outcome. Very template; classic "call-to-action three-way".
- Hyperbole / marketing cadence: `You will know within an afternoon if OCM fits.` — the promise is concrete enough to survive, but the shape is sales.
- Filler-as-filler: `The more voices while it's being shaped, the better the standard gets.` — mild but a genuine transition; borderline.
- `scoped scope of work` — repetition, likely a typo.
- Consulting rhythm: `Not selling OCM. Stewarding it as a multi-vendor standard.` — the parallel sentences are actually good, target voice. Keep.

**Impact:** Moderate. This is the ask slide; the "three doors" shape is inherent, but the language has drifted toward pitch-deck cadence.

**Proposed rewrite:**

> Close with the ask. Three doors, architect-shaped.
>
> Evaluate — `ocm.software`. Read the spec, run the conformance scenario at `conformance/scenarios/sovereign`, judge fit. An afternoon is enough to know.
>
> Pilot — `github.com/open-component-model`. Take one product, one team, scoped work. Spec, implementation, conformance suite, roadmap — all in the open.
>
> Engage — community channels on the website. NeoNephos Foundation governance. Standards get better when more voices shape them while they're being shaped.
>
> Land: not selling OCM. Stewarding it as a multi-vendor standard. Ship the release as one unit. Thanks — questions.

Also: fix the typo `scoped scope of work` → `scoped work`.

---

## Slide 16 — APPENDIX · REPLICATION

**AI-slop patterns found:**
- Preamble / meta-scaffolding: `APPENDIX — pull only if asked about cluster-side component mirroring or 'how do I get a version from one repo into another without running the CLI?'.` — this is legitimate stage direction for an appendix slide, borderline fine.
- Consulting rhythm: `Not on the main deck because the four-card chain is the load-bearing story for a 30-minute architect talk. This is the answer to a specific question, not part of the story arc.` — meta-scaffolding, but again: the slide IS an appendix and the note is telling the presenter when to use it. Legitimate.
- Enumeration with parallel structure: `Use cases: delivery pipelines, promotion between environments, air-gap mirroring kept in-cluster rather than on a workstation.` — mild but appropriate for an appendix.

**Impact:** Low. Appendix slides are allowed to be more mechanical. The note reads like a reference card, which is what appendix notes should be.

**Proposed rewrite:** Optional. Trim only if desired.

> Appendix. Pull only when asked about cluster-side component mirroring, or "how do I get a version from one repo into another without running the CLI?"
>
> A fifth controller, `Replication`, sits alongside the four-card chain — not within it. The chain delivers content into the cluster; Replication transfers a resolved component version from one OCM repository to another. Same descriptor, same digests, fresh access fields.
>
> References a source `Component` CR and a target `Repository` CR. When the resolved version of a source changes, Replication transfers that version with its full reference graph into the target. Mirrors `ocm transfer cv` on the CLI. Records `status.lastTransferredDigest` after each successful run; a later reconciliation on the same digest is a no-op.
>
> Use cases: delivery pipelines, promotion between environments, air-gap mirroring kept in-cluster rather than on a workstation.
>
> Kept off the main deck because the four-card chain is the load-bearing story for a 30-minute talk. This is an answer to a specific question, not part of the arc.

---

## Slide 17 — HOW OCM COMPARES

**AI-slop patterns found:**
- Enumeration with over-perfect parallel structure: four bullets — cosign / SLSA / SBOM / OCM — each `<name> - <mechanism>. <weakness>. <how OCM uses it>.` The shape is the strongest template in the deck.
- Consulting rhythm: `Set the comparative anchor an architect-track audience expects.` — meta-scaffolding.
- Meta-scaffolding: `The 'partial' cells are calibrated honesty` — this is actually a decent phrase (owning the trim edges), but the meta-framing "calibrated honesty" IS the target voice. Borderline.
- Meta-scaffolding closer: `Close the slide with the band line: 'OCM rides on top…'` — stage direction is fine; the quoted line is direct and works.

**Impact:** Moderate. This is the differentiation slide and the four-way parallel structure is inherent to the comparison. But every bullet ending in `OCM uses / carries / signs …` starts to feel formulaic — the tone drifts from architect-review to product-comparison-matrix.

**Proposed rewrite:**

> The comparative anchor an architect audience will look for. Each tool operates on a different unit; OCM operates one level up.
>
> cosign and Sigstore sign one OCI artifact. Strong per-image trust. They don't bundle. They don't travel across registries without re-sign or `cosign copy`. OCM uses Sigstore as one of its signing schemes — for the descriptor, not per-image.
>
> SLSA and in-toto attest the build that produced one artifact. Provenance, not bundling. Not natively air-gap; needs a separate transport story. OCM carries SLSA and in-toto attestations as resources inside the component.
>
> SBOMs and OCI 1.1 referrers inventory one artifact's contents and attach to that artifact's digest. Discovery, not bundling. Don't span a multi-artifact release. OCM carries SBOMs as resources; the descriptor names which SBOM belongs to which artifact.
>
> OCM signs the component — a named, versioned bundle of artifacts plus access paths. One signature covers every digest. Location-independent: access rewritten on transfer, signature still verifies. Air-gap native: CTF round-trip, no callback to source.
>
> The "partial" cells are the honest bits. SLSA attestations can travel with their subject if you choose to. OCI 1.1 referrers are digest-addressable, so partially location-independent. Not overclaiming.
>
> Close: OCM rides on top. It doesn't replace the per-artifact tools — it adds the release-level envelope they don't. Next slide (Constructor) shows what that envelope looks like.

---

## Slide 18 — APPENDIX · ABBREVIATIONS

Slide has no speaker notes. No audit needed.

---

## Summary — recurring patterns across the deck

Three tics show up on more slides than not:

1. **Balanced-bullet enumerations.** Slides 2, 3, 4, 6, 8, 9, 13, 15, 17 all use a bullet block where every entry has the same syntactic shape. Sometimes earned (slide 10, slide 11), often not. Break the shape on the slides where the content doesn't demand parallelism.
2. **"Three things to land" / "One job" openers.** Slides 6, 9, 12, 14. Consulting rhythm. Cut the announcement; deliver the thing.
3. **Meta-scaffolding stage directions.** `Foreshadow the dependency now`, `Differentiator framing for security architects`, `Set the comparative anchor`. Legitimate when they tell the presenter what to DO, wasteful when they tell the presenter what they're ABOUT to say.

Formatting-wise: the Q&A backup paragraphs collapse into walls of prose on many slides (3, 6, 8, 11, 12). Under speaking pressure these are hard to scan. Recommendation: break each Q&A into its own paragraph starting with `Q&A —` so the presenter can find the right answer by eye.

Non-voice issue: em-dashes rendered as ASCII hyphens throughout. Fix at typography-pass time, not voice-pass time.
