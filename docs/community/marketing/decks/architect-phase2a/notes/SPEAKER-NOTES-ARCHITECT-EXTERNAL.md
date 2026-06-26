# Speaker Notes — External Architect Deck (`OCM-Sovereign-Delivery-Architect-External.pptx`)

**Audience.** External software, cloud and security architects. They've heard the name OCM, they've maybe skimmed a README, but they do not have a working mental model. Their default posture is "show me how it works." They're suspicious of marketing prose, comfortable with YAML, and they will start parsing your CLI snippets before you finish the sentence.

**Talk length.** ~30 minutes presented. Q&A on top. The middle section (slides 5–12) is the technical spine; do not rush it. The bookends (1–4 and 13–15) carry the framing.

**Tone.** Technically grounded. Peer-to-peer. Honest about the trim edges. Never explain the obvious — they know what a registry is, what a Helm chart is, what an SBOM is. Don't say "revolutionary" or "best-in-class". If a phrase lands sharp, keep it sharp.

**CLI is for speaker notes, not for slides.** When you read a CLI snippet here, you're reading it aloud or pointing at it on a backup deck slide if asked. The deck itself stays clean.

**Stop-sentence rhythm.** Inherited from the exec deck. Three things to land — first this, second that, third the other. Honour the pauses; they are doing structural work.

---

## SLIDE 1 — PAIN / HERO  (00:00 — 00:45, ~45 sec)

**On screen.** Title L1 (white): "You ship pieces." Title L2 (gradient cyan): "Nothing carries the release." Subtitle: "Images, charts, SBOMs, configs — each signed differently, if at all. No identity for the release itself." Footer: "Open Component Model — open source, NeoNephos Foundation." Brand row bottom-left.

**Speaker notes.**

Open with the observation, not the product. The subtitle does the targeting work for you — anyone in the room shipping any of those four artifact types should recognise themselves immediately.

> "Look at any release you've shipped in the last six months. You shipped images. You shipped a chart. You shipped a config bundle, an SBOM, maybe a binary. Each one named differently. Each one signed differently — if it was signed at all. Each one living somewhere different."

Pause. Look at the room.

> "You shipped pieces. Nothing carried the release. That's the gap I want to close in the next thirty minutes."

Move on. No brand pitch yet. The deck does that at the end.

---

## SLIDE 2 — DIAGNOSIS  (00:45 — 02:15, ~90 sec)

**On screen.** Eyebrow: DIAGNOSIS. Title: "In every existing tool, identity is bound to location." Three bullets — OCI image / Helm chart / SBOM. Caption at the bottom: "Cosign attestations sign each piece. None of them sign the release as one named, location-independent unit."

**Speaker notes.**

This is the slide that explains *why* the existing toolbox doesn't compose. Slow down. The footer is calibrated for cosign-attestation shops in the room — they're not wrong to sign each piece; they're missing the release-level envelope.

> "Three artifact types you ship every day. Look at how each one is identified."

**Point at OCI image.** "An OCI image is `registry/repo:tag` — or `repo@sha256:…` if you're disciplined. Mirror that image to a second registry, and every reference downstream has to be rewritten. The image is the same bytes. Its identity changed."

**Point at Helm chart.** "A Helm chart is `repository URL plus chart name plus version`. Same problem, different vocabulary. You can't address the chart without naming its repo. Move the repo, every `helm install` breaks."

**Point at SBOM.** "An SBOM doesn't even have a stable identifier of its own. It's linked to its subject artifact by a path, a filename convention, an OCI referrer relationship. Repackage the subject, the SBOM dangles."

Beat. Now the calibration for the cosign shops:

> "If you're running cosign with attestations today — and many of you are — you already sign each of these pieces. That's good work; keep it. What you don't have is a name for *the release as a whole*. The thing you ship out the door, that needs to verify in a sovereign zone with no callback to the source. There's nothing in the existing toolbox you can put a signature on that means 'this release, as one unit, across every location it'll travel.'"

> "That's the diagnosis. Identity is bound to location. The release as one named, signed, transportable thing — doesn't exist yet."

---

## SLIDE 3 — THE HINGE  (02:15 — 04:00, ~105 sec)

**On screen.** Eyebrow: THE HINGE. Title: "Identity that travels with the artifact." Three bullets on the left — Coordinates / Digest / Access. ASCII diagram on the right showing `github.com/acme.org/helloworld:1.0.0` fanning out across EU reg / US reg / Air gap, with caption "Same coordinate. Different access. Signature still verifies." Bottom caption: "Move the artifact; the digest stays; only the access changes. That's the trick."

**Speaker notes.**

This is the conceptual fulcrum. If they understand this slide, the next ten slides are mechanics. If they don't, the rest is noise. Let it breathe.

> "OCM separates three things that the existing tools fuse together. Coordinates, digest, access. Three properties of the same resource, but each does a different job."

**Bullet 1 — Coordinates.** "The component has a name — a DNS-style path like `github.com/acme.org/helloworld` — and a SemVer version. That pair is globally unique. It does not encode a registry. It does not encode a URL. It's a name. Globally unique, location-agnostic."

**Bullet 2 — Digest.** "Every resource inside that component carries a SHA-256 content hash. Computed once, at pack time. The digest is what we sign. It is the content identity."

**Bullet 3 — Access.** "And separately — *separately* — there's an access record. Type, plus enough fields to fetch the bytes. `OCIImage/v1` with an image reference. `LocalBlob/v1` with a local hash. `S3/v1` with a bucket and key. The access is where the resource currently lives."

Point at the diagram.

> "Now look at what happens on transport. You promote the component from a EU registry to a US registry to an air-gapped CTF tarball. The coordinate doesn't change. The digest doesn't change. Only the access field gets rewritten. The signature, which covers the digest, still verifies — anywhere."

Beat. Land it.

> "Move the artifact. The digest stays. Only the access changes. That's the whole trick."

---

## SLIDE 4 — POSITIONING  (04:00 — 05:15, ~75 sec)

**On screen.** Eyebrow: WHERE OCM SITS. Title: "One component wraps every artifact, signed once." Three columns — ANY FORMAT / ANY LOCATION / ONE SIGNATURE — each ending with the noun "component" in the body. Bottom caption: "A component is the unit you sign, transport, and deploy. The next slides show how it's built."

**Speaker notes.**

This slide does two jobs. First — pre-empt the "what does this replace?" question. Second — define the *noun* the rest of the deck rests on. From here forward, "component" is a thing the audience knows the shape of.

> "Before we go further, let me say what OCM is *not*. It is not a replacement for OCI. It is not a replacement for Helm. It is not a replacement for your SBOM tooling. It composes around all of them. And it does that by defining one new thing — the *component*."

**Point at ANY FORMAT.** "Every artifact format you ship today stays exactly what it is. A Helm chart is still a Helm chart. An OCI image is still an OCI image. SBOMs stay SPDX or CycloneDX. Each one becomes a *resource* inside the component."

**Point at ANY LOCATION.** "Coordinates travel. The component has a name and version that don't encode a registry. Move it across registries; the name stays the same."

**Point at ONE SIGNATURE.** "One signature covers every digest in the component. The whole release is one signed unit."

Beat. Land the definition.

> "A component is the unit you sign, transport, and deploy. That's the noun. Hold it. The next ten slides are about how it's built, how it travels, how it's verified, and what changes for you on the platform side."

---

## SLIDE 5 — CONSTRUCTOR  (05:15 — 08:00, ~165 sec)

**On screen.** Eyebrow: CONSTRUCTOR. Title: "What you write." YAML block on the left (the `component-constructor.yaml` straight from the getting-started doc — `github.com/acme.org/helloworld` at v1.0.0 with a local-file resource and an OCI image resource). Two right-side callouts: `input:` (by value) and `access:` (by reference). Bottom caption: "Two ways in. Same descriptor."

**Speaker notes.**

This is the first YAML the audience sees. Walk through it like you would for a colleague. Architects want to know the shape, not the marketing.

> "This is what you write by hand. A file called `component-constructor.yaml`. About eighteen lines. Let's read it from the top."

Point at each section.

> "`components` — a list. You can declare more than one in a single file, but most of the time it's one. The component has a name — `github.com/acme.org/helloworld` — and a version, `1.0.0`. The name has to be a DNS-style path; that's by spec. The version is SemVer."

> "`provider` — who owns this component. Just metadata, but it has to be there."

> "Then `resources`. This is where the interesting design call happens. Every resource you list here ends up inside the component. And there are two ways to attach a resource — `input:` or `access:`."

Point at the first resource.

> "`mylocalfile`. Type `blob`. Note the `input:` block. That's the by-value form. The constructor reads the file off disk at pack time and embeds the bytes inside the component archive. After pack, the bytes travel with the component. You can hand the archive to someone on a USB stick; the file is in there."

Point at the second resource.

> "`image`. Type `ociImage`. Note the `access:` block instead. That's the by-reference form. The constructor records a pointer — `ghcr.io/stefanprodan/podinfo:6.9.1` — and resolves the digest at pack time. The bytes stay in the source registry until the transport step decides to copy them."

Beat.

> "Input by value. Access by reference. That's the only architectural choice you make at pack time. Local files and config bundles tend to be `input`. Big images tend to be `access`. You can mix freely."

Optional CLI mention if a hand goes up:

> "The CLI call is `ocm add cv` — pointed at this file, default output is a transport archive in the current directory."

If you have time, mention the supported input/access types in passing — File, Dir, Helm, OCIImage, generic HTTP — and move on.

**Anticipated questions.**
- *"What happens if the file path is wrong?"* — Pack fails. The constructor is strict; no silent zero-byte resources.
- *"Can I add an SBOM here?"* — Yes. SBOM is just another resource. Type `sbom` is conventional; what matters is that the SBOM file is in the resources list.
- *"Can I generate this YAML from a CI step?"* — Yes. It's plain YAML; templating is up to you.

---

## SLIDE 6 — DESCRIPTOR  (08:00 — 11:00, ~180 sec)

**On screen.** Eyebrow: DESCRIPTOR. Title: "What gets signed and travels." YAML block on the left — the post-pack component descriptor. We show ONE resource (the image) with `access`, `digest`, and a `...` line standing in for the other resources and references a real component would carry. The `access:` line carries a `# excluded from signature` comment to make the rule visible. Below that, a `signatures` block with the descriptor digest, algorithm, and a hex-encoded signature placeholder. Three right-side callouts aligned to the YAML sections: `access:` (excluded — rewritten on every transfer), `digest:` (content identity — input to the descriptor hash), `signature:` (one hash — over the canonicalized descriptor).

**Speaker notes.**

This is the payoff for slide 5. **First thing to clarify in the spoken open: this is a generated artifact, not something you write.** The constructor on slide 5 was the input you wrote; the descriptor on slide 6 is what `ocm add cv` produced.

> "Slide 5 was the input you write — about eighteen lines, hand-edited. This is the output the pack step produces. The component descriptor. You'll see it in your registry as an OCI artifact; you'll see it on disk inside a CTF tarball. You will not normally hand-edit it. This is the thing that travels."

Set expectations on the trim before walking it.

> "I'm showing one resource — the image — to keep focus on the mechanism. Real components carry many resources and may reference other components. That's the `...` line. The rules I'm about to walk apply identically to every entry."

Walk through it section by section.

> "Top of the file — same name, same version. That coordinate from slide 3."

Point at the image resource.

> "Look at the image. Three things matter. The `type` says `ociImage`. The `access` says `OCIImage/v1` with the *resolved* image reference — the constructor's tag has been pinned to a digest. The component carries the resolved form, not the tag. That kills a class of supply-chain attacks where someone repoints a tag between pack and deploy."

> "Notice the `# excluded from signature` comment next to the access line. That comment is doing real work — it names the rule that makes transport possible. Access is excluded from the canonical form; everything else is in."

> "Now `digest`. SHA-256 over the resource bytes. Computed at pack time. This is the content identity. And — this is the load-bearing part — this digest is one of the inputs to the descriptor hash."

Point at the signatures block.

> "Bottom of the file. `signatures:` — a list. Each entry signs ONE hash: the SHA-256 of the canonicalized descriptor. That single hash covers every resource digest in the descriptor. The signature value is computed over that one hash. On the slide we show a placeholder for the bytes."

Beat. Now deliver the payoff.

> "Three things to notice. First — what's signed is the descriptor hash. Which means the one signature covers every artifact in the release. Second — what *isn't* signed is the access. Access fields are excluded from the canonical form. That's what makes transport work. We can rewrite access freely on every move, and the signature still verifies. Third — multiple signatures are allowed. You can dual-sign with an RSA key and a Sigstore identity. Verifiers pick the trust model they accept."

> "Sign the descriptor hash, not the access. That sentence is the entire transport story compressed into seven words."

**Anticipated questions.**
- *"How is the canonical form defined?"* — Spec-defined normalisation (`jsonNormalisation/v4alpha1`). See the website's signing-and-verification doc; it's deterministic across implementations.
- *"What about layered signing — sign on build, re-sign on entry to a sovereign zone?"* — Yes. Add more entries to the `signatures` list. Each entry is independent. None of them invalidates the others.
- *"What if a resource is mutated downstream?"* — Then its digest doesn't match the value in the descriptor, the descriptor hash check fails, and verification fails. That's the whole point.
- *"What does `componentReferences` look like in the descriptor?"* — Same shape as a resource entry: `name`, `componentName`, `version`, plus a digest of the referenced descriptor. We introduce composition on slide 8.

---

## SLIDE 7 — FOUR VERBS, ONE COMPONENT  (11:00 — 12:15, ~75 sec)

**On screen.** Eyebrow: FOUR VERBS, ONE COMPONENT. Title: "Pack · Sign · Transport · Deploy." Four-tile flow with arrows: PACK → SIGN → TRANSPORT → DEPLOY → SOVEREIGN CLOUD. Footer caption: "The signed component descriptor is itself an OCI artifact (media type `application/vnd.ocm.software.component-descriptor.v2`). It lives in your registry. The next four slides are mechanics."

**Speaker notes.**

This slide does two jobs. First — name the primitive the audience has been waiting to hear named ("where does the thing actually live?"). Second — organise the next four slides under one mental picture.

> "Look at the footer line for a moment. The component descriptor — the thing you just saw on slide six — is itself an OCI artifact. Media type `application/vnd.ocm.software.component-descriptor.v2`. It lives in your registry, right next to the images it references. Same registry, no new infrastructure. That's the primitive."

Beat.

> "Now four verbs, same flow, every component, every time. The tile labels are the exec version — ignore them, look at the verbs."

> "Pack — bundle once, name once. We just did that."

> "Sign — one signature covers every digest. Just did that too."

> "Transport — registry to registry, registry to tarball, tarball to registry. Same command shape. The signature survives every move."

> "Deploy — at the destination, a controller verifies the signature, resolves digests, applies what the resource says."

Point at the cloud on the right.

> "Sovereign cloud, air-gapped network, customer-owned cluster. The component lands. No callback upstream."

> "Next four slides — one slide per verb. Mechanics. And then on slide 8 we introduce the composition primitive that makes the day-2 mechanic on slide 12 work."

---

## SLIDE 8 — COMPOSE  (12:15 — 14:00, ~105 sec)

**On screen.** Eyebrow: COMPOSE. Title: "Leaf carries resources. Product carries references." Two side-by-side YAML blocks. LEFT box labelled LEAF: two leaf components — `acme.org/sovereign/notes:1.0.0` and `acme.org/sovereign/postgres:1.0.0` — each with `image`, `chart`, and a `...` line under `resources`. RIGHT box labelled PRODUCT: `acme.org/sovereign/product:1.0.0` with `componentReferences:` to both leaves by `componentName` and `version`. Composition arrow LEAF → PRODUCT between the boxes.

**Speaker notes.**

This slide introduces the composition primitive. The audience needs to see it on its own before slide 12 leans on it for day-2. Don't rush; the shape on this slide is what the rest of the talk rests on.

> "Every example so far has been one component with a few resources inside. Real products are compositions. Two boxes on this slide. Same descriptor shape on both sides. Different role."

**Point at LEAF (left box).** "Two leaf components. `acme.org/sovereign/notes` at 1.0.0 — that's the web app. Image, chart, and a `...` for the rest: config, SBOM, whatever else the notes team packs. `acme.org/sovereign/postgres` at 1.0.0 — same shape, the database. Image, chart, `...`. Leaves carry the actual artifacts. Each leaf is independently versioned, independently signed, independently transportable."

**Point at PRODUCT (right box).** "Now look at the product. Same DNS-style name, same SemVer. No `resources:` block at all. Just `componentReferences:` — by `componentName` and `version`. The product owns *nothing* on its own. It composes the two leaves into one named, signed unit."

Beat. Land the primitive.

> "Leaves carry artifacts. Products compose. Same descriptor shape on both sides — there is no second YAML language, no parent schema. A component is a component. The role is decided by whether you put `resources:` or `componentReferences:` in it."

Point at the arrow.

> "The arrow is the composition relationship. The product references the leaves by name and version — globally unique coordinate, no registry encoded. When you sign the product descriptor, the signature covers the resolved digests of both child descriptors. Verify the parent; you transitively verify the children."

Pivot to slide 12.

> "Hold this picture. On slide 12 we're going to bump one line on the product — the notes version — and watch the whole composition re-sign end-to-end. This composition primitive is what makes that day-2 mechanic work."

**Anticipated questions.**
- *"What's actually in a leaf versus a product?"* — Leaves have a `resources:` block; products have a `componentReferences:` block. Nothing stops a component from having both, but the convention — and the one the conformance suite tests — is leaf-or-product, not mixed.
- *"What happens if the notes team adds a new resource — a sidecar image, say?"* — They bump notes from 1.0.0 to 1.0.1, repack, re-sign. The product still references `version: 1.0.0` until someone updates that line. Independent cadence.
- *"How do component coordinates compose? Is there a namespace collision risk?"* — Coordinates are globally unique by DNS-style path plus SemVer. Two teams can each own `acme.org/<team>/...` and never collide.
- *"Does the product's signature cover the children's bytes, or just their digests?"* — The product's signature covers the children's *descriptor digests*. Each child carries its own signature over its own resource digests. Verifying down the tree is what the controllers and the CLI do automatically.
- *"Can a leaf reference another leaf?"* — Yes. `componentReferences:` is recursive. The conformance scenario uses a two-level graph; deeper graphs work the same way.

---

## SLIDE 9 — SIGN  (14:00 — 16:30, ~150 sec)

**On screen.** Eyebrow: SIGN. Title: "One signature shape. Three trust models." Three columns — RSA / GPG / SIGSTORE. Caption at the bottom: "Same descriptor hash. Three ways to vouch for it. Pick what your org already runs."

**Speaker notes.**

This is the slide where the security architects in the room start paying close attention. Three trust models, all generally available. The honesty beat here isn't "early access" — it's "pick the one your org already runs."

> "OCM separates the signature *shape* from the trust model. The descriptor is signed in one canonical way. What changes is how you prove the signing key belongs to whoever you think it belongs to. Three columns, three trust models, all GA."

**Point at RSA.** "RSA. If your organisation already runs a PKI — keys in Vault, in an HSM, rotated on a schedule — this is the natural path. Same keys your release team manages today. The OCM signature is RSA-PSS over the canonical descriptor."

**Point at GPG.** "GPG. OpenPGP keys, the model your team probably already uses for git commit signing, package signing, mailing-list signing. Familiar key-ring semantics, ASCII-armored signatures. If your release engineers already manage OpenPGP keys for one process, point them at OCM for the release-level signature too."

**Point at Sigstore.** "Sigstore. Keyless via OIDC. Best fit for OSS pipelines where the signer is a GitHub Actions workflow or any other identity provider — no long-lived key material at rest. Compatible with the cosign verification flow, with OCM-specific extensions. The trust anchor is your OIDC issuer plus the rekor transparency log."

Beat. Now deliver the discipline:

> "Three things to land. First — the *signature shape* is the same in all three cases. It covers the canonical descriptor; it covers every digest in the descriptor. Second — verifiers can accept multiple trust models in parallel. You can require an RSA signature from your release team and a Sigstore signature from CI, and check both. Third — pick what your org already runs today. RSA if you have PKI. GPG if your team already manages OpenPGP keys. Sigstore if you're keyless via OIDC. OCM doesn't force a religious choice."

CLI for the curious:

> "`ocm sign cv ./transport-archive//github.com/acme/widget:v1.4.2 --signature acme-release-key --private-key ./release-key.pem`. Adds an entry to the `signatures` list in the descriptor. Idempotent if the signature already exists."

**Anticipated questions.**
- *"Can I sign without modifying the descriptor?"* — No. The signature is part of the descriptor. That's by design — there's nothing to lose in transit.
- *"What about GPG specifically — what does the descriptor entry look like?"* — Same `signatures:` block, with the algorithm field naming the GPG variant. The website's `how-to/Sign and Verify/sign-component-version.md` page has the GPG walkthrough with a concrete key fingerprint and the `gpg --armor` command shape.
- *"What about post-quantum?"* — Spec is open to additional algorithm IDs. Today: RSA-PSS, GPG/OpenPGP signatures, Sigstore's ECDSA-P256. Roadmap covers ML-DSA when the standard stabilises.
- *"Sigstore — same caveats as cosign?"* — Yes. Make sure your OIDC issuer is trusted in the verifier's policy. Same operational discipline you'd apply to any keyless flow.

---

## SLIDE 10 — TRANSPORT  (16:30 — 19:00, ~150 sec)

**On screen.** Eyebrow: TRANSPORT. Title: "Three patterns. One command." Three columns — REGISTRY → REGISTRY / REGISTRY → CTF / CTF → REGISTRY. Each has a short two-line description. Caption: "Access fields rewrite at transfer. Digests don't. Signature still verifies — anywhere."

**Speaker notes.**

This is the slide where the air-gap conversation lives. It is the slide where most architects say "wait, do that again."

> "Transport is a single mechanic — copy a component from one repository to another. Three patterns that cover essentially every delivery topology you'll see in real customers."

**Point at REGISTRY → REGISTRY.** "Standard promotion. Dev registry to staging registry to prod registry. Cross-cloud — GHCR to ECR, Harbor to Artifactory. Same component name, same digests, every access field rewritten to point at the new registry."

**Point at REGISTRY → CTF.** "Export to a tarball. CTF — Common Transport Format — is OCM's filesystem-friendly archive. A directory of blobs plus an index file. You can tar it up, copy it to a USB stick, write it to a Blu-ray. The whole component, every resource, in one self-contained tree."

**Point at CTF → REGISTRY.** "And the air-gap import. The CTF arrives inside the secure zone. You point `ocm transfer` at it, and at the local registry. Every resource is uploaded, every access field is rewritten to the local registry, the signature is verified — no traffic to the source. Verification is purely local."

Beat. Deliver the payoff.

> "Three things to land. First — same command in all three cases. `ocm transfer ctf` or `ocm transfer cv`, with a source and a destination. The CLI doesn't care which combination of registry-or-tarball you pick. Second — what changes on every transfer is the `access` field. Digests don't. The signature covers the digest, not the access, which is why the signature survives every hop. Third — verification can happen at the destination, with no callback to the source. That's the air-gap property. That's what 'sovereign-ready' means in mechanics."

CLI examples:

> "Registry to registry: `ocm transfer cv ghcr.io/source//acme/widget:v1.4.2 ghcr.io/target`."
>
> "Registry to CTF: `ocm transfer cv ghcr.io/source//acme/widget:v1.4.2 ./offline-bundle --type=ctf`."
>
> "CTF to registry: `ocm transfer ctf ./offline-bundle registry.sovereign.local`."

**Anticipated questions.**
- *"What if the source has the resource and the destination has a different digest at the same coordinate?"* — Transfer refuses. Digests are immutable identity; mismatch is a failure.
- *"Can I transfer just one resource?"* — At the component level, no — the unit is the descriptor. At the resource level, you can `ocm download resource` for inspection, but you can't selectively re-pack without a new version.
- *"What about size? CTF tarballs for a real product?"* — Hundreds of MB to several GB depending on what's inside. Real customers ship them on portable media or via approved transfer mechanisms.
- *"Does `ocm transfer` copy the resource bytes by default?"* — No — flagged on slide 14. Transfer defaults to descriptor-only. Pass `--copy-resources` for the air-gap case where the bytes have to travel with the descriptor.

---

## SLIDE 11 — DEPLOY  (19:00 — 21:30, ~150 sec)

**On screen.** Eyebrow: DEPLOY. Title: "Four controllers verify and apply. One mirrors." Five CR cards. The top row is a chain of four cards left-to-right with arrows: Repository → Component → Resource → Deployer. Each top-row card carries a single-sentence body. A fifth card — Replication — is offset below the chain, centered, with no arrow connecting it to the chain.

**Speaker notes.**

This is the slide where Kubernetes folks lean in. The four-card chain is verify-and-apply. The fifth card sits alongside the chain rather than within it, and the title is the architectural statement: "Four controllers verify and apply. One mirrors."

> "OCM ships a small set of Kubernetes controllers. Four of them form the chain that brings a component into the cluster. A fifth sits alongside the chain. Let me walk both."

**Point at Repository (chain card 1).** "Repository. Where component versions live. One per source — an OCI registry, a CTF mounted from a PVC, an S3 bucket. The other controllers find descriptors through this object."

**Point at Component (chain card 2).** "Component. Pulls one version. Verifies its signature against a trust anchor you give it — the public key, the certificate chain, or the Sigstore identity policy. If verification fails, nothing downstream sees a verified descriptor. The whole chain stops here."

**Point at Resource (chain card 3).** "Resource. One artifact, by digest. The controller picks which resource — image, chart, raw manifest — out of the verified component, resolves its access record, and fetches the bytes. The resource is exposed to the cluster as a typed artifact."

**Point at Deployer (chain card 4).** "Deployer. Applies it to the cluster. The interesting one for platform teams: it can apply raw manifests directly, hand off to Flux for a HelmRelease, or hand off to Argo for an Application. Pluggable at this tier — point your existing reconciliation engine at the Resource CRs and OCM doesn't fight your platform stack."

Beat. Now pivot to Replication.

> "That's the chain. Repository, Component, Resource, Deployer — verify and apply. Now look at the card sitting below the chain. It's not connected by an arrow on purpose. It does a different job."

**Point at Replication.** "Replication. The controller equivalent of `ocm transfer`. It references a `Component` for its source, and a `Repository` for its target. When the source `Component`'s resolved version changes, Replication transfers that version — together with the full reference graph of components it brings with it — into the target repository."

> "Two phases when it runs. First it walks the reference graph through the resolution worker pool — that's `ResolutionInProgress` in its status. Then it executes the transfer — `TransferInProgress`. On success it records `status.lastTransferredDigest`. If a later reconciliation sees the same digest, it's a no-op. The controller doesn't re-transfer unchanged content."

> "Use cases. Delivery pipelines — promote a component version between environments without leaving the cluster. Backup. Air-gap scenarios where a management cluster mirrors content into a downstream registry. Anything you'd reach for `ocm transfer` in a CLI for, run as a controller instead."

Beat. Land the title.

> "Four controllers verify and apply. One mirrors. That's the architectural shape. The chain is for delivery into the cluster; Replication is for delivery between repositories."

Honesty pre-empts slide 14:

> "One honest edge that we'll come back to in three slides: the controllers ship as v1alpha1. The CRD surface can move. Pin minor versions in your platform installs."

**Anticipated questions.**
- *"Does this replace Argo?"* — No. It replaces the manual `kubectl apply` step. Argo and Flux remain on top as the UI and reconciliation engine.
- *"Does Replication replace `ocm transfer` in the CLI?"* — No. The CLI command still exists; Replication is its in-cluster equivalent. Same mechanic, different driver — one for an operator at a terminal, one for a controller watching a `Component`.
- *"Can Replication target a non-OCI repository?"* — The current shape references a `Repository` with a `repositorySpec` — the example in the docs uses `type: OCIRepository`. Recursion depth, copy mode, and credentials are configured via OCM configuration referenced from `spec.ocmConfig`, under the `transfer.config.ocm.software` key. For non-OCI targets, check the latest `Repository` types supported in the controllers' API reference.
- *"What about secret rendering at deploy time?"* — Workflow concern, not a model concern. Secrets-as-resources is supported via External Secrets / sealed-secrets patterns; the secrets themselves don't live in the descriptor.
- *"How does verification config get to the Component controller?"* — Trust anchor lives in a Secret or a dedicated config object referenced from the ComponentCR. There's no single "TrustPolicyCR" yet — verification config lives next to the consumer.

---

## SLIDE 12 — DAY 2  (21:30 — 24:30, ~180 sec)

**On screen.** Eyebrow: DAY 2. Title: "Bump the product version. / Everything follows." Two side-by-side full descriptor YAMLs. LEFT — day-1 product 1.0.0 referencing notes 1.0.0 + postgres 1.0.0, ending with a `signatures:` block (`- name: acme-release-key` / `value: a4b1c2d3e5f6789abc012345def04691...`). RIGHT — day-2 product 1.1.0 with notes bumped to 1.1.0 and postgres unchanged at 1.0.0, ending with `signatures:` block carrying a different `value: 9c2af18b3e7d52914a8c6b0f1d2e8f37...`. Arrow between the blocks labelled "bump version" in mid-blue above it. Three changes highlighted in brand blue: the product version, the notes child version, the signature value. Pt24 mid-blue footer beneath both blocks: "Every digest pinned by the signature. The cluster cannot drift."

**Speaker notes.**

This is the slide where the conformance scenario lives. Composition was introduced on slide 8 — the audience already knows what a product + two leaves looks like. This slide does one job: the day-2 upgrade mechanic, signed end-to-end. Don't re-explain composition; lean on it.

> "We saw composition on slide 8. Product, notes, postgres. Now what happens on day 2 when the notes team ships a security patch."

Point at the left YAML.

> "Day 1. The product at 1.0.0. References notes at 1.0.0 and postgres at 1.0.0. At the bottom, a `signatures:` block — one signature, key name `acme-release-key`, value `a4b1c2d3...`. That hex string is the descriptor hash signed end-to-end. It covers every component reference and, transitively, every resource digest under those references."

Point at the arrow and its label.

> "Now the notes team ships a security patch. Notes goes from 1.0.0 to 1.1.0. Inside the sovereign zone, the platform team commits two changes on the product: `version: 1.0.0` becomes `1.1.0`, and the notes child reference goes from 1.0.0 to 1.1.0. That's the operator action. The arrow names it: bump version."

Point at the right YAML, walking the three highlights.

> "Day 2. Three lines on the slide are highlighted in brand blue. The product version. The notes child version. And the signature value — `9c2af18b...`. Different bytes. The signature has changed because the descriptor has changed, and the descriptor has changed because one child version has changed. Bump one line; the whole chain re-signs."

> "Postgres is unchanged. Its version stays at 1.0.0. Its digests stay the same. But its digests are still covered by the new signature on the new product descriptor, because the product's signature is over the canonical form of the descriptor as a whole."

Point at the footer.

> "Read the footer. *'Every digest pinned by the signature. The cluster cannot drift.'*"

Beat. Now the differentiator.

> "A `helm upgrade` cannot give you this property. A chart version says nothing about which image tag will resolve where, what a registry might have re-pushed under the same tag, or whether the values overlay has been altered. OCM's day-2 is signed end-to-end. Bump `spec.version` on the product, the controller pulls the new descriptor, verifies the signature *before* it touches the cluster, and either everything reconciles in lockstep or nothing does. The cluster cannot drift away from what you signed."

> "This whole flow is in our conformance scenarios. Product, notes, postgres. We test it on every release. If you want to see it run end-to-end, the scenario lives in the open-component-model repository."

**Anticipated questions.**
- *"What about rollback?"* — Same primitive in reverse. Commit `version: 1.0.0` and the notes child back to 1.0.0 on the product. The controller pulls the day-1 descriptor (which is still signed). Signatures verify. Cluster rolls back.
- *"Can children be versioned at independent SemVer cadences?"* — Yes. Independent components, independent versions. Bump notes whenever the notes team ships; bump postgres on its own schedule; the product picks the combination it wants to release.
- *"What is the schema migration story?"* — Whatever the notes component packaged: Helm pre-upgrade hook, init container, separate Job resource — your choice. OCM doesn't reinvent the migration mechanic; it just makes sure the migration job's image is itself a pinned, signed resource that arrived in the same descriptor as the new app image.
- *"What if a child is signed by a different team?"* — Multiple signatures supported. Verification policy lives at the controller; you decide which keys you trust at which layer. The product's signature covers child *digests*; a child's own signature covers its *resources*.
- *"What if I don't use Helm — am I tied to it for day-2?"* — No. The mechanic is "controller sees a new descriptor, verifies it, the deployer applies." Whether the deployer points at a raw manifest, a HelmRelease, or an Argo App is your choice; the signing and verification property holds regardless.

---

## SLIDE 13 — ADOPTION  (24:30 — 26:30, ~120 sec)

**On screen.** Eyebrow: ADOPTION. Title: "Two paths to a first OCM component." Two columns — FROM ZERO — CLI / ON YOUR CLUSTER — CONTROLLERS. Each is four short lines. Caption: "Pick the path. The conformance scenario tests both on every release."

**Speaker notes.**

End the technical section by handing them a starting point. Two paths, pick one. Both are testable on a laptop in an afternoon.

> "If you go home and prototype OCM tomorrow, there are two reasonable entry points. Both are real. Both are tested in our conformance suite on every release."

**Point at FROM ZERO — CLI.** "From-zero path. You don't need any cluster. Install the CLI. Take one component you already ship — an image plus a chart, or whatever you have. Write the constructor. Pack it. Sign it with an RSA key. Export it as a CTF tarball. Carry the tarball to a second machine. Import it. Verify. Round trip in thirty minutes, one afternoon end-to-end. This is the path I recommend for the first hands-on contact, even if you eventually go to the cluster path."

**Point at ON YOUR CLUSTER — CONTROLLERS.** "Cluster path. The OCM controllers are a Helm install. Drop them on any cluster you already operate — kind, k3s, EKS, OpenShift, doesn't matter. Point them at your registry with credentials. Apply a Component resource that names one component you've already packed. Watch it pull, verify, and resolve. That's a working OCM control loop in a single afternoon."

Beat.

> "Last line on the right is for the platform leads in the room. If your org runs OpenControlPlane — SAP's open multi-tenant control plane — OCM ships as a service-provider integration there. One openMCP resource, and tenant clusters across the org get the OCM controllers installed. Same controllers, same mechanic; the install is just declarative across tenants instead of cluster-by-cluster."

> "The conformance scenario in our repo runs both paths on every release. If either one stops working, the release doesn't ship. So the example you pick up off the website tomorrow is the same example we verify works green."

**Anticipated questions.**
- *"How long to org-wide adoption?"* — One team, one afternoon. One product, one sprint. Org-wide, a quarter to a year depending on scope and on how much pack-time work has to shift left.
- *"Do I need OpenControlPlane?"* — No. The cluster path is a plain Helm install on any K8s cluster. OpenControlPlane is for organisations already running a multi-tenant control plane.
- *"Do the controllers need anything else to deploy Helm charts?"* — For the Helm-deploy path you bring Flux alongside the OCM controllers — Flux reconciles the HelmRelease that the Deployer hands it. For raw manifests, the Deployer is enough on its own.

---

## SLIDE 14 — WHAT'S SHARP  (26:30 — 28:00, ~90 sec)

**On screen.** Eyebrow: WHAT'S SHARP. Title: "Two honest edges." Two bullets in a blue box — (1) Transfer defaults to descriptor-only; pass `--copy-resources` for air-gap. (2) Controllers are v1alpha1 — pin minor versions. Caption: "Honest now beats apologetic later. Plan for the trim edge."

**Speaker notes.**

This is the slide that earns trust. Architects do not believe a deck without a sharp-edges slide. Two edges, delivered straight. No softening.

> "Two edges I want to call out before you go home and prototype this."

**Bullet 1 — Transfer defaults to descriptor-only.** "When you run `ocm transfer`, by default it copies only the descriptor — the metadata, the references, the signatures. The bytes of the resources stay at their original access locations. That's fine for promotion inside one connected estate. It is *not* fine for air-gap. For the air-gap case you pass `--copy-resources` so the bytes travel with the descriptor into the CTF tarball. Default is descriptor-only; if you want bytes too, you ask for them. Worth catching in a CI step the first time someone runs an air-gap export."

**Bullet 2 — Controllers are v1alpha1.** "The Kubernetes controllers ship at v1alpha1. The CRD surface can still move between minor versions — fields renamed, behaviour adjusted. The mechanic — Repository, Component, Resource, Deployer, Replication — is settled. The exact shape of those CRDs isn't. Pin minor versions in your platform installs. Treat upgrades the way you'd treat any v1alpha1 — check the changelog, test in staging."

Beat.

> "Honest now beats apologetic later. If either of these edges is a deal-breaker for your platform, tell us — we'd rather know early. If they're trim work, plan for them; the rest of the model is sound."

---

## SLIDE 15 — CTA  (28:00 — 30:00, ~120 sec)

**On screen.** Eyebrow: JOIN US. Title: "Ship the release as one unit." Three lines: Try it — `ocm.software` / Build with us — `github.com/open-component-model` / Talk to us — community channels on the website. NeoNephos Foundation logomark bottom-right.

**Speaker notes.**

Close with the ask. Plain language. Three doors. The title is the whole talk in six words.

> "Ship the release as one unit. That's the talk in six words. Three doors out of this room."

> "Try it. `ocm.software` — install the CLI, walk through the getting-started guide, pack one of your own components. You'll know within an afternoon whether OCM fits your delivery model."

> "Build with us. `github.com/open-component-model` — the spec, the implementation, the conformance suite, the roadmap. All open. All in the open. If you find an edge, file an issue; if you build on top, we want to know."

> "Talk to us. The community channels are linked from the website — the maintainers are there, customers are there, the foundation governance discussions happen there. If your organisation is at the supply-chain pressure point I described at the start, we want to hear about your delivery problem in your words."

Beat.

> "We're not selling OCM. We're stewarding a standard under NeoNephos Foundation governance. The more voices in the room while it's being shaped, the better the standard gets."

> "That's the talk. Thank you. Happy to take questions."

(Then: take questions.)

---

## TIMING TOTAL

| Slide | Topic | Duration |
|---|---|---|
| 1 | Pain | 0:45 |
| 2 | Diagnosis | 1:30 |
| 3 | The Hinge | 1:45 |
| 4 | Positioning | 1:15 |
| 5 | Constructor | 2:45 |
| 6 | Descriptor | 3:00 |
| 7 | Four Verbs, One Component | 1:15 |
| 8 | COMPOSE | 1:45 |
| 9 | Sign | 2:30 |
| 10 | Transport | 2:30 |
| 11 | Deploy | 2:30 |
| 12 | Day 2 | 3:00 |
| 13 | Adoption | 2:00 |
| 14 | What's Sharp | 1:30 |
| 15 | CTA | 2:00 |
| **Total** | | **30:00** |

Buffer is in the seam between slides 7 and 8 — if Q&A wants to interject after the four-verbs overview, give it 30 seconds and rejoin at slide 8.

---

## Q&A PREP — questions architects ask after this deck

- **"Is OCM the same as OCI?"** → No, but it sits on top of OCI as the most common transport. OCI stores blobs; OCM defines a typed, signed envelope around named bundles of blobs. The component descriptor is itself an OCI artifact with media type `application/vnd.ocm.software.component-descriptor.v2`. (slides 3, 4, 7)
- **"Does OCM replace Helm / Kustomize?"** → No. Helm and Kustomize render *into* resources that OCM packs. Rendering happens upstream at pack time. (slides 11, 14)
- **"How does this coexist with cosign / Argo / Flux / Kyverno?"** → It doesn't fight them. Cosign signs OCI artifacts directly; OCM signs the descriptor that references those artifacts by digest. Argo and Flux reconcile what the DeployerCR produces. Kyverno admission policies still apply to the manifests OCM hands to the cluster. You don't unwind your supply-chain controls; OCM adds a release-level signed envelope above them. (slide 13)
- **"Sigstore-compatible?"** → Yes. GA. Same caveats as any keyless flow — make sure your OIDC issuer is trusted in the verifier's policy. (slide 9)
- **"What about GPG?"** → GA. Middle column on slide 9. OpenPGP keys, ASCII-armored signatures, same `signatures:` block. The website's `how-to/Sign and Verify/sign-component-version.md` page has the walkthrough. (slide 9)
- **"What's the canonicalisation algorithm?"** → Spec-defined deterministic normalisation — `jsonNormalisation/v4alpha1`. Defined in the OCM spec under `04-extensions/04-algorithms/component-descriptor-normalization-algorithms.md`. Deterministic across implementations; verification doesn't depend on whose CLI produced the descriptor. This matters for security architects who plan multi-vendor trust paths. (slide 6)
- **"What's the verification flow look like in code?"** → `ocm verify cv <ref>` against a trust policy. The controllers do the same in-cluster — the ComponentCR carries a reference to a secret holding the trust anchor (public keys, certificate chain, or Sigstore identity policy). Verification API is stable. (slides 9, 11)
- **"Where is the trust policy itself defined?"** → For the CLI it's a YAML file passed via `--policy`; for the controllers it's a Secret or a dedicated config object referenced from the ComponentCR. There's no single "TrustPolicyCR" yet — verification config lives next to the consumer. This is on the roadmap to consolidate. (slides 9, 11)
- **"What about config that legitimately differs per environment?"** → Three options. (a) Resources by reference (`access:`) with environment-specific access URLs — the digest is computed at pack time on the *value* you intend to ship. (b) Multiple component versions per environment — pack once per env. (c) Externalised secrets/config via standard K8s mechanisms (External Secrets, Sealed Secrets) — the OCM descriptor doesn't try to be a secrets store. For 50-overlay-per-release shops, option (b) is the honest answer and the CI cost is real.
- **"How does the descriptor express composition?"** → Slide 8 shows the constructor side: `componentReferences:` with `name`, `componentName`, `version` per child. In the descriptor each entry also carries the resolved digest of the referenced descriptor. The parent's signature covers those child digests, so verifying the parent transitively verifies the children's identity. Slide 12 shows the day-2 mechanic on top of this primitive. (slides 8, 12)
- **"Does Replication replace `ocm transfer` in the CLI?"** → No. CLI still exists; Replication is its in-cluster equivalent. Same mechanic, different driver. (slide 11)
- **"Can Replication target a non-OCI repo?"** → The docs example uses `OCIRepository`. Recursion depth, copy mode, and credentials are configured via OCM configuration referenced from `spec.ocmConfig`, under the `transfer.config.ocm.software` key. For non-OCI targets, check the controllers' API reference for the supported `Repository` types in your version. (slide 11)
- **"Does it work with cosign for non-OCM artifacts?"** → cosign signs OCI artifacts directly. OCM signs the OCM descriptor, which references OCI artifacts by digest. Different layers; not in conflict. Both signatures can live in the same registry. (slides 6, 13)
- **"Is the spec stable?"** → Component descriptor v2 is stable. CLI surface is stable for `add cv`, `transfer cv`, `transfer ctf`, `sign cv`, `verify cv`. All three signing trust models — RSA, GPG, Sigstore — are GA. Controllers' CRD shapes are still moving — pin minor versions in your platform installs. (slide 14)
- **"What's the relationship to OpenControlPlane?"** → OpenControlPlane is one consumer / one platform integration. OCM is a delivery format; OpenControlPlane runs it as a service. You can use either independently. (slide 13)
- **"What does this cost?"** → Open source. NeoNephos Foundation governance. SAP funds core engineering. No commercial gate. (slide 15)

---

## NOTE — what to leave OUT of this deck even if asked

- **Detailed crypto primitives.** RSA-PSS parameters, ECDSA curve choice, OpenPGP packet structure. Architects who want this read the spec.
- **Internal-only roadmap.** The external roadmap is on GitHub; promises about Q3 next year are a different conversation.
- **Per-customer war stories.** BWI and SAP NS2 are exec-deck material. For architects, the conformance scenario is the proof point.
- **Detailed migration playbooks.** "How do I migrate fifty existing Helm charts to OCM" is a workshop, not a deck slide.

---

## DELIVERY NOTES

- **The conceptual slot is slides 3–6.** If you only have fifteen minutes total, deliver 1, 3, 6, 10, 13, 15 — skip everything else. The hinge (3), the descriptor (6), and the transport (10) carry the whole technical argument.
- **YAML is the trust signal.** Architects believe YAML before they believe prose. Slides 5, 6, 8, and 12 are not optional — let them sit on screen, let people read them.
- **Be honest on slide 14.** Don't bury the two edges. Lead with them when a hand goes up about production readiness. Architects respect the disclosure; they distrust decks that don't have one.
- **Stop-sentence rhythm survives.** Hero slide, slides 6, 10, 12 — each closes with a tight phrase. Slide 6 closes with "Sign the descriptor hash, not the access." Slide 10 closes with the transport caption. Slide 12 closes with the new mid-blue footer: "Every digest pinned by the signature. The cluster cannot drift." Honour the pause; don't run into the next slide.
- **CLI lives in your mouth, not on the slide.** If a hand goes up, you read the command. The deck stays clean.
