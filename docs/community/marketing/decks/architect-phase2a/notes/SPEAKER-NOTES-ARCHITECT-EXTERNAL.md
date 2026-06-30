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

> "You shipped pieces. Nothing carried the release. That's the gap I want to close. By the end of the deck you'll have a thirty-minute path to your first OCM component on a laptop — and an afternoon to one running on a cluster. Until then, here's why that matters."

Move on. No brand pitch yet. The deck does that at the end.

---

## SLIDE 2 — DIAGNOSIS  (00:45 — 02:15, ~90 sec)

**On screen.** Eyebrow: DIAGNOSIS. Title: "In every existing tool, identity is bound to location." Three bullets — OCI image / Helm chart / SBOM. Caption at the bottom: "Cosign attestations sign each piece. None of them sign the release as one named, location-independent unit."

**Speaker notes.**

This is the slide that explains *why* the existing toolbox doesn't compose. Slow down. The bullets concede the digest reality up front so a hostile reader can't dismiss the slide as a strawman against tag-based identity — the gap is at the *release* level, not at the per-artifact level. The footer is calibrated for cosign-attestation shops in the room — they're not wrong to sign each piece; they're missing the release-level envelope.

> "Three artifact types you ship every day. Look at how each one is identified."

**Point at OCI image.** "The digest pins the bytes. Even if you're using `repo:tag`, you can pin by digest and the bytes hold. But nothing pins the *release* the image belongs to. The digest names one artifact, not a release."

**Point at Helm chart.** "The version pins the chart. Same story. The chart bytes are pinned by version, sometimes by digest with OCI charts. But nothing pins the chart to the image, the config, and the SBOM it ships with as one release unit."

**Point at SBOM.** "An SBOM referrer attaches to one subject digest — that part works, OCI 1.1 referrers are a real mechanism. But no referrer spans the whole release. You can attach an SBOM to an image; you cannot attach an SBOM to 'this product, this version, every artifact in it.'"

Beat. Now the calibration for the cosign shops:

> "If you're running cosign with attestations today — and many of you are — you already sign each of these pieces. That's good work; keep it. What you don't have is a name for *the release as a whole*. The thing you ship out the door, that needs to verify in a sovereign zone with no callback to the source. There's nothing in the existing toolbox you can put a signature on that means 'this release, as one unit, across every location it'll travel.'"

> "That's the diagnosis. Identity is bound to location. The release as one named, signed, transportable thing — doesn't exist yet."

---

## SLIDE 3 — THE HINGE  (02:15 — 04:00, ~105 sec)

**On screen.** Eyebrow: THE HINGE. Title: "Identity that travels with the artifact." Three bullets on the left — Component identity / Digest / Access. ASCII diagram on the right showing `github.com/acme.org/helloworld:1.0.0` fanning out across EU reg / US reg / Air gap, with caption "Same component identity. Different access. Signature still verifies." Bottom caption: "Move the artifact; the digest stays; only the access changes. That's the trick." A brand-blue footer at the bottom states the load-bearing sentence: *"Move the artifact. The digest stays. Only the access changes."*

**Speaker notes.**

This is the conceptual fulcrum. If they understand this slide, the next ten slides are mechanics. If they don't, the rest is noise. Let it breathe.

> "OCM separates three things that the existing tools fuse together. Component identity, digest, access. Three properties of the same resource, but each does a different job."

**Bullet 1 — Component identity.** "The component has a name — a DNS-style path like `github.com/acme.org/helloworld` — and a SemVer version. That pair is globally unique. It does not encode a registry. It does not encode a URL. It's a name. Globally unique, location-agnostic."

**Bullet 2 — Digest.** "Every resource inside that component carries a SHA-256 content hash. Computed once, at pack time. The digest is what we sign. It is the content identity."

**Bullet 3 — Access.** "And separately — *separately* — there's an access record. Type, plus enough fields to fetch the bytes. `OCIImage/v1` with an image reference. `LocalBlob/v1` with a local hash. `Helm/v1` with a Helm repo URL and chart name. The access is where the resource currently lives."

Point at the diagram.

> "Now look at what happens on transport. You promote the component from a EU registry to a US registry to an air-gapped CTF tarball. The component identity doesn't change. The digest doesn't change. Only the access field gets rewritten. The signature, which covers the digest, still verifies — anywhere."

Beat. Land it.

> "Move the artifact. The digest stays. Only the access changes. That's the whole trick."

**Q&A backup on "globally unique."** A hostile architect will ask "who arbitrates component-name uniqueness — what stops me publishing `github.com/microsoft/azure-cli:1.0.0`?" The honest answer: *"'Globally unique' inherits from DNS-prefix naming — same model as Go import paths. We don't run a registry that arbitrates conflicts; uniqueness is delegated to DNS. Two parties claiming `acme.org/helloworld` is prevented the same way two parties claiming `acme.org` is prevented — by DNS delegation, not by OCM."*

**Q&A backup on squatting / name-spoofing supply-chain attacks.** Follow-on: "what if someone forges a perfectly-signed component under my name?" The honest answer: *"Trust today is per-component — the verifier knows what trust anchor to apply to the descriptor in front of it, not what anchor to apply to a name prefix it hasn't seen yet. A regulated environment relies on (a) controlling which registry the controllers are configured to pull from, and (b) per-component verifier config. Per-name-prefix trust-anchor binding is not in the spec or the controllers today."* Don't overclaim a feature OCM doesn't have.

---

## SLIDE 4 — POSITIONING  (04:00 — 05:15, ~75 sec)

**On screen.** Eyebrow: WHERE OCM SITS. Title: "Wraps every artifact. Signs the whole release." Three columns — ANY FORMAT / ANY LOCATION / ONE SIGNATURE — each ending with the noun "component" in the body. Bottom caption: "A component is the unit you sign, transport, and deploy. The next slides show how it's built."

**Speaker notes.**

This slide does two jobs. First — pre-empt the "what does this replace?" question. Second — define the *noun* the rest of the deck rests on. From here forward, "component" is a thing the audience knows the shape of.

> "Before we go further, let me say what OCM is *not*. It is not a replacement for OCI. It is not a replacement for Helm. It is not a replacement for your SBOM tooling. It composes around all of them. And it does that by defining one new thing — the *component*."

**Point at ANY FORMAT.** "Every artifact format you ship today stays exactly what it is. A Helm chart is still a Helm chart. An OCI image is still an OCI image. SBOMs stay SPDX or CycloneDX. npm packages, maven artifacts, raw binaries — each one becomes a *resource* inside the component. The artifact `type:` field is free-form; the access can be `File/v1` or `LocalBlob/v1` for anything without a dedicated access binding. So OCM components carry these things today."

**Q&A backup for ANY FORMAT.** If asked about npm and maven specifically: "OCM v1 shipped dedicated `NPM/v1` and `Maven/v1` access types. We're bringing those back to v2 — they're on the near-term roadmap. Until then, npm and maven artifacts ride in via `File/v1` or `LocalBlob/v1`. Same component shape; you get a dedicated access type later for nicer pull semantics."

**Point at ANY LOCATION.** "Component identity travels. The component has a name and version that don't encode a registry. Move it across registries; the name stays the same."

**Point at ONE SIGNATURE.** "One signature covers every digest in the component. The whole release is one signed unit."

Beat. Land the definition.

> "A component is the unit you sign, transport, and deploy. That's the noun. Hold it. The next ten slides are about how it's built, how it travels, how it's verified, and what changes for you on the platform side."

**Anticipated questions.**
- *"How does OCM relate to OCI 1.1 referrers and sigstore bundles? If I already sign images with cosign and ship attestations, what does adopting OCM give me — and what do I have to give up?"* — We don't replace cosign / sigstore / OCI referrers. Existing per-artifact signatures travel inside the component descriptor untouched. OCM adds a *release-level envelope*: one signature over the canonicalized descriptor that covers the digests of every resource in every referenced component. If you cosign-sign your images today and ship a sigstore bundle per chart, keep doing that — OCM signs the wrapper above them. What you gain: one verifiable name for the release as a whole, location-independent identity (mirror without re-signing), and signed composition (the product signature transitively covers every child digest). What you give up: nothing in your current signing flow; you add OCM signing on top.
- *"Are 'npm', 'maven', 'SBOM' really first-class resource types?"* — `type:` on a resource is a free-form string in v2 (see `bindings/go/descriptor/v2/descriptor.go:102`). An OCM component carries any of those today via `File/v1` or `LocalBlob/v1` access. Dedicated `NPM/v1` and `Maven/v1` access types: Maven is tracked under epic ocm-project#836 with GA target end of 2026; NPM is on the GA roadmap, also targeting end of 2026.
- *"You called this the 'component descriptor'. I've seen 'Software Bill of Delivery' (SBOD) used elsewhere — is that the same thing?"* — Yes. "Software Bill of Delivery" — SBOD — is our positioning term against SBOM; you may have heard it in earlier presentations or on the website. Technically an SBOD is the same object architects call **the component descriptor**: the serialized form of an OCM component version. Different words, one object. The architect deck uses "descriptor" because that's the wire-format noun; the positioning conversations use "SBOD" because that's the marketing-shaped counterpart to SBOM.

---

## SLIDE 5 — CONSTRUCTOR  (05:15 — 08:00, ~165 sec)

**On screen.** Eyebrow: CONSTRUCTOR. Title: "What you write." YAML block on the left (the `component-constructor.yaml` straight from the getting-started doc — `github.com/acme.org/helloworld` at v1.0.0 with a local-file resource and an OCI image resource). The YAML's inline comments carry the input-vs-access distinction: `# Embed by value` on the `input:` block, `# Reference external artifact` on the `access:` block. Bottom caption: "Two ways in. Same descriptor."

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

**On screen.** Eyebrow: DESCRIPTOR. Title: "What gets signed and travels." YAML block on the left — the post-pack component descriptor. We show ONE resource (the image) with `access`, `digest`, and a `...` line standing in for the other resources and references a real component would carry. The YAML's inline comments now carry the load-bearing semantics: the `access:` block is annotated as excluded from signature (rewritten on every transfer), the `digest:` block is annotated as the content identity that feeds the descriptor hash, and the `signatures:` block is annotated as the single hash over the canonicalized descriptor. The `digest:` block and `signatures:` block lines are rendered in brand blue, marking what's new compared to the constructor on slide 5.

**Speaker notes.**

This is the payoff for slide 5. **First thing to clarify in the spoken open: this is a generated artifact, not something you write.** The constructor on slide 5 was the input you wrote; the descriptor on slide 6 is what `ocm add cv` produced.

> "Slide 5 was the input you write — about eighteen lines, hand-edited. This is the output the pack step produces. The component descriptor. You'll see it in your registry as an OCI artifact; you'll see it on disk inside a CTF tarball. You will not normally hand-edit it. This is the thing that travels."

Set expectations on the trim before walking it.

> "I'm showing one resource — the image — to keep focus on the mechanism. Real components carry many resources and may reference other components. That's the `...` line. The rules I'm about to walk apply identically to every entry."

Walk through it section by section.

> "Top of the file — same name, same version. That component identity from slide 3."

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
- *"How is the canonical form defined?"* — Spec-defined normalisation (`jsonNormalisation/v4alpha1`). See the website's signing-and-verification doc; it's deterministic across implementations. Signatures are over canonical bytes — JSON/YAML field ordering and whitespace can't break verification.
- *"What about layered signing — sign on build, re-sign on entry to a sovereign zone?"* — Yes. Add more entries to the `signatures` list. Each entry is independent. None of them invalidates the others.
- *"What if a resource is mutated downstream?"* — Then its digest doesn't match the value in the descriptor, the descriptor hash check fails, and verification fails. That's the whole point.
- *"What does `componentReferences` look like in the descriptor?"* — Same shape as a resource entry: `name`, `componentName`, `version`, plus a digest of the referenced descriptor. We introduce composition on slide 8.
- *"You named RSASSA-PSS on the slide. What's the trust model — and why should I trust this more than sigstore?"* — Algorithm choice is plug-and-play; RSASSA-PSS shown here is one option. Sigstore (ECDSA-P256 + Fulcio short-lived cert + Rekor transparency log) is another, also GA on `v1alpha1` today. OpenPGP keyring is a third. The signed object is the canonicalized descriptor regardless of algorithm. Trust model is per-scheme: RSA-PSS uses bare public-key pinning (operator pins the public key); Sigstore uses OIDC issuer + Fulcio + Rekor (operator pins the issuer); OpenPGP uses a keyring (operator pins the key fingerprint). Pick the scheme that fits your environment.
- *"What about transitive trust across `componentReferences`?"* — The signature transitively pins referenced components by digest. The product signature covers every `componentReferences` entry's descriptor digest, so re-signing or re-publishing a referenced component breaks the product signature. At deploy time the verifier checks each component against its own trust anchor: the referenced component against the referenced component's anchor, the product against the product's anchor. Per-component verifier config, not implicit fall-through.

---

## SLIDE 7 — THE FOUR MOVES  (11:00 — 12:15, ~75 sec)

**On screen.** Eyebrow: THE FOUR MOVES. Title: "Pack · Sign · Transport · Deploy." Four-tile flow with arrows: PACK → SIGN → TRANSPORT → DEPLOY → SOVEREIGN CLOUD. Footer caption: "The signed component descriptor is itself an OCI artifact (media type `application/vnd.ocm.software.component-descriptor.v2`). It lives in your registry. The next four slides are mechanics."

**Speaker notes.**

This slide is the hinge from noun to verb. On slides 5 and 6 the audience saw the *static artifact* — what you write and what travels. This slide pivots to the *dynamic lifecycle* — what happens to that artifact over its life.

Open with the bridge so the seam between slide 6 and 7 is invisible:

> "On the last two slides you saw the static artifact — what you write, what travels. Now four moves on that artifact. And actually — we've covered the first half of two of them already. The constructor on slide five is the *input* to Pack. The descriptor on slide six is the *output* of Pack, the *target* of Sign, and the *unit* of Transport. So you've already met three of these four moves, you just hadn't seen them named."

Beat. Now land the primitive:

> "Look at the footer line for a moment. The component descriptor — the thing you just saw on slide six — is itself an OCI artifact. Media type `application/vnd.ocm.software.component-descriptor.v2`. It lives in your registry, right next to the images it references. Same registry, no new infrastructure. That's the primitive."

Beat.

> "Now four moves. These are *lifecycle* moves, not CLI verbs — the CLI you'll actually type is `ocm add cv`, `ocm sign cv`, `ocm transfer cv`, then `kubectl apply` against the Deployer CR. Same four moves, slightly different names."

> "Pack — bundle once, name once. We just did that."

> "Sign — one signature covers every digest. Just did that too."

> "Transport — registry to registry, registry to tarball, tarball to registry. Same command shape. The signature survives every move."

> "Deploy — at the destination, a controller verifies the signature, resolves digests, applies what the resource says."

Point at the cloud on the right.

> "Sovereign cloud, air-gapped network, customer-owned cluster. The component lands. No callback upstream."

> "Next four slides — one slide per move. Mechanics. And then on slide 8 we introduce the composition primitive that makes the day-2 mechanic on slide 12 work."

---

## SLIDE 8 — COMPOSE  (12:15 — 14:00, ~105 sec)

**On screen.** Eyebrow: COMPOSE. Title: "Service carries resources. Product carries references." Two side-by-side YAML blocks. LEFT box labelled SERVICE: two service components — `acme.org/sovereign/notes:1.0.0` and `acme.org/sovereign/postgres:1.0.0` — each with `image`, `chart`, and a `...` line under `resources`. RIGHT box labelled PRODUCT: `acme.org/sovereign/product:1.0.0` with `componentReferences:` to both services by `componentName` and `version`. Composition arrow SERVICE → PRODUCT between the boxes.

**Speaker notes.**

This slide introduces the composition primitive. The audience needs to see it on its own before slide 12 leans on it for day-2. Don't rush; the shape on this slide is what the rest of the talk rests on.

> "Every example so far has been one component with a few resources inside. Real products are compositions. Two boxes on this slide. Same descriptor shape on both sides. Different role."

**Point at SERVICE (left box).** "Two service components. `acme.org/sovereign/notes` at 1.0.0 — that's the web app. Image, chart, and a `...` for the rest: config, SBOM, whatever else the notes team packs. `acme.org/sovereign/postgres` at 1.0.0 — same shape, the database. Image, chart, `...`. Services carry the actual artifacts. Each service is independently versioned, independently signed, independently transportable."

**Point at PRODUCT (right box).** "Now look at the product. Same DNS-style name, same SemVer. No `resources:` block at all. Just `componentReferences:` — by `componentName` and `version`. The product owns *nothing* on its own. It composes the two services into one named, signed unit."

Beat. Land the primitive.

> "Services carry artifacts. Products compose. Same descriptor shape on both sides — there is no second YAML language, no parent schema. A component is a component. The role is decided by whether you put `resources:` or `componentReferences:` in it. One release unit, transferable, signable end-to-end."

Point at the arrow.

> "The arrow is the composition relationship. The product references the services by name and version — globally unique component identity, no registry encoded. When you sign the product descriptor, the signature covers the resolved digests of both child descriptors. Verify the parent; you transitively verify the children."

Pivot to slide 12.

> "Hold this picture. On slide 12 we're going to bump one line on the product — the notes version — and watch the whole composition re-sign end-to-end. This composition primitive is what makes that day-2 mechanic work."

**Anticipated questions.**
- *"What's actually in a service versus a product?"* — Services have a `resources:` block; products have a `componentReferences:` block. Nothing stops a component from having both, but the convention — and the one the conformance suite tests — is service-or-product, not mixed.
- *"What happens if the notes team adds a new resource — a sidecar image, say?"* — They bump notes from 1.0.0 to 1.0.1, repack, re-sign. The product still references `version: 1.0.0` until someone updates that line. Independent cadence.
- *"How do component identities compose? Is there a namespace collision risk?"* — Component identities are globally unique by DNS-style path plus SemVer. Two teams can each own `acme.org/<team>/...` and never collide.
- *"Does the product's signature cover the children's bytes, or just their digests?"* — The product's signature covers the children's *descriptor digests*. Each child carries its own signature over its own resource digests. Verifying down the tree is what the controllers and the CLI do automatically.
- *"Can a service reference another service?"* — Yes. `componentReferences:` is recursive. The conformance scenario uses a two-level graph; deeper graphs work the same way.
- *"Walk me through the trust chain when product P references components signed by different teams with different keys."* — Per-component. The product signature pins each reference's descriptor digest, so re-signing or re-publishing a referenced component breaks the product signature. At deploy time the verifier checks each component against the public key(s) configured on *that* Component CR's `verify:` field: notes against the notes team's key, postgres against the postgres team's key, product against the product team's key. Verification is opt-in on each CR — with no `verify:` entries the controller pulls but does not check signatures (see slide 11). For global enforcement there's no admission webhook shipping with OCM; production installs bring their own (Kyverno, Gatekeeper, or a custom webhook against the Component resource).

---

## SLIDE 9 — SIGN  (14:00 — 16:30, ~150 sec)

**On screen.** Eyebrow: SIGN. Title: "Same signed object. Three signing options." Three columns — RSA / GPG / SIGSTORE. Column bodies (hybrid form): RSA — "Bare public-key pinning. / If you already rotate a signing key." GPG — "OpenPGP keys, ASCII-armored. / If your team runs a keyring." Sigstore — "Keyless via OIDC + Rekor. / If you already trust your identity provider." Caption at the bottom: "Same descriptor hash. Three ways to vouch for it. Pick what your org already runs."

**Speaker notes.**

This is the slide where the security architects in the room start paying close attention. Three signing options, all stable in the CLI on the v1alpha1 API surface. Two of them — Plain RSA and GPG — share the same *trust model* (key pinning); Sigstore swaps it for identity-based trust. The honesty beat here isn't "early access" — it's "pick the one your org already runs." One nuance to land if asked: the *CLI* signs and verifies all three schemes today; the *v1alpha1 Kubernetes controller* implements RSA only on the verify path right now — OpenPGP and Sigstore are CLI-only, with controller support on the roadmap. Don't bury this if a Kubernetes architect presses; it's on slide 14's honest-edges list in spirit, and you should name it cleanly here if it comes up.

> "OCM separates the signature *shape* from the signing option. The descriptor is signed in one canonical way. What changes is the key material you use to sign and how the relying party establishes that the signing key belongs to whoever you think it belongs to. Three columns, three options, all stable today."

**Point at RSA.** "RSA — bare public-key pinning. The relying party knows the public key out-of-band and pins it; no certificate chain, no PKI required. If your release engineers already rotate a long-lived signing key, this is the natural path. The OCM signature is RSA-PSS over the canonical descriptor."

**Point at GPG.** "GPG. Same trust model as Plain RSA — key pinning — just with OpenPGP key material instead of bare RSA. The model your team probably already uses for git commit signing, package signing, mailing-list signing. Familiar key-ring semantics, ASCII-armored signatures. If your release engineers already manage OpenPGP keys for one process, point them at OCM for the release-level signature too — same pinning discipline, different encoding."

**Point at Sigstore.** "Sigstore. Different trust model — keyless via OIDC. Best fit for OSS pipelines where the signer is a GitHub Actions workflow or any other identity provider — no long-lived key material at rest. Compatible with the cosign verification flow, with OCM-specific extensions. The trust anchor is your OIDC issuer plus the rekor transparency log."

Beat. Now deliver the discipline:

> "Three things to land. First — the *signed object* is the same in all three cases. It is the canonical descriptor digest; it covers every resource digest in the descriptor. Second — verifiers can accept multiple signing options in parallel. You can require an RSA signature from your release team and a Sigstore signature from CI, and check both. Third — pick what your org already runs today. RSA if you already manage a long-lived signing key. GPG if your team uses OpenPGP. Sigstore if you're keyless via OIDC. OCM doesn't force a religious choice."

CLI for the curious:

> "`ocm sign cv ./transport-archive//github.com/acme/widget:v1.4.2 --signature acme-release-key --private-key ./release-key.pem`. Adds an entry to the `signatures` list in the descriptor. Idempotent if the signature already exists."

**Anticipated questions.**
- *"What about PEM-encoded RSA / certificate chains?"* — A fourth option exists: RSA with an X.509 certificate chain, PEM encoding. Still experimental — the CLI prints `experimental` warnings on every sign and verify. We didn't put it on the slide because it's not yet at the same stability bar as the other three. Watch the docs; we'll promote it when the encoding stabilizes.
- *"Why call GPG a 'signing option' but not a 'trust model'?"* — GPG follows the same trust model as Plain RSA: key pinning. The relying party knows the public key out of band and pins it. GPG just uses OpenPGP key material instead of bare RSA keys. PEM and Sigstore introduce *different* trust models (cert-chain trust and identity-based trust, respectively). (Note: the column header says "OpenPGP" on the deck — GPG is one implementation of OpenPGP; Sequoia and RNP produce compatible signatures.)
- *"Can I sign without modifying the descriptor?"* — No. The signature is part of the descriptor. That's by design — there's nothing to lose in transit.
- *"What about post-quantum?"* — Spec is open to additional algorithm IDs. Today: RSA-PSS, GPG/OpenPGP, Sigstore ECDSA-P256. Roadmap covers ML-DSA when the standard stabilises.
- *"Three options is bad for a security primitive. What's the policy floor — what stops me down-signing a component with a weak RSA key and bypassing the org's Sigstore policy?"* — The hardest question in this slot. Honest answer, and it has to be carefully worded because the shape of the Component CR matters here. The Component CR carries an optional `verify:` field — a list of `{signature-name, public-key}` pairs. Verification is opt-in at the CR level: if `verify:` is empty, the controller pulls and resolves but does not verify; if `verify:` is populated, the controller checks each named signature against the pinned public key for that name. The CR does **not** pin a *scheme* — there is no "this Component accepts only Sigstore" field on the resource. The scheme is derived from the descriptor's `Algorithm` field on the signature entry itself. So the per-component pin is name+key, not scheme+anchor. Second piece of honesty: the v1alpha1 controller implements **RSA only** on the verify path today. OpenPGP and Sigstore are signed and verified by the *CLI* — the controller will reject a non-RSA `Algorithm` with an "unsupported signature algorithm" error. So the down-sign-to-weak-scheme attack the question worries about is, in the controller today, narrower than it sounds: the controller won't accept the other schemes at all. Controller parity with the CLI on OpenPGP and Sigstore is on the roadmap. Third piece: there is **no admission webhook in the OCM controller distribution**. Global "every Component in this cluster must verify against issuer X with scheme Y" enforcement is not something OCM ships — production installs that want that floor bring their own admission layer (Kyverno, Gatekeeper, or a custom validating webhook) and write the policy there. The slide doesn't claim a built-in policy floor; the controller defers to per-CR `verify:` configuration plus whatever admission layer the platform team installs. Don't overclaim — say "per-component opt-in by name and key; cluster-wide floor is bring-your-own admission; controller is RSA-only today, CLI covers all three."

---

## SLIDE 10 — TRANSPORT  (16:30 — 19:00, ~150 sec)

**On screen.** Eyebrow: TRANSPORT. Title: "Three patterns. One command." Three columns — REGISTRY → REGISTRY / REGISTRY → CTF / CTF → REGISTRY. Each has a short two-line description. The third column (CTF → REGISTRY) carries an "AIR-GAP" tag above it. Caption: "Access fields rewrite at transfer. Digests don't. Signature still verifies — anywhere." Mid-grey footer below the columns: *"CTF = Common Transport Format — a filesystem-based OCM repository, portable via any transfer mechanism."*

**Speaker notes.**

This is the slide where the air-gap conversation lives. It is the slide where most architects say "wait, do that again."

> "Transport is a single mechanic — copy a component from one repository to another. Three patterns that cover essentially every delivery topology you'll see in real customers."

**Point at REGISTRY → REGISTRY.** "Standard promotion. Dev registry to staging registry to prod registry. Cross-cloud — GHCR to ECR, Harbor to Artifactory. Same component name, same digests, every access field rewritten to point at the new registry."

**Point at REGISTRY → CTF.** "Export to a tarball. CTF — Common Transport Format — is OCM's filesystem-friendly archive. A directory of blobs plus an index file. You can tar it up, copy it to a USB stick, write it to a Blu-ray. The whole component, every resource, in one self-contained tree."

**Point at CTF → REGISTRY.** "And the air-gap import. The CTF arrives inside the secure zone. You point `ocm transfer` at it, and at the local registry. Every resource is uploaded, every access field is rewritten to the local registry, the signature is verified — no traffic to the source. Verification is purely local."

Beat. Deliver the payoff.

> "Three things to land. First — same command in all three cases. `ocm transfer cv` with a source and a destination. Source or destination can be a registry reference or a `ctf::./path` prefix — the CLI doesn't care which combination of registry-or-tarball you pick. Second — what changes on every transfer is the `access` field. Digests don't. The signature covers the digest, not the access, which is why the signature survives every hop. Third — verification can happen at the destination, with no callback to the source. That's the air-gap property. That's what 'sovereign-ready' means in mechanics."

CLI examples:

> "Registry to registry: `ocm transfer cv ghcr.io/source//acme/widget:v1.4.2 ghcr.io/target`."
>
> "Registry to CTF: `ocm transfer cv ghcr.io/source//acme/widget:v1.4.2 ctf::./offline-bundle`."
>
> "CTF to registry: `ocm transfer cv ctf::./offline-bundle//acme/widget:v1.4.2 registry.sovereign.local`."

**Anticipated questions.**
- *"What if the source has the resource and the destination has a different digest at the same component identity?"* — Transfer refuses. Digests are immutable identity; mismatch is a failure.
- *"Can I transfer just one resource?"* — At the component level, no — the unit is the descriptor. At the resource level, you can `ocm download resource` for inspection, but you can't selectively re-pack without a new version.
- *"What about size? CTF tarballs for a real product?"* — Hundreds of MB to several GB depending on what's inside. Real customers ship them on portable media or via approved transfer mechanisms.
- *"Does `ocm transfer` copy the resource bytes by default?"* — **No — and this is the footgun on the headline air-gap use case.** Default `ocm transfer` copies only the component descriptor; the access fields still point back at the source registry. For air-gap (CTF → Registry) you MUST pass `--copy-resources` so the bytes travel with the descriptor. Flagged on slide 14 as one of the three honest edges. Worth catching in a CI step the first time someone runs an air-gap export — silent failure mode otherwise is that verify-on-destination resolves access fields to the upstream registry the destination can't reach.
- *"Sigstore signatures in an air-gap destination — does the verifier still have to call Rekor and Fulcio?"* — No, but you have to pre-distribute the trusted-root file once. For Sigstore specifically: the trusted-root file (Fulcio CA + Rekor public key for the configured OIDC issuer) must be distributed into the destination once, out of band — same way you'd pre-distribute any other trust anchor. After that, `ocm verify cv` runs offline. RSA and OpenPGP need only their pinned public keys, no trusted-root file. The air-gap property holds for all three signing schemes; Sigstore just has one extra pre-distribution step.

---

## SLIDE 11 — DEPLOY  (19:00 — 21:30, ~150 sec)

**On screen.** Eyebrow: DEPLOY. Title: "OCM controllers verify and apply." Four CR cards in a left-to-right chain with arrows: Repository → Component → Resource → Deployer. Each card carries a single-sentence body.

**Speaker notes.**

This is the slide where Kubernetes folks lean in. The four-card chain is verify-and-apply. The title is the architectural statement: "OCM controllers verify and apply."

> "OCM ships a small set of Kubernetes controllers. Four of them form the chain that brings a component into the cluster. Let me walk through it."

**Point at Repository (chain card 1).** "Repository. Where component versions live. One per source — an OCI registry, a CTF mounted from a PVC, an S3 bucket. The other controllers find descriptors through this object."

**Point at Component (chain card 2).** "Component. Pulls one version. Verifies its signature against a trust anchor you give it — the public key, the OpenPGP keyring, or the Sigstore identity policy. **Verification is opt-in**: without a `verify:` entry on the Component CR pointing at a key or secret, the controller resolves and pulls but does not check signatures. Production installs should require verification via admission policy. If verification *is* configured and fails, nothing downstream sees a verified descriptor. The chain stops here."

**Point at Resource (chain card 3).** "Resource. One artifact, by digest. The controller picks which resource — image, chart, raw manifest — out of the verified component, resolves its access record, and fetches the bytes. The resource is exposed to the cluster as a typed artifact."

**Point at Deployer (chain card 4).** "Deployer. Applies it to the cluster — and *this* is where localization happens. The Deployer resolves image references and other deploy-time pointers from the *verified* component descriptor at apply time, not at transfer time. That's the v2 mechanism. It can apply raw manifests directly, or hand off to your GitOps engine (Flux today, Argo CD path landing in the docs before this deck ships) for a HelmRelease. Pluggable at this tier — point your existing reconciliation engine at the Resource CRs and OCM doesn't fight your platform stack."

> "Honest layering, foreshadowed so slide 14 doesn't feel retroactive: the four-card chain on its own deploys raw Kubernetes manifests via the Deployer. For the Helm-deploy reference flow the chain feeds a `ResourceGraphDefinition` that kro reconciles, with Flux (or Argo CD) applying the resulting `HelmRelease`. The OCM controllers don't ship kro, Flux, or Argo CD — bring your own. Slide 14 names this as one of three honest edges."

Beat. Land the title.

> "Four controllers verify and apply. The chain is the architectural shape: descriptor in at Repository, verified bytes out at Deployer, with localization happening at apply time, sourced from the descriptor the chain has already verified."

Honesty pre-empts slide 14:

> "Two honest edges that we'll come back to in three slides: the controllers ship as v1alpha1, so the CRD surface can move — pin minor versions in your platform installs. And the Helm-deploy reference flow needs kro plus your deployer of choice."

Q&A backup — Replication appendix:

> "If anyone asks about the controller equivalent of `ocm transfer` for mirroring between repositories — there is one. It's called `Replication`, it sits alongside the chain (not within it), and there's an appendix slide for it. Happy to walk through it in Q&A."

**Anticipated questions.**
- *"Does this replace Argo CD?"* — No. It replaces the manual `kubectl apply` step. Argo CD as an alternative to Flux for the Helm-deploy path is landing in the docs (additional tabs in the existing how-tos) before this deck ships. Until then, the canonical example is kro + Flux; Argo CD is symmetrical.
- *"Do I need kro and Flux to use this?"* — For the Helm-deploy reference flow, yes — `deploy-helm-chart.md` walks Component → Resource (a `ResourceGraphDefinition`) → kro → Flux/`HelmRelease`. For the raw-manifest path, the Deployer is enough on its own. The OCM controllers don't ship kro or Flux; bring your existing GitOps engine.
- *"Where does localization actually happen?"* — At the Deployer, at apply time. The Deployer resolves image refs and other templating from the verified descriptor and feeds them into the deployment tool (Flux/HelmRelease via kro for the Helm path, or raw manifest apply). Transfer doesn't rewrite resource bytes — that would change digests and invalidate signatures. The deploy-time injection is the v2 mechanism.
- *"Is there a controller-shaped `ocm transfer`?"* — Yes — `Replication`. Pull the appendix slide if it comes up.
- *"What about secret rendering at deploy time?"* — Workflow concern, not a model concern. Secrets-as-resources is supported via External Secrets / sealed-secrets patterns; the secrets themselves don't live in the descriptor.
- *"How does verification config get to the Component controller? Is it always on?"* — Trust anchor lives in a Secret or a dedicated config object referenced from the Component CR's `verify:` field. There's no single global "TrustPolicyCR" yet — verification config is per-Component. Without a `verify:` entry the controller resolves and pulls but does not check signatures. Production installs SHOULD pin verification via admission policy (Kyverno / Gatekeeper). Don't assume the controller is verifying by default — it isn't.

---

## SLIDE 12 — DAY 2  (21:30 — 24:30, ~180 sec)

**On screen.** Eyebrow: DAY 2. Title: "Bump the product version. / Everything follows." Two side-by-side full descriptor YAMLs. LEFT — day-1 product 1.0.0 referencing notes 1.0.0 + postgres 1.0.0, each `componentReferences:` entry showing its own `digest: { hashAlgorithm: SHA-256, value: ... }` sub-block (the digest of the child descriptor), ending with a `signatures:` block (`- name: acme-release-key` / `value: a4b1c2d3e5f6789abc012345def04691...`). RIGHT — day-2 product 1.1.0 with notes bumped to 1.1.0 and postgres unchanged at 1.0.0; the notes entry's child digest has changed, the postgres entry's child digest is unchanged, and the `signatures:` block carries a different `value: 9c2af18b3e7d52914a8c6b0f1d2e8f37...`. Arrow between the blocks labelled "bump version" in mid-blue above it. The brand-blue highlights mark the product version, the notes child version, the notes child digest, and the signature value — every line that changed. Postgres's digest stays the same. Pt24 mid-blue footer beneath both blocks: "Every digest pinned by the signature. The cluster cannot drift."

**Speaker notes.**

This is the slide where the conformance scenario lives. Composition was introduced on slide 8 — the audience already knows what a product + two leaves looks like. This slide does one job: the day-2 upgrade mechanic, signed end-to-end. Don't re-explain composition; lean on it.

> "We saw composition on slide 8. Product, notes, postgres. Now what happens on day 2 when the notes team ships a security patch."

Point at the left YAML.

> "Day 1. The product at 1.0.0. References notes at 1.0.0 and postgres at 1.0.0. At the bottom, a `signatures:` block — one signature, key name `acme-release-key`, value `a4b1c2d3...`. That hex string is the descriptor hash signed end-to-end. It covers every component reference and, transitively, every resource digest under those references."

Point at the arrow and its label.

> "Now the notes team ships a security patch. Notes goes from 1.0.0 to 1.1.0. Inside the sovereign zone, the platform team commits two changes on the product: `version: 1.0.0` becomes `1.1.0`, and the notes child reference goes from 1.0.0 to 1.1.0. That's the operator action. The arrow names it: bump version."

Point at the right YAML, walking the three highlights.

> "Day 2. Three lines on the slide are highlighted in brand blue. The product version. The notes child version. And the signature value — `9c2af18b...`. Different bytes. The signature has changed because the descriptor has changed, and the descriptor has changed because one child version has changed. Bump one line; the whole chain re-signs."

> "Look closer at the `componentReferences:` block. Each entry now carries its own `digest:` sub-block — `hashAlgorithm: SHA-256` plus a `value:` — that's the digest of the referenced *descriptor*. The notes entry's child digest is highlighted in brand blue on day 2: it changed, because the notes descriptor changed. The postgres entry's child digest is unchanged — postgres is still 1.0.0, same descriptor, same hash. The parent's signature covers both child digests, so the day-2 signature transitively pins the new notes descriptor and the unchanged postgres descriptor as one unit."

> "Postgres is unchanged. Its version stays at 1.0.0. Its digests stay the same. But its digests are still covered by the new signature on the new product descriptor, because the product's signature is over the canonical form of the descriptor as a whole."

Point at the footer.

> "Read the footer. *'Every digest pinned by the signature. The cluster cannot drift.'*"

Beat. Now the differentiator.

> "A `helm upgrade` cannot give you this property. The differentiator for security architects: OCM is a release-level *envelope*. `helm upgrade` upgrades one chart; cosign signs one image. OCM's signature covers the whole release as one unit — every digest in every resource of every referenced component is pinned by the one parent signature. Drift would mean breaking that envelope. Not 'helm upgrade can't do this' — it's that the unit of signing is different. Bump `spec.version` on the product, the controller pulls the new descriptor, verifies the signature *before* it touches the cluster, and either everything reconciles in lockstep or nothing does. The cluster cannot drift away from what you signed."

> "This whole flow is in our conformance scenarios. Product, notes, postgres. We test it on every release. If you want to see it run end-to-end, the scenario lives in the open-component-model repository."

**Anticipated questions.**
- *"What about rollback?"* — Same primitive in reverse. Commit `version: 1.0.0` and the notes child back to 1.0.0 on the product. The controller pulls the day-1 descriptor (which is still signed). Signatures verify. Cluster rolls back.
- *"Can children be versioned at independent SemVer cadences?"* — Yes. Independent components, independent versions. Bump notes whenever the notes team ships; bump postgres on its own schedule; the product picks the combination it wants to release.
- *"What is the schema migration story?"* — Whatever the notes component packaged: Helm pre-upgrade hook, init container, separate Job resource — your choice. OCM doesn't reinvent the migration mechanic; it just makes sure the migration job's image is itself a pinned, signed resource that arrived in the same descriptor as the new app image.
- *"What if a child is signed by a different team?"* — Multiple signatures supported. Verification policy lives at the controller; you decide which keys you trust at which layer. The product's signature covers child *digests*; a child's own signature covers its *resources*.
- *"What if I don't use Helm — am I tied to it for day-2?"* — No. The mechanic is "controller sees a new descriptor, verifies it, the deployer applies." Whether the deployer points at a raw manifest, a HelmRelease, or an Argo App is your choice; the signing and verification property holds regardless.
- *"What stops a malicious operator from committing a forged descriptor with bumped versions, an attacker's image references, and a signature from a leaked key?"* — Nothing OCM-specific. Same threat model as any signed-release system: rotate keys, require dual-sign, audit access to signing material. What OCM gives you is *one* signature to audit instead of N — easier to monitor, easier to revoke. The composition property doesn't change the trust model; it changes the *unit of signing*.

---

## SLIDE 13 — ADOPTION  (24:30 — 26:30, ~120 sec)

**On screen.** Eyebrow: ADOPTION. Title: "Two paths to a first OCM component." Two columns — FROM ZERO — CLI / ON YOUR CLUSTER — CONTROLLERS. Each is four short lines. The CLI column closes with *"Thirty minutes on a laptop."* The controllers column closes with *"Thirty minutes on any cluster."* Caption: "Pick the path. The conformance scenario tests both on every release."

**Speaker notes.**

End the technical section by handing them a starting point. Two paths, pick one. Both are testable on a laptop in an afternoon.

> "If you go home and prototype OCM tomorrow, there are two reasonable entry points. Both are real. Both are tested in our conformance suite on every release."

**Point at FROM ZERO — CLI.** "From-zero path. You don't need any cluster. Install the CLI. Write the constructor for one simple component — the website tutorial walks `github.com/acme.org/helloworld` end-to-end. Pack it. Sign it with an RSA key. Export it as a CTF tarball. Carry the tarball to a second machine. Import it. Verify. Cold-start budget: about thirty minutes — CLI install plus the simple pack/sign/verify documented in the signing tutorial. This is the path I recommend for the first hands-on contact, even if you eventually go to the cluster path."

**Point at ON YOUR CLUSTER — CONTROLLERS.** "Cluster path. Spin up a kind cluster (or use any cluster you already operate). Helm-install the OCM controllers, plus kro, plus your deployer of choice — Flux or Argo CD. Point them at your registry. Apply a Component resource that names one component you've already packed. Watch it pull, verify, and resolve. Cold-start budget: an afternoon — that's the bootstrap (kind + controllers + kro + Flux/Argo CD) plus a Helm-deploy of the simple component documented in the getting-started tutorial. The slide deliberately doesn't put marketing minutes on the bullets — these are the honest numbers."

Beat.

> "Last line on the right is for the platform leads in the room. If your org runs OpenControlPlane — SAP's open multi-tenant control plane — OCM ships as a service-provider integration there. One openMCP resource, and tenant clusters across the org get the OCM controllers installed. Same controllers, same mechanic; the install is just declarative across tenants instead of cluster-by-cluster."

> "The conformance scenario in our repo runs both paths on every release. If either one stops working, the release doesn't ship. So the example you pick up off the website tomorrow is the same example we verify works green."

**Anticipated questions.**
- *"How long to org-wide adoption?"* — One team, one afternoon. One product, one sprint. Org-wide, a quarter to a year depending on scope and on how much pack-time work has to shift left.
- *"Do I need OpenControlPlane?"* — No. The cluster path is a plain Helm install on any K8s cluster. OpenControlPlane is for organisations already running a multi-tenant control plane.
- *"Do the controllers need anything else to deploy Helm charts?"* — For the Helm-deploy path you bring your deployer of choice (Flux today, Argo CD path landing in the docs before the deck ships) alongside the OCM controllers and kro — the deployer reconciles the `HelmRelease` that the Deployer-driven `ResourceGraphDefinition` hands it. For raw manifests, the Deployer is enough on its own.
- *"Thirty minutes really? Cold-start?"* — Honest scope on the CLI side: install CLI (~5 min), write constructor for the `helloworld` example (~10 min), pack/sign/verify (~10 min), CTF round-trip if you walk to a second laptop (~5 min). That's the website signing tutorial verbatim. Cold-start with a more interesting component — one with a real OCI image and a Helm chart — adds time for resource collection but not for the OCM mechanics. On the cluster side, an afternoon is honest: ~15 min for the controller environment bootstrap (kind + kro + Flux/Argo CD + OCM controllers), ~30 min for the Helm-deploy walk-through. If you don't pre-install the controllers, "deploy a component" is closer to 45 minutes than 30.

---

## SLIDE 14 — WHAT'S SHARP  (26:30 — 28:00, ~90 sec)

**On screen.** Eyebrow: WHAT'S SHARP. Title: "Three honest edges." Three bullets in a blue box — (1) Transfer defaults to descriptor-only; pass `--copy-resources` for air-gap. (2) Controllers are v1alpha1 — pin to specific release tags. (3) Helm-deploy adds kro + Flux or Argo CD — the OCM controllers don't ship them. Bring your existing GitOps engine. Caption: "Honest now beats apologetic later. Plan for the trim edge."

**Speaker notes.**

This is the slide that earns trust. Architects do not believe a deck without a sharp-edges slide. Three edges, delivered straight. No softening.

> "Three edges I want to call out before you go home and prototype this."

**Bullet 1 — Transfer defaults to descriptor-only.** "When you run `ocm transfer`, by default it copies only the descriptor — the metadata, the references, the signatures. The bytes of the resources stay at their original access locations. That's fine for promotion inside one connected estate. It is *not* fine for air-gap. For the air-gap case you pass `--copy-resources` so the bytes travel with the descriptor into the CTF tarball. Default is descriptor-only; if you want bytes too, you ask for them. Worth catching in a CI step the first time someone runs an air-gap export."

**Bullet 2 — Controllers are v1alpha1.** "The Kubernetes controllers ship at v1alpha1. The CRD surface can still move between releases — fields renamed, behaviour adjusted. The mechanic — Repository, Component, Resource, Deployer — is settled. The exact shape of those CRDs isn't. Pin to specific release tags in your platform installs. Treat upgrades the way you'd treat any v1alpha1 — check the changelog, test in staging."

**Bullet 3 — Helm-deploy adds kro + Flux or Argo CD.** "On slide 11 we walked the four-controller chain and foreshadowed the dependency. Here's the full picture. The four-card chain on its own deploys raw Kubernetes manifests via the Deployer. For the Helm-deploy reference flow, the Deployer feeds a `ResourceGraphDefinition` that kro reconciles, with your GitOps engine — Flux today, Argo CD path landing in the docs before this deck ships — applying the resulting `HelmRelease`. The OCM controllers don't ship kro, Flux, or Argo CD; you bring them. Three installs for Helm-deploy. Plan for it. Nuance for Q&A: kro is actually required for any non-raw-manifest deploy path (it reconciles the `ResourceGraphDefinition` regardless of whether the leaf is Helm or something else); the GitOps engine is the Helm-deploy-specific add. The bullet reads `kro + Flux or Argo CD` because that's the operational dependency tuple the platform team installs for the documented happy path."

Beat.

> "Honest now beats apologetic later. If any of these edges is a deal-breaker for your platform, tell us — we'd rather know early. If they're trim work, plan for them; the rest of the model is sound."

---

## SLIDE 15 — CTA  (28:00 — 30:00, ~120 sec)

**On screen.** Eyebrow: JOIN US. Title: "Ship the release as one unit." Three lines: Evaluate — `ocm.software` · run conformance/scenarios/sovereign / Pilot — `github.com/open-component-model` · one product, one team / Engage — community channels on the website · NeoNephos Foundation. NeoNephos Foundation logomark bottom-right.

**Speaker notes.**

Close with the ask. Architect-shaped: Evaluate, Pilot, Engage. The title is the whole talk in six words.

> "Ship the release as one unit. That's the talk in six words. Three doors out of this room."

> "Evaluate. `ocm.software` — the spec, the concept docs, the conformance suite. Run the conformance scenario at `conformance/scenarios/sovereign` — it's a working end-to-end example you can read in an afternoon. You'll know whether OCM fits your delivery model after that read."

> "Pilot. `github.com/open-component-model` — one product, one team, scoped scope of work. Spec, implementation, conformance suite, roadmap. All open, all in the open. If you find an edge, file an issue; if you build on top, we want to know."

> "Engage. The community channels are linked from the website — the maintainers are there, customers are there, the foundation governance discussions happen there. If your organisation is at the supply-chain pressure point I described at the start, we want to hear about your delivery problem in your words."

Beat.

> "We're not selling OCM. We're stewarding a standard under NeoNephos Foundation governance. The more voices in the room while it's being shaped, the better the standard gets."

> "That's the talk. Thank you. Happy to take questions."

(Then: take questions.)

---

## SLIDE 16 — APPENDIX · REPLICATION  (PULL-ON-DEMAND, not in main 30-min flow)

**On screen.** Eyebrow: APPENDIX · REPLICATION. Title: "Alongside the chain. Not within it." Four greyed-out chain cards at the top (Repository → Component → Resource → Deployer) reminding the audience of slide 11. A larger Replication card in brand blue, offset below the chain, with body text: "Transfers a resolved component version from one OCM repository to another. Records status.lastTransferredDigest. Same digest → no-op." Footer in mid-blue: "Controller-shaped equivalent of the OCM CLI's `ocm transfer cv` — point it at a source `Component` and a target `Repository`, and it keeps them in sync."

**Speaker notes.**

Pull only on demand — typical triggers: "is there a controller for `ocm transfer`?", "how do I mirror components between management cluster and tenant clusters?", "what about in-cluster air-gap promotion?".

> "There's a fifth controller I didn't put on slide 11 because the four-card chain is the load-bearing story. It's called Replication, and it sits alongside the chain — not within it. The chain delivers content *into* the cluster. Replication transfers content *from* one OCM repository *to* another."

**Point at the chain (greyed).** "These four are unchanged from slide 11 — that's the verify-and-apply path."

**Point at Replication.** "Replication references a `Component` for its source and a `Repository` for its target. When the source `Component`'s resolved version changes, Replication transfers that version — with its full reference graph of components — into the target repository."

> "It records `status.lastTransferredDigest` after each successful run. A later reconciliation that sees the same digest is a no-op. The controller doesn't re-transfer unchanged content."

> "Use cases. Delivery pipelines — promote a component version between environments without leaving the cluster. Backup. Air-gap scenarios where a management cluster mirrors content into a downstream registry on a separate trust boundary. Anything you'd reach for `ocm transfer` on a workstation, run as a controller instead."

> "Same mechanic as the CLI verb. Different driver — one for an operator at a terminal, one for a controller watching a `Component`."

**Anticipated questions.**
- *"Why isn't this in the main deck?"* — Because the four-card chain is the architectural message. Replication is a coda for a specific use case. We pull it when it matters.
- *"Can Replication target a non-OCI repository?"* — The current shape references a `Repository` with a `repositorySpec` — the example in the docs uses `type: OCIRepository`. Recursion depth, copy mode, and credentials are configured via OCM configuration referenced from `spec.ocmConfig`, under the `transfer.config.ocm.software` key.
- *"Status `ResolutionInProgress` / `TransferInProgress`?"* — Two phases per reconcile. First the resolution worker walks the reference graph; then the transfer executes. Standard controller-status pattern.

---

## SLIDE 18 — APPENDIX · HOW OCM COMPARES  (Q&A BACKUP, not in main 30-min flow)

**Why this slide exists as appendix, not main flow.** This deck is for architects coming from different areas trying to find out what OCM *is*, not for an architecture-decision board. A comparative slide in the main arc would either (a) sit too early (before the audience knows what's being compared) or (b) sit too late (interrupt the closing posture after slides 14–15). It belongs nowhere good in the arc. It belongs here, as the answer to one specific question: "Why not just compose cosign + in-toto + OCI 1.1 referrers + my GitOps engine?"

Pull this slide ONLY if a hostile architect asks the composition-of-existing-tools question in Q&A.

**On screen.** Eyebrow: HOW OCM COMPARES. Title: "Composes with what's there." A three-row bordered table containing the per-artifact tools, with the OCM row sitting *outside* the box below it. Row labels and columns:

```
                       WHAT IT SIGNS              LOCATION-      AIR-GAP
                                                  INDEPENDENT    NATIVE
┌────────────────────┬────────────────────────┬──────────┬───────────┐
│ cosign / sigstore  │ one OCI artifact       │ no       │ no        │
│ SLSA / in-toto     │ one build's provenance │ no       │ partial   │
│ SBOM / OCI 1.1 refs│ one artifact's contents│ partial  │ no        │
└────────────────────┴────────────────────────┴──────────┴───────────┘

OCM                     a component (the bundle)   yes        yes
```

The "out of the table" placement of OCM is the slide's whole argument made visual: the per-artifact tools form one comparison group; OCM is a *different unit* of analysis, not just a row in the same group. Bottom caption (mid-blue): "OCM rides on top. It doesn't replace the per-artifact tools — it adds the release-level envelope they don't."

**Speaker notes (Q&A delivery).**

> "Good question — and an honest answer. Each of those tools does one job well, and OCM doesn't replace any of them. Look at the unit each one operates on."

**Point at row 1 — cosign / sigstore.** "Cosign signs one OCI artifact at a time. Per-image trust is strong. But the signature is tied to that artifact's digest in that registry — promote across registries with `cosign copy` and you have to re-sign or re-attach. OCM uses Sigstore as one of its three signing schemes for the component descriptor — same crypto, different unit."

**Point at row 2 — SLSA / in-toto.** "SLSA attests the build process. Provenance, not bundling. Not natively air-gap — the attestation has to travel with its subject somehow, and that's your problem to solve. OCM carries SLSA and in-toto attestations as resources inside the component; the descriptor signature covers their digests."

**Point at row 3 — SBOM / OCI 1.1 referrers.** "OCI 1.1 referrers attach an SBOM to a subject digest — that part works, real mechanism, digest-addressable. But no referrer spans a multi-artifact release. You can attach an SBOM to one image; you can't attach one to 'this product, this version, every artifact in it.' OCM carries SBOMs as resources; the descriptor names which SBOM belongs to which artifact."

**Point at the OCM row outside the box.** "OCM operates one level up. It signs **the component** — a named, versioned bundle of artifacts plus access paths. One signature covers every digest. Location is rewritten on transfer; the signature still verifies. CTF round-trip with no callback to source — that's the air-gap property the rows inside the box don't have."

Beat. Land the close.

> "OCM rides on top. It doesn't replace the per-artifact tools — it adds the release-level envelope they don't. Every signature you already produce travels inside the component. We sign the wrapper above them. That's why the OCM row is outside the table on this slide — it's a different unit of conversation."

**Anticipated follow-ups.**
- *"Why is SLSA 'partial' on air-gap?"* — SLSA attestations CAN travel with their subject if you ship them together (in-toto bundles, OCI 1.1 referrers). No native air-gap transport in the SLSA spec itself; depends on the carrier. OCM's CTF round-trip is built in.
- *"Why is SBOM 'partial' on location-independent?"* — OCI 1.1 referrers are digest-addressable, so attaching an SBOM to `image@sha256:abc...` works across registries that support referrers. Not every registry supports them, and the attachment is one artifact at a time, not release-wide.
- *"What about Helm chart signing — `helm package --sign`?"* — Helm provenance signs one chart's tarball. Same pattern as cosign for OCI — per-artifact, location-bound. Carries inside an OCM component as a `Helm/v1` resource if you want it.
- *"Are you claiming OCM replaces cosign?"* — No. We claim OCM signs a **different unit** — the release-as-bundle — that cosign can't sign. Most production setups will run both: cosign on each image, OCM on the component containing them.

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
