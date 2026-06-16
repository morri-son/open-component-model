# OCM Technical Deck — Slide Content

Companion to `TECHNICAL-DECK-OUTLINE.md`. For each slide: title, eyebrow, body content (with options where the framing benefits from variants), notes on what diagram or artifact it needs, speaker's notes, and one anticipated question.

**Audience:** platform architects, SREs, security engineers, lead/principal devs.

**Style note:** more verbose than the exec deck. Practitioners read 100-word slides; that's allowed here. Code snippets and YAML belong on the slide (not just in the speaker notes).

---

## Slide 1 — "The wall every platform team hits at scale"

**Eyebrow:** THE WALL

**Title (Option A — pain-led):** *Twenty repos, six registries, three signing schemes, no spine.*
**Title (Option B — question-led):** *What's your spine for cross-stack delivery?*
**Title (Option C — confession-led):** *We had cosign, SBOMs, and Helm. We still couldn't ship into a sovereign region.*

**Body:**
> A modern delivery is six repos, three registries, four signing schemes, and an SBOM somewhere. Each piece works. The *delivery* doesn't compose. There is no name that travels with the artifact across registries. There is no signature that survives transport intact. There is no SBOM that knows where the artifact ended up.
>
> The reason isn't bad tools. It's a missing layer.

**Diagram:** primitives-composed visual showing 6–8 disjoint stacks (OCI, Helm, npm, S3, GitHub, SBOM tooling) with broken / dashed connectors and a single big `?` or `??` marker in the middle.

**Speaker notes:** "Skip the apologies; everyone in this room has felt this. Spend 30 seconds naming the symptom — then move."

**Anticipated question:** *"Why doesn't OCI Distribution + cosign solve this already?"*
→ Park for slide 9 / 15. Don't argue here.

---

## Slide 2 — "Diagnosis: identity is bound to location"

**Eyebrow:** DIAGNOSIS

**Title:** *In every existing tool, identity is bound to location.*

**Body:**
> The container is its registry path. The chart is its repo URL. The SBOM is the file in CI. The signature is the cosign attachment to the OCI manifest.
>
> Move any of them and the identity changes. Mirror the registry, fork the chart, archive the SBOM — the chain breaks. You can't sign a delivery once and have it survive transit, because *there is no "delivery" identity to sign*. Only artifacts have identity, and artifacts only have identity at locations.
>
> Compliance retrofits don't fix this. They paper over it.

**Diagram:** 5–6 artifact pills, each shown twice (at "source" and "destination"), with a fault-line crack in the middle showing identity *changed* across the boundary.

**Speaker notes:** "This is the punchline of the whole pain section. If they nod here, the rest of the deck is downhill."

**Anticipated question:** *"Isn't that what OCI references / digests are for?"*
→ Acknowledge: digests give content-identity at a location. They don't give *delivery-identity* across locations. Slide 9 will earn this.

---

## Slide 3 — "What 'location-independent identity' means"

**Eyebrow:** THE HINGE CONCEPT

**Title:** *Identity that travels with the artifact.*

**Body:**
> A component has a name (`github.com/acme/widget`) and a version (`v1.4.2`). That name + version is its **OCM Coordinates** — globally unique, technology-agnostic, location-agnostic.
>
> The same component descriptor exists in any registry. Same digest. Same signature. Same SBoD. The Coordinates don't change when you transfer.
>
> Inside the descriptor, every artifact has a **digest** (location-independent content identity) and an **access** (where it currently lives). Move the artifact; the digest stays; only the access changes.
>
> *That's the trick.*

**Diagram:** identity chip ("`github.com/acme/widget : v1.4.2`") at centre; same chip shown unchanged at three different registry cylinders; arrows between registries showing transit.

**Speaker notes:** "This is the slide where the audience either gets it or doesn't. If they get it, the rest of the deck is them filling in the picture. Spend 90 seconds. Don't skip."

**Anticipated question:** *"How is that different from a fully-qualified OCI reference like `registry/repo:tag@digest`?"*
→ The OCI ref is bound to `registry`. Strip the registry; the ref breaks. OCM Coordinates have no registry. The component descriptor has *its own* identity, separate from any registry where it currently lives.

---

## Slide 4 — "Eight words to learn"

**Eyebrow:** GLOSSARY

**Title:** *Eight words. After this, the rest reads itself.*

**Body (table layout):**

| Term | One-line definition |
|---|---|
| **Component** | A named, versioned bundle of resources, references, and metadata. The unit of delivery. |
| **Component Version** | A specific `name:version`. Immutable once published. |
| **Component Descriptor** | The YAML / JSON artifact that *is* the Component Version. Signed. Travels. |
| **Resource** | An artifact in the descriptor — image, chart, binary, SBOM, ... |
| **Source** | A pointer to where the resource was *built from* (git URL, commit, branch). |
| **Reference** | A pointer to *another* Component Version. Composition. |
| **Repository** | Where Component Descriptors are stored. Often: an OCI registry. Sometimes: CTF, S3, filesystem. |
| **Coordinates** | The component's `name:version` — globally unique, location-independent. |

**Diagram:** none. The table is the slide.

**Speaker notes:** "Don't read the whole table. Highlight three: Coordinates (the identity), Descriptor (the artifact), Reference (composition). The other five fall into place."

**Anticipated question:** *"How is a Reference different from a Resource?"*
→ A Resource is *a thing*. A Reference is *another component*. Reference enables composition (component-of-components); Resources are the leaves.

---

## Slide 5 — "A Component Descriptor, in full"

**Eyebrow:** SHOW, DON'T TELL

**Title:** *What you actually sign.*

**Body:** A real component descriptor on the slide. Strip to the most useful 25–30 lines:

```yaml
component:
  name: github.com/acme/widget
  version: v1.4.2
  provider: name=acme
  resources:
    - name: widget-image
      type: ociImage
      version: v1.4.2
      access:
        type: ociRegistry
        imageReference: ghcr.io/acme/widget:v1.4.2
      digest:
        hashAlgorithm: SHA-256
        normalisationAlgorithm: ociArtifactDigest/v1
        value: 9f86d081...
    - name: widget-chart
      type: helmChart
      version: 0.4.1
      access:
        type: helm
        helmRepository: https://charts.acme.io
        helmChart: widget:0.4.1
      digest: { ... }
    - name: sbom
      type: sbom-cyclonedx
      access: { type: localBlob, ... }
  componentReferences:
    - name: shared-base
      componentName: github.com/acme/base
      version: v2.1.0
  signatures:
    - name: acme-signing-key
      digest: { ... }
      signature: { algorithm: RSASSA-PSS, mediaType: application/vnd.ocm.signature.rsa, value: ... }
```

**Margin annotations:**
- *(point at `digest`)* — this is what gets signed; not `access`.
- *(point at `componentReferences`)* — this is how composition works.
- *(point at `signatures`)* — yes, multiple signatures are normal.

**Speaker notes:** "Spend 90 seconds. Read it like a poem. The audience hasn't seen this before; let them photograph it. Worth pausing for questions."

**Anticipated question:** *"Where does this YAML live?"*
→ Inside the OCM repository (typically OCI). The descriptor is itself an OCI artifact under a well-known media type. `ocm get cv github.com/acme/widget:v1.4.2` returns it.

---

## Slide 6 — "From SBOM to SBoD — what the envelope adds"

**Eyebrow:** BRIDGE TO THE EXEC STORY

**Title:** *The envelope, not a replacement.*

**Body:**
> Your SBOM tooling emits CycloneDX or SPDX. OCM doesn't replace it. OCM adds a layer:
>
> - **Inside:** the same SBOM you already produce. Resource type `sbom-cyclonedx` or `sbom-spdx`. Lives unchanged.
> - **Around it:** every other artifact (image, chart, binary, config) — each with its own digest, all referenced under one Coordinates.
> - **Around all of it:** one signature covering every digest in the descriptor.
>
> The SBoD is the descriptor + signature + content. The SBOM is one resource inside.

**Diagram:** the v3 nested-rings diagram (SBoD → Payload → SBOM, three concentric layers). Annotation: "your tooling produces this innermost ring; OCM produces the two around it."

**Speaker notes:** "The exec deck made the case for SBoD. Here we earn it: practitioners need to see *exactly where their existing tooling fits*. The answer: unchanged, in the innermost ring."

**Anticipated question:** *"Does adopting OCM force a CycloneDX migration / SPDX-to-X conversion?"*
→ No. Resource type tells consumers what's inside. Multiple SBOM formats can coexist as separate resources.

---

## Slide 7 — "Pack — what `ocm add cv` actually does"

**Eyebrow:** MECHANICS 1/4

**Title:** *`Pack` — three lines on disk, one descriptor.*

**Body (CLI on slide):**

```bash
$ cat resources.yaml
- name: widget-image
  type: ociImage
  input:
    type: ociImage
    image: ghcr.io/acme/widget:v1.4.2

$ ocm add cv ./component-archive --component github.com/acme/widget:v1.4.2 \
    --provider name=acme --resources resources.yaml

$ ocm get cv ./component-archive --output yaml
component:
  name: github.com/acme/widget
  version: v1.4.2
  resources:
    - name: widget-image
      type: ociImage
      digest:
        value: 9f86d081...
      access:
        type: localBlob
        localReference: sha256:...
```

**Side-bar / annotations:**
- `add cv` writes the descriptor + materialises blobs into `./component-archive` (a CTF — Common Transport Format).
- Each resource gets a digest computed locally — this is what travels.
- `ocm push` later changes `localBlob` → `ociRegistry` access, leaves the digest unchanged.

**Speaker notes:** "Show the CLI; show the YAML. Practitioners trust what they can read. The single most important byte on this slide: the digest doesn't change between local and remote."

**Anticipated question:** *"What's a CTF?"*
→ Common Transport Format — a tar archive with a known directory layout. It's a portable component-archive. Slide 10 lives here.

---

## Slide 8 — "Sign — three trust models, one signature shape"

**Eyebrow:** MECHANICS 2/4

**Title:** *One signature shape. Three trust models.*

**Body:**

| Trust model | Use when | Algorithm | Notes |
|---|---|---|---|
| **RSA** (your existing PKI) | You already have an enterprise CA. | `rsassa-pss`, `rsassa-pkcs1-v1_5` | Works with your HSM, your IAM, your audit trail. |
| **GPG / OpenPGP** | Per-team or per-developer signing. | `OpenPGP/RFC4880` | The descriptor signature carries the GPG key id. |
| **Sigstore (keyless)** | Ephemeral identities, no long-lived keys. | `cosign` | Currently *early access* in OCM v2 — usable, evolving. |

> Whichever you pick, the signature shape is the same: *one signature over the normalised hash of the descriptor*. The descriptor's hash includes every resource's digest. Verify the descriptor; you've verified everything.

```yaml
signatures:
  - name: acme-signing
    digest:
      hashAlgorithm: SHA-256
      normalisationAlgorithm: jsonNormalisation/v1
    signature:
      algorithm: RSASSA-PSS
      mediaType: application/vnd.ocm.signature.rsa
      value: MIIBCgKCAQEA...
```

**Speaker notes:** "Three things to land: (1) you can pick. (2) you can pick *more than one* — multi-signature is normal. (3) Sigstore is real but flagged early-access; don't oversell to a security-team audience."

**Anticipated question:** *"Why not just cosign the OCI artifact?"*
→ Cosign signs *containers*, by content. OCM signs *deliveries*, by descriptor. The descriptor includes every resource's digest, so signing the descriptor signs the whole delivery. Slide 14 is the deeper version of this answer.

---

## Slide 9 — "Why signatures survive transport"

**Eyebrow:** THE ONE SLIDE THAT MATTERS

**Title:** *`access` vs `digest` — the split that lets signatures travel.*

**Body:**
> Every resource in a descriptor has two pointers:
>
> - **`digest`** — content identity. SHA-256 of the artifact's normalised bytes. Computed once, at packaging.
> - **`access`** — where the artifact currently lives. OCI registry path, helm repo URL, S3 bucket, CTF blob.
>
> The signature covers the **digest**. Not the access.
>
> Transfer the component to a different registry. The `access` field is rewritten by the transfer (`ocm transfer`). The `digest` is unchanged. The signature still verifies. Anywhere. By anyone. Without callback.

**Diagram:** show one resource entry on the left with both `access:` and `digest:` highlighted. Arrow to the right shows the same resource entry after transfer; `access:` has a strikethrough → new value; `digest:` is unchanged. A signature mark covers only the `digest:` line.

**Speaker notes:** "If they remember one slide from the deck, make it this one. The whole sovereign-cloud, air-gap, no-callback story rests on this split. Don't move on until they say 'oh.'"

**Anticipated question:** *"How is the digest computed for a Helm chart vs a container vs a binary?"*
→ Per resource type, via a registered *normalisation*. `ociArtifactDigest/v1` for OCI, `helmChart/v1` for Helm, `genericBlobDigest/v1` for blobs. The normalisation algorithm is part of the signature, so verifiers know how to recompute.

---

## Slide 10 — "Transport — Registry · CTF · Air gap"

**Eyebrow:** MECHANICS 3/4

**Title:** *Three patterns, one command.*

**Body:**

```bash
# Registry → registry (mirror).
ocm transfer cv \
  ghcr.io/acme//github.com/acme/widget:v1.4.2 \
  registry.eu-sovereign.acme.io//github.com/acme/widget:v1.4.2

# Registry → CTF (pack for export).
ocm transfer cv \
  ghcr.io/acme//github.com/acme/widget:v1.4.2 \
  ./widget-v1.4.2.ctf.tar

# CTF → registry (import on the other side).
ocm transfer cv \
  ./widget-v1.4.2.ctf.tar \
  registry.airgapped.example.com//github.com/acme/widget:v1.4.2
```

> **What `transfer` does:**
> - Walks every resource and reference recursively.
> - Rewrites every `access:` to point at the new repository.
> - Re-uploads blobs as needed.
> - **Leaves every `digest:` unchanged.**
> - Preserves all signatures.

**Side panel:**
- Three identical commands, three different patterns.
- The CTF is a tar file. Burn it to a CD, walk it across, scp it.
- Verify on the other side: `ocm verify cv ... --pubkey ...`.

**Speaker notes:** "Show the three forms. The 'CTF is a tar file' line is the moment for an air-gap audience."

**Anticipated question:** *"What if the destination registry already has some of the blobs?"*
→ Transfer is digest-aware; existing blobs are skipped. Subsequent transfers of the same component are nearly free.

---

## Slide 11 — "Deploy — controllers, localization, kro"

**Eyebrow:** MECHANICS 4/4

**Title:** *Repository → Component → Resource → Deployer.*

**Body:**

> OCM ships Kubernetes controllers. They reconcile a four-layer chain:
>
> 1. **Repository CR** — points at an OCM repo (OCI, S3, etc.) + a verification policy.
> 2. **Component CR** — a Component Version inside that Repository, plus an interval (`pull every N`).
> 3. **Resource CR** — a single resource extracted from that Component Version.
> 4. **Deployer CR** — what to *do* with the resource. Ship the kro PreparedManifest, the FluxCD-compatible Kustomization, or the Helm release.
>
> Localization happens between (3) and (4): per-target overrides and substitutions, declared once in the Component Version.

**Diagram:** four-layer stack — Repository → Component → Resource → Deployer — with a side-arrow showing localisation injecting at Resource. Below the stack: small icons for FluxCD / Argo / kro.

**Speaker notes:** "The exec deck said 'bring your own GitOps.' This is what that means in practice. The OCM controllers don't replace Argo or Flux — they sit beside them and feed Resource CRs. Or you use OCM's own deployer."

**Anticipated question:** *"How does this work with our existing Argo CD / Flux setup?"*
→ Two patterns. (a) OCM Resource CR exposes the resource as a Flux-compatible manifest set; Flux deploys it. (b) OCM Deployer reconciles directly. Pick per team; both are first-class.

---

## Slide 12 — "Day-2 — subscribe, upgrade, drift, prune"

**Eyebrow:** DAY-2

**Title:** *What the controllers do once you stop watching.*

**Body:**
> - **Subscribe.** Component CR has an `interval` — every N minutes, the controller checks for a newer version in the repository. Bump the version field, the chain reconciles.
> - **Upgrade.** New Component Version available → re-fetch descriptor → signature verify → resource extract → deploy. All inside the cluster. *No upstream callback.*
> - **Drift.** Compute hash of deployed resources vs hash in descriptor. Re-apply on drift, on a separate interval.
> - **Prune.** Old resource versions are released when no Resource CR references them.
>
> All of it is policy-driven; verification, intervals, and substitutions are CR fields, not code.

**Diagram:** a closed loop arrow inside a sovereign zone (re-use slide 6 sovereign diagram primitive), labelled "subscribe / verify / deploy / verify drift / prune" around the loop.

**Speaker notes:** "Day-2 is where most other tooling falls apart in a sovereign zone — they expect upstream connectivity. OCM's controllers don't. Hand-wave fact: this is the part the conformance scenario actually exercises."

**Anticipated question:** *"What if the registry inside the sovereign zone goes down?"*
→ Controllers retry per their interval; existing deployments keep running (Resource CR is the source of truth, not the registry). Recovery is reading from the in-cluster registry once it's back. No external dependency.

---

## Slide 13 — "Plugins — extend OCM without forking it"

**Eyebrow:** EXTENSIBILITY

**Title:** *Plugins are processes. Plugins are negotiated. Plugins are versioned.*

**Body:**
> OCM has a plugin system: a separate executable that implements one or more capabilities (input handler, downloader, blob handler, transfer handler, value substitution, ...).
>
> Plugins are:
> - **Processes**, not in-process libraries. Multi-language. Swap-without-rebuild.
> - **Capability-negotiated** — OCM core asks "what do you do?", plugin lists capabilities, both sides version-check before use.
> - **Distributable as components** — the plugin itself can be packed as an OCM component and pulled across the same channel as the rest of your delivery.
>
> Use cases: custom storage backend (your enterprise blob store), domain-specific resource types, signature algorithms not in core, transfer policies for a regulated network.

**Diagram:** OCM core in the centre; three external boxes (each labelled "plugin: <capability>") connected via dashed arrows; one labelled-as-component plugin with a "delivered-as-OCM" badge.

**Speaker notes:** "If they're going to argue for OCM internally, the plugin question will come up. Land: yes you can extend it; no you don't fork; yes the plugin can ship as a component itself."

**Anticipated question:** *"How does versioning work between core and plugins?"*
→ Capability negotiation includes version. If a core asks for capability v2 and the plugin only implements v1, core falls back to v1 or refuses, per declared compatibility. Documented per capability.

---

## Slide 14 — "OCM vs cosign + SBOM"

**Eyebrow:** COMPARISON 1/4

**Title:** *Different layers. Composable.*

**Body (two-column):**

| | cosign + SBOM | OCM |
|---|---|---|
| What it signs | Individual OCI artifacts | The whole delivery (every artifact + every reference + the descriptor itself) |
| Scope | Per-image | Per-component |
| Cross-stack | OCI only | OCI · Helm · npm · S3 · CTF · ... |
| Identity | Registry-bound | Coordinates (location-independent) |
| Verifies-after-mirror | Yes (same registry path) | Yes (any registry, any access) |
| SBOM placement | Side-attached attestation | Resource inside the descriptor |
| Air-gap | DIY tooling | First-class CTF |

> **OCM doesn't replace cosign. It uses cosign keys (Sigstore) where you want, and signs the whole delivery descriptor at a level cosign can't reach.**

**Speaker notes:** "Lead with the truth: cosign is great for OCI. OCM extends signing to a delivery model. The composition story (cosign keys, OCM-level signature) is the punchline."

**Anticipated question:** *"Can we keep our cosign keys and use them with OCM?"*
→ Yes. Sigstore mode in OCM uses the same keyless flow / cosign keys. The OCM signature on the descriptor sits on top.

---

## Slide 15 — "OCM vs OCI Distribution alone"

**Eyebrow:** COMPARISON 2/4

**Title:** *OCI gives you a registry. OCM gives you a delivery.*

**Body:**
> OCI Distribution (the spec) gives you content-addressable storage for arbitrary blobs. With OCI Image Spec extensions, you can pack a Helm chart, an SBOM, a binary, etc.
>
> Things OCI alone doesn't give you:
> - A *named, versioned delivery* containing those artifacts as a unit.
> - Cross-registry identity. (Move blobs to another registry → new repo paths.)
> - One signature covering the whole delivery.
> - A transport format independent of the registry.
> - Composition: components-of-components.
>
> *OCM v2 components are themselves OCI artifacts.* `helm pull` works on a Helm resource inside an OCM component, directly. OCM v2 doesn't fight OCI — it's a higher-level model on top.

**Diagram:** two-layer cake. Bottom layer: OCI Distribution + OCI Image Spec (boxes labelled with media types). Top layer: OCM (Component Descriptor, Coordinates, Signature). Arrow: "OCM uses OCI as its primary repository type; OCM v2 components are OCI-native."

**Speaker notes:** "Honest framing: OCI is the substrate, OCM is the model. The audience came in suspecting redundancy; show the layering and the suspicion dissolves."

**Anticipated question:** *"Is there a non-OCI repository type?"*
→ Yes — CTF (filesystem / tar), S3, plugin-backed. OCI is the most common; others matter for air-gap and edge.

---

## Slide 16 — "OCM vs Argo / Flux / GitOps"

**Eyebrow:** COMPARISON 3/4

**Title:** *Different question. Different layer.*

**Body:**
> GitOps tools (Argo CD, FluxCD) answer: *given a manifest in git, how do I reconcile it into a cluster?*
>
> OCM answers: *what is the manifest, where do its artifacts come from, are they signed, where did they come from, how do I transport them across a boundary, how do I keep the chain of custody intact?*
>
> The two compose:
> - **Pattern A:** OCM Resource CR exposes a manifest set; Flux/Argo reconciles it. OCM is upstream of GitOps.
> - **Pattern B:** OCM Deployer reconciles directly. Skip GitOps entirely.
> - **Pattern C:** OCM ships the manifests *into* git, signed. GitOps reconciles from git as before; OCM is the producer, not the deployer.
>
> Pick per team. None of them require ripping out what you have.

**Diagram:** two parallel pipelines, OCM on the left ending at Resource CR / Manifest, GitOps on the right starting at git/manifest and ending at the cluster. Arrows showing the three composition patterns.

**Speaker notes:** "Don't pretend OCM replaces GitOps. The audience knows that's a lie. Show the three patterns; let them pick the one that matches their org chart."

**Anticipated question:** *"Pattern C — how does OCM 'ship into git' actually work?"*
→ A transfer target can be a git repository. The descriptor + extracted manifests are committed; the GitOps controller picks up the commit. Signatures are verifiable from the descriptor in the commit.

---

## Slide 17 — "Gotchas and edges"

**Eyebrow:** WHAT'S SHARP

**Title:** *Three honest edges. Plan around them.*

**Body:**

| Edge | What it means | Plan |
|---|---|---|
| **Sigstore is early-access in OCM v2.** | The signing flow works. Verification is evolving. Trust roots / TUF integration are open work. | Use RSA / GPG for production today; experiment with Sigstore in non-prod. |
| **Plugin distribution is conceptually elegant, operationally young.** | You can package plugins as components. The end-to-end story (sign-plugin → transfer-plugin → install-plugin) is documented but not yet "muscle-memory" for most adopters. | Start with built-in capabilities; reach for plugins when the gap is real. |
| **CRD churn during the v2 → v3 controllers transition.** | OCM v2 controllers are stable. The roadmap signals further consolidation. Some `*.ocm.software/v1alpha1` types may evolve. | Pin the controller version. Treat the CR shape as an internal contract for now. |

> Everything else — Pack, Sign, Transport, Deploy on the runtime side — is stable surface.

**Speaker notes:** "Names what's sharp. Practitioners pay attention to a deck that admits its edges. The audience that pushed back on slide 7 is now leaning in."

**Anticipated question:** *"How long is 'early access' likely to be 'early access'?"*
→ The TUF + trust-root work is on the SIG Spec roadmap; the project hasn't published a date. Watch the ADR repo and Zulip for milestone signals.

---

## Slide 18 — "The 30-minute PoC"

**Eyebrow:** SMALLEST USEFUL PROOF

**Title:** *Air-gap round-trip. Thirty minutes. One component.*

**Body:**

```bash
# 1. Pick a component you already ship. Pack it.
ocm add cv ./poc --component github.com/your-org/widget:v0.1.0 \
    --provider name=your-org --resources resources.yaml

# 2. Sign it with a throwaway RSA key.
ocm sign cv ./poc --signature poc-signing \
    --keyless false --rsa-key ./poc-key.pem

# 3. Pack into a CTF (the "USB stick").
ocm transfer cv ./poc ./widget-v0.1.0.ctf.tar

# 4. Carry the CTF to a separate machine / network.
scp widget-v0.1.0.ctf.tar airgap-host:/tmp/

# 5. Verify on the other side.
ssh airgap-host
ocm verify cv /tmp/widget-v0.1.0.ctf.tar --pubkey poc-key.pub
# OK: 1 component, 1 signature, every digest verified

# 6. Push into the destination registry.
ocm transfer cv /tmp/widget-v0.1.0.ctf.tar \
    registry.airgap.example.com//github.com/your-org/widget:v0.1.0
```

> **What you just proved:** identity travelled, signature survived transport, no upstream callback, no cosign-equivalent gymnastics, and the destination registry is now self-sufficient.
>
> **What's next:** wire the OCM controllers to the destination registry, deploy the resources, observe the day-2 loop. ~2 hours.

**Speaker notes:** "Hand them the script. The 'aha' moment is step 5 — verification of a sealed delivery on a network the source has never touched."

**Anticipated question:** *"What if our security team won't approve a throwaway RSA key?"*
→ Use your enterprise CA. Slide 8's RSA flow is the production path. Throwaway is for the PoC.

---

## Slide 19 — "Adoption ramp — week 1 to quarter 1"

**Eyebrow:** WHAT CHAMPIONING LOOKS LIKE

**Title:** *Twelve weeks to "OCM is how we ship one regulated component."*

**Body (calendar layout):**

| Week | What you do | What you have at the end |
|---|---|---|
| **1** | Run the 30-min PoC. Pack one production component. CTF round-trip. Verify. | Confidence + an internal demo. |
| **2** | Pick the component your security team has the most evidence-pain about. Re-pack it under OCM. Capture the SBoD. | One component shipping under OCM. |
| **3–4** | Wire the OCM controllers in a non-prod cluster. Deploy the component end-to-end. Drift, upgrade. | A live OCM-managed deployment. |
| **5–6** | Add a sovereign / air-gap target. Run the same component CTF round-trip into it. | Sovereign-region capability proven. |
| **7–8** | Add ODG / Compliance Dashboard against the same component. Wire to your DORA reporting. | Audit-evidence pipeline lit up. |
| **9–10** | Bring two more components under OCM. Refactor for shared `componentReferences`. | Composition story proven. |
| **11–12** | Expand controllers to one prod cluster. Document the runbook. Train the on-call. | Production OCM, one regulated component, end-to-end. |

> The path doesn't require a tooling rewrite. Each week's work is *additive*.

**Speaker notes:** "This is the slide your champion takes to their VP. Twelve weeks, no rip-and-replace, one production-shipped regulated component at the end."

**Anticipated question:** *"What if our team has no slack for week-1?"*
→ The PoC is a single afternoon. The champion runs it solo, brings the result to the next platform-team meeting. The calendar starts when leadership sees the demo.

---

## Slide 20 — "Where OCM is on the maturity curve"

**Eyebrow:** PRACTITIONER CANDOR

**Title:** *What's stable. What's evolving. What's open.*

**Body (three-column):**

| **Stable surfaces** | **Evolving surfaces** | **Open / future** |
|---|---|---|
| Component descriptor (v2 spec) | Sigstore signing | Trust-root / TUF integration |
| `ocm` CLI core commands (Pack / Sign / Transport / Verify) | OCM controllers (CRD shape stabilising) | New repository types beyond OCI/CTF/S3 |
| OCI / CTF / S3 repository types | Plugin distribution as components | DORA-metrics-as-resource type |
| RSA / GPG signing | Compliance Dashboard / ODG integration depth | Domain-specific media types |
| Conformance scenario (sovereign air-gap) | kro / Flux / Argo deployer adapters | |

> **Bet on the stable surfaces today. Watch the evolving ones. Volunteer on the open ones if you have the appetite.**

**Speaker notes:** "Don't oversell. The audience trusts a project that maps its own maturity. The 'volunteer' framing on the right column is also a SIG-membership call."

**Anticipated question:** *"How do you decide what's 'stable'?"*
→ Spec-frozen + conformance-tested + community-adoption-tested. The stable list is the surface the v2 announcement and conformance scenario both depend on.

---

## Slide 21 — "Governance"

**Eyebrow:** WHY YOUR BET DOESN'T DEPEND ON ONE VENDOR

**Title:** *Open standard. Neutral steward. Real governance.*

**Body:**
> **Stewardship.** OCM is governed by NeoNephos Foundation, hosted under Linux Foundation Europe. Neutral, audited, member-funded.
>
> **Working bodies.**
> - **TSC** — technical decisions of record.
> - **SIG Runtime** — controllers, CLI, daily mechanics.
> - **SIG Spec** *(forming)* — Component Descriptor evolution; v3 work.
>
> **Licensing trajectory.** Moving to **Community Specification License** in Q2 2026 — explicitly anti-vendor-lock. Apache-2 elsewhere.
>
> **Conformance.** Open-source conformance scenario in the monorepo, exercised on every release. The "trust travels" claim is testable, not just stated.
>
> **Cadence.** Public roadmap. Public Zulip. Public mailing lists. Member contributions land in the same repo as everything else.

**Diagram:** lightweight org chart — NeoNephos at top, TSC under it, two SIGs (Runtime / Spec) below. Side-bar with the licence trajectory.

**Speaker notes:** "This slide is a direct answer to the 'will OCM go HashiCorp' question every senior buyer asks. Land the Community Specification License — it's the strongest single anti-lock-in signal a project can give."

**Anticipated question:** *"Who's funding it? What happens if a key contributor steps back?"*
→ Multi-org TSC and SIG membership. Funding via NeoNephos members (SAP, BwI, others). Bus factor isn't 1; isn't 2.

---

## Slide 22 — "Build with us"

**Eyebrow:** CTA

**Title:** *Three doors. Pick one this week.*

**Body:**
> 🔧 **Build it** — `github.com/open-component-model` — clone, run the 30-min PoC, file the first issue.
>
> 💬 **Talk to us** — Zulip: `linuxfoundation.zulipchat.com / open-component-model`. Mailing list: `lists.neonephos.org`.
>
> 📦 **Ship with us** — `ocm.software/adopters` — register your team's adoption; you get reviewer time on your conformance run, public visibility in the next adopters update, and direct line to SIG Runtime.
>
> *Bonus: the conformance scenario is in the monorepo. Run it before your audit cycle, share results, build credibility with your own security team.*

**Side panel — "What success looks like 90 days from now":**
> One regulated component, packed under OCM, signed with your enterprise CA, deployed via OCM controllers into one production cluster, with the OCM Compliance Dashboard wired to your existing DORA reporting.

**Speaker notes:** "End decisive. Three doors, one ask: pick *one* this week. The 'success-in-90-days' panel is what they email their VP after the meeting."

**Anticipated question:** *"What if our org wants commercial support?"*
→ Several NeoNephos members offer it; SAP NS2 and partners specifically for regulated/public-sector. Direct intro available via SIG Runtime.

---

## Open questions for the project owner

Carried over from the outline:

1. Are we comfortable with **slide 17 (gotchas)** in print? Recommend yes — it's the credibility lever.
2. **Slide 20 maturity:** name "Sigstore: early access" explicitly, or group? Recommend explicit.
3. **Slide 18 PoC:** I picked air-gap CTF round-trip as smallest-useful. Alternative: Helm-via-controllers. Pick one for the canonical deck.
4. **Slide 14 vs 15 ordering:** lead with cosign+SBOM (current), or with OCI? Defaulting to cosign+SBOM as the more common conflation.
5. **Speaker notes vs slide notes:** the "what to say" lines above can either go on the slide as small-print or as PowerPoint speaker notes. Recommend speaker notes — keeps slides clean.
6. **Code snippets on-slide vs in-handout:** I default to on-slide for the technical deck. Alternative: snippets as a separate handout. Recommend on-slide.
7. **Sigstore / cosign nomenclature:** I use both. Some audiences treat them as synonyms; others not. Worth deciding house style.

*Generated 2026-06-16. Companion to `TECHNICAL-DECK-OUTLINE.md`. Ready for review.*
