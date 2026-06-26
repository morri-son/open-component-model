# Phase 2a Architect Deck — Session 1 Handoff

**Written:** 2026-06-22, end of grilling session
**Worktree:** `marketing/deck`
**Supersedes nothing.** Companion to `HANDOFF-PHASE2-ARCHITECT.md` (the prior handoff, still valid as context).

This document captures every decision locked during the grill-me session that kicked off Phase 2a. Read this before drafting any further architect-deck slides, and read `HANDOFF-PHASE2-ARCHITECT.md` for the bigger-picture Phase-1 lessons that still apply.

---

## State at end of session

- **Six trunk slides committed in full text** (1 through 6). Slide 6 added in extended grilling after initial handoff write.
- **Trunk sequence agreed** for all 14 slides.
- **Hidden-slide strategy agreed** — warm-ups (W1/W2/W3) and α-alternates parked in the `.pptx` for team review.
- **No `.pptx` built yet.** User builds slides 1–6 in PowerPoint, then iterates via screenshots in the next session — Phase-1 working pattern.
- **Slides 7 through 14 are NOT drafted.** Sequence-and-purpose agreed; text TBD next session. Slide 13 (ADOPTION) sketched in this doc but not formally locked.

---

## Decisions locked

### Audience model

| Decision | Lock |
|---|---|
| **Two forked decks** — external + internal architect | ✓ |
| ~70% shared trunk, ~30% audience-specific framing | ✓ |
| **No v1/v2 distinction.** OCM is OCM. Don't mention v2, don't mention v1-as-legacy. Treat the current implementation as "the OCM". | ✓ |
| **External deck audience prior**: design for (b) leaning (a) — has heard of OCM, may have read website overview, no working mental model yet | ✓ |
| **Internal deck audience prior**: design for (c) leaning (b) — has seen sponsor deck, possibly peer-LoB usage, wants contrast and trade-offs | ✓ |

### Format & shape

| Decision | Lock |
|---|---|
| **14 trunk slides** per deck (default delivery) | ✓ |
| **Dual-purpose, talk-biased** — clean deck for presenting; full prose in speaker notes; deep-dive readers go to the website | ✓ |
| Target talk length: ~30 min default; ~35 min with warm-ups unhidden | ✓ |
| **No YAML walls** on slides except slides 7/8 (constructor + descriptor) | ✓ |
| **No CLI snippets on slides** — CLI lives in speaker notes only | ✓ |
| **Speaker notes carry the prose**, pointing to specific website pages for deep dives | ✓ |

### Hidden slide strategy

**External deck:**
- **W1 — Refresher** ("what OCM is, in 60 seconds"). Placed between hero and diagnosis. Reuses exec-deck hub-and-spoke diagram. Speaker unhides for (a)/(b)-prior rooms.
- **W2 — Eight words of deck vocabulary**. Placed before slide 3 (the hinge). For audiences with terminology but no mental model.
- **W3 — From SBOM to SBoD**. Placed before slide 5. For external architects who haven't seen the exec deck.

**Internal deck:**
- **W1 only** — same refresher. Internal architects know SBoD; W2 and W3 not needed.

**Placement rules:**
1. Hidden slides go **immediately before** the trunk slide they support, not in a back-appendix. Speaker right-clicks → "Show Slide" → it appears in sequence.
2. Each hidden slide must work as a standalone insert (no inter-hidden-slide dependencies).
3. The default un-hidden deck must read coherently without any of them.

**α-alternate slides** (rejected-but-not-killed variants from grilling) live as additional hidden slides for team review. Cut to one per audience or move to a clearly-labelled appendix before the live talk. **Do NOT carry multiple competing variants into a real presentation** — Phase 1's three-SBOD-diagram trap.

### Comparators / positioning

The "comparator block" terminology was retired during grilling. The honest framing is **positioning slides**, not comparator slides.

| Decision | Lock |
|---|---|
| **"OCM vs cosign + SBOM" slide deleted.** Cosign is one signing backend on a menu with RSA and PEM. SBOM is a resource type inside OCM. Neither is a competitor. | ✓ |
| **"OCM vs OCI Distribution alone" reframed as positioning slide.** OCM is built on OCI. The slide is about *where OCM sits* relative to artifact tools — not a vs-comparison. | ✓ |
| **"OCM and GitOps" stays as positioning slide.** Three composition patterns (not a vs-framing). | ✓ |
| **"Signing backends" (RSA · PEM · Sigstore-early-access) becomes a mechanics slide**, not a comparator. | ✓ |
| **SBOM handling detail** (resource vs label) lives in slide-8 (descriptor) speaker notes, not on a slide. | ✓ |
| **OCI-as-primary-impl detail** (component descriptors ARE OCI artifacts; `helm pull` works on charts inside OCM components directly) lives in slide-5 speaker notes, not on the slide. | ✓ |

### Slides cut entirely from the trunk

- Plugin-system slide → appendix only
- "Eight words to learn" glossary slide → hidden warm-up W2 only
- "OCM vs cosign+SBOM" comparator → deleted as fake comparator
- Live demo slot → never on slide; PoC is the demo replacement
- Component descriptor full YAML wall on one slide → split into slides 7/8

---

## Trunk sequence (variant β — locked)

| # | Eyebrow | Title | Purpose |
|---|---|---|---|
| 1 | (hero) | *You ship pieces. / Nothing carries the release.* | Pain hook the architect recognises. |
| 2 | DIAGNOSIS | *In every existing tool, identity is bound to location.* | Name the root cause. |
| 3 | THE HINGE | *Identity that travels with the artifact.* | Architectural insight. 90 seconds. |
| 4 | OCM IN ONE PICTURE | *Pack · Sign · Transport · Deploy.* | Reuse exec-deck diagram, no rework. |
| 5 | WHERE OCM SITS | *One wrapper. All artifacts. Signed once.* | Positioning slide — three columns ARTIFACT FORMATS / LOCATION / TRUST. |
| 6 | COMPOSITION + DAY 2 | *One product. Three components. One line to upgrade.* | Multi-component product + day-2 reconciliation, anchored in the `conformance/scenarios/sovereign` story. Replaces the earlier "GitOps positioning" slot. |
| 7 | CONSTRUCTOR | *What you write.* | YAML, input. Real ground-truth from `getting-started/create-component-version.md`. |
| 8 | DESCRIPTOR | *What gets signed and travels.* | YAML, output. Digest vs access callouts. |
| 9 | SIGN | *One signature shape. Three trust models.* | RSA · PEM · Sigstore (Sigstore flagged early-access). |
| 10 | TRANSPORT | *Three patterns, one command.* | Registry · CTF · air-gap. The "signature survives transport" payoff lands here. |
| 11 | DEPLOY | *Repository → Component → Resource → Deployer.* | 4-CR controller chain. Day-2 lives on slide 6, not here. One sentence on Argo-CD-as-UI in speaker notes. |
| 12 | WHAT'S SHARP | *Three honest edges.* | Candor: Sigstore early-access, CRD shape stabilising, controllers raw-manifests-only. |
| 13 | ADOPTION | *Two paths to a first OCM component in production.* | Two columns: FROM ZERO (CTF round-trip) / ON YOUR EXISTING PLATFORM (OpenControlPlane service-provider). Slide-text sketched but not formally locked — finalise next session. |
| 14 | CTA | *Build with us.* | Three doors. |

Variant α (comparators-late, mechanics-heavy) is parked as hidden alternate slides in the same `.pptx` for team review. Variant γ (confession-led two-half structure) shelved.

**The "GitOps positioning slide" originally slated for slide 6 was retired in extended grilling.** GitOps tools (Argo CD, Flux) compose with OCM at the Deployer tier — they're not parallel architectures, so a positioning slide implied a comparison that doesn't exist. The architect's real Argo-CD question is *"can my team keep its UI?"* — answered in one speaker-notes sentence on slide 11 (DEPLOY), not on a slide.

---

## Full slide text for slides 1–5

### Slide 1 — HERO (Hero-E-v2)

**Layout:** `Hero` — full-bleed banner, brand row at footer.

**Title line 1 (white, 115pt):**
> You ship pieces.

**Title line 2 (gradient noun, 115pt):**
> Nothing carries the release.

**Subtitle (cyan):**
> Identity stops at the artifact. So does everything you do with it.

**Footer (white):**
> Open Component Model — open source, NeoNephos Foundation.

**Brand row:** OCM logo left, NeoNephos logo right (same as exec deck).

**Speaker notes (30–45 sec):**
> "Every architect in this room has been here. The image is in some registry; the chart is in another; the SBOM is a file in CI; three signing tools that don't talk to each other. Each piece works. The release as a whole — has no name that travels, no signature that survives transport, no identity that crosses a boundary. Today I want to spend thirty minutes on what we built so that changes. It's called the Open Component Model. Open source, governed by NeoNephos. We're not selling it; we're showing you what it does."

**Build-script note:** Line 2 at 28 chars may need 105pt drop from the Phase-1 default 115pt — verify in PowerPoint before locking. The `.potx` Hero layout supports per-deck overrides.

**α-alternate (hidden):** Hero-I — *Pieces ship. / The release doesn't.* with subtitle *"Every team already ships. The release as one signed, transferable thing — doesn't exist yet."* (Internal version: swap "team" → "LoB".)

---

### Slide 2 — DIAGNOSIS (Variant 2.A)

**Layout:** `Plain` or `Plain / Compact` — eyebrow + title + body bullets + small subtitle below body.

**Eyebrow:**
> DIAGNOSIS

**Title:**
> In every existing tool, identity is bound to location.

**Body (three blue-bullets, anchor + half-sentence format):**
- **Container** — its registry path. Move the registry, the reference changes.
- **Chart** — its repo URL. Mirror the repo, the chart's identity changes.
- **SBOM** — the file in CI. Archive it, the chain breaks.

**Subtitle (small, below body):**
> You can't sign a delivery once and have it survive transit — there is no "delivery" identity to sign.

**Speaker notes (~60 sec):**
> "Take any of these. The container is its registry path — `ghcr.io/acme/widget:v1.4.2`. Move the container to a different registry and the reference changes. The Helm chart is its repo URL — mirror the repo, same problem. The SBOM is a file produced in CI — archive the file, the chain to the artifact it described breaks. Compliance retrofits don't fix this. They paper over it. The root cause is upstream of every tool: there is no name for the release itself, only for the artifacts at their current locations. Sign a 'release'? You can't — there's nothing to sign."

**α-alternate (hidden):** Variant 2.B — title *"Why doesn't this already work?"*, body uses repeated *"X — Strip Y, it breaks."* cadence with subtitle *"Identity is bound to location. Every existing tool. That's the missing layer."*

---

### Slide 3 — THE HINGE (Variant 3.A)

**Layout:** `Plain` with the body split into two halves — text bullets on the left, small inline diagram on the right. May require a custom 2-column body geometry; or use `Content / 2-Column` if available in the master.

**Eyebrow:**
> THE HINGE

**Title:**
> Identity that travels with the artifact.

**Body — left half (three blue-bullets):**
- **Coordinates** — a component has a name (`github.com/acme/widget`) and a version (`v1.4.2`). Globally unique. Location-agnostic.
- **Digest** — every resource inside the component carries a content hash. Computed once.
- **Access** — where the resource currently lives. Rewritten on transfer. *Digest stays.*

**Body — right half (small inline diagram):**
A coordinate chip showing `github.com/acme/widget:v1.4.2` at top; the same chip shown unchanged at three small registry cylinders below; arrows between the registries indicating transit. The chip is identical at every position — that's the visual point.

**Subtitle (small, below body):**
> Move the artifact; the digest stays; only the access changes. That's the trick.

**Speaker notes (~90 sec):**
> "Three things to understand and the rest of the deck is downhill. First — coordinates. A component has a name and a version. The name is a DNS path you own; the version is SemVer. Together they identify the component, globally, without referencing any registry. Coordinates don't move. Second — digest. Every resource inside the component carries a SHA-256 of its content, computed at packaging time. The digest is what gets signed. Third — access. Every resource also carries an access field, telling you where it currently lives. When you transfer a component from one registry to another, the access field gets rewritten. The digest doesn't. The signature still verifies. Anywhere. That's the architectural primitive everything else hangs off of. Spend a moment with it."

**α-alternate (hidden):** Variant 3.B — title *"Identity is not location. They're two fields."*, body just two bullets (`digest:` and `access:`), subtitle *"The signature covers the digest. Move the artifact. The signature still verifies."*

**Diagram source asset:** New SVG required. Filename suggestion: `diagrams/architect/03-coordinates-travel.svg`. Should match the visual language of the Phase-1 hub-and-spoke (clean, minimal, brand palette).

---

### Slide 4 — OCM IN ONE PICTURE (diagram reuse)

**Layout:** `Content / Diagram` — exec-deck reuse.

**Eyebrow:**
> OCM IN ONE PICTURE

**Title:**
> Pack · Sign · Transport · Deploy

**Diagram:** Reuse the exec-deck `diagrams/05-pack-sign-transport-deploy-v2.svg` (or `-v1` if v2 is not present). No rework.

**Speaker notes (~75 sec):**
> "The whole flow on one slide. Four verbs. Pack — bundle every artifact your component needs into one named, versioned unit. Sign — one signature covers every artifact's digest. Transport — move the unit across registry boundaries, into a CTF for air-gap delivery, into a sovereign cloud. The signature survives because, as we saw on the hinge slide, what's signed is the digest, not the access. Deploy — at the destination, verify the signature, unpack, deploy via the OCM controllers or feed your existing GitOps. We'll spend the next handful of slides on each verb."

---

### Slide 5 — WHERE OCM SITS (Option 1A)

**Layout:** `Content / 3-Column` — same layout as exec slide 5.

**Eyebrow:**
> WHERE OCM SITS

**Title:**
> One wrapper. All artifacts. Signed once.

**Body (three columns, ALL CAPS anchor + 3 lines of text per column):**

```
ARTIFACT FORMATS          LOCATION                    TRUST
You keep yours.           Identity travels.           One signature.
Helm, OCI, SBOM, npm —    The component carries       Covers every digest.
every kind is a resource. its name across registries. Survives transport.
```

**Subtitle (small, below columns):**
> Architects came in with three tools. They leave with one unit.

**Speaker notes (~75 sec):**
> "Three things to land. First — every artifact format you already use stays exactly as it is. Container images stay images. Helm charts stay charts. SBOMs stay SPDX or CycloneDX. Binaries, config files, npm packages — every kind becomes a resource in an OCM component. Second — identity. The component has a name and version that don't depend on where it's stored. Move it across registries; the name doesn't change. Third — trust. One signature covers every resource's digest. Transfer the component; the signature still verifies, at the destination, without round-tripping to source. That's the wrapper. One around all of them."
>
> *Footnote for Q&A:* "One implementation detail worth knowing — OCM components are themselves OCI artifacts, so your existing OCI registry holds them with no extensions. Helm charts inside an OCM component are still standard OCI Helm artifacts; `helm pull` works on them directly. That's a property of the current implementation, not the architectural model — but it's the property that matters in your registry team's review meeting."

**α-alternate (hidden):** Option 1B — single-column stop-sentence stack:
- **One unit** — a named, versioned set of artifacts. Container, chart, SBOM, binary — any format.
- **One identity** — the name travels with the unit. Move it across registries; the name doesn't change.
- **One signature** — covers every resource's digest. Verifies anywhere, after any transfer.

Subtitle: *Your tools stay. The thing you sign and ship changes.*

---

### Slide 6 — COMPOSITION + DAY 2 (Option A)

**Layout:** custom 2-column body — composition tree on the left, YAML callout on the right. The `Content / 2-Column` layout in `OCM-Master.potx` likely covers this; otherwise it's a custom layout cousin of slide 3's text-plus-inline-diagram split.

**Eyebrow:**
> COMPOSITION + DAY 2

**Title:**
> One product. Three components. One line to upgrade.

**Body — left half (composition tree, monospace, brand-blue parent + grey children):**

```
acme.org/sovereign/product:1.0.0
  ├── acme.org/sovereign/notes:1.0.0
  └── acme.org/sovereign/postgres:1.0.0
```

Small icons next to each child (web-app glyph for notes, database glyph for postgres). Parent node highlighted.

**Body — right half (day-2 patch, YAML monospace at ~22pt):**

```yaml
spec:
  version: 1.1.0   # was: 1.0.0
```

Small caption underneath the YAML, light grey, ~14pt:
> *OCM Controller pulls 1.1.0 · Resource CRs resolve new digests · notes rolls forward · schema migration runs.*

**Subtitle (small, below both halves):**
> Composition is a first-class primitive. Upgrade is one line.

**Speaker notes (~90 sec):**
> "Two architectural points on one slide. First — composition. A product component references other components. Our conformance scenario models a real two-service product — a notes app and a Postgres database — as one parent component called `acme.org/sovereign/product`. That parent doesn't contain copies of the children; it references them by coordinates. The descriptor names `notes:1.0.0` and `postgres:1.0.0` as references, and when the product is signed, the digests of those references are part of what's covered by the signature. Composition with integrity.
>
> Second — day 2. The operator changes one field — `spec.version` from `1.0.0` to `1.1.0`. The OCM Controller sees the change, pulls the new descriptor, verifies the signature, the Resource CRs resolve to the new image digests, Flux sees them, the notes pods roll forward. The 1.1.0 release of notes adds a `title` field to the Note schema — that's a real database migration — it rides along because the migration logic was packaged into the new image. None of this involves a call back to the source environment. The cluster has the new component because the new descriptor was pulled from the local registry; everything else is reconciliation.
>
> This is what the conformance test runs on every release. It's not a slide. It's a passing test."

**Source for this slide:** `conformance/scenarios/sovereign/` in the repo. Specifically:
- `components/product/component-constructor.yaml` — the `componentReferences` to notes + postgres
- `deploy/sample-product-1.0.0.yaml` and `deploy/sample-product-1.1.0.yaml` — the day-1 and day-2 CRs (single `spec.version` diff)
- `components/notes/cmd/sovereign-notes/main.go` and `sovereign-notes-v1/main.go` — the v1 vs v2 source showing the schema delta (added `title` field)
- `README.md` and `USAGE.md` — the phase-1 (bootstrap) / phase-2 (self-management) narrative

**Out-of-scope for this slide (kept for Q&A only):**
- kro / ResourceGraphDefinition mechanics — the slide mentions reconciliation without naming kro on the slide. Speaker explains if asked.
- ORD metadata bundled in the notes component — a conformance-test concern, not architect-pitch material.
- ESO / Sealed Secrets — the conformance scenario's postgres password is demo-only; production guidance is "use ESO or similar". Speaker mentions if a security architect asks.
- Flux specifically — Flux is the conformance scenario's chosen deployer; the deck's stance on deployers is that they're pluggable. Speaker says "Flux in the conformance scenario; your team picks the deployer" if asked.

**α-alternate (hidden):** Option B — story-led two-column day-1/day-2:

```
DAY 1 — SHIP                          DAY 2 — RECONCILE
Sign a product that references        Bump the product version.
notes 1.0.0 and postgres 1.0.0.       Notes 1.0.0 → 1.1.0.
Air-gap transfer. Verify.             OCM pulls. Flux rolls. No callback.
Apply one bootstrap. Kro takes over.  Schema migration rides along.
```

Subtitle: *Composition is the unit. Reconciliation is the operation.*

---

## Hidden warm-up slides — drafted but TBD on details

These need final text drafting but the *purpose and placement* is locked.

### W1 — Refresher ("what OCM is, in 60 seconds")

- **Placement:** between slide 1 (hero) and slide 2 (diagnosis), in BOTH external and internal decks.
- **Content:** reuse the exec-deck hub-and-spoke diagram from `diagrams/03-meet-ocm-hub-and-spoke.svg`. Title: *"Meet OCM."* Subtitle: *"One identity, every boundary."* Exact same as exec slide 3.
- **Speaker use:** speaker unhides if the room hasn't seen the exec deck or doesn't know what OCM is.
- **Text:** lift verbatim from exec deck slide 3 — no rework.

### W2 — Eight words of vocabulary (external only)

- **Placement:** before slide 3 (the hinge).
- **Content:** an architect-vocabulary table — Component, Component Version, Component Descriptor, Resource, Source, Reference, Coordinates, Digest. One-line definition per term.
- **Source:** mirror the technical-deck-content.md slide-4 table (already drafted there). Verify each term against `website/content/docs/concepts/component-identity.md`.
- **Text:** TBD next session.

### W3 — From SBOM to SBoD (external only)

- **Placement:** before slide 5.
- **Content:** essentially the exec-deck slides 4a + 4b condensed to one slide. SBOD-contains-SBOM diagram + a one-sentence claim. *"The SBOM is one resource inside the SBoD. OCM doesn't replace your SBOM tooling — it gives the SBOM an envelope."*
- **Source:** lift from exec deck slides 4a/4b speaker notes.
- **Text:** TBD next session.

---

## Open questions for the next session

Carried over from grilling — items that came up but weren't resolved because slides 6+ weren't drafted.

### Slide 6 — COMPOSITION + DAY 2 (LOCKED — see full text above)

Slide 6 was originally slated as a GitOps positioning slide. **Retired in extended grilling.** Replaced with COMPOSITION + DAY 2, anchored in the `conformance/scenarios/sovereign/` story (product → notes + postgres; day-1 to day-2 via `spec.version` patch). Full text is locked above in the slides-1-6 section.

### Slide 7/8 — YAML constructor + descriptor

- Constructor YAML (slide 7): use the 18-line version verbatim from `getting-started/create-component-version.md` lines 73–92.
- Descriptor YAML (slide 8): trim the 24-line version to ~22 lines by dropping `relation:` and `meta:` fields; add a small signature block (truncate `value:` to `<256-byte signature>` placeholder, NOT a hex value).
- **Visual:** monospace font, 18–20pt, right-side callout labels pointing at `input:` / `access:` (slide 7) and `digest:` / `access:` (slide 8).
- Real names: `github.com/acme.org/helloworld`, `1.0.0`, `acme.org`. Two resources (`mylocalfile` blob + `image` ociImage). Keep the example trivial; the architect's attention is on the *shape*, not the contents.

### Slide 9 — SIGN

- Three trust models: **RSA · PEM (early access) · Sigstore (early access)**.
- Phase-1 two-line column format works here.
- Open: does the slide name the early-access flags inline, or fold them into slide 12 (WHAT'S SHARP)? Recommend inline on slide 9 (each early-access flag next to its name) AND restated on slide 12 (the candor slide). Slight duplication is the right honesty.

### Slide 10 — TRANSPORT

- Three patterns: **Registry → Registry · Registry → CTF · CTF → Registry (air-gap import)**.
- This is the slide where the "signature survives transport" payoff lands. The architectural insight from slide 3 (digest stays, access changes) gets demonstrated by example.
- Speaker notes carry the three `ocm transfer cv` CLI commands; slide shows just the three patterns as titles + one-line descriptions.

### Slide 11 — DEPLOY

- Repository → Component → Resource → Deployer CR chain.
- **Day-2 ops moved off this slide entirely.** Day-2 lives on slide 6 (COMPOSITION + DAY 2), where the conformance-scenario story makes it concrete. Slide 11 references slide 6 in one sentence: *"as we saw on slide 6, day-2 is a one-line edit."*
- **Argo-CD-as-UI sentence** in speaker notes: *"If your platform team already runs Argo CD for the dashboard, point Argo at the Resource CRs OCM produced — your team gets the deploy in the UI they're used to. The reconciliation can be OCM's built-in deployer, Flux, or Argo itself. Argo, Flux, and OCM's deployer are all consumers of the same Resource CR."* This deflects the most-common Argo question without burning a slide.
- Open: does the slide use a diagram (the 4-CR stack) or text? Recommend diagram — architects retain a 4-box stack better than four bullets.

### Slide 12 — WHAT'S SHARP

Three honest edges named explicitly:
- **Sigstore signing — early access.** Interface may evolve.
- **PEM signature encoding — early access.** Interface may evolve.
- **Controllers apply raw manifests only.** Helm rendering and Kustomize overlays must happen at component-build time, not deploy time.

Open: include a fourth edge ("CRD shape stabilising") or leave at three? Recommend three — Phase-1 discipline says three is the magic number for this kind of list.

### Slide 13 — ADOPTION (sketched, not locked — finalise next session)

**Two paths, not one.** Slide 13 reframed from single CTF-round-trip CTA to a two-column "meet you where you are" slide.

- **Eyebrow:** ADOPTION
- **Title:** *Two paths to a first OCM component in production.*
- **Body (two columns, exec-deck two-line column shape):**

  ```
  FROM ZERO                              ON YOUR EXISTING PLATFORM
  Pack one component. Sign it.           Install OCM as a service.
  Air-gap CTF round-trip.                One openMCP resource.
  Verify on the other side.              Tenant clusters get the toolkit.
  Thirty minutes. One afternoon.         No HelmRelease wiring.
  ```

- **Subtitle (small):** *Pick the path. The conformance scenario tests both on every release.*
- **Speaker (~60 sec):**
  > *"Two ways the project is actually adopted. Path one — start from zero. Pick one component you already ship. Pack it, sign it, transfer it as a CTF tar file, verify on the other side. Thirty minutes of an architect's afternoon and you've proven the supply-chain story in your own environment. Path two — if you already run OpenControlPlane as your control plane, OCM ships as a service-provider in openMCP. Your platform team installs the OCM K8s Toolkit on tenant clusters with one openMCP resource. No HelmRelease per cluster. No bespoke wiring. Both paths are in the conformance scenario; both run on every release."*

**Source for the second path:** `https://github.com/open-component-model/service-provider-ocm` (v0.2.0, June 2026). README: *"An openMCP Service Provider that installs and manages OCM K8s Toolkit on workload clusters via Flux HelmReleases."* User population: platform teams running multi-tenant clusters with openMCP already.

**Open** when this slide is formally drafted:
- Should the two-column layout be the standard `Content / 2-Column` or a tweaked variant? Phase-1 didn't use this layout heavily — verify the master supports it cleanly.
- The CTF script lifted from `TECHNICAL-DECK-CONTENT.md` slide 18 lives in speaker notes, not on the slide.
- For internal-architect deck — is the second path's openMCP framing replaced by an SAP-internal control-plane reference (e.g., Hyperspace integration)? Probably yes — confirm with user. External keeps openMCP; internal swaps the second column's example.

### Slide 14 — CTA

- Three doors: **Try it · Build with us · Talk to us.**
- Same shape as exec deck slide 13.
- Open: does the internal architect deck have a different CTA (closer to the sponsor deck's "Sponsor · Scale · Standardize")? Probably yes — internal architects are evaluating migration paths, not adoption. TBD when the internal deck is drafted.

### Internal-deck-specific decisions deferred

- Hero variant for internal — Hero-I with "Every LoB already ships" subtitle was discussed but not locked. Confirm next session.
- Slide 5 columns may need an internal-tuned variant (e.g., the LOCATION column could reference cross-LoB transport explicitly).
- The "What's sharp" candor on slide 12 may need an internal-shaped twist (e.g., specific known issues in the SAP-internal rollout that external audiences shouldn't see).

---

## Working method confirmed

1. **Two forked decks built independently** — don't try to maintain a single source-of-truth that generates both. Phase 1 used two separate `build_pptx.py` scripts; same pattern here.
2. **Multi-variant drafting up front for contested slides.** Variants live as hidden slides in the `.pptx` during team review. Cut to one per audience BEFORE the live talk.
3. **Hidden slide use cases:**
   - α-alternates (rejected-but-not-killed variants)
   - Audience warm-ups (W1/W2/W3)
   - Trademark notices (Phase-1 pattern, no change)
4. **No automated generation of variant decks.** A single `.pptx` per audience holds all the variants; the speaker controls which slides show.
5. **PowerPoint is the source of truth from this point forward.** Build scripts mirror the live `.pptx`, not the other way around. Phase 1 settled on this; Phase 2a inherits.
6. **No commits, no pushes, no PR.** User does this themselves at session boundaries.

---

## File layout for slides 1–5 build

```
docs/community/marketing/decks/architect-phase2a/
  OCM-Sovereign-Delivery-Architect-External.pptx     # ← create when starting build
  OCM-Sovereign-Delivery-Architect-Internal.pptx     # ← create when internal deck starts
  (reuse) OCM-Master.potx                            # symlink to exec-phase1/ OR copy
  build-pptx/
    build_pptx_architect_external.py                 # mirror exec-phase1/build_pptx.py shape
    build_pptx_architect_internal.py                 # mirror exec-phase1/build_pptx_internal_sponsor.py shape
  notes/
    SPEAKER-NOTES-ARCHITECT-EXTERNAL.md              # extensive prose, matches Phase-1 style
    SPEAKER-NOTES-ARCHITECT-INTERNAL.md
  diagrams/
    (reuse from exec-phase1/) hub-and-spoke, pack-sign-transport-deploy, sovereign-airgap
    architect/
      03-coordinates-travel.svg                       # NEW — slide 3 inline diagram
      07-input-vs-access.svg                          # NEW — slide 7 callout pointers (optional)
      08-digest-vs-access.svg                         # NEW — slide 8 callout pointers (optional)
```

The diagrams that are NEW for the architect deck are minimal — slide 3 is the only one that needs real visual work. Slides 7/8 callouts may be doable as PowerPoint shapes drawn on top of YAML text rather than separate SVGs.

---

## Definition of done — session 1

- ✅ Slide sequence agreed (14 trunk + 3 hidden warm-ups external / 1 hidden warm-up internal + α-alternates)
- ✅ Full text drafts for slides 1, 2, 3, 4, 5, **6** (hero / diagnosis / hinge / in-one-picture / where-ocm-sits / composition+day-2)
- ✅ Slide 13 (ADOPTION) sketched with two-paths framing and OpenControlPlane integration; not yet formally locked
- ✅ Open questions flagged for slides 7 through 14 (this document)
- ✅ Argo-CD-as-UI sentence captured for slide 11 speaker notes
- ✅ No `.pptx` built — user handles next

## Definition of done — session 2 (proposed)

Either path is fine; user picks:

**Path A — Continue text-first:**
- Draft slides 7, 8, 9, 10 in full text
- Slides 7/8 are mostly mechanical given the YAML is already chosen
- Slide 10 (TRANSPORT) where the "signature survives transport" payoff lands
- Finalise slide 13 (currently sketched, not locked)

**Path B — Build-and-iterate:**
- User builds slides 1–6 in PowerPoint
- Sends screenshots for review
- Iterate on visual rhythm before drafting more text — Phase-1 working pattern

Phase 1 used Path B. Recommend the same.

---

**End of session 1 handoff.**
