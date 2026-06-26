# OCM Community Deck — Option A: "The Day a CVE Drops" (v0.4)

**Status:** v0.4 — restructure aligned with architect deck's slide-8-becomes-Compose decision, ODG mechanism corrected to ADR-0016 (Referrers API, `software.ocm.*` namespace), hero gradient locked whole-line, 2am redo as cards.
**Audience:** Engineers — DevOps, SRE, platform, GitOps practitioners.
**Slot:** ~30 min, talk-biased. **13 slides.** Hero + 11 beats + signature close + Q&A backdrop.
**Master narrative this is cut from:** [../../narratives/NARRATIVE.md](../../narratives/NARRATIVE.md).
**Architect deck this borrows patterns from:** `../architect-phase2a/build-pptx/build_pptx_architect_external.py`.

---

## v0.4 changes from v0.3

**Structural** (aligned with architect deck restructure):
- **NEW slide 8 — Compose.** A product is a tree: product component → notes + postgres (leaf components). Defines the noun *"product component"* visually before slide 9 says *"bump the product."*
- **Bump (slide 9, was 8)** now does ONE job: the Day-2 upgrade mechanic. The composition tree moves to slide 8 (Compose); slide 9 keeps the YAML diff + kro/OCM/Flux cascade.
- Renumbered downstream: ODG → 10, 2am redo → 11, close → 12, adopt → 13.

**Slide 1 hero — whole-line gradient.**
- Single-line title with gradient applied to the whole *"It's 2am. A CVE drops."* string. No split prefix/noun.
- Mirror architect Hero's two-line pattern flattened to one.

**Slide 10 ODG mechanism (was wrong in v0.3).** Per ADR-0016 *"OCI Ownership Annotations & Referrers Manifest"*:
- The image manifest is **unchanged** — annotations do not get baked into the image.
- OCM publishes a **separate ownership-referrer manifest** alongside, `artifactType: application/vnd.ocm.software.ownership.v1+json`, whose `subject` field points at the image's digest.
- That referrer's annotations carry the OCM coordinates: `software.ocm.component.name`, `software.ocm.component.version`, `software.ocm.artifact`.
- ODG (or any tool) discovers it via the OCI Referrers API — concretely `oras discover <image>@<digest> --artifact-type application/vnd.ocm.software.ownership.v1+json`.
- The **slide design is side-by-side** (scanner-output | ODG-discovery), using the **same `eu.gcr.io/acme/notes@sha256:70a2577d…` digest on both sides** so the eye traces the join.
- Old `cloud.gardener/ocm-*` keys are obsolete; v0.3 used them — corrected.

**Slide 11 — 2am redo as cards** (was numbered list). Four stacked cards with arrows, mirroring architect slide 11 (Deploy) visual structure for continuity. Each card holds one role: scanner → ODG → dashboard → action. The digest from slide 10 propagates through the cards.

---

## Story arc — 13 slides

```
 1. HERO          It's 2am. A CVE drops.                          (bookend ↘ gradient)
 2. PAIN          Your release isn't a thing. It's a scavenger hunt.
 3. NO NAME       The release has no name.                        (delayed beat)
 4. PACK          Pack.                          [constructor YAML]
 5. SIGN          What gets signed and travels.  [descriptor YAML]
 6. TRAVELS       Travels.                       [3 transport patterns]
 7. DEPLOY        Apply once. The controllers take over.
 8. COMPOSE       A product is a tree.           [product → notes + postgres]
 9. BUMP          Bump the product. Everything follows.  [Day-2 YAML diff + cascade]
10. ODG           ODG: the scanner speaks libraries. OCM speaks components.
                                                  [side-by-side with shared digest]
11. 2AM REDO      It's 2am. You already know.    [4 cards: scanner→ODG→dash→action]
12. CLOSE         A release is a thing, not a scavenger hunt.   [CTA layout]
13. ADOPT         Two paths. Pick the one that fits Monday.     [Q&A backdrop]
```

---

## Slide details (only what changed in v0.4)

### Slide 1 — Hero  *(REWORKED)*

**Layout:** Hero (master template).
**Title (single line, gradient applied to the whole line, ≈ 96pt):**
> It's 2am. A CVE drops.

**Subtitle:** *Where is it running?*
**Lockup:** Open Component Model — open source, NeoNephos Foundation.

The architect Hero uses split white/gradient across two lines; this Hero collapses to one line with gradient on the whole string. Single-line fits at ~96pt across a 1920px-wide slide. Will verify in the rendered PPTX.

---

### Slide 8 — Compose  *(NEW SLIDE)*

**Layout:** Plain (master template).
**Eyebrow:** COMPOSE
**Title:** A product is a tree.

**Body — small composition tree (centred, monospace), brand-blue parent + grey children:**

```
github.com/acme/sovereign/product : 1.0.0
   ├── github.com/acme/sovereign/notes    : 1.0.0
   └── github.com/acme/sovereign/postgres : 1.0.0
```

**Two-row caption underneath (≥ 22pt, brand grey):**
> Leaf components carry resources. The product references them.
> One name, one signature, covers the whole tree.

**Why:** introduces *"product component"* as a first-class concept so slide 9's *"bump the product"* lands without explanation. Mirrors the architect deck's new slide-8 framing.

**Source:** `conformance/scenarios/sovereign/components/product/component-constructor.yaml` (componentReferences to notes + postgres).

---

### Slide 9 — Bump  *(SIMPLIFIED — composition removed)*

**Layout:** Plain.
**Eyebrow:** DAY 2
**Title:** Bump the product. Everything follows.

**Left half — YAML diff, large (28pt), centred-vertical:**
```yaml
spec:
  version: 1.1.0   # was: 1.0.0
```

**Right half — numbered cascade (kro → OCM → Flux), 4 steps, 22pt:**
> **1.** kro re-renders the RGD with the new spec.version.
> **2.** Component CR's semver updates; controllers resolve and verify.
> **3.** Resource CRs resolve new digests for the child charts and images.
> **4.** Flux HelmReleases roll the new artifacts.

**Below (full-width, brand-blue, italic, 28pt):**
> *You changed one line. The cluster did the rest.*

Composition tree dropped — that's slide 8 now.

---

### Slide 10 — ODG  *(MECHANISM CORRECTED PER ADR-0016)*

**Layout:** Content / 2-Column (master template).
**Eyebrow:** ODG
**Title:** The scanner speaks libraries. OCM speaks components.

**Layout shape:** two parallel columns under the title. Same image-digest string highlighted in brand blue on both sides — the eye traces the join.

**LEFT COLUMN — WHAT THE SCANNER REPORTS** (Consolas, grey body, blue keys):
```
CVE-2026-XXXX in libfoo

eu.gcr.io/acme/notes
@sha256:70a2577d…              ← brand blue

package · version · digest
```

**RIGHT COLUMN — WHAT ODG DISCOVERS** (Consolas, blue keys, black values):
```
$ oras discover \
    eu.gcr.io/acme/notes@sha256:70a2577d… \    ← brand blue (same string)
    --artifact-type \
      application/vnd.ocm.software.ownership.v1+json

→ annotations:
    software.ocm.component.name
      = github.com/acme/notes
    software.ocm.component.version
      = 1.0.0
    software.ocm.artifact
      = { name: notes-image, kind: resource }
```

**Footer (italic, brand grey, centred):**
> *The image is unchanged. Ownership rides in a side-car.*

**Why this design:**
- The shared digest string is the visual anchor — the audience sees it on the left (scanner's output) and immediately on the right (input to `oras discover`). The join is shown, not described.
- Console-style typography on both sides signals *"this is what you'd actually run."*
- The footer line lands the architectural insight: image stays clean; ownership is a separate referrer manifest, not an annotation on the image itself.

**Source:** `docs/adr/0016_ownership_annotations.md` from the OCM v2 repo. `artifactType: application/vnd.ocm.software.ownership.v1+json`; subject points at the image digest; annotations name component + version + artifact.

---

### Slide 11 — 2am redo  *(CARDS, NOT NUMBERED LIST)*

**Layout:** Plain.
**Eyebrow:** AT 2AM
**Title:** It's 2am. You already know.   *(bookend with slide 1)*

**Body:** four stacked cards, each ~1400×140px, rounded blue border, brand-blue eyebrow label + black body. Blue arrows between cards.

```
 ┌─ SCANNER ──────────────────────────────────────────────────────┐
 │  CVE-2026-XXXX in libfoo                                       │
 │  found in image eu.gcr.io/acme/notes@sha256:70a2577d…          │  ← brand-blue digest
 └────────────────────────────────────────────────────────────────┘
                                ↓
 ┌─ ODG ──────────────────────────────────────────────────────────┐
 │  oras discover that digest with the OCM ownership artifactType │
 │  → component github.com/acme/notes : 1.0.0 (resource notes-image)│
 └────────────────────────────────────────────────────────────────┘
                                ↓
 ┌─ DASHBOARD ────────────────────────────────────────────────────┐
 │  owner   = team-notes                                          │
 │  env     = eu-prod-12                                          │
 │  triaged = no                                                  │
 └────────────────────────────────────────────────────────────────┘
                                ↓
 ┌─ ACTION ───────────────────────────────────────────────────────┐
 │  Page team-notes. Patch on the shelf. Bump product. Done.      │
 └────────────────────────────────────────────────────────────────┘
```

**Footer (italic, brand blue, centred):** *Thirty seconds. Coffee's still warm.*

**The digest `@sha256:70a2577d…` is the same string from slide 10.** Visual continuity.

**Why cards, not numbered:**
- Mirrors architect slide 11 (Deploy 4-CR chain) visual structure — the audience already knows what cards-with-arrows mean in this deck.
- Cards carry one role each. Easier to parse at the back of the room than a numbered list.

---

## Unchanged from v0.3

Slides 2, 3, 4, 5, 6, 7, 12, 13 retain their v0.3 design. The major v0.3 → v0.4 work concentrated on slides 1, 8 (new), 9 (simplified), 10 (corrected), 11 (cards).

## Design conventions inherited from architect deck

- `add_yaml_block` for slides 4, 5, 9 (YAML rendering).
- `set_blue_box_bullets` for slides 2, 6 (anchor-word bullet lists).
- `add_callout` for slides 4, 5 callouts (if used).
- `Plain` layout for 2-line titles; `Plain / Compact` for 1-line.
- `Hero` for slide 1, `CTA` for slide 12.
- Native PPT shapes for slides 7 (controllers box), 8 (tree), 11 (cards).
- No micro-text. No italic footer captions (except the deliberate "Thirty seconds" and "image is unchanged" lines).

## What I will NOT do without sign-off

- Move ODG to a UI-screenshot slide (still text-only, by your earlier direction).
- Add a fifth column / row to slide 13 (Adopt stays at two paths).
- Push titles further into single-word territory (slide 4 *Pack.*, slide 6 *Travels.* — happy with where they stand for now).
