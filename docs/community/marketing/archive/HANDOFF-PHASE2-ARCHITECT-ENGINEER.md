# Phase 2 Handoff — Architect + Engineer/Community Decks

**Status at session close:** Exec pair (external + internal-sponsor) is shipped. Branch `marketing/deck` has uncommitted polish; user pushes when ready.
**Repo:** `docs/community/marketing/decks/exec-phase1/` (branch `marketing/deck`)
**Read first:** `narratives/NARRATIVE.md`, `narratives/NARRATIVE-INTERNAL-SPONSOR.md`. Do not re-derive the exec narrative.

---

## What's done

- 11-slide external + 14-slide internal-sponsor exec decks, brand-correct (`OCM-Master.potx`, 20"×11.25").
- Slide 3 hub-and-spoke: e-ticket OCM-component icon (mini), arrows land precisely on outer hub circle r=104. Compliance arrows reversed (frameworks → hub).
- Slide 7b air-gap: e-ticket icon (full) on both sides, `github.com/acme/app · v1.0.0`, green check-badges (#16A34A) on the three verifier tiles, `TRANSPORT` label on arrow, `SAME IDENTITY · SAME SIGNATURE · ANY LOCATION` accent.
- Slide 9 tile icons: lock (signing), package-export (air-gap), rocket, radar, source-of-truth, report-analytics. Lock = OCM signing convention everywhere.
- Slide 10 logo wall: 4+4 logos clickable with 20pt captions. NeoNephos in row-1.
- Slide 10a internal: 4-logo wall + "Aligned with [NeoNephos]" composite line, caption under composite.
- Hidden 2-slide trademark notice at the back of each deck (`show="0"`).
- `assets/adopters/LICENSING.md` covers all logos.

## How to rebuild

```bash
cd docs/community/marketing/decks/exec-phase1/build-pptx
rm -f _raster/*.png   # clear if SVG edits don't appear
python3 build_potx.py
python3 build_pptx.py
python3 build_pptx_internal_sponsor.py
```

`rsvg-convert` required (`brew install librsvg`). PowerPoint caches images — close before reopening rebuilt files.

## Conventions to preserve

1. **No possessive apostrophes on acronyms** (`OCM's`, `SAP's` → reformulate). Triggers PowerPoint grammar underline.
2. **Hero titles max 2 lines** at 115pt. Never 3.
3. **Lock = signing.** Same glyph on slide 3 hub, slide 6 Pack/Sign, slide 7b component, slide 9 tile.
4. **Green (#16A34A) is the only off-color** in the entire deck. Used once on slide 7b. Don't introduce more.
5. **One signature lookup, one source of truth.** Edit `OCM-Master.potx` layouts (`build_potx.py`) for cross-deck style; deck scripts only set content.
6. **Speaker notes live in the room, not on slides** — internal-architect quibbles are handled in the room, not by adding text.

## Audience tier model (agreed last session)

| Trunk | Status | External/Internal |
|---|---|---|
| **Exec / LoB-head** | done | external + internal-sponsor (forks) |
| **Architect** | next | external + internal (forks) |
| **Engineer / OSS-community** | after | one trunk, OSS-community slides toggled per venue |

Phase-2 exec variants (FSI-EU, conference) per `archive/HANDOFF-PHASE2.md` remain deferred until venues confirmed.

---

## Architect deck — what it is

**Lead axis:** OCM as the architectural primitive. *Why this composes; where it fits; what it does and doesn't claim.* Audience already accepts compliance/sovereignty pressure — they're deciding whether to standardize on OCM as their delivery primitive.

**Length target:** 15–18 slides.

**Reuse from exec deck:**
- Slide 1 hero (adapt: same line lengths, voice shifts to architectural)
- Slide 2 Why now (drop or compress — architects know the regulatory landscape)
- Slide 3 hub-and-spoke (keep as-is)
- Slide 4a/4b SBoD (keep)
- Slide 6 Pack/Sign/Transport/Deploy (keep)
- Slide 7a/7b sovereign-ready (keep)

**New depth required:**
- **Component descriptor anatomy** — show actual YAML. `name`, `version`, `provider`, `resources[]`, `sources[]`, `references[]`, `signatures[]`, `labels`, `digests`. Reference: `website/content/docs/concepts/component-identity.md`.
- **Signing trust models** — three models on one slide: key pinning / certificate chain / Sigstore identity. Reference: `signing-and-verification-concept.md`.
- **Transfer + localization** — `ocm transfer cv` semantics, `--copy-resources`, CTF, localization at deploy time (not at transfer time). Reference: `transfer-concept.md`.
- **Controller chain** — Repository → Component → Resource → Deployer (4 CRDs). v1→v2 change table from `blog/2026-03-16-ocm-controllers-differences.md`.
- **Canonical repos + resolvers** — location-free references, resolver propagation, conflict detection. Reference: `canonical-components.md`.
- **Plugin extensibility** — process-based plugins, types, registry. Reference: `plugin-system.md`.
- **Asset-to-Owner trace** — *the* concrete proof point: scanner finding → OCI manifest annotation `cloud.gardener/ocm-component` → component coordinate → owner lookup. Pulled from the 2024-05 internal deck (slides 14–17), not in the exec narrative. Make this slide.

**Two architect cuts:**
- **External:** regulated-enterprise architects + foundation events. Lead with "OCM is the right primitive for *N regulated delivery contexts* you already know."
- **Internal:** SAP chief architects. Same body, opener handles SAP-internal "why not extend our existing tooling" objections inline.

Architect-deck variant filenames (suggested): `OCM-Architect.pptx` and `OCM-Architect-Internal.pptx`. Build scripts: `build_pptx_architect.py` / `build_pptx_architect_internal.py`. Reuse `OCM-Master.potx`.

**Layouts that may be needed and don't exist yet:** code-block layout (monospace YAML/CLI), 2-column comparator with code on one side. Add to `build_potx.py` if needed.

---

## Engineer / OSS-community deck — what it is

**Lead axis:** *Build with us.* Hands-on, code-first. *No* compliance/sovereignty pressure framing — engineers want to ship.

**Length target:** 18–22 slides. Toggle 3–4 OSS-community slides at the end depending on venue.

**Source material:** `blog/ocm_v2_announcement.md` is the closest thing to a canonical narrative — read it first.

**Spine:**
- Hero: "OCM v2 — pack, sign, transport, deploy."
- What's in the monorepo: CLI / Kubernetes controllers / Go library — one tree.
- CLI walkthrough: `ocm add cv` → `ocm sign cv` → `ocm transfer cv` → `ocm verify cv`. Real shell snippets.
- Kubernetes controllers: 4 CRDs + ApplySet. No Flux required (replaceable, but not required).
- kro RGD pattern for advanced deployment.
- OCI-native: native Image Index storage, `helm pull oci://...` works, Referrers API.
- Plugin SDK (Go).
- Conformance scenarios.
- Sigstore (early access).
- ODG integration roadmap.

**OSS-community toggle slides (end of deck, optional):**
- Governance: NeoNephos TSC, SIG Runtime, planned SIG Spec, Community Specification License Q2 2026.
- Apeiro adoption: Gardener, openMCP, Platform Mesh, Konfidence.
- Contribution paths: Zulip channel, mailing list, repo, charter links.

**Filenames:** `OCM-Engineer.pptx` (or `OCM-Build-With-Us.pptx`). One trunk, OSS slides included; engineer-only venues hide them.

---

## Open polish items

- `archive/MARKETING-PEER-REVIEW.md` §4.2 has two unresolved external-deck copy decisions (concession line wording variant, CTA escalation).
- Speaker notes — currently empty on every slide. Add when there's a confirmed venue. Not blocking.
- The handoff in `archive/HANDOFF-PHASE2.md` describes Phase-2 *exec variants* (FSI-EU, conference). Defer until venues confirmed; not on the architect/engineer track.

---

## How to start the next session

1. `cat narratives/NARRATIVE.md narratives/NARRATIVE-INTERNAL-SPONSOR.md` — confirm exec voice.
2. `cat blog/ocm_v2_announcement.md` — confirm engineer voice.
3. Read `website/content/docs/concepts/*.md` — depth source material for architect deck.
4. **Decide first:** architect master narrative (`narratives/NARRATIVE-ARCHITECT.md`), then build.
5. **Lock the narrative before authoring slides.** Same pattern as exec phase — the architect narrative is where all the architectural decisions land; the build script is downstream.

User strongly prefers: terse output, no redundant exploration, ignore harness task-tracking reminders for trivial work. Pick Opus for narrative authoring, switch to Sonnet for variant cuts.

*Generated 2026-06-18, session close.*
