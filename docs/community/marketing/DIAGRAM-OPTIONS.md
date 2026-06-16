# Diagram Variants — Options for Discussion

For each diagram slide, this document presents the existing SVG plus 1–3 alternatives. All variants live in `decks/exec-phase1/diagrams/` and are 1760×540 (sized to the layout's diagram region).

You can pick any combination — different slides can use different stylistic registers. The goal is to give you **building blocks**, not a finished house.

The reusable primitives library lives at `decks/exec-phase1/diagrams/primitives/` (29 SVGs documented in `primitives/PRIMITIVES.md`) — every diagram below is composable from those parts, so you can mix and remix.

---

## Slide 3 — "Software delivery is fragmented"

### v1 (current) — `03-fragmented.svg`
Conceptual: stacks pulling in different directions. Quick to read but light on specificity.

### v2 — `03-fragmented-v2.svg`
**Five team-stack tiles in a row, each with their own signing/scanning toolkit, each with a red ! warning and "own signing tooling" annotation. Caption beneath stitches the message: 5 teams, 5 schemes, no composition.**

- Pros: concrete, names recognisable (cosign, trivy, prov files, syft, cyclonedx). Lands the "stack-by-stack tooling" point hard.
- Cons: dense; the eye has to scan all 5 tiles. Best used if you want to spend 30s on this slide.

### v3 — `03-fragmented-v3.svg`
**"Before / After" split-screen. Left half: chaotic cluster of artifact pills with broken/dashed connectors and a big red X at the centre — "many stacks, many signatures." Right half: one signed envelope containing all artifact types, identity chip, and a clean proof-line list.**

- Pros: shows the *answer* right next to the *problem*. Most exec-friendly framing.
- Cons: can feel like marketing-deck cliché. Works only if you accept the "before/after" trope.

**My recommendation:** v3. Best mix of clarity and concision. v2 is the fallback if you want more technical specificity.

---

## Slide 4 — "SBoD contains the SBOM"

### v1 (current) — `04-sbom-inside-sbod.svg`
Existing composition diagram. Status: review whether the metaphor lands. (I haven't recreated it.)

### v2 — `04-sbom-inside-sbod-v2.svg`
**One large signed envelope (SBoD) with its seal in the top-right corner. Inside it: a row of artifact pills (OCI/Helm/npm/Binary/Config) and an explicit nested SBOM box as one payload item among many. Right column: vertical verb chain "Built. Signed. Transported. Deployed." with proof lines.**

- Pros: literal "envelope contains payload" metaphor. The verb chain is a strong slow-read element.
- Cons: the SBOM box is one of six things — if "SBoD contains SBOM" needs to be the dominant message, this slightly buries it.

### v3 — `04-sbom-inside-sbod-v3.svg`
**Three concentric layers (matryoshka): outermost = SBoD, middle = payload, innermost = SBOM. Each layer's stroke gets darker as you go in. Right column carries the verb chain and a punchline "Your SBOM tooling is unchanged."**

- Pros: the nesting *is* the diagram. Strongest visual statement of "SBOM lives inside SBoD."
- Cons: takes more vertical space; right-column caption gets compressed.

**My recommendation:** v3 for the conceptual punch, v2 for richer payload context. Pick based on which message dominates the speaker's intent.

---

## Slide 5 — "Pack · Sign · Transport · Deploy"

### v1 (current) — `05-pack-sign-transport-deploy.svg`
Existing wide diagram. Renders small in some viewers per spec note.

### v2 (existing alt) — `05-pack-sign-transport-deploy-v2.svg`
Existing, slightly different framing.

### v3 — `05-pack-sign-transport-deploy-v3.svg`
**Four step cards in a row (Pack/Sign/Transport/Deploy), each with a number, big verb, one-line subtitle, and a small visual primitive. A fifth dashed-border card on the right ("Sovereign Cloud — VERIFIED"). Connecting arrows between them.**

- Pros: the lifecycle is unambiguous. Each step has its own small visual proof.
- Cons: dense — five cards is a lot of horizontal real estate.

### v4 — `05-pack-sign-transport-deploy-v4.svg`
**Minimalist horizontal flow. Numbered circles on a line, big verb labels, one-line subtitles. Optional fifth "VERIFIED" badge in the sovereign cloud as a faded checkmark.**

- Pros: cleanest possible read. Suitable for a slow exec read-aloud.
- Cons: less visual richness; trades information density for clarity.

**My recommendation:** v4 for an exec audience, v3 if you need more "depth" cues per step.

---

## Slide 6 — "Sovereign-ready / Trust, but verify"

### v1 (current) — `06-sovereign-airgap.svg`
Existing diagram. Shows the air-gap concept.

### v2 — `06-sovereign-airgap-v2.svg`
**Two-zone diagram with a thick "AIR GAP" divider. Left zone: Build → Sign → Pack → CTF (Common Transport Format). Right zone (dark sovereign cloud): receive → verify → registry → deploy, with a closed-loop "scale" loop showing day-2 ops happen entirely inside. A red blocked-arrow at the bottom explicitly says "no upstream callback." Caption mentions the conformance scenario.**

- Pros: operationally specific (CTF is named, day-2 closed loop is shown). Strongest credibility for a technical exec.
- Cons: dense; needs careful explanation.

### v3 — `06-sovereign-airgap-v3.svg`
**Pure conceptual. Two concentric circles: outer = open world, inner = sovereign zone (dark fill). A signed envelope crosses inward through a "verify" gate. Inside the inner circle: a closed-loop arrow + "day-2 stays inside" label. A red blocked-arrow shows "no callback to upstream."**

- Pros: maximum conceptual clarity. No operational detail to distract.
- Cons: the "closed-loop" is symbolic; doesn't show what actually happens inside.

**My recommendation:** v2 for technical execs (operations, CIO, CISO). v3 for business execs (CEO, board) who don't need CTF specifics.

---

## Notes on building from primitives

The `primitives/` directory has 29 reusable SVG components. The diagrams above use them implicitly (rounded boxes, artifact pills, signed envelopes, registry cylinders, K8s clusters, boundary lines, arrows, badges).

**To assemble a custom diagram:** open the relevant primitive SVGs in your editor, copy their `<g>` content into a new SVG file with a `1760×540` viewBox, position with `transform="translate(x,y)"`, and chain together. The brand palette and stroke widths are baked into each primitive — they'll compose visually consistent.

For a quick reference of what's available, see `primitives/PRIMITIVES.md`.

---

## Tile icons (slide 8)

Audited separately — see `decks/exec-phase1/diagrams/icons/TILE-ICON-OPTIONS.md`. Only the **`cloud-upload` icon** for "Air-gapped delivery" was rated as wrong-metaphor; replacement `package-export.svg` has been fetched and is ready to use.

---

## What's left to discuss

- **Which diagram variant to wire into each slide.** The build script (`build_pptx.py`) currently uses the v1 SVGs. Once you pick variants, I update the script.
- **Compliance Dashboard thumbnail for slide 7.** Subagent recommended adding one — sourced from the IPCEI deck (March 2025 GA pitch). Needs sanitisation. Not yet started.
- **Section dividers.** Subagent suggested between slides 3↔4 and 6↔7. Two new layout invocations on the .potx Section Divider layout. Not yet started.
- **Hero per-vertical variants.** Outlined in `CONTENT-OPTIONS.md` §"Cross-deck additions". Not yet started.

*Generated 2026-06-16.*
