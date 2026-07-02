# Exec Deck Conventions

**Applies to:** OCM-Story-Exec-External · OCM-Story-Exec-Internal-Sponsor

**Purpose.** The rules the two exec decks follow, in one file. Shorter than the architect conventions, the exec decks are shorter and less mechanic-driven.

## Arc shape

The exec deck is ~15 slides, 15-minute talk. Structure (shared between external and internal):

```
 1  Hero               Audience-shaped opener
 2  Why Now            Ecosystem velocity / window / disinvestment cost
 3  The Answer         Meet OCM. One identity, every boundary.
 4  The Shift          SBOM lists. SBOD delivers.
 5  Shift Visual       SBOM inside SBOD (diagram)
 6  How OCM Composes   Signing / Transport / Compliance (three columns)
 7  In One Picture     Pack · Sign · Transport · Deploy (shared with architect Slide 7)
 8  Sovereign-Ready    Trust, but verify
 9  Air-Gap Visual     Trust travels with the component
10  Scan / Compliance  ODG as compliance-automation engine
11  What OCM Unlocks   Six outcomes (tile family)

External track ends around here (with a peer-ecosystem slide + CTA).
Internal track adds:
12  Open Ecosystem     Gardener · Kyma · OCP · Konfidence (logo row)
13  SAP-Internal       Hyperspace · RBSC · CSI · Steampunk · SS&D (bullet list)
14  CTA                Sponsor · Scale · Standardize
15  Glossary           Appendix
```

## Tone difference from architect decks

- **Less mechanic, more outcome.** The exec deck names what happens ("sign the release as one unit") but doesn't walk YAML or descriptors.
- **More sovereign / regulatory framing.** NIS2, CRA, DORA are backdrop; the audience knows them.
- **Slide 7 stays the same.** Pack · Sign · Transport · Deploy is the shared bridge across all four decks, it's the one slide where architect and exec audiences see the same content.

## Slide 7: the shared bridge

Every deck (architect + exec, external + internal) uses the same Slide 7. The four cards with icons, arrows, and the Sovereign Cloud target glyph. Rendered by `slide_6_native.py` in `decks/exec-phase1/build-pptx/` and imported by the architect scripts.

Never diverge. If someone proposes changing Slide 7, that changes ALL FOUR decks. Push back hard.

## Adopter proofs

**External exec:** peer-ecosystem framing, Gardener, Kyma, Open Control Plane, Konfidence, with the NeoNephos alignment claim.

**Internal exec:** two slides split (10a external ecosystem, 10b SAP-internal teams). This is what the architect-internal deck combines into ONE slide (Slide 15), audience is architect, wants the pattern at a glance.

## CTA verbs

- **External:** (varies, check the current external exec deck)
- **Internal:** Sponsor · Scale · Standardize. Match the exec voice, not the architect voice.

## What NOT to do

- **Don't cross-pollinate architect voice into exec.** No YAML on exec slides. No spec-level detail. If a claim needs "the canonical descriptor digest" to make sense, it's an architect slide.
- **Don't add mechanic slides.** Exec deck stops at "Pack · Sign · Transport · Deploy." No `ocm add cv` walkthroughs.
- **Don't over-caveat.** Trim edges belong on the architect deck (Slide 14); the exec deck lands the strategic message.
