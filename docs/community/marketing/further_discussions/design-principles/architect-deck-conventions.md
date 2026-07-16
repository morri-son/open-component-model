# Architect Deck Conventions

**Applies to:** OCM-Story-Architect-External · OCM-Story-Architect-Internal

**Purpose.** The rules the two architect decks follow, in one file. When a session works on either deck, this is the rubric.

## Arc shape (locked): CORE spine and SURVEY tier

Every architect deck follows the same 18-slide sequence plus appendices. The slides are still all present and all built. What changed (2026-07-15): the 30-minute *narration* no longer treats all 18 as equal-weight. Each slide has a **tier** that tells the speaker how much of the attention budget it earns in the main pass.

Why the tier model replaces the old flat "walk every slide" arc: the technical story is both deep and broad. Depth (YAML, signatures, day-2) is what architects came for and is not the problem. Breadth is: slides 9, 10, 11 are three consecutive parallel-structure slides (three schemes, three topologies, four CRs) landing in the attention-fatigue zone the marketing canon warns about. Walking all three in full is what overwhelms. The fix is not to cut them, it is to narrate the argument-carrying CORE slides in full and skim the SURVEY slides unless the room engages. Same deck, same slides, thinner talk.

```
 #  Slide                Tier     Job
 1  Pain / Opener        CORE     Why-does-this-matter setup
 2  Diagnosis + Stakes   CORE     Nothing identifies the release, and here is what that costs
 3  The Hinge            CORE     Identity that travels with the release. (pivot beat)
 4  Positioning          CORE     Wraps every artifact. Signs the whole release. (+ compare one-liner)
 5  Constructor          CORE     What you write. (YAML)
 6  Descriptor           CORE     What gets signed and travels. (YAML)
 7  Overview             CORE     THE FOUR MOVES, Pack · Sign · Transport · Deploy. (mnemonic anchor)
 8  Compose              CORE     Service carries resources. Product carries references.
 9  Sign                 SURVEY   Same signed object. Three signing options. (skim; schemes = depth-on-demand)
10  Transport            CORE     Three patterns. One command. (air-gap is the emotional peak; narrate it)
11  Deploy               SURVEY   Repository → Component → Resource → Deployer. (skim; per-CR = depth-on-demand)
12  Composition          CORE     One product. Three components. One line to upgrade. (the payoff)
13  Adoption             CORE     (audience-shaped)
14  What's Sharp         CORE     Three honest edges.

The payoff-and-appendix tail diverges by deck (external has no adopter-proof slide, so it is one shorter in the main arc):

  EXTERNAL                          INTERNAL
  15  CTA          CORE             15  Adopter proof   CORE
  --- appendices ---                16  CTA             CORE
  16  Replication  pull-on-demand   --- appendices ---
  17  Compare      FIRST-PULL       17  Replication     pull-on-demand
  18  Glossary     pull-on-demand   18  Glossary        pull-on-demand
```

**CORE** slides carry the argument. Narrate in full even under time pressure. Cutting one breaks the arc.
**SURVEY** slides carry breadth the argument does not strictly need in one pass. Point at the structure, land one sentence, advance. The detail lives in the speaker notes as depth-on-demand and is walked only when a persona in the room engages that specific slide.
**FIRST-PULL** appendix: not narrated in sequence, but high-demand. The speaker expects to pull it and should know it cold. Distinct from a pull-on-demand appendix (Replication, Glossary) that may never come up.

CORE / SURVEY / FIRST-PULL are **authoring vocabulary for this file**, not presenter-facing. The speaker notes never say "SURVEY tier"; they give the plain instruction ("Skim this slide in a 30-minute talk, don't walk it. ..."). Slide 1's notes carry a one-paragraph pacing preface that explains the walk-vs-skim approach once, so the presenter meets the idea before Slide 9.

Note on numbering: the external and internal appendix order differs. External appendix 17 is the Compare table (FIRST-PULL); internal has no Compare slide (its SAP-stack comparison lives in Slide 4 notes) so its 17 is Replication and 18 is the Glossary. Do not add a Compare slide to the internal deck: the internal composability question is "does this replace RBSC / Hyperspace / ODG?", already answered in Slide 4 notes. A shared Compare slide can't serve both audiences (external compares against CNCF tools, internal against the SAP stack), and internal doesn't need a table.

## Slide-7 is the mnemonic anchor

**Pack · Sign · Transport · Deploy.** Slides 8–11 walk them, in this order. Any deck that breaks this order breaks the mnemonic.

- Slide 8 = Pack
- Slide 9 = Sign
- Slide 10 = Transport
- Slide 11 = Deploy

Do not swap 9 and 10 (has happened before; caught in June 2026 and corrected).

## The Constructor / Descriptor pair (Slides 5–6)

Two YAML slides that show the two nouns:
- **Slide 5 (Constructor)**, what YOU write. Hand-authored input, ~17 lines.
- **Slide 6 (Descriptor)**, what gets signed. Generated by `ocm add cv`.

Together they teach: "you write A, tool produces B, signature covers B."

YAML colour discipline:
- Keys: mid-blue
- Values: dark-grey
- Signature-related lines: brand-blue (Slide 6 highlight)
- Structure (`:`, `-`): darker grey

## Slide 2 (Diagnosis + Stakes): name the gap, then name the cost

Headline: `Every tool identifies one artifact. Nothing identifies the release.` Three bullets, one per artifact type (OCI image, Helm chart, SBOM/signatures), each ending on the absent release. No "pins" verb, no on-slide "referrer" jargon (see A26).

The slide does two jobs, gap and cost. The bullets prove the gap. The stop-line proves the cost: `You can't sign, ship, or audit what you can't name.` Speaker notes carry the three concrete failures the website names (broken deployment, stalled audit, half-shipped air-gap transfer) so the audience feels the consequence before the mechanics start. Without the cost beat, Act 1 is a clean puzzle with no stakes, which reads as high-level to an architect. The mechanism on Slide 5 onward has to be owed something.

## Slide 4 (Positioning): the "does not replace" beat

Every architect deck sets this before walking mechanics. Three columns:
- ANY FORMAT, OCI, Helm, configs, SBOMs, npm, maven, binaries
- ANY LOCATION, component identity travels; no registry in the name
- ONE SIGNATURE, covers every digest; survives transport

This is where "OCM does not replace X" gets defended. Notes carry the "what does this replace?" Q&A backup, CNCF-flavoured for external, SAP-stack-flavoured for internal. The compose-vs-OCM one-liner lives in the notes here (`those tools sign artifacts; OCM signs the release they can't name as a unit, different unit of analysis`), because the hostile architect raises the composability objection here, not at the end. For external, this is the trigger to pull the Compare appendix (Slide 17) out of order; see the FIRST-PULL note below.

## Slide 9 (Sign): three signing options [SURVEY tier]

Three columns (locked wording):
- **RSA**, bare public-key pinning
- **OpenPGP**, OpenPGP keys, ASCII-armored (NOT "GPG")
- **Sigstore**, keyless via OIDC + Rekor

**Tier:** SURVEY. In the 30-minute talk, skim: point at the three headers, land "one signed object, three ways to prove the key, pick what your org runs," advance. The three schemes are breadth the argument does not need in the main pass; Slide 7 already carried "Sign." Walk the detail only when a security architect engages.

**Q&A discipline:** the columns are CLI-surface, not controller-surface. Controller v1alpha1 today = RSA only. This is on the speaker-notes level, not the slide.

## Slide 10 (Transport): three patterns

- Registry → Registry (promotion, cross-cloud)
- Registry → CTF (archive out)
- CTF → Registry (air-gap import)

One command: `ocm transfer cv <src> <dst>`. Same command across all three. Air-gap footgun (`--copy-resources`) named on Slide 14, not here.

## Slide 11 (Deploy): the four-CR chain [SURVEY tier]

Repository → Component → Resource → Deployer. Card family (four cards). Verification-opt-in disclosure lives in speaker notes for the Component card.

**Tier:** SURVEY. In the 30-minute talk, name the chain and land one property: the controllers verify before they apply. The per-CR walk is depth-on-demand for a Kubernetes-platform architect. Two beats stay in the main pass even when skimming: verification-opt-in on the Component card, and the BYO-GitOps dependency (kro + Flux/Argo), because Slide 14 pays both off.

## Slide 12 (Composition): Day-2 upgrade mechanic

One product, three components. Change one line in `componentReferences:`, re-sign the product, downstream picks up. This is the "why the model is worth investing in" beat, makes composition tangible.

Changed-value highlights: use brand-blue for the two changed lines. Every other line stays neutral.

## Slide 13 (Adoption): audience-shaped

- **External:** two cards, "FROM ZERO, CLI" + "ON YOUR CLUSTER, CONTROLLERS." Time budgets (30 minutes) hidden in speaker notes only.
- **Internal:** two cards, "PACK & SHIP" + "DEPLOY & OPERATE." SAP tools (RBSC, ODG, OCP) named in card body. Hyperspace v1/v2 caveat in notes.

## Slide 14 (What's Sharp): three honest edges

Locked content:
1. Controllers are v1alpha1, pin to specific release tags
2. Transfer defaults to descriptor-only; pass `--copy-resources` for air-gap
3. Helm-deploy adds kro + Flux or Argo CD, the OCM controllers don't ship them

Load-bearing slide. Never drop.

## Slide 15 (Adopter Proof): internal deck only

Two-column, combining what the exec-internal deck splits across two slides:
- LEFT: 4 open-source SAP projects (Gardener, Kyma, OpenControlPlane, Konfidence) as a 2×2 logo grid. Gardener and Konfidence use wordmark logos (no caption); Kyma and OpenControlPlane use icons with the project name as a caption.
- RIGHT: 5 SAP-internal teams as a bullet list (Hyperspace, RBSC, CSI, Steampunk, SS&D)

External deck does NOT have this slide (its adopter proof shape is different, CNCF-facing).

## Slide 16 (CTA): audience-shaped

- External: Evaluate · Pilot · Engage
- Internal: Pilot · Standardize · Steward (Standardize = bottom-up team standard, NOT SLC-29 mandate)

Layout is CTA-master (dark background), three action-path lines. Brand row footer.

## Slide 17 (Replication): appendix

Pull-on-demand. Not in main narration. Shows: dimmed chain echo (grey four-card row) + highlighted Replication card (brand-blue accent). Verifies against `website/content/docs/reference/kubernetes-api/replication.md`.

## Slide 18: deck-specific appendix

- External: cosign/SLSA/SBOM/OCM comparison matrix (built by separate `build_slide_4b_compare.py`)
- Internal: Acronym glossary (12 terms, two columns, only terms that appear on other slides in this deck)

## Appendix tiers: FIRST-PULL vs pull-on-demand

Not all appendices are equal. The external Compare slide (Slide 17) is **FIRST-PULL**: the composability objection is the hostile architect's opening move and it lands on Slide 4, so the speaker should expect to jump to Compare out of order and must know it cold. Replication and the Glossary are **pull-on-demand**: they may never come up. This distinction is narration guidance, not a build difference; all appendices are built the same way and sit after the main arc.

Internal has no Compare slide. Its composability question is "does this replace RBSC / Hyperspace / ODG?", answered in Slide 4 notes (SAP-stack Q&A). A shared Compare slide cannot serve both decks: external compares against CNCF tools (cosign, SLSA, SBOM, OCI referrers), internal against the SAP stack. Different comparison sets, so two treatments, and internal's is light enough to live in notes. Do not add a Compare slide to the internal deck.

## Speaker notes discipline

Every slide's speaker notes have this structure:

```
[Opening beat, 1-2 sentences setting up the slide]
[Body walkthrough, what to say while pointing at each element]
[Stop-sentence, the closing beat]
Q&A backup on X: ...
Q&A backup on Y: ...
CLI (if relevant): `ocm ...`
```

Notes are indexed by slide number. External deck: `speaker_notes.py` key = slide number in canonical order (9=Sign, 10=Transport). Internal deck: `speaker_notes_internal.py` overrides only the audience-shaped slides (1, 4, 13, 15, 16, 18); rest inherited from external.

## What the persona pass tests

When a session reviews an architect deck, run it against these persona reads:
1. **Lead Architect**, is anything overclaimed vs. code? Is composition safety explicit?
2. **Hostile Enterprise Architect**, where's the "why not compose X+Y" question landed? Are trim edges named?
3. **Marketing Comms**, is vocabulary consistent? Is any language marketing-overreach?
4. **SAP Internal Architect** (internal deck only), does the SAP-stack framing hold up? Are v1/v2 caveats named?

If a review finds an issue any of these personas would raise, fix at the source (`speaker_notes.py` for external, `speaker_notes_internal.py` for internal, slide-text in the build script).
