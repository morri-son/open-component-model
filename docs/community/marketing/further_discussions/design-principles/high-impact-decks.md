# High-Impact Deck Principles

**Purpose.** The design principles this skill enforces. Not "generic slide-deck advice from the internet," but the specific rules that emerged from Phase 2B critique of the OCM decks. When a session evaluates a slide, these are the rubrics.

## One-job rule

Every slide answers ONE question. If a slide answers two, either split it, cut one, or lose the audience. Signs a slide has two jobs:
- Two eyebrow labels
- The title AND the subtitle both make claims
- Body content has two distinct groups the audience must integrate mentally

Ask of every slide: **what one thing does the audience know after seeing this that they didn't before?** If you can't name it in one sentence, the slide isn't ready.

## Stop-sentence rhythm

Every slide has a closing beat. A stop-sentence, a punchline, a phrase the speaker can land and then pause. Without it, slides run into each other and the audience doesn't know when to breathe.

Examples from Phase 2B decks:
- Slide 2 (Cause): *"Diagnosis: identity is bound to location."*
- Slide 3 (Insight): *"Move the artifact. The digest stays. Only the access changes. That is the whole trick."*
- Slide 6 (Descriptor): *"Sign the descriptor hash, not the access. Seven words; whole transport story."*
- Slide 14 (What's sharp): *"Honest now beats apologetic later. Plan for the trim edge."*

If a slide doesn't have a stop-sentence, ask "what does the speaker actually say last on this slide?" If the answer is "reads the last bullet," the slide isn't ready.

## The eyebrow is optional, not mandatory

Old convention: every slide has an eyebrow (ARCHITECTURE, DIAGNOSIS, POSITIONING). New convention (from architect-internal deck): drop the eyebrow when the title alone is stronger without it.

Rule: **don't add visual noise to earn a section label**. If the slide's content makes the section obvious, the eyebrow is redundant.

## Card family over bullet forests

When the slide has 3–5 parallel items with structure, use **cards**, not bullets. Bullets are for genuinely linear sequences.

Cards benefit:
- Parallel structure is visible (audience sees "three of a thing" at a glance)
- Each card can have a header + body pattern
- Better for skimming
- Reinforces the shape of the mental model (three moves, four moves, three options)

Card family conventions in these decks:
- ALL-CAPS left-aligned label at top
- Subtle top stripe (brand-blue accent)
- Dark grey body text
- Soft drop shadow (not hard border)
- Rounded corners (adjustments[0] = 14 / min-dimension)

Bullets are correct for:
- Sequential lists (steps 1–4 in narration)
- Short reference lists (glossary appendix)
- Q&A backups in speaker notes

## Colour discipline

The OCM palette is:
- Brand blue (`#0F6BFF`), headlines, anchors, callouts
- Mid blue (`#0A3A99`), secondary emphasis
- Cyan (`#5CD6FF`), highlight, subtitles on dark
- Grey-mid (`#6B7280`), dimmed or secondary
- Grey-soft (`#F3F4F6`), card backgrounds
- Black + White

Rules:
- **Do NOT colour body text.** Body is black. Colour is for structure (headers, labels, anchors), never for emphasis inside prose.
- **Brand blue is the punctuation.** Sparse. If a slide has 8 things in brand blue, none of them stand out.
- **Cyan is for on-dark contrast.** Subtitles on the hero, gradient endpoints.
- **Grey-mid is for dimming**, not for "I don't want to commit to black." Use it deliberately (e.g. slide 16 replication appendix greys the chain to emphasise the new card).

## YAML for architects

Architect audiences read YAML faster than prose. If a slide is trying to explain data structure, **show the YAML**, don't paraphrase.

- Colour discipline in YAML: keys in mid-blue, string values in dark-grey, signature-related lines in a specific colour (see external Slide 6 for the pattern)
- Show ~15–18 lines. Longer than that, split the slide.
- Real YAML, not pseudo-YAML. Values that would actually parse.

## Vocabulary consistency

If you call it "component" on slide 4, don't call it "descriptor" on slide 12 to mean the same thing. If it's the same thing, use the same word.

The decks maintain these disciplines:
- "Component identity", never "coordinates"
- "OpenPGP" (header) with "GPG is one implementation" (notes)
- "SBOD" and "component descriptor", both fine, but call out that they refer to the same object
- "Access" for the fetch pointer, "Digest" for the SHA-256, "Resource" for the artifact-inside-a-component

## Honest edges

Every architect deck has a "What's Sharp" slide (Slide 14 in the architect line). Three honest edges. Trim edges named openly. Never hide them.

Why: architects will find the edges. A deck that names them upfront earns trust. A deck that hides them, loses it.

Phase 2B locked edges for the external deck:
1. Controllers are v1alpha1. Pin to specific release tags.
2. Transfer defaults to descriptor-only. Pass `--copy-resources` for air-gap.
3. Helm-deploy adds kro + Flux or Argo CD. The OCM controllers don't ship them.

Internal-architect deck inherits these three unchanged.

## No em dashes

Not in slide text. Not in speaker notes. Not in card bodies, subtitles, footers, captions, or Q&A backups. See `voice-guide.md` for the full replacement table.

The short version. Every em dash gets rewritten to a period, colon, comma, parenthesis, line break, or two separate sentences. En dashes in numeric ranges (`2024–2026`) stay. Middle dots in mnemonics (`Pack · Sign · Transport · Deploy`) stay. Hyphens in compound words (`air-gap`, `location-independent`) stay. Only the em dash (`—`, U+2014) is banned.

Why: German-speaking and technically-schooled audiences read a prose em dash as an AI-content signal. The signal has become reliable enough that every em dash on a slide costs credibility with the audience the deck is designed for.

Sweep protocol: before shipping any slide text or speaker notes, grep for `—` and rewrite. This applies to text on the slide itself and to the notes pane. Zero exceptions in the OCM decks.

## No marketing overreach

Reject these words from slide text and speaker notes:
- "revolutionary"
- "best-in-class"
- "industry-leading"
- "seamlessly"
- "cutting-edge"
- "next-generation"

Replace with specific claims backed by facts:
- Instead of "revolutionary component model" → "descriptor-based release model"
- Instead of "seamless integration" → "OCM CLI plugin for RBSC works today"
- Instead of "cutting-edge signing" → "keyless via Sigstore (OIDC + Rekor)"

Marketing overreach is caught fastest by the **Hostile Enterprise Architect** persona. Test any claim against "does this survive that reading?"

## Speaker notes carry Q&A backups

The slide is the anchor. Speaker notes are where the speaker parks the answers to the questions the slide will provoke. Structure:

- Opening beat: 1–2 sentences setting up the slide
- Body walkthrough: what the speaker says while pointing
- Stop-sentence: the closing beat
- **Q&A backups**: 1–3 anticipated questions with answers, prefixed "Q&A on X:"

If a question comes up in every review of the slide, the answer goes into the speaker notes as a Q&A backup, not on the slide. The slide stays clean.

## Slide-count discipline

- Architect deck: **~16–18 slides** for a 30-min talk. External runs 16 + appendix; internal runs 17 + 2 appendices.
- Exec deck: **~15 slides** for a 15-min talk. Sparser.
- Appendices don't count toward the flow.

Cutting: if you're over budget, cut earliest and latest. The middle (mechanics) is load-bearing.

## Consistency across the deck family

The four decks (architect-external, architect-internal, exec-external, exec-internal-sponsor) share:
- Slide 7 mnemonic (Pack · Sign · Transport · Deploy)
- Colour palette
- Card family
- Typography (Aptos)
- Diagram idioms (coordinate travel visual, four-move cards, replication chain)

Divergences are intentional (audience-shaped). Don't drift the shared parts.

## Verification pattern for technical claims

Any slide that asserts a technical fact about OCM must be verifiable from:
1. The spec (`ocm-spec/doc/`)
2. The website (`website/content/docs/`)
3. The implementation (`bindings/go/`, `kubernetes/controller/`)

If a claim can't be verified from one of these, either:
- Verify with the user before shipping
- Reframe as future/roadmap ("on the roadmap") not present-tense
- Drop it

This is how the "Q&A on verifier policy floor" hallucination got caught in June 2026. The note claimed features that don't exist in the K8s controller code. The correction pattern: audit against code, then correct at the canonical source (external `speaker_notes.py`), then propagate to all copy-paste docs.
