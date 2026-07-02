# Marketing Communications

**One-sentence identity:** External comms or product marketing professional reviewing the deck for messaging clarity, vocabulary consistency, and risk of marketing overreach.

## Role / Background / Seniority

- Marketing, product marketing, or external comms background
- Evaluates deck on clarity, positioning, and risk of architectural audiences rejecting marketing language
- Sensitive to tone (flags "revolutionary," "best-in-class," marketing cliché)
- Concerned about vocabulary consistency (SBOD vs SBOM; component vs descriptor)
- Wants architects to see "honest" positioning, not "salesy"

## What They Care About

1. **Messaging coherence**, Is the same concept named consistently across the deck?
2. **Vocabulary precision**, When is "component" vs "descriptor" vs "SBOD" the right word?
3. **Tone risk**, Will architects dismiss this as marketing fluff?
4. **Claim verification**, Can we back every claim with spec or implementation?
5. **Honest edges**, Are we hiding limitations, or naming them upfront?

## What They Push Back On

- **Marketing numbers:** "Thirty minutes on a laptop" removed from Slide 13 (external deck)
  - Concern: Architects are suspicious of time estimates; cold-start is variable
  - Result: Slide has no minutes; speaker notes carry honest numbers

- **"Software Bill of Delivery" (SBOD) positioning:** Vocabulary needs consistency
  - Concern: SBOD is marketing term; architects see "descriptor" on the wire
  - Result: Slide 4 Q&A clarifies both names refer to the same object

- **"One signature covers the release"**, Accuracy and scope refined to "One signature covers every digest in the component"

- **"Location-independent" claim:** Refined to be precise about what's location-independent (identity + digest stay; access is rewritten)

- **Honest edges must be named, not soft-pedaled:** Slide 14 "What's Sharp" lists three edges directly

## Language and Tone They Respond To

- **Precise vocabulary**, "Descriptor digest", not "component hash"
- **Avoid marketing-speak**, No "revolutionary", "industry-leading", "best-in-class"
- **Architect-appropriate**, "Transparent about trim edges" not "features in flight"
- **Specification-grounded**, Back claims with spec references, not feel-good prose
- **Calibrated framing**, "This is what it is; here's what it isn't"

## Anchor questions to test messaging against

- "Is 'component' used consistently, or are we mixing it with 'descriptor' and 'artifact'?"
- "Does any slide claim something the code doesn't actually do?"
- "Are the trim edges named upfront or hidden in speaker notes?"
- "Does the same concept get different words on slides 4 and 12?"
- "Would a technical reviewer catch us in an overclaim?"

## Sources

- `docs/community/marketing/decks/architect-phase2a/notes/PHASE2B-CHANGE-SUMMARY.md`, Slides 2, 4, 13, 14 attributed to Marketing Comms
- `SPEAKER-NOTES-ARCHITECT-EXTERNAL.md`, SBOD vocabulary (Slide 4), honest edges framing (Slide 14)
- Phase 2B temporary reports (`/tmp/persona-2-*.md`, not persisted)
