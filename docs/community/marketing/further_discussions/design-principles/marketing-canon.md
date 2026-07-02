# Marketing Canon: Four Lenses for Deck Review

Every review this skill produces goes through four lenses. Not because the skill is doing marketing (it isn't, decks are strategic engineering artifacts), but because bad decks fail on one of four dimensions that these fields have named better than any of us would in isolation.

The four canons below are compressed. This is not a reading list; it's the operational subset. Each one gives the skill a specific way to catch what a slide is doing wrong.

## 1. Narrative structure: where does the tension live?

**The three-act shape.** Every deck that lands has three acts:

- **Act 1, setup.** State the problem. Make the audience feel it. End Act 1 with a promise that we'll show them the answer.
- **Act 2, mechanics.** Show how it works. This is where the audience has to concentrate; you've earned their attention with Act 1, now you spend it.
- **Act 3, payoff.** Adoption, proof, next steps. Release the tension.

Miss any of the three and the deck fails predictably. Skip Act 1 and the audience doesn't care. Rush Act 2 and they don't believe you. Skip Act 3 and they leave with no action.

The architect deck's shape:
- Act 1: slides 1–4 (pain, cause, hinge, positioning)
- Act 2: slides 5–12 (the mechanics, constructor, descriptor, four moves, compose, sign, transport, deploy, day-2)
- Act 3: slides 13–16 (adoption, honest edges, adopter proof, CTA)

The exec deck's shape is the same in outline but the act boundaries move: Act 1 is slides 1–3 (pain, why now, the answer), Act 2 is slides 4–10 (shift, compose, one picture, sovereign-ready, air-gap, scan), Act 3 is slides 11–14 (outcomes, adopters, CTA).

**The Minto pyramid (BLUF for structured argument).** When a slide argues something, put the point at the top and the evidence below. Not the other way around. Audiences are impatient. The top of the slide is the load-bearing sentence. Everything under it either supports or specifies.

This is why slide titles say things like "In every existing tool, identity is bound to location" (an assertion) and not "Investigating identity models" (a topic label). Assertions land. Topic labels don't.

**MECE.** When a slide has parallel elements, three columns, four cards, five bullets, they need to be Mutually Exclusive and Collectively Exhaustive. If two columns overlap, one is redundant. If the set doesn't cover the space, the audience senses the gap. This is why the four moves (Pack · Sign · Transport · Deploy) work and why "signing, security, and reliability" doesn't, the second set has overlapping members.

**The pivot beat.** Every arc has a moment where the audience shifts from problem-space to solution-space. In the architect deck it's slide 3 (The Hinge, "identity that travels with the artifact"). That's the pivot. Everything before is diagnosis; everything after is prescription. If you can't identify the pivot beat in a deck, the deck doesn't have one, and you should build one.

## 2. Cognitive science: what can the audience actually hold?

**Working memory.** Humans hold about 4 ± 1 chunks. Not seven. Not "a lot when they're engaged." Four. When a slide has 8 bullets, 6 of them are noise. When a diagram has 12 arrows, most of them are decoration. Design for four.

This is why the architect deck's mechanic slides (constructor, descriptor, sign, transport, deploy) each carry 3–4 primary elements, not 8. It's why the four moves is four, not six.

**Attention budget.** Every talk has a budget. The audience arrives with a fixed amount of attention and spends it. Slide 1 costs cheap; slide 12 costs expensive; the last slide is the payoff. Design the budget:
- Cheap slides for setup and pain
- Expensive slides for mechanics, YAML, diagrams, the four moves
- Cheap slides for adoption and CTA (they've spent; give them back)

A common failure: putting the most complex slide 20 minutes in, when the audience is already tired. Complexity should hit while attention is fresh.

**Curse of knowledge (Heath brothers).** The experts giving the talk cannot un-know what they know. They forget that "identity is bound to location" is not obvious to someone who has never thought about component delivery. They forget that "sign the descriptor hash, not the access" is a whole worldview in seven words.

Every slide should be tested against "would someone who's never heard OCM understand this?" If the answer is no, that's fine, but then the slide needs to earn its confusion by paying off in the next 2–3 slides.

**Cognitive load, extraneous vs germane.** Extraneous cognitive load is decorative confusion: fancy transitions, unlabeled arrows, colours that don't mean anything, jargon used to sound smart. Germane cognitive load is the work of learning: parsing a YAML block, following an arrow through a diagram, holding a definition in mind while the next slide extends it.

Rule: eliminate extraneous, protect germane. The OCM decks' colour discipline (brand-blue as punctuation, not decoration) is an extraneous-load-reduction. The YAML on slides 5–6 is germane; the audience is meant to work through it.

## 3. Sticky messaging: what survives?

**SUCCES framework (Heath brothers).** A message is sticky if it's:

- **Simple.** A single core idea, stripped to its essence. Not "OCM enables sovereign-cloud delivery through location-independent identity, cryptographic signing, and standards-based transport", but "sign the descriptor hash, not the access."
- **Unexpected.** Break a pattern. The audience thinks they know the space; you show them something they didn't expect. In OCM: "the signature covers every digest, even after access rewriting" is unexpected to anyone whose mental model of signing includes "the artifact must not change." That's the thing they'll remember.
- **Concrete.** Specific images, specific commands, specific mechanisms. `ocm transfer cv <src> <dst>` is concrete. "Software supply chain security" is abstract.
- **Credible.** Backed by mechanism, code, spec, not by assertion. "SBOD is the category SAP defined" is credible. "OCM is the industry standard" is not.
- **Emotional.** Not sentimental, but hooked to something the audience cares about. Architects care about correctness, honesty, defensibility. Executives care about position, ecosystem, risk. Speak to that, not to a generic "value proposition."
- **Stories.** A narrative frame beats a bullet list. "Here's what happens when you `ocm transfer cv` from a public registry to an air-gapped CTF" is a story. "Air-gap transport is supported" is a bullet.

Rule of thumb: if a message doesn't hit at least four of SUCCES, it won't stick. A message that hits five or six sticks reliably.

**The stop-sentence.** Every scene needs a landing. In sticky-messaging terms: give the audience one line to hold onto that they can repeat. In the OCM decks:
- Slide 3: "Move the artifact. The digest stays. Only the access changes. That is the whole trick."
- Slide 6: "Sign the descriptor hash, not the access. Seven words; whole transport story."
- Slide 14: "Honest now beats apologetic later. Plan for the trim edge."

Stop-sentences are what audiences quote in the meeting afterwards. Every important slide needs one.

**Concrete over abstract, always.** "OCM composes signatures across artifacts" is abstract. "One signature over the canonical descriptor covers every resource digest" is concrete. The concrete version is stickier because it names the mechanism.

**The unexpected turn.** The strongest beats in a deck are the moments where the audience's default expectation is broken. The persona-lens for this: what does a Lead Architect expect coming into slide N, and what would surprise them? If nothing on slide N surprises anyone, slide N is doing setup work, that's fine, it's earning tension for later. If slide N is meant to *land* something and it's still not surprising, rewrite it.

## 4. Presentation design: slides vs speaker

**Presentation Zen / Duarte principle: the slide is not the presentation.** The slide is the anchor. The speaker is the presentation. Slides that try to be self-contained (bullets that summarize everything the speaker will say) are documents, not slides. Documents are for reading; slides are for speaking to.

The rule: **if the audience can read the slide and get the same value as being in the room, the slide has swallowed the speaker's job.** Slides should be incomplete. They should require narration.

This is why the OCM decks have short titles, short subtitles, and short body text. The speaker fills in. The speaker notes tell them what to fill in.

**The S-curve (Duarte's *Resonate*).** A talk has an emotional S-curve: current reality → new bliss. Slides oscillate between "here's what is" and "here's what could be." That oscillation is what keeps attention. A deck that only shows "what is" is diagnosis without prescription. A deck that only shows "what could be" is dreamware.

In the OCM architect deck:
- Slide 1 (pain, what is) → Slide 3 (hinge, what could be)
- Slide 2 (cause, what is) → Slide 4 (positioning, what could be)
- Slides 5–12 alternate: descriptor mechanism (is) → what that enables (could)

The rhythm keeps the audience oscillating between problem and answer. If a stretch of slides all sits in one register, the deck flatlines.

**Slide choreography.** Not every slide has the same weight. The Steve-Jobs move: three slides of setup, one slide of payoff. The payoff slide should look and feel *different* from the setup, bigger type, less content, a single object on screen. In the OCM decks, slide 7 (The Four Moves) is a payoff slide; it earns its centrality by being the visual anchor for what came before and what's coming.

Rule: **payoff slides should feel like moments, not like more information.** Setup slides carry the information; payoff slides carry the emotion.

**The eyebrow question.** Every slide has an eyebrow question: what does this slide answer? If you can't state it in one sentence, the slide has too many jobs. When there's an ALL-CAPS eyebrow label ("DIAGNOSIS", "THE HINGE"), the eyebrow question is compressed into two words. When there's no eyebrow, the title is doing the eyebrow work, check that it does.

**Silence as design.** Real presentations have pauses. The stop-sentence gets a pause after it. The complex slide gets a pause before it. In the deck, "silence" shows up as whitespace: cards with breathing room, columns with air between them, YAML with line-height that lets the eye rest. Rushed slides look rushed on paper too, dense, edge-to-edge, no breath.

## How to use these lenses in a review

When reviewing a slide, run it against the four lenses in this order:

1. **Narrative:** what act is this slide in? What tension does it carry? Where does it hand off to the next slide? If you can't answer any of these, the slide isn't earning its place in the arc.
2. **Cognitive:** how many things is it asking the audience to hold? Fewer than four? If not, cut. Is the load germane (they need to learn this) or extraneous (decoration)?
3. **Sticky:** what will the audience quote after? If nothing, the slide has no landing. What's unexpected here?
4. **Design:** what's the slide's job vs the speaker's? Is the slide complete-and-self-contained (bad) or a scaffold for what the speaker will say (good)?

The order matters. Narrative first, if the slide is in the wrong act or has no tension, no amount of cognitive-load tuning will save it.

## What this skill does with the canon

When the user says "review slide N through the marketing lens," the skill:
1. Pulls up the slide-text and speaker-notes for slide N.
2. Applies the four lenses in order.
3. Produces findings for each lens with specific quotes from the slide.
4. Suggests concrete rewrites where the lens catches something.
5. Cross-references the persona files if a specific audience read matters.

When the user says "propose a slide for X," the skill:
1. Locates X in the arc (act 1, 2, or 3? Which beat?).
2. Names the tension state (setting up, holding, releasing).
3. Names what the slide should carry vs what the speaker carries.
4. Drafts slide-text + speaker notes in the voice guide.
5. Applies the SUCCES check before showing.

Not every review needs all four lenses. But every review should be able to name which lens it's using. Vague reviews ("this could be clearer") are lower-value than lens-specific reviews ("the payoff on slide 7 is undermined because slide 6 already released the tension, move the composition punchline earlier or split slide 7 into setup + payoff").
