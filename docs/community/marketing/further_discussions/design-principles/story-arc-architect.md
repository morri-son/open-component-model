# Story Arc: Architect Deck (Per-Slide Analysis)

Both architect decks, external and internal, share the same 18-slide narrative arc. The technical spine (slides 2–12) is byte-identical between the two; the audience-shaped slides (1, 13, 15, 16, 18) diverge. This file walks the arc slide-by-slide. Each slide gets a narrative role, a tension state, what the slide carries, what the speaker carries, and how it hands off.

Read this alongside `marketing-canon.md`, the four lenses are the tools; this file shows them applied.

## Act structure

- **Act 1 (setup):** slides 1–4. Establish the problem, name the cause, hint at the answer, position the answer. Ends with a promise.
- **Act 2 (mechanics):** slides 5–12. The audience does the work. YAML, four moves, sign, transport, deploy, day-2 composition.
- **Act 3 (payoff):** slides 13–16. Adoption paths, honest edges, adopter proof (internal only), CTA. Release the tension, hand over the action.
- **Appendices:** slides 17–18. Pull-on-demand. Do not run in the main arc.

Total narrated: ~28 minutes. Slide 7 sits at the exact middle. That is not coincidence, it is the mnemonic anchor.

**Narration tiers (added 2026-07-15, see A27 and `architect-deck-conventions.md`).** The act structure below is unchanged, but the 30-minute talk no longer narrates all slides at equal weight. CORE slides carry the argument and are walked in full: 1-8, 10, 12-16. SURVEY slides carry breadth the argument does not need in one pass and are skimmed unless the room engages: Slide 9 (Sign, three schemes) and Slide 11 (Deploy, four-CR chain), their detail is depth-on-demand in the speaker notes. This is the fix for "deep AND broad overwhelms": tier the narration, do not cut slides. The pivot (S3), mnemonic (S7), air-gap peak (S10), day-2 payoff (S12), and trust-earning (S14) are all CORE and protected.

## Act 1: Setup (slides 1–4)

### Slide 1: Pain / Opener

*External text:* "You ship pieces. Nothing carries the release."
*Internal text:* "What's a release, as one signed unit?, The model. The mechanic. The honest edges."

- **Narrative role:** cold-open (external) or promise-frame (internal). Both establish that the arc is about *release-level integrity*, not artifact-level signing.
- **Tension:** rising. This slide is where the audience decides whether to keep listening.
- **Slide carries:** the noun. "Release" (external) or "signed unit" (internal). No mechanism yet, mechanism would be premature.
- **Speaker carries:** the gap. Not "here's OCM." Rather: "here's the thing you already feel, that nobody has named for you." External speakers open cold; internal speakers acknowledge the audience has heard the name and re-frame as *architecture-track depth*.
- **Handoff:** the audience walks off slide 1 with a felt problem and a question. Slide 2 delivers the diagnosis.

### Slide 2: DIAGNOSIS

*Text:* "In every existing tool, identity is bound to location."

Three bullets, one per artifact type. OCI images pinned by digest, Helm charts by version, SBOMs by referrer, each pins something, none pins the release.

- **Narrative role:** cause. Names *why* the problem on slide 1 exists. Not "your tools are bad", but "your tools each solve one piece, and the pieces don't compose."
- **Tension:** holding. Audience is now in "I see the problem" mode. This is the hardest slide to write because it must concede what's true (digest pins the bytes) before naming what's missing (nothing pins the release).
- **Slide carries:** three bullets in parallel structure. Same syntactic shape per bullet, that's germane cognitive load, the audience is learning the pattern.
- **Speaker carries:** the concession. "Yes, cosign attestations sign each piece. Keep doing that. What's missing is a name for the release as one unit." The concession earns the argument.
- **Handoff:** the audience wants a solution now. Slide 3 gives them the fulcrum.

### Slide 3: THE HINGE

*Text:* "Identity that travels with the artifact."

Native PowerPoint coordinate-travel diagram: one identity chip at top, three registry cylinders below, per-cylinder access label.

- **Narrative role:** **pivot beat.** This is where the deck turns from problem-space to solution-space. If the audience does not get this slide, no later slide will land.
- **Tension:** rising then partly released. The audience sees the reframe: identity ≠ location.
- **Slide carries:** the diagram. Not text-heavy. The three cylinders are the payoff, one identity, three places, same digest.
- **Speaker carries:** the reframe. "Move the artifact. The digest stays. Only the access changes. That is the whole trick." Land it. Pause. Do not continue immediately.
- **Handoff:** the audience now needs to know what this pivot lets them do. Slide 4 positions the answer against their existing tools.

### Slide 4: POSITIONING

*Text:* "Wraps every artifact. Signs the whole release."

Three columns: ANY FORMAT · ANY LOCATION · ONE SIGNATURE.

- **Narrative role:** promise. The slide says: here is what OCM is, and, critically, what it is not. It does not replace your OCI, your Helm, your cosign. It composes around them.
- **Tension:** released briefly. This is the end of Act 1. The audience should have a mental image of *what OCM is* before the mechanics start.
- **Slide carries:** three column headers, one two-line body per column. MECE by construction, every artifact goes through this frame.
- **Speaker carries:** the "does not replace" beat, calibrated to audience:
  - External: cosign, sigstore, OCI 1.1 referrers. Peer-CNCF framing.
  - Internal: RBSC, Hyperspace, Open Delivery Gear. SAP-stack framing.
  Q&A backup on SBOD vs SBOM belongs here, internal audience has heard "SBOD" and needs to know it's the same object.
- **Handoff:** promise made. Now the audience wants to see the mechanism. Slide 5 opens Act 2.

## Act 2: Mechanics (slides 5–12)

Act 2 is where attention gets spent. The audience is now working. They will follow, but they will also fatigue. Design the sequence so each slide earns its complexity.

### Slide 5: CONSTRUCTOR

*Text:* "What you write." YAML, ~17 lines, hand-authored.

- **Narrative role:** first concrete artifact. The audience sees what a component looks like *as input*.
- **Tension:** rising, new information, new attention cost.
- **Slide carries:** the YAML. Colour-disciplined (keys mid-blue, values dark-grey). Real, not pseudo-YAML.
- **Speaker carries:** the walk. Point at `components:`, one entry, name DNS-style, version SemVer. Point at `resources:`, every artifact. Point at `input:` vs `access:`, by-value vs by-reference. Do not rush.
- **Handoff:** the audience has now seen what you write. The next slide shows what you don't write, what gets generated, signed, and travels.

### Slide 6: DESCRIPTOR

*Text:* "What gets signed and travels." YAML again, generated, not hand-edited.

- **Narrative role:** the counterpart to slide 5. This is where the signature story lives.
- **Tension:** peak of Act 2 setup. This slide is the hardest in the mechanics range. Signature semantics land here.
- **Slide carries:** the descriptor YAML with `access`, `digest`, `signatures:` fields highlighted. Colour discipline shifts: signatures are brand-blue.
- **Speaker carries:** three beats, in order. Signed: the descriptor hash, covers every resource digest. Not signed: the access fields, so transport can rewrite them. Stop-sentence: "Sign the descriptor hash, not the access." Seven words. Land and pause.
- **Handoff:** the audience now understands the mechanism at low altitude. Slide 7 pulls back to high altitude, the four moves.

### Slide 7: THE FOUR MOVES

*Text:* "Pack · Sign · Transport · Deploy."

Four cards with icons, connected by arrows, ending at a Sovereign Cloud target glyph.

- **Narrative role:** **the mnemonic anchor of the entire deck.** Every architect deck AND every exec deck uses this slide. Same content, same shape. It is the bridge.
- **Tension:** released. Act 2's first three slides (5, 6) were intense. Slide 7 is a payoff slide by design, bigger type, less content, one visual object.
- **Slide carries:** the four verbs. Pack. Sign. Transport. Deploy. In that order. Ever.
- **Speaker carries:** the framing. "These are lifecycle moves, not CLI verbs. The CLI is `ocm add cv`, `ocm sign cv`, `ocm transfer cv`, `kubectl apply`. Same four moves." That earns the payoff feel.
- **Handoff:** the audience now has a mnemonic. Slides 8–11 walk each move.

### Slide 8: COMPOSE

*Text:* "Service carries resources. Product carries references."

Two YAML blocks side by side. Service (`resources:`) vs Product (`componentReferences:`).

- **Narrative role:** introduce composition. The audience needs this before signing, transport, and deploy make sense at scale, because real components have parents and children.
- **Tension:** rising again. New concept, new cognitive load.
- **Slide carries:** two YAML blocks, one composition arrow between them.
- **Speaker carries:** transitive trust. The product's signature covers each reference's descriptor digest, re-signing a child breaks the parent. This is the load-bearing detail architects will test.
- **Handoff:** now that the audience knows components can compose, they need to see how each of the four moves works on both simple and composed components. Slides 9–11 do that.

### Slide 9: SIGN

*Text:* "Same signed object. Three signing options." Three columns, RSA · OpenPGP · Sigstore.

- **Narrative role:** the flexibility promise. Not one signing scheme; three trust models, one signed object.
- **Tension:** holding. This is a survey slide, audience skims, speaker deepens.
- **Slide carries:** three column headers with a two-line body each. Discipline: OpenPGP (not GPG) in the middle column. Slide 10 header is deliberately singular ("SIGN"), no plural, no "signing options" in the title itself, the subtitle carries that.
- **Speaker carries:** honest scope. All three work in the CLI. The v1alpha1 Kubernetes controller implements *RSA only* today. If a security architect asks, say so, don't dodge. Q&A backup on the Component CR `verify:` field goes here: pins signature-name + public-key, not scheme.
- **Handoff:** the audience knows how signing works. Now, how does the signed thing travel?

### Slide 10: TRANSPORT

*Text:* "Three patterns. One command."

Three columns: Registry → Registry · Registry → CTF · CTF → Registry.

- **Narrative role:** the transport promise. One command, three topologies. The air-gap case is the emotional peak.
- **Tension:** rising in air-gap direction. The audience is regulated-industry-adjacent; air-gap is the payoff they've been waiting for.
- **Slide carries:** three transport patterns. Same command across all three: `ocm transfer cv <src> <dst>`.
- **Speaker carries:** the air-gap footgun. Default transfer copies only the descriptor; access fields still point back at the source. For actual air-gap you MUST pass `--copy-resources`. Named upfront so slide 14 doesn't feel retroactive.
- **Handoff:** the component now travels. What happens when it lands?

### Slide 11: DEPLOY

*Text:* "Repository → Component → Resource → Deployer."

Four-card chain in the card family (mirrors slide 7's shape).

- **Narrative role:** the destination story. Kubernetes-side. The four CRs that verify, resolve, and apply.
- **Tension:** holding.
- **Slide carries:** four cards, arrows between. Same visual family as slide 7, the audience recognizes the pattern.
- **Speaker carries:** verification-opt-in disclosure on the COMPONENT card. Without a `verify:` entry, the controller pulls but does not check signatures. This is where a Lead Architect leans in, don't hide it.
- **Handoff:** the audience has seen pack, sign, transport, deploy for a single component. Now, how does day-2 upgrade work?

### Slide 12: COMPOSITION (Day-2)

*Text:* "One product. Three components. One line to upgrade."

YAML: change one line in the product's `componentReferences:`, re-sign, downstream picks up.

- **Narrative role:** the day-2 payoff. Everything before was pack-time; this slide is what happens *forever after*.
- **Tension:** peak of Act 2. This is the last mechanic slide, and it's the one that makes the model worth investing in.
- **Slide carries:** two changed lines highlighted in brand-blue, everything else in neutral grey. Visual discipline says: your eye goes to blue, blue is the change.
- **Speaker carries:** the operational rhythm. "Commit. The controller pulls the new descriptor, verifies the signature, applies. Notes rolls forward; postgres is untouched." Stop-sentence: "Every digest pinned by the signature. The cluster cannot drift."
- **Handoff:** Act 2 is done. The audience knows the mechanism end-to-end. Now they need to know what to do with it.

## Act 3: Payoff (slides 13–16)

Act 3 releases tension. Adoption, honest edges, adopter proof, CTA. Slides here should feel lighter, the audience has spent attention; give them back.

### Slide 13: ADOPTION

*External text:* "Two paths to a first OCM component", FROM ZERO (CLI) vs ON YOUR CLUSTER (controllers).
*Internal text:* "Two SAP-shaped paths", PACK & SHIP (CLI + RBSC) vs DEPLOY & OPERATE (Open Delivery Gear + Open Control Plane).

- **Narrative role:** the "how do I start" answer. First concrete next-step.
- **Tension:** releasing. Two cards, parallel structure, low text density.
- **Slide carries:** two card headers, four body lines each. Clean columns.
- **Speaker carries:** audience-shaped. External speaker sells time budget (30-min laptop, 30-min cluster) in notes only, never on slide. Internal speaker owns the Landscaper sunset and Hyperspace v1/v2 gap in notes.
- **Handoff:** the audience now has a first-move. But before they leave, we owe them the honest edges.

### Slide 14: WHAT'S SHARP

*Text:* "Three honest edges."

- **Narrative role:** the trust-earning beat. Every deck that lands has this slide. Without it, architects assume you're hiding worse.
- **Tension:** low, audience is comfortable now, this is a "we're peers" slide.
- **Slide carries:** three bullets. Not softened. Not apologetic. Just accurate.
  1. Controllers are v1alpha1, pin to specific release tags.
  2. Transfer defaults to descriptor-only; pass `--copy-resources` for air-gap.
  3. Helm-deploy adds kro + Flux or Argo CD, the OCM controllers don't ship them.
- **Speaker carries:** the framing. "Honest now beats apologetic later. Plan for the trim edge."
- **Handoff:** the audience trusts you more than they did on slide 13. Now, if this is real, who else runs it?

### Slide 15: ADOPTER PROOF (internal deck only)

*Internal text:* "Open ecosystem on the left. SAP teams on the right." Two-column: 4 open-source SAP projects + 5 SAP-internal teams.

- **Narrative role:** proof of production. Answers the "is this real?" question with logos and names, not adjectives.
- **Tension:** releasing.
- **Slide carries:** logos and text. Zero mechanism.
- **Speaker carries:** the Hyperspace v1/v2 caveat. In production for SBOM aggregation on v1; v2 integration on 2026 roadmap. Not aspirational.
- **Handoff:** the audience has now seen: pain, mechanism, adoption path, honest scope, and real users. They are ready for the ask.

*External deck does not have this slide. The external adopter-proof shape is different, CNCF-facing peer projects live in speaker notes for slide 16, not on a slide.*

### Slide 16: CTA

*External text:* "Ship the release as one unit.", Evaluate · Pilot · Engage.
*Internal text:* "Pilot. Standardize. Steward.", the three SAP-adoption verbs.

- **Narrative role:** the ask. Three concrete next actions.
- **Tension:** fully released.
- **Slide carries:** three action-path lines, one verb per line.
- **Speaker carries:** the specificity. Each verb has one concrete first-move. Not "pilot OCM", but "pack one product as an OCM component in your team this quarter."
- **Handoff:** to Q&A. The main arc ends here.

## Appendices (17–18): pull-on-demand

### Slide 17: REPLICATION APPENDIX

Dimmed four-card chain (grey) + one highlighted Replication card (brand-blue).

- **Role:** answers "how does cluster-side mirroring work without the CLI?" Not narrated. Pulled if asked.
- **Slide carries:** the visual, chain echo + highlighted subject.
- **Speaker carries:** one line if asked. "Replication is the controller-side equivalent of `ocm transfer cv`. `status.lastTransferredDigest` is the check."

### Slide 18: deck-specific appendix

*External:* HOW OCM COMPARES matrix (cosign / SLSA / SBOM / OCM).
*Internal:* Acronym glossary.

- **Role:** kill an objection the audience is holding. External kills "why not compose existing tools?" Internal kills "wait, what's ODG / RBSC / SS&D?"
- **Slide carries:** dense information, this slide breaks the low-density rule *deliberately* because it's a lookup, not a beat.
- **Speaker carries:** minimal. "This slide is for Q&A. Don't narrate."

## Beats to protect

If a session proposes changes that break any of these, push back:

- **The pivot at slide 3.** "Identity that travels with the artifact" is the whole reframe. Anything that dilutes it dilutes the deck.
- **Slide 7 as the shared bridge.** The four moves is the mnemonic across all four decks. If someone proposes changing to three moves or five, they are proposing to break the deck family.
- **The stop-sentence rhythm.** Slides 3, 6, 7, 12, 14 all have stop-sentences. Any of them can be improved, none of them can be dropped.
- **Slide 14 as trust-earning.** The three honest edges. If a session wants to remove one to make the deck "sharper," they are proposing to make the deck untrustworthy.
- **The Act 3 release.** After slide 12, tension releases. Slides 13–16 should feel lighter. If a session tries to add mechanic-density to Act 3, it's fighting the arc.

## Where the arc could be sharpened (open questions)

These are candidate improvements this file does not settle, a future session should decide with the user.

- **Slide 1 vs Slide 3 tension.** The internal-architect Slide 1 ("What's a release, as one signed unit?") already gestures at the answer. Does that undercut the slide 3 pivot? Or does it prep the audience so slide 3 lands harder?
- **Slide 2 concession weight.** The "cosign is fine, keep doing that" concession is speaker-only. Should it be on the slide? Risk: on-slide it flattens the tension.
- **Slide 8 (Compose) placement.** Currently between Sign and Transport. Could it move before Sign? Argument for: composition is orthogonal to signing; putting it first frames the whole rest. Argument against: composition is easier to explain once the audience has seen a single component signed.
- **Slide 12 as Act 2 end vs Act 3 start.** Currently framed as end-of-mechanics (Act 2). Could equally be framed as start-of-payoff (Act 3). Depends on whether "day-2 lives forever" is a mechanism or a promise.

These are worth exploring, not settling by fiat.
