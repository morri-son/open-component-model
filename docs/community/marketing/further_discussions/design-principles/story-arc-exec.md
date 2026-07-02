# Story Arc: Exec Decks

Per-slide narrative-arc analysis for the two OCM exec decks: `OCM-Story-Exec-External` and `OCM-Story-Exec-Internal-Sponsor`. The exec altitude sits above the architect deck, 15-minute talk, outcome-first, no YAML, mechanism named but not walked. The two decks open differently, external opens on three concrete blind spots, internal opens on strategic position, but they converge at Act 2 and share the Pack · Sign · Transport · Deploy bridge (Slide 8 external, Slide 7 internal). They diverge again at the close: external ends on Pilot · Evaluate · Engage, internal on Sponsor · Scale · Standardize.

## Act structure at a glance

| Act | External (17 slides) | Internal Sponsor (15 slides) |
| --- | --- | --- |
| Act 1, setup | 1 Hero · 2 Three Blind Spots · 3 Why Now · 4 The Answer | 1 Hero · 2 Why Now · 3 The Answer |
| Act 2, mechanics | 5 The Shift · 6 SBOM inside SBOD · 7 How OCM Composes · 8 In One Picture · 9 Sovereign-Ready · 10 Air-Gap · 11 Scan | 4 The Shift · 5 SBOM inside SBOD · 6 How OCM Composes · 7 In One Picture · 8 Sovereign-Ready · 9 Air-Gap · 10 Scan |
| Act 3, payoff | 12 What OCM Unlocks · 13 Trusted in Production · 14 CTA | 11 What OCM Unlocks for SAP · 12 Open Ecosystem · 13 SAP-Internal · 14 CTA |
| Appendix | 15 Abbreviations · 16–17 Trademarks | 15 Appendix (Abbrev / Trademarks) |

External spends one extra slide in Act 1 (Three Blind Spots is the pain hit before Why Now). Internal splits proof across two slides in Act 3 (open peers vs SAP-internal teams). The mechanic block is otherwise identical, one slide offset.

## External arc: slides 1 through 17

### Slide 1: Your supply chain has blind spots

- **What the slide is.** Hero. "Your supply chain has blind spots. Three minutes from now, you'll know what they are." NeoNephos attribution.
- **Narrative role.** Opening pain-strike. Names an unnamed problem, sets a promise with a countdown clock.
- **Tension state.** Rising, from zero.
- **What the SLIDE carries.** Three lines. The word `blind spots`, that's the whole hook. Line break isolates "blind spots" on its own line.
- **What the SPEAKER carries.** No notes exist. The speaker holds the room for two beats and lets the slide do the ambush.
- **Handoff.** Promise made, "three minutes from now." Slide 2 has to discharge that contract.

### Slide 2: Three Blind Spots

- **What the slide is.** Three columns naming the failures the current model can't see: Identity Drift, No Release Envelope, Unverified Arrival.
- **Narrative role.** Discharge of the Slide 1 promise. Concrete pain in three pictures.
- **Tension state.** Rising, peaking.
- **What the SLIDE carries.** Three column headers and one-sentence subheadings each. Sparse by design, reader can scan in eight seconds.
- **What the SPEAKER carries.** The colour: "signed at source, then it moved, to a mirror, to a customer's registry, into an air gap." The audience recognizes their own delivery chain in the paraphrase. Voice-of-audience framing ("if a regulator asks for proof …").
- **Handoff.** Stop-line: "Those are the blind spots. Now, why now." Pain named. Time-pressure argument next.

### Slide 3: Why Now

- **What the slide is.** Three columns of external forces: Sovereignty Pressure, Regulation Tightening, Supply-Chain Attacks Are Real. Named regulations (DORA, NIS2, CRA) and named breaches (SolarWinds, xz, log4shell).
- **Narrative role.** Time-pressure. Answers "why this quarter, not next year."
- **Tension state.** Holding at peak, pain now has a deadline.
- **What the SLIDE carries.** Regulation acronyms as brand-recognition anchors. Breach names as memory-anchors, the audience remembers waking up to those.
- **What the SPEAKER carries.** The frame that these are converging, not sequential. "The lesson the industry took: signatures must survive the journey, or compliance is theatre." That's the stop-line the audience quotes afterwards.
- **Handoff.** "Not faster pipelines. Different mechanics." Signals the pivot to solution-space.

### Slide 4: The Answer

- **What the slide is.** Meet OCM. Hub-and-spoke: artifacts on left, boundaries on right, compliance frameworks at bottom. One identity, every boundary.
- **Narrative role.** Pivot beat. Problem-space to solution-space.
- **Tension state.** First release, the audience finally has a name for what's next.
- **What the SLIDE carries.** The diagram does most of the work. Three axes, all covered, that's the MECE claim. `v1.0.0` bottom-right is a credibility anchor (this is a real released thing, not a research paper).
- **What the SPEAKER carries.** A two-second silence before speaking, so the audience reads the diagram. Then one line per axis. Land: "Meet OCM. One identity, every boundary." Move on.
- **Handoff.** Answer named. Now Act 2 has to earn it.

### Slide 5: The Shift

- **What the slide is.** SBOM lists. SBOD delivers. Three bullets defining SBOM, defining SBOD, naming the containment relationship.
- **Narrative role.** Conceptual reframe. The category the rest of the deck lives in.
- **Tension state.** Holding, new tension of "learn this term" replaces old tension of pain.
- **What the SLIDE carries.** The one-line contrast (`SBOM lists. SBOD delivers.`) is the stop-line. Third bullet does the disarm: OCM does not replace SBOM tooling.
- **What the SPEAKER carries.** Slow down here, this is the conceptual pivot of Act 2. "SBOM lists. SBOD delivers. The SBOM lives inside the SBOD." Say it slowly enough that people can write it down.
- **Handoff.** Term introduced. Next slide shows what's actually inside the envelope.

### Slide 6: The Shift: SBOM inside SBOD

- **What the slide is.** SBOD diagram. Component identity at the top (`github.com/acme/app:v1.0.0`), artifacts down the left (Docker images, Helm charts, K8s manifests, config, SBOM), signature bracket on the right, "one digest covers all."
- **Narrative role.** Visual anchor for the term just introduced. If they remember one picture from the talk, it's this one.
- **Tension state.** Releasing, abstraction turns concrete.
- **What the SLIDE carries.** The diagram. The location-independent identity at the top is the sneaky payload, it introduces the name-vs-location distinction before Slide 9 leans on it.
- **What the SPEAKER carries.** Silence. "If you take one thing from this talk, take this picture." Then pause. Do not talk over the diagram.
- **Handoff.** Envelope shown. Next slide addresses the objection sitting in every architect's head, "we already have signing."

### Slide 7: How OCM Composes

- **What the slide is.** Three columns: Signing, Transport, Compliance. Two lines each, "what you have today" then "what OCM adds."
- **Narrative role.** Objection-handling. Concede-then-extend.
- **Tension state.** Holding, releases skepticism, but doesn't yet release the main story.
- **What the SLIDE carries.** The two-line pattern is the whole argument. You keep your tools. OCM adds connective tissue. The columns are MECE across the three concerns everyone in the room already owns budget for.
- **What the SPEAKER carries.** The disarm out loud: "You probably hear me say 'OCM' and think, we already have signing. We have registries. We have scanners." Then walk each column with one punchline. Land: "Same tools. New connective tissue."
- **Handoff.** Objection defused. Now the picture that ties it all.

### Slide 8: OCM in One Picture

- **What the slide is.** Pack · Sign · Transport · Deploy → Sovereign Cloud. Four card icons, arrows, target glyph. The shared bridge slide across all four OCM decks.
- **Narrative role.** Payoff slide of Act 2. Demo replacement. Mnemonic.
- **Tension state.** Releasing, the whole mechanic collapses into four words.
- **What the SLIDE carries.** Four verbs. The shape is the argument. Sovereign Cloud on the right as the terminal state.
- **What the SPEAKER carries.** Point at each card while naming it. "One signature covers every artifact in the bundle. By digest. So if anything changes, the signature breaks." Physical choreography, the pointing is what makes it stick. Land: "Pack, sign, transport, deploy. That's OCM in operation."
- **Handoff.** Mnemonic established. Now the sovereign-cloud target gets its own dedicated slide.

### Slide 9: Sovereign-Ready

- **What the slide is.** Four bullets, Identity, Signatures, Transfer, Day-2 ops, each with `location-independent` or `self-contained` as the property, then a consequence.
- **Narrative role.** The regulator-and-CISO slide. Names sovereignty as a property, not a checkbox.
- **Tension state.** Holding, new tension around "prove this survives the air gap."
- **What the SLIDE carries.** The parallel structure, anchor · property · consequence. Repeated `No callback upstream` across bullets is the deliberate refrain.
- **What the SPEAKER carries.** "Sovereign-ready isn't a checkbox. It's a property of the delivery model." Then walk the four properties, holding "no callback" as the refrain. Stop-line: "The component is the trust boundary, not the registry, not the network."
- **Handoff.** Property claimed. Next slide proves it visually.

### Slide 10: Sovereign-Ready: Air-Gap

- **What the slide is.** Air-gap diagram. Source (Pack · Sign, public registry) on the left, trust boundary in the middle, sovereign target (Verify · Deploy, local registry, K8s cluster, auditor) on the right.
- **Narrative role.** Visual proof of the previous slide's property claim.
- **Tension state.** Releasing, audience sees the mechanism cross the boundary and land intact.
- **What the SLIDE carries.** The topology. Three checks on the destination side (local registry / cluster / auditor) close the loop, verification, deployment, and audit all happen inside the boundary.
- **What the SPEAKER carries.** Walk the diagram left to right, one sentence per column. Land: "Same identity. Same signature. Any location. That's the property."
- **Handoff.** Sovereign story landed. Compliance tooling next.

### Slide 11: Scan

- **What the slide is.** Compliance as a system property, not a quarterly retrofit. Four bullets naming ODG, the dashboard, async scans, contextual rescoring, identity-correlated evidence.
- **Narrative role.** "And there's tooling around it." The system-property claim gets its dashboard.
- **Tension state.** Releasing, the last mechanic beat.
- **What the SLIDE carries.** The one-liner subtitle carries the whole argument. `Open Delivery Gear` is introduced by name only, no walk-through.
- **What the SPEAKER carries.** Brief. Don't go deep. The scenario paraphrase, "when CVE-something-2026 drops at 11pm, you don't ask which of our products is affected, you query the OCM coordinate system", is the story-frame that makes it stick. Land: "Compliance becomes a property of the system. Not a Q3 deliverable."
- **Handoff.** Mechanics done. Act 3 opens.

### Slide 12: What OCM Unlocks

- **What the slide is.** Six-tile grid. Signing across stacks · Air-gapped delivery · K8s-native deploy · Async scans · One source of truth · Automated compliance reporting.
- **Narrative role.** Outcome enumeration. Payoff surface.
- **Tension state.** Released. This is give-back territory.
- **What the SLIDE carries.** Six tiles carry themselves; audience is reading, not being told. Each tile is name + one-line mechanism.
- **What the SPEAKER carries.** Don't read the tiles. Sweep across them in one paragraph, name the through-line: "All from one model. That's the point."
- **Handoff.** Outcomes shown. Now proof they're real.

### Slide 13: Trusted in Production

- **What the slide is.** Two-tier logo wall. Top row: BWI, SAP NS2 (production adopters). Bottom row: Gardener, Kyma, OpenControlPlane, Platform Mesh (peer projects). NeoNephos alignment footer.
- **Narrative role.** Credibility ground. Four claims stacked in the title, SAP stewards, NeoNephos governs, production-grade, sovereign-ready.
- **Tension state.** Released, audience is receiving proof.
- **What the SLIDE carries.** Logos. Two-tier layout separates production adopters from peer projects, deliberate MECE split.
- **What the SPEAKER carries.** Ground each row. BWI = German federal IT. SAP NS2 = regulated US workloads. Gardener = SAP's open Kubernetes orchestrator, five years in production. Don't oversell, the specificity is the credibility. Land: "Aligned with NeoNephos. Open source. Production-grade."
- **Handoff.** Proof landed. Ask next.

### Slide 14: Start delivering with confidence

- **What the slide is.** Three action lines: Pilot / Evaluate / Engage. Plus footer links, ocm.software, GitHub, community channels.
- **Narrative role.** Close. The ask.
- **Tension state.** Released, converting to action.
- **What the SLIDE carries.** Three verbs. QR code as the low-friction entry point.
- **What the SPEAKER carries.** Exec-shaped asks, not platform-lead asks. Pilot one regulated delivery this quarter. Have platform-eng and security brief you back. Bring your problem to the standard while it's being shaped. Close: "Pilot. Evaluate. Engage. That's the ask. Thank you." Then take questions.
- **Handoff.** Talk ends. Q&A begins.

### Slides 15–17: Appendix and trademarks

- **What the slides are.** Abbreviation reference (BSI C5, BTP, CRA, DORA, ODG, SBOD, SBOM, Sigstore, etc.). Two trademark-notice slides.
- **Narrative role.** Reference. Not part of the arc. Left in the deck for follow-up questions and external-publication compliance.
- **Tension state.** N/A.
- **What the SLIDE carries.** All the weight. No speaker notes yet, these are read-only slides.
- **What the SPEAKER carries.** Nothing during the talk. Post-talk reference.
- **Handoff.** None.

## Internal arc: slides 1 through 15

### Slide 1: Every LoB ships

- **What the slide is.** Hero. "Every LoB ships. Separately, every time. OCM is the shared standard. Each LoB still ships, on the same model." NeoNephos + SAP steward attribution.
- **Narrative role.** Opening pain-strike, internal-shaped. Names the SAP-specific pain: fragmented delivery across lines of business.
- **Tension state.** Rising, from zero.
- **What the SLIDE carries.** The `Separately, every time` line. That's the mirror the audience sees themselves in. Third line concedes autonomy, LoBs still ship, and names the shared piece.
- **What the SPEAKER carries.** No notes yet, the SLIDE carries the full weight. A senior speaker will land the "separately, every time" with a beat of silence.
- **Handoff.** Pain named. Why-now argument follows.

### Slide 2: Why Now

- **What the slide is.** Three columns of strategic pressure: Ecosystem Velocity, The Window, Disinvestment Cost. Subtitle: "Compliance and sovereignty are given. Our strategic position is a choice."
- **Narrative role.** Time-pressure, but rotated. External Slide 3 argued regulatory urgency; internal Slide 2 argues position-in-ecosystem urgency. The audience is sponsors, they need the strategic frame, not the compliance frame.
- **Tension state.** Rising, peaking.
- **What the SLIDE carries.** `The biggest contributor shapes the standard` and `Walking away costs more than staying`, those two lines carry the argument for a sponsor.
- **What the SPEAKER carries.** No notes yet, the SLIDE carries the full weight. The subtitle does the reframe: sovereignty is a given, position is the choice.
- **Handoff.** Strategic pressure named. Answer follows.

### Slide 3: The Answer

- **What the slide is.** Identical to external Slide 4. Meet OCM. Hub-and-spoke, three axes, `v1.0.0`.
- **Narrative role.** Pivot beat. Same function as external, problem-space to solution-space.
- **Tension state.** First release.
- **What the SLIDE carries.** The diagram. Same content, same visual weight.
- **What the SPEAKER carries.** No notes yet. External speaker notes for Slide 4 transfer directly, the audience-shaped framing is identical at this altitude.
- **Handoff.** Answer named. Act 2 begins.

### Slide 4: The Shift

- **What the slide is.** SBOM lists. SBOD delivers. Same three bullets as external Slide 5, plus a fourth: "SBOD is the category SAP defined. Now governed through NeoNephos."
- **Narrative role.** Conceptual reframe, with an internal ownership claim tacked on.
- **Tension state.** Holding.
- **What the SLIDE carries.** The extra bullet is the internal-specific payload, the sponsor needs to hear that SAP is the origin of the category and that governance is external (NeoNephos).
- **What the SPEAKER carries.** No notes yet, the extra bullet earns its own beat: "SAP defined this. NeoNephos governs it. That's the position."
- **Handoff.** Term introduced, ownership claimed. Visual next.

### Slide 5: The Shift: SBOM inside SBOD

- **What the slide is.** Same SBOD diagram as external Slide 6 (`github.com/acme/webshop:v1.0.0` instead of `app`, otherwise identical).
- **Narrative role.** Visual anchor.
- **Tension state.** Releasing.
- **What the SLIDE carries.** The diagram. Same as external.
- **What the SPEAKER carries.** No notes yet. External Slide 6 speaker notes transfer directly.
- **Handoff.** Envelope shown. Objection-handling next.

### Slide 6: How OCM Composes

- **What the slide is.** Identical to external Slide 7. Three columns: Signing / Transport / Compliance.
- **Narrative role.** Objection-handling. Same function.
- **Tension state.** Holding.
- **What the SLIDE carries.** Same two-line concede-then-extend pattern.
- **What the SPEAKER carries.** No notes yet. External Slide 7 speaker notes transfer directly.
- **Handoff.** Objection defused. Mnemonic next.

### Slide 7: OCM in One Picture

- **What the slide is.** The shared Slide 7 across all four decks. Pack · Sign · Transport · Deploy → Sovereign Cloud.
- **Narrative role.** Act 2 payoff. Demo replacement.
- **Tension state.** Releasing.
- **What the SLIDE carries.** The four verbs and the target glyph. Same as external Slide 8. Do not diverge, this is the bridge slide across all four decks.
- **What the SPEAKER carries.** No notes yet. External Slide 8 speaker notes transfer directly. Point at each card while naming it.
- **Handoff.** Mnemonic locked. Sovereign story next.

### Slide 8: Sovereign-Ready

- **What the slide is.** Same four bullets as external Slide 9. Identity, Signatures, Transfer, Day-2 ops. Each with location-independent / self-contained property.
- **Narrative role.** Property claim.
- **Tension state.** Holding.
- **What the SLIDE carries.** The parallel structure.
- **What the SPEAKER carries.** No notes yet. External Slide 9 notes transfer directly. Stop-line: "The component is the trust boundary, not the registry, not the network."
- **Handoff.** Property claimed. Visual proof next.

### Slide 9: Sovereign-Ready: Air-Gap

- **What the slide is.** Same air-gap diagram as external Slide 10.
- **Narrative role.** Visual proof.
- **Tension state.** Releasing.
- **What the SLIDE carries.** The topology.
- **What the SPEAKER carries.** No notes yet. External Slide 10 notes transfer directly.
- **Handoff.** Sovereign story landed. Compliance next.

### Slide 10: Scan

- **What the slide is.** Same as external Slide 11 with one addition, ODG named explicitly in the first bullet: "Open Delivery Gear (ODG), the OCM compliance automation engine, built on the same primitives."
- **Narrative role.** Compliance tooling introduction.
- **Tension state.** Releasing, Act 2 closing beat.
- **What the SLIDE carries.** Five bullets now instead of four. ODG gets its own line.
- **What the SPEAKER carries.** No notes yet. External Slide 11 notes transfer, with ODG earning a slightly earlier mention.
- **Handoff.** Mechanics done. Act 3 opens.

### Slide 11: What OCM Unlocks for SAP

- **What the slide is.** Six tiles, all SAP-flavoured. Faster sovereign delivery · Compliance leverage across LoBs · Integration after acquisition · Cross-LoB security correlation · One source of truth · Ecosystem stewardship.
- **Narrative role.** Outcome enumeration, sponsor-shaped. Each tile answers a specific sponsor concern, LoB fragmentation, M&A, cross-LoB blast radius.
- **Tension state.** Released.
- **What the SLIDE carries.** Six tiles. `Integration after acquisition` and `Cross-LoB security correlation` are the two tiles a sponsor did not see coming, those are the ones that convert.
- **What the SPEAKER carries.** No notes yet. The SLIDE carries the full weight. A speaker will linger on Integration-after-acquisition, the M&A story is the emotional hook for this audience.
- **Handoff.** Outcomes shown. Proof splits across two slides.

### Slide 12: Where OCM is Shipping: Open Ecosystem

- **What the slide is.** Peer-project logo row. Gardener, Kyma, OpenControlPlane, Konfidence.
- **Narrative role.** External credibility. "We're not alone."
- **Tension state.** Released.
- **What the SLIDE carries.** Logos. The `Peer in the open ecosystem` framing, SAP is peer, not owner.
- **What the SPEAKER carries.** No notes yet, the SLIDE carries the full weight. A speaker will name each project's role in one line.
- **Handoff.** Open proof shown. Internal proof next.

### Slide 13: Where OCM is Shipping: SAP

- **What the slide is.** Five SAP internal teams already running on OCM: Hyperspace, RBSC, CSI, Steampunk, Sovereign Services & Delivery. One-line role each.
- **Narrative role.** Internal credibility. The sponsor's peers are already running this.
- **Tension state.** Released, the ask is next.
- **What the SLIDE carries.** Five names and their function. This is the "your neighbours already went" slide.
- **What the SPEAKER carries.** No notes yet, the SLIDE carries the full weight. A speaker will pick the one team most adjacent to the sponsor's LoB and dwell.
- **Handoff.** Peer pressure applied. Ask next.

### Slide 14: Sponsor · Scale · Standardize

- **What the slide is.** Three asks. Sponsor (allocate engineering capacity), Scale (pack one regulated component this quarter), Standardize (bring your LoB into steering, `#sap-tech-ocm`).
- **Narrative role.** Close. Sponsor-shaped CTA.
- **Tension state.** Converting to action.
- **What the SLIDE carries.** Three verbs, sponsor-flavoured. Not `Pilot / Evaluate / Engage`, this audience owns engineering capacity, not a pilot budget.
- **What the SPEAKER carries.** No notes yet. The SLIDE carries the full weight. The Slack channel is on-slide, the sponsor writes it down.
- **Handoff.** Talk ends.

### Slide 15: Appendix

- **What the slide is.** Abbreviation reference. (The internal deck's appendix and trademark slides run 15–17 in the file, but the user's arc definition stops at 15.)
- **Narrative role.** Reference. Not arc.
- **Tension state.** N/A.
- **What the SLIDE carries.** All the weight. No speaker notes.
- **What the SPEAKER carries.** Nothing during the talk. Follow-up reference only.
- **Handoff.** None.

## Where they converge and where they diverge

### The shared bridge: Slide 7 (internal) / Slide 8 (external)

Pack · Sign · Transport · Deploy is byte-identical across both exec decks and both architect decks. Four verbs, four cards, one target glyph. The mnemonic is the deck's most portable asset, it survives being pulled out of context, embedded in a memo, quoted in a meeting. That's why the bridge exists. Never diverge, a change to Slide 7 changes all four decks.

### The near-shared middle: Slides 5–10 external ≈ Slides 4–9 internal

The Act 2 mechanic block is one slide offset but otherwise almost identical: SBOM/SBOD reframe, the envelope diagram, Compose objection-handling, the shared bridge, Sovereign-Ready property claim, air-gap visual. The offset comes from Act 1, internal skips the Three Blind Spots slide, so the mechanic block starts one slide earlier.

The only textual difference in the middle: internal Slide 4 adds a fourth bullet, "SBOD is the category SAP defined. Now governed through NeoNephos." That's a sponsor-only claim; it would land as brag on an external slide. Internal Slide 10 also names ODG explicitly in the first bullet, where external Slide 11 introduces ODG in speaker notes only.

### The divergent opening: pain-shape by audience

External opens on **concrete failure modes**: Identity Drift, No Release Envelope, Unverified Arrival. Three pictures the audience can recognize in their own delivery chain. The pain is technical and universal.

Internal opens on **strategic position**: Ecosystem Velocity, The Window, Disinvestment Cost. Three forces the audience can recognize in their own portfolio. The pain is positional and SAP-specific. The subtitle, "Compliance and sovereignty are given. Our strategic position is a choice.", is the whole rotation in one line.

Both openings serve the same narrative function (rising tension, pain that the answer will discharge) but they're pitched at different levels of the org: external decks pitch at the delivery-owner level, internal decks pitch at the sponsor level who is deciding where to allocate engineering capacity.

### The divergent close: CTA verbs

External closes on **Pilot · Evaluate · Engage**. Verbs pitched at an outside executive who can commission a pilot, hear a briefing, and join the steering conversation. Three low-commitment on-ramps.

Internal closes on **Sponsor · Scale · Standardize**. Verbs pitched at a sponsor who already has engineering capacity to allocate. The ask is bigger and more specific: allocate stewardship capacity, pack one regulated component this quarter, join the internal Slack channel. The internal CTA assumes the audience owns the resources; the external CTA assumes the audience needs to build a case.

### The divergent proof: one slide vs two

External Slide 13 collapses production adopters and peer projects onto one logo wall, two-tier. The audience is external, they don't need the SAP-internal team names.

Internal splits the proof: Slide 12 (open peer ecosystem) and Slide 13 (SAP-internal teams). Two slides because the sponsor cares about both, open ecosystem signals the position isn't hostage to SAP, and the internal team list signals that peers inside the company are already committed. The architect-internal deck compresses these back to one slide (its Slide 15) because the architect audience wants the pattern at a glance rather than the political framing.
