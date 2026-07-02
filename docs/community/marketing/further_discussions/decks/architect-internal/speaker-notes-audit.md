# Speaker Notes Audit — architect-internal

Purpose: catch AI-slop patterns in `speaker-notes.md` before the deck goes in front of an SAP-internal architect audience. Same lens as the architect-external audit — the voice-guide's rules for rhythm, tone, and jargon apply — but the reader is different. Internal architects know the SAP stack (RBSC, Hyperspace, Piper, Landscaper, Open Delivery Gear, Open Control Plane, SLC-29) and will spot vague adopter claims, missing sunset dates, or hand-waving about migrations faster than an external audience would. That makes the audience-shaped slides — 1, 4, 13, 15, 16, 18 — the ones with the most room to slip.

The technical spine of the deck (slides 2–12, plus 14 and the replication appendix at 17) reuses the architect-external notes verbatim or near-verbatim. Findings for those slides live in `../architect-external/speaker-notes-audit.md`; this file references that audit rather than repeating the analysis. Only the audience-shaped slides get a full pass here.

Format per slide: findings, impact, proposed rewrite. Clean slides get one line.

---

## Slide 1 — What's the release

**Findings.**

- The framing is fine — opening with a question, not the noun, is exactly what the voice-guide calls for. It also does real work: half the room has been briefed, half hasn't, and the question gives both a common start.
- "Gives both groups in the room the same starting point" is doing organizer-notes work more than speaker-notes work. It explains why the frame exists rather than telling the presenter what to say. Fine, but it's the kind of meta-commentary that could be trimmed if the note gets edited for length.
- The scripted sentence — *"For the next 30 minutes we're walking the model behind one signed unit — what it is, how it travels, and what's still sharp."* — is well-shaped. Three concrete beats, no hyperbole, lands on `what's still sharp` which foreshadows slide 14 without overplaying it. Keep.
- One nit: the slide title in the notes is `What's the release` with a stray back-tick style curly apostrophe (`What‘s`) — cosmetic, but worth fixing so grep doesn't miss it.

**Impact.** Low. This slide's notes are close to voice already. The main risk is the meta-commentary sentence reading like it was written for the deck author, not the speaker.

**Proposed rewrite.** Minor tidy — collapse the meta-commentary into one sentence that still tells the speaker what the slide does:

> Open with the question, not the noun. The already-briefed half recognises the frame; the un-briefed half gets handed it.
>
> One sentence to land: *"For the next 30 minutes we're walking the model behind one signed unit — what it is, how it travels, and what's still sharp."* Then slide 2.

---

## Slide 2 — DIAGNOSIS

Reuses external notes verbatim. See `../architect-external/speaker-notes-audit.md` slide 2. Only cosmetic difference is a missing paragraph break before `Diagnosis: identity is bound to location.` — worth adding for the presenter's eye but not a voice issue.

---

## Slide 3 — THE HINGE

Reuses external notes verbatim, including both Q&A backups (name uniqueness, squatting / per-component trust). See `../architect-external/speaker-notes-audit.md` slide 3.

---

## Slide 4 — WHERE OCM SITS

**Findings.**

- The opening sentence — *"OCM does NOT replace OCI, Helm, cosign, sigstore, your SBOM tooling. It WRAPS them — adds one envelope signature over the whole release."* — is clean, direct, does the pre-emption work the slide is there for. Keep.
- Bullet shapes are close to template shape: `Any format`, `Any location`, `One signature`, each followed by an em-dash and a one-liner. This is exactly the AI-slop enumeration pattern the voice-guide flags — three items, same syntactic shape, same length. The external deck has the same shape here, so this is inherited, not a new issue. Worth flagging anyway. A real enumeration would have items of different lengths.
- The SAP-stack Q&A backup is the substantial audience-shaped addition. It works — RBSC, Hyperspace, Open Delivery Gear each get one clause naming what they do and what OCM does relative to them. `RBSC ships products; OCM describes the product so RBSC can ship it consistently` is the shape the voice-guide wants: concede, then extend.
- The `Hyperspace builds artifacts; OCM is the metadata wrapper added on top - the existing Piper steps stay.` line is doing important reassurance work — an internal architect worried that OCM adoption means rewriting Piper steps gets the direct answer. Good.
- `Open Delivery Gear handles compliance automation on top of OCM components` — accurate, but `compliance automation` is vague. If the audience is going to ask "compliance for what," the current wording won't survive it. Sharpen with a concrete example (SLSA provenance rollup? SBOM aggregation? policy checks?) or drop the modifier and just say `runs on top of OCM components`.
- `None of these are replaced. OCM is the shared primitive they all align on.` — solid landing. `shared primitive` is the right level of abstraction here; not MBA-speak, actually names the mechanism.
- The SBOM Q&A backup is fine — concrete, names the mechanism (SBOMs go INTO the component as resources), no hedging.
- One structural note: the internal deck's slide 4 notes drop the external deck's `SBOD` (Software Bill of Delivery) vocabulary backup. That's a defensible choice — SBOD is our external-facing positioning term and might read as marketing to an internal architect audience. But if `SBOD` is ever going to come up (someone saw a website page, someone saw an earlier deck), the backup should be there. Consider adding a one-line: *If asked about SBOD: it's the external-facing name for the component descriptor. Same object, different word.*

**Impact.** Medium. The SAP-stack Q&A is the load-bearing addition for the internal audience — it's where the deck earns the right to be different from the external version. `compliance automation` is the weakest word in the whole note; everything else holds.

**Proposed rewrite.**

Replace the Q&A backup on SAP-stack equivalents with:

> Q&A backup on SAP-stack equivalents:
> - RBSC ships products; OCM describes the product so RBSC can ship it consistently.
> - Hyperspace builds artifacts; OCM is the metadata wrapper added on top — the existing Piper steps stay.
> - Open Delivery Gear runs on top of OCM components — SBOM aggregation, compliance signal rollup, policy hooks.
> - None of these are replaced. OCM is the shared primitive they all align on.
>
> Q&A backup if asked about SBOD: it's the external-facing name for the component descriptor. Same object, different word.

---

## Slides 5–12

Technical spine — reuses external notes verbatim or near-verbatim. See `../architect-external/speaker-notes-audit.md` slides 5–12. Minor differences observed:

- Slide 7 (OCM IN ONE PICTURE) — identical.
- Slide 8 (COMPOSE) — one paragraph-break difference, no wording change.
- Slide 11 (DEPLOY) — `Flux or Argo CD` reads `Flux (or Argo CD)` in external. Same claim.
- Slide 12 (DAY 2) — one paragraph reordering, no wording change.

None of these are voice issues.

---

## Slide 13 — ADOPTION

**Findings.**

- The two-path framing — PACK & SHIP / DEPLOY & OPERATE — is the right shape for the internal audience. External gets `From zero (CLI)` and `On your cluster (controllers)`; internal gets the SAP-toolchain-facing version. Correct call.
- PACK & SHIP: *"OCM CLI produces component descriptors. RBSC integration with the CLI is live. The 30-minute laptop hands-on is the first half of this card; the production shape is wiring it into the team's release pipeline."* — direct, names the mechanism, no puff. Keep.
- DEPLOY & OPERATE: *"Open Delivery Gear runs the compliance automation engine using the OCM coordinate system. Open Control Plane is the declarative deployment runtime — the long-term replacement for Landscaper."* — `compliance automation engine` reappears here. Same issue as slide 4: `automation engine` is filler. What does it actually do? Recommend `runs compliance and SBOM rollup using the OCM coordinate system` or similar concrete phrasing.
- The Landscaper sunset Q&A backup is exactly the shape the voice-guide wants: names the current state (Landscaper deploys type-A services today), names the migration window (end-of-year / early next year), names the invariant (OCM components stay the same). Good.
- The Hyperspace Q&A backup is honest and specific — `Hyperspace integration exists today on OCM v1. The v2 migration is on the 2026 roadmap, not started yet.` This is the tone the voice-guide asks for on trim edges: not softened, not apologetic, accurate. The follow-up — *"Internally, Hyperspace already uses OCM for SBOM aggregation"* — concedes what's true before naming what's missing. Textbook.
- `This is why it's on the adopter-proof slide but not as an adoption path - the path is still being built.` — good honest line. Keep.
- The renames Q&A backup — `OCM Gear → Open Delivery Gear (ODG)`, `Managed Control Plane → Open Control Plane` — is useful reference material and the closing beat *"We hardened the naming when we hardened the projects"* has the dry wit the voice-guide allows. Keep.
- No hyperbole, no MBA vocabulary, no fake enumerations. This is one of the strongest slides in the deck.

**Impact.** Low-to-medium. The `compliance automation engine` phrasing is the one thing that reads AI-shaped; the rest is solid.

**Proposed rewrite.** Only the DEPLOY & OPERATE line needs work:

> DEPLOY & OPERATE: Open Delivery Gear runs compliance and SBOM rollup using the OCM coordinate system. Open Control Plane is the declarative deployment runtime — the long-term replacement for Landscaper.

Everything else stands.

---

## Slide 14 — WHAT'S SHARP

Reuses external notes verbatim. See `../architect-external/speaker-notes-audit.md` slide 14. The three edges (transfer defaults, controllers v1alpha1, kro + Flux/Argo dependency) are the same three the external deck names. No divergence needed — the sharp edges are sharp for everyone.

---

## Slide 15 — ADOPTER PROOF

**Findings.**

- The framing sentence — *"Adopter proof, two columns. The exec-internal deck splits this across two slides; we combine into one for the architect-track audience."* — is fine. Tells the presenter why the layout differs from the exec deck.
- LEFT column (four open-source projects: Gardener, Kyma, Open Control Plane, Konfidence): the parenthetical `Konfidence (aka DWC – Deploy with Confidence)` is good — surfaces the internal name an architect will actually recognise. `All aligned with the NeoNephos Foundation` is the right anchor. `These are not just adopters - they are part of the open ecosystem OCM is building with.` — one soft edge here. `part of the open ecosystem OCM is building with` is slightly puffy. `Aligned around a shared foundation` or `co-developing under NeoNephos` says the same thing more concretely. Optional edit.
- RIGHT column (five SAP-internal teams: Hyperspace, RBSC, CSI, Steampunk, Sovereign Services & Delivery): `These are SAP-only; no public logos.` — dry, direct, exactly the voice. Keep.
- Hyperspace caveat: repeats the same v1 / v2 / SBOM aggregation story from slide 13. Repetition is deliberate — the audience will ask again if it's not repeated. Keep. The `BUT:` is a minor voice affectation; the voice-guide is fine with it as a genuine turn signal, not filler.
- Sovereign Services & Delivery paragraph: *"the Sovereign Cloud delivery use case is the cleanest current OCM end-to-end story (pack, sign, ship via Landscaper today, will move to Open Control Plane)."* — the parenthetical does real work. Concrete, names the pipeline, names the migration. Good.
- Q&A backup on conspicuous absences: *"ACD, Hana Cloud / SGSC traceability - these were in the 2024 plan but have not made the same progress. We don't claim them as adopters; we claim them as 'considering / in conversation.' Better to under-claim than over-claim."* This is the deck's most voice-guide-shaped moment. Names the absences openly, concedes the 2024 plan overreached, ends on the calibration principle. Keep untouched.

**Impact.** Low. The one soft phrase (`part of the open ecosystem OCM is building with`) is the only edit worth making. Everything else is on-voice.

**Proposed rewrite.** Micro-edit on the LEFT column line:

> LEFT — four SAP-internal projects that are also open source: Gardener (managed Kubernetes), Kyma (cloud-native runtime), Open Control Plane, Konfidence (aka DWC — Deploy with Confidence). All aligned under NeoNephos Foundation governance and co-developing the surrounding open ecosystem.

Rest stands.

---

## Slide 16 — Ship the release as one unit.

**Findings.**

- Pilot / Standardize / Steward is a good architect-shaped closer for an internal audience. Three concrete next-quarter actions, each named. The external deck's closer (Evaluate / Pilot / Engage) is community-facing; this one is org-facing. Correct differentiation.
- PILOT: *"Pack one product as an OCM component, in your team, this quarter. Not a laptop demo - a real product, in your existing pipeline. RBSC is the cleanest first wire-up if you ship via RBSC today."* — direct, names the concrete step, gives a specific first-wire-up recommendation. Keep.
- STANDARDIZE has the deck's most important reframe: *"we are NOT mandating OCM via SLC-29 or via a top-down product standard. The 2024 plan named that path; the 2026 strategy is different. We invest in the CLI/Toolkit quality so that OCM becomes the standard because it's the best tool for the job — bottom-up."* This is the beat the internal audience needs to hear. Names the 2024 plan explicitly, names the shift, names the mechanism (invest in CLI/Toolkit quality). No MBA-speak. Keep.
- One small snag: *"The Elton Mathias support from SGSC is still on the table for future inclusion, but it's not the lever we're pulling first."* — this is genuinely inside-baseball. Two proper nouns (Elton Mathias, SGSC) in one sentence; if the room doesn't already know who Elton is and what SGSC's leverage is, the line reads as a private aside. Options: (a) drop it, (b) expand it into one clause explaining what the SGSC lever actually is. If the presenter is comfortable it will land, keep. If not, cut.
- STEWARD: *"Bring your LoB into the OCM steering conversation. Slack #sap-tech-ocm. We meet every four weeks; cross-LoB design decisions land there. If your LoB has a stake in component-delivery architecture, you should be in the room."* — concrete channel, concrete cadence, concrete invitation. Good.
- Closing line: *"'One primitive. Your stack. Your call.' Then pause. Don't trail into the appendix."* — three short beats, mirrors the rhythm rule. Keep.

**Impact.** Low-to-medium. Two edits worth considering: the Elton Mathias / SGSC line (drop or expand), and one cosmetic — the STANDARDIZE line has `CLI/ Toolkit` with a stray space. Fix.

**Proposed rewrite.** Two micro-edits:

1. Fix the spacing: `CLI/Toolkit quality`.
2. Elton Mathias / SGSC — either drop the sentence, or expand:

> The SGSC-side support (Elton Mathias's team) is on the table for future inclusion. Not the first lever we're pulling.

Choose based on whether the room will recognise the name. If in doubt, drop.

Everything else stands.

---

## Slide 17 — APPENDIX · REPLICATION

Reuses external notes near-verbatim (external slide 16). See `../architect-external/speaker-notes-audit.md` slide 16. One minor difference: the internal deck drops `air-gap mirroring kept in-cluster rather than on a workstation` from the use-cases list. Defensible — the internal audience is less air-gap-obsessed — but if the use case is real, keep it. Trivial.

---

## Slide 18 — APPENDIX · ABBREVIATIONS

No notes. Nothing to audit. The slide-text audit (separate file) is where the abbreviation set gets checked for completeness against the audience's likely vocabulary.

---

## Summary

The internal deck's notes are, on the whole, on-voice. The strongest slides are 13 (ADOPTION) and 15 (ADOPTER PROOF) — both do the hard work of naming what's in flight, what's on the roadmap, and what's been quietly dropped, without softening.

Weakest spots:

1. Slide 4 — `compliance automation engine` and its cousin phrasings are filler. Replace with concrete mechanism.
2. Slide 13 — same phrase reappears. Fix in both places.
3. Slide 16 — the Elton Mathias / SGSC sentence is inside-baseball. Drop or expand.
4. Slide 4 — dropped SBOD backup may be needed for an audience that has seen the external material.

No slide-1 rewrite required beyond a cosmetic tidy. Slides on the technical spine are covered by the external audit and don't need re-review.
