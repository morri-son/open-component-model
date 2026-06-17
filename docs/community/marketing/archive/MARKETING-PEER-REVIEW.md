# Marketing Peer Review — Exec Deck Content Variants

Second-chief review of `NARRATIVE.md`, `MARKETING-CRITIQUE-EXEC.md`, `EXEC-DECK-REWORK-OPTIONS.md`, `CONTENT-OPTIONS.md`, `DIAGRAM-OPTIONS.md`. Register: direct second opinion (substance, not just expansion), with embedded *hostile-reviewer* subsections that pressure-test each framing as a competitor or skeptical CIO would.

This is a peer review, not a rewrite. Where I disagree with the first chief on substance, I say so plainly and recommend overriding. The first chief's analysis is strong on slides 1, 8, and 10, soft on slides 2/3 and on cost-of-inaction, and *systematically blind* to internal-sponsor framing (as the handoff anticipated).

Audience scoping established with the user up front:
- **External canonical audience** = small-to-mid regulated-industry **board / CTO** ("we have to comply but can't build it ourselves").
- **Internal-sponsor canonical audience** = SAP **LoB heads + chief architects** ("is this the right architecture bet for my domain, and does it win me deals?"). LoB head decides; architect objections handled inline. SAP board / CTO is *not* the internal target.

Generated 2026-06-17.

---

## 1. Cross-doc coherence read

**Verdict:** narrative and critique pull in mostly the same direction. The seam where they pull *apart* is structural, not cosmetic, and the first chief did not name it.

### 1.1 Where the docs align

`NARRATIVE.md`'s thesis (compliance + sovereignty as one argument) is internally consistent with `NARRATIVE-AT-A-GLANCE.md` and survives critique pressure on slides 1, 4, 5, 6 — these are the deck's strongest beats and the first chief flags them as such. The 4-step / 5-step bridge (NARRATIVE.md lines 38–44) is genuinely the right call, not a compromise. The Pack · Sign · Transport · Deploy mechanic and the Pack · Scan · Ship · Deploy · Scale Out lifecycle live in different cognitive registers; collapsing them would weaken both.

### 1.2 Where the docs pull apart

**The narrative's "lead axis" (NARRATIVE.md lines 26–34) is calibrated for an audience that has not yet committed.** Compliance is framed as *demand*, sovereignty as *constraint*. This is correct for an external small-co board/CTO who is being introduced to OCM cold. It is the **wrong** lead axis for an SAP LoB head, who is not deciding whether to comply with DORA (their products already must) but whether OCM is the right SAP-wide *primitive* for shipping regulated software.

The first chief's `EXEC-DECK-REWORK-OPTIONS.md` does not surface this seam at all — every option in that doc varies the *framing* of the lead axis (risk / ROI / peer / regulator) without questioning whether the lead axis itself fits the room. For an external audience, that's fine. For internal-sponsor, it produces a deck that spends its first three slides on a question the audience has already answered.

**Implication for Phase 2:** internal-sponsor cannot be served by a small overlay on any of the four external variants. It needs a **distinct lead axis** — strategic-fit + ecosystem-leverage — and therefore a sibling narrative document. See §3 and §5.

### 1.3 The 5th and 6th docs (`CONTENT-OPTIONS.md`, `DIAGRAM-OPTIONS.md`)

`CONTENT-OPTIONS.md` is older and more granular than `EXEC-DECK-REWORK-OPTIONS.md`. The two overlap heavily; `EXEC-DECK-REWORK-OPTIONS.md` is the load-bearing doc. CONTENT-OPTIONS is still useful as a wording reservoir but should not drive variant selection. **Recommendation: treat `EXEC-DECK-REWORK-OPTIONS.md` as the framing menu and `CONTENT-OPTIONS.md` as a tactical lookup table for line-level wording.**

`DIAGRAM-OPTIONS.md` is out of scope for content variants per the handoff (design frozen). The named diagrams matter only where critique points to them: the conformance-scenario story on slide 6 (v2 vs v3 air-gap diagram) and the dashboard screenshot on slide 7. Both are addressed in §2.

---

## 2. Per-framing critique — risk / ROI / peer / regulator

The first chief proposed four axes for slide 1 hero variants and (implicitly) for the deck as a whole. This section grades each axis on three dimensions: **audience fit**, **proof asymmetry** (where claims outrun evidence), and **hostile-reviewer survival**.

### 2.1 Risk-led / stake-frame (Option A — first chief's "recommended for first-time exec audience")

**Audience fit: high for cold execs; weak elsewhere.** "Three minutes from now, you'll know what your supply chain doesn't" reads to me as a marketing-mature opener for a *cold* exec who has not engaged with OCM before. It works for an external small-co board/CTO. My read: it's *wrong* for any audience already invested or already accountable for the problem — they'd typically bristle at being told they don't know something.

**Proof asymmetry: weakest of the four.** Stake-led openers create a debt the deck has to repay by slide 4. Currently slide 4 (SBoD) is a *category claim*, not a proof of stake. The audience is told "you don't know what you don't know" on slide 1, and by slide 4 they've been handed a new vocabulary word, not a thing they can verify. **The first chief's recommendation puts the deck in proof debt and doesn't surface that debt.**

**Hostile-reviewer subsection (devil's advocate):**
> *Skeptical CIO:* "Three minutes from now I'll know what my supply chain doesn't? My SBOM tool already tells me. I have cosign. I have provenance. I have an SBOM-as-a-service contract. What does this deck know that those don't?"
>
> The risk-led opener invites this exact challenge and the deck doesn't answer it until slide 5 at earliest. The first chief's critique #12 (comparator differentiation) is the same problem, surfaced separately. Risk-led + no comparator slide = the deck loses the room by slide 3.

**Verdict:** keep risk-led as *one* variant, but only when paired with a comparator slide (cosign / SBOM tooling / OCI+Sigstore+script) inserted between the current slides 4 and 5. **The first chief's recommendation that risk-led is the canonical exec opener should be downgraded** — it's the canonical *cold-room* opener, not the canonical exec opener.

**LOCKED (2026-06-17):** with the comparator-slide gate above, **the cold-room canonical hero is first chief's `EXEC-DECK-REWORK-OPTIONS.md` Option A** — title *"Three minutes from now, you'll know what your supply chain doesn't"* + subtitle *"A new model for delivering software the auditor can verify, the operator can run, and the regulator already requires."* Now applied in `NARRATIVE.md` slide 1.

**Caveat on the first chief's example stakes** (line 14–17 of `MARKETING-CRITIQUE-EXEC.md`): the three example stakes the first chief gave alongside the recommendation — *"$2.7B average cost of a software supply-chain breach in 2025"*, *"DORA goes into force this quarter. Here's what it asks of you"*, *"Three of your suppliers had software signed by tools that don't talk to each other"* — were drafted June 2025 and **do not survive a 2026 currency-check**. The $2.7B is exactly the kind of fabricated-feeling number we agreed we cannot produce; "DORA goes into force this quarter" is now 18 months stale; the suppliers line presumes audience facts a speaker cannot know. The Option A title and subtitle survive currency-check; the *example stakes* in the critique paragraph do not. Reading the first chief generally: the diagnosis is sharp, but the example replacements are draftsmanship and should be re-checked against current state before lifting verbatim.

### 2.2 ROI-led / outcome-frame (Option D — "audit-as-fire-drill to audit-as-property")

**Audience fit: strong for CFO-adjacent; weaker for CTO/CISO.** "From audit-as-fire-drill to audit-as-property" is a quotable line and translates the deck's thesis directly. My read: it lands hardest with whoever owns the audit P&L. It lands softer with whoever owns architecture or security posture, because they typically care more about the *mechanism* than the *category transformation*.

**Proof asymmetry: medium.** This framing demands quantified ROI — and the first chief flags this themselves (#9: "the deck has no business outcomes anywhere"). Slide 8 Option B (ROI-quantified tiles) tries to address this but the numbers are placeholders ("Cuts per-stack signing tooling by N tools"). **The ROI-led framing only works with at least three defensible numbers somewhere in the deck.** Currently zero exist.

**Hostile-reviewer subsection:**
> *Skeptical CFO:* "Show me one customer who cut audit prep from weeks to hours. With OCM specifically. Not 'with better signing in general.'"
>
> The deck cannot answer this today. The adopters slide (9) lists logos without per-logo outcome data. The first chief's slide-9 Option D (logos + quote + scale number) is correct in shape but currently aspirational — there are no numbers and no quote.

**Verdict:** ROI-led is the *strongest* framing if quantified evidence can be sourced. It is the *weakest* framing if presented with placeholder numbers, because each placeholder amplifies the credibility gap. **Recommendation: build the ROI-led variant only after at least three real numbers and one attributable quote are in hand.** Until then, ROI-led is paper.

### 2.3 Peer-led / category-claim (Option C — "SAP, BwI, Gardener — and now you?")

**Audience fit: strong for industry events with adopters in the room; weak anywhere else.** The peer-led opener is high-leverage *exactly* where the audience already attributes credibility to the named peers and is in a room where social proof compounds. Outside that context, my read is that it lands as name-dropping.

**Proof asymmetry: lowest of the four.** Peer-led is the only framing where the *opener itself* is the proof. Slide 1 says "SAP, BwI, Gardener" and the rest of the deck just has to not contradict it. This is operationally efficient.

**Hostile-reviewer subsection:**
> *Skeptical mid-market CIO:* "Great, SAP and BwI use it. They have 100,000 engineers. We have 150. What does adoption look like for someone our size?"
>
> Peer-led optimizes for emulation by buyers who *aspire* to be like the named peers. It actively *un-sells* to buyers who recognize they are not those peers. The first chief did not flag this asymmetry.

**Verdict:** peer-led is correct for industry-event keynote and *wrong* for cold mid-market sales. **The first chief's recommendation that peer-led is a viable canonical hero should be scoped: it's a contextual variant, not a default.**

### 2.4 Regulator-led / DORA-frame (Option B — "DORA is in force. Is your software delivery audit-ready?")

**Audience fit: strong for FSI / EU regulated-sector CISO; weak for US, defense, or non-financial-services audiences.** This framing is *narrowly* excellent. DORA is a European financial-services regulation. It does not apply to US companies, defense contractors (NIS2 yes, DORA no), or healthcare/pharma. Pitching DORA-led to a non-FSI audience signals you don't understand their regulation.

**Proof asymmetry: medium.** The deck can defend DORA claims (the regulation is public, the requirements are documented), but it cannot show DORA-aligned reporting actually working in production without slide-7 dashboard evidence. The first chief flags this on slide 7 (#6: "zero visual evidence") — DORA-led raises the cost of that gap.

**Hostile-reviewer subsection:**
> *Skeptical risk officer at a German Sparkasse:* "DORA is in force. What about the nine other things — VAIT, BAIT, MaRisk, the Schrems II implications, the BSI C5 audit cycle? Do you address all of those, or just DORA?"
>
> Regulator-led variants invite the audience to test whether the deck handles *their* regulation specifically, not the headline regulation. The first chief's option B (DORA-aligned slide 7) is correct in shape but DORA is the easiest case — the deck doesn't pressure-test against the harder regional ones.

**Verdict:** keep regulator-led as the FSI-EU variant. Don't generalize it to a "regulator-led canonical." The first chief's framing is right; the *scope* it implies is too broad.

### 2.5 The axes the first chief did not consider

Two axes are conspicuously absent from `EXEC-DECK-REWORK-OPTIONS.md`:

- **Strategic-fit / ecosystem-leverage** — the internal-sponsor frame (covered in §3).
- **Pragmatic / migration-cost** — what does adoption *actually* cost, in engineering time and tooling retirement? This is the question every chief architect asks within the first 5 minutes and the deck does not address it. See §4 Gap 1.

---

## 3. The internal-sponsor framing

The handoff treats this as a fifth axis to compare against the first chief's four. After review, my position is stronger: **internal-sponsor is not the fifth axis. It is a different deck.** It shares slides 4–8 with the external variants in mechanism, but lead axis, hero, slide 9, and CTA all change, and `NARRATIVE.md`'s thesis itself does not serve it.

### 3.1 Audience and decision

- **Primary:** SAP LoB heads (specific LoBs in scope: TBD with user — see §6 open questions). Decision: *should my product line standardize on OCM for regulated delivery, or roll my own / pick a vendor / wait?*
- **Secondary:** SAP chief architects. Decision: *is OCM the right architectural primitive for this domain?* Their objections are handled inline; they are not the audience the deck optimizes for.
- **Out of scope:** SAP board / CTO office (per user direction — internal political reality is that this audience already has context or doesn't run through this deck).

### 3.2 Proposed lead axis

**Strategic fit + ecosystem leverage**, not compliance + sovereignty.

The internal LoB head already accepts compliance and sovereignty as table-stakes constraints. What they don't yet accept is *that OCM is the SAP-wide answer to those constraints*. The deck's job is to convince them that:

1. **OCM is paying off internally** — traction across SAP product lines, components shipped, regulated deliveries enabled.
2. **OCM has ecosystem leverage** — SAP investment compounds because OCM is built on and integrates with the same primitives many regulated-delivery projects share (OCI, Helm, Sigstore among them) and is governed under NeoNephos. Walking away forfeits leverage built up over years.
3. **OCM is the strategic-fit choice** — alternative paths (proprietary tooling, single-vendor lock-in, "wait for the standard to emerge") all underweight SAP's sovereignty agenda and EU competitiveness positioning.
4. **The cost of disinvestment is concrete** — what we lose if we walk away, what competitors gain if NeoNephos OCM stewardship migrates elsewhere.

### 3.3 Slide-by-slide departures from the canonical narrative

| Slide | External (NARRATIVE.md) | Internal-sponsor variant |
|---|---|---|
| 1 Hero | "Secure Delivery for Sovereign Clouds" | *"OCM: SAP's bet on the open standard for regulated delivery."* (or similar — calls out the bet by name) |
| 2 Why now | DORA / NIS2 / supply-chain / sovereignty pressure | Compliance + sovereignty are *given*. Why now = **competitors and adjacent ecosystems are moving; standardization windows close**. |
| 3 Pain | Fragmentation across stacks | Fragmentation **across SAP LoBs** — each one carrying its own compliance retrofit cost. |
| 4 SBoD | Category claim | Same — but reframed as "the category SAP led the definition of." Strategic positioning, not just tech. |
| 5 Mechanic | Pack · Sign · Transport · Deploy | Unchanged. The mechanic is the same regardless of audience. |
| 6 Sovereign-ready | Trust, but verify | Unchanged in mechanism; *proof* shifts from "validated in conformance scenario" to "deployed in BwI / SAP NS2 sovereign environments." |
| 7 Compliance / ODG | ODG as compliance engine | ODG **as the SAP compliance leverage point** — "every SAP LoB gets compliance correlation by component, without each LoB building its own" |
| 8 What OCM unlocks | Generic outcome tiles | **Outcomes for SAP product lines specifically**: faster sovereign-region GTM, audit-prep cost reduction across LoBs, M&A integration efficiency. |
| 9 Adopters / governed | External adopters wall | **Internal traction wall**: open-peer projects + internal SAP projects standardising on OCM (Hyperspace, RBSC). The "what we lose if we walk away" beat lives here. |
| 10 CTA | "Try it / Build with us / Talk to us" | **"Sponsor / scale / standardize."** Specific ask: what budget / headcount / mandate does this deck want from the LoB head? |

### 3.4 Sibling narrative document

`NARRATIVE.md` should remain locked for external variants. A sibling document — proposed name `NARRATIVE-INTERNAL-SPONSOR.md` — should be authored before Phase 2 begins. Estimated 30–60 lines, mirroring `NARRATIVE.md`'s structure but with the lead axis and slide-9 / slide-10 sections rewritten.

**Recommendation: write the sibling narrative as part of Phase 1 closure (not Phase 2).** It is the source-of-truth for the internal-sponsor variant, and Phase 2 should not start variant authoring without it. Two-question check before drafting it (see §6 open questions).

### 3.5 Hostile-reviewer subsection

> *Skeptical SAP chief architect:* "OCM has been around for years. If it were going to win the standardization war, it would have already. Why should my LoB bet on it now instead of waiting two more years to see what survives?"
>
> The internal-sponsor deck has to address this directly. Two answer shapes work: (a) "the standardization window is *closing*, not opening — late entrants pay migration cost" — requires evidence that other ecosystems are converging on OCM-shaped solutions; (b) "wait-and-see has a cost we can quantify — N engineering-years per LoB on retrofit tooling per year of delay" — requires the cost numbers from Gap 1.
>
> Without one of these answer shapes, the internal-sponsor variant is vulnerable to the wait-and-see objection on slide 5 and never recovers.

---

## 4. Gaps the first chief missed

Four gaps surfaced during review. Severity is the criticality before Phase 2 starts.

### 4.1 Gap 1 (severity: must-fix-before-Phase-2) — No "what does OCM cost to adopt?" beat

The first chief's #13 mentions cost as *"how much does this cost to license"* — i.e., is OSS really free. The deeper miss is **adoption cost**: migration time, tooling retirement, time-to-first-signed-component-in-production, integration cost with existing SBOM/signing infrastructure.

Every exec who buys the thesis typically asks this within the first few minutes. The deck does not answer it. For internal-sponsor, this is the single most important slide — an LoB head who can't quantify "what does it cost my team to adopt" cannot defend the decision upward.

**Where to put it:** new slide between current 8 and 9, or a footer line on slide 5. **Minimum content:** time-to-first-signed-component (target: weeks not quarters), retired-tooling list, what-stays-unchanged list (existing SBOM tooling, existing GitOps, existing PKI). The "what stays unchanged" framing is the lower-anxiety version and probably the right one for exec audiences.

**Applies to:** all variants. The internal-sponsor variant additionally needs to cite SAP-specific adoption examples (LoB X took N weeks; tooling retirement footprint).

### 4.2 Gap 2 (severity: must-fix-before-Phase-2) — No concession line anywhere

The deck never says "OCM is wrong / overkill / not yet ready for X." Marketing-mature decks for technical audiences include exactly one such line, because:

- It is *credibility currency*: the audience typically trusts the rest of the deck more after reading one honest concession.
- Chief architects (the secondary internal audience) typically look for it. Its absence reads as marketing rather than engineering.
- Hostile reviewers (skeptical CIOs, competitors) often *invent* a concession the deck didn't make and use it against you.

**Candidate concessions, ranked by defensibility:**
1. *"OCM is overkill if you ship into one cloud, with one stack, with no sovereignty pressure."* — true, easy to defend, narrows the audience honestly.
2. *"OCM v2 just shipped. The CLI is simpler; the identity model is the same; expect surface-area changes through 2026."* — incorporates the first chief's #14 (no roadmap maturity beat) into a concession frame.
3. *"OCM does not replace cosign or your SBOM tooling. It composes with both."* — already in the wording but never *named as a concession*; the framing matters.

**Where to put it:** one line on slide 5 (proof line), or a sub-bullet on the new slide-9-ecosystem beat. Single line is sufficient; do not give it its own slide.

**Applies to:** all variants. Especially load-bearing for internal-sponsor (chief architects).

### 4.3 Gap 3 (severity: internal-sponsor-specific) — No upstream-ecosystem leverage story

OCM is *built on* OCI, Helm, and Sigstore primitives. Currently the deck mentions these as *integrations OCM uses* but doesn't make the *ecosystem-shared-foundations* claim explicit. For an internal-sponsor LoB head, this is the difference between "OCM is a project we fund" (a cost) and "OCM is SAP's leverage point in the OSS supply-chain ecosystem" (an asset).

**Note (2026-06-17 correction):** an earlier draft of this doc framed OCM as "contributing upstream to kro and ESO." That was factually wrong — *individual OCM contributors are also maintainers in those adjacent projects (kro, ESO), but the OCM project itself does not contribute to them as upstream*. The cross-pollination happens at the contributor level, not the project level. The "ecosystem leverage" claim now stands on the open peer projects (Gardener, Kyma, Konfidence, OCP) + internal SAP traction (Hyperspace, RBSC) alone. See `narratives/NARRATIVE-INTERNAL-SPONSOR.md` slide 10a/10b.

**Where to put it:** slide 9 enrichment for the internal-sponsor variant. Replace or augment the second adopter tier ("Built into the open-source ecosystem") with a "Contributing upstream" section listing the projects OCM contributes to / depends on, framed as ecosystem leverage.

**Applies to:** internal-sponsor variant primarily. External variants benefit lightly but it's not load-bearing for them.

### 4.4 Gap 4 (severity: optional sharpener) — No acknowledgment that the audience may already have failed once

Most regulated-industry execs have sat through *some* prior compliance-tooling initiative — an internal SBOM rollout, a signing project, a "let's standardize this" effort that stalled. The deck speaks as if the audience starts fresh. A single line — *"If your last compliance-tooling project stalled, this is why, and this is what's different"* — converts skeptics by validating their experience.

**Where to put it:** sub-bullet or pull-quote on slide 3 (current pain). One line, no whole slide.

**Applies to:** all variants. Highest-leverage for risk-led and ROI-led; lower-leverage for peer-led (peer-led works on aspiration, not validation).

---

## 5. Top-5 sharpening recommendations (concrete edits before Phase 2)

These are the edits I'd commit to `NARRATIVE.md`, `EXEC-DECK-REWORK-OPTIONS.md`, or as new docs *before* any variant deck is built. Ordered by leverage.

### 5.1 Author `NARRATIVE-INTERNAL-SPONSOR.md` as a sibling to `NARRATIVE.md`

Different lead axis (strategic fit + ecosystem leverage), different slide 9 (internal traction + upstream contributions), different slide 10 (sponsor / scale / standardize ask). Slides 4–7 mostly inherit from `NARRATIVE.md`.

**Why first:** Phase 2 cannot author the internal-sponsor variant deck without this. The handoff's question 4 ("is the locked NARRATIVE.md actually locked") is answered: yes for external, no for internal — internal needs its own narrative.

**Estimated cost:** 30–60 lines, plus a grilling pass with the user on lead-axis wording.

### 5.2 Add an "adoption cost / what-stays-unchanged" beat to `NARRATIVE.md`

New slide between current 8 and 9, or strong footer line on slide 5. Content: time-to-first-signed-component, retired-tooling list, what-stays-unchanged list.

**Why second:** without this, every variant fails the chief architect's first question and the LoB head's "what does it cost my team" question. Currently zero of the four external framings address it.

**Estimated cost:** 10–15 lines added to `NARRATIVE.md`; one new option-set in `EXEC-DECK-REWORK-OPTIONS.md`.

### 5.3 Add one explicit concession line in `NARRATIVE.md`

One line, on slide 5 proof line, naming OCM as overkill in some scenario or naming a v2 maturity caveat.

**Why third:** credibility currency. The deck currently reads as undefeated, which is the marketing failure mode for technical audiences.

**Estimated cost:** one line. Choose between the three candidates in §4.2.

### 5.4 Downgrade risk-led from "canonical exec opener" in `EXEC-DECK-REWORK-OPTIONS.md`

The first chief's recommendation that Option A (risk-led) is canonical should be revised to "canonical *cold-room* opener; pair with comparator slide." Without that pairing, risk-led puts the deck in proof debt by slide 4.

**Why fourth:** structural — affects which variant is built first in Phase 2. Without this revision, Phase 2 starts with the variant most vulnerable to the cosign / Sigstore comparator objection.

**Estimated cost:** edit to `EXEC-DECK-REWORK-OPTIONS.md` §"Slide 1 — Hero", add comparator slide as a structural prerequisite.

### 5.5 Commit at least three numbers (or accept that ROI-led variant is paper)

The ROI-led framing only works with defensible quantified evidence. Currently the deck has zero numbers. Either:

(a) Source three numbers + one attributable quote before building the ROI-led variant. Candidates: components delivered in production, sovereign deployments enabled, audit-prep delta from a real customer.

(b) Do *not* build the ROI-led variant in Phase 2; defer it until evidence is in hand.

**Why fifth:** scoping — affects whether the ROI variant is built. Either path is fine; the choice should be made before Phase 2, not during.

**Estimated cost:** depends on path. Path (a) requires sourcing from internal SAP / BwI / Gardener teams. Path (b) is free but loses the strongest exec framing.

---

## 6. Open questions to resolve before Phase 2

Several were resolved with the user during Phase 1 grilling (marked **RESOLVED** below); a smaller set remain open and are flagged in `NARRATIVE-INTERNAL-SPONSOR.md` for follow-up.

1. **RESOLVED — Sibling internal narrative scope.** User decision (2026-06-17): draft now. `NARRATIVE-INTERNAL-SPONSOR.md` authored as part of Phase 1 closure. Lead axis: loss-frame ("what we lose by walking away"). Concession line wording: B1-r2 ("OCM's value is strategic — ecosystem leverage, sovereignty positioning, standardization. The transactional case is built per-LoB, with your team."). Internal-traction-wall shape: C1 (named projects only, no metrics).
2. **RESOLVED — Comparator slide structural decision.** User decision (2026-06-17): **Path A** — new dedicated comparator slide between current 4 and 5 ("How OCM composes — OCM doesn't replace your tools. It gives them something to sign together."). Deck length grows from 11 to 12 physical slides. New slide is now `NARRATIVE.md` slide 5; subsequent beats renumbered (mechanic = 6, sovereign-ready = 7a/7b, ODG = 8, tiles = 9, governance = 10, CTA = 11).
3. **RESOLVED — Numbers sourcing.** User cannot deliver real numbers. ROI-led variant **deferred** in Phase 2. Internal-sponsor narrative bakes the no-numbers concession into slide 6.
4. **RESOLVED — Concession line wording.** B1-r2 chosen for internal-sponsor. External variants still need a concession line; candidates remain in §4.2 of this doc.
5. **RESOLVED — First-variant-to-build-in-Phase-2.** User decision (2026-06-17): **internal-sponsor first** (now grounded in `NARRATIVE-INTERNAL-SPONSOR.md`), then *risk-led + comparator slide* (most-used external variant).
6. **RESOLVED — SAP LoBs in scope for internal-sponsor variant.** User decision (2026-06-17): four projects highlighted as adoption examples on slide 9 (outcomes) — **Hyperspace** (most-relevant; hosts internal Dev Portal and lifecycle/delivery), **Gardener** (most externally visible peer), **CSI** (largest internal footprint), **Konfidence** (now open source, known across many teams). Slide 10 (peer wall) keeps the full seven-project list (CSI / Gardener / Kyma / Konfidence / OCP / Hyperspace / RBSC) split into open-peer projects (Section 1) and internal SAP projects (Section 2 — Hyperspace and RBSC).
7. **Slide 3 structural decision — RESOLVED.** User decision (2026-06-17): adopt Option 3 ("Meet OCM. One identity, every boundary."). The "pain" beat dissolves into slide 2 column 3; the "compliance retrofits" framing relocates to slide 7 ("compliance as a system property — not a quarterly retrofit"). Hub-and-spoke diagram produced at `decks/exec-phase1/diagrams/03-meet-ocm-hub-and-spoke.svg`. Both external and internal narratives use this structure.
8. **Internal-sponsor slide 9/10 ecosystem framing — RESOLVED.** OCM positioned as *peer in the open ecosystem* (CSI, Gardener, Kyma, Konfidence, OCP; forthcoming: NeoNephos foundation projects) on slide 10a, with *internal SAP traction* (Hyperspace, RBSC) on slide 10b. The earlier draft section listing kro / ESO as "upstream contributions" was **dropped (factually wrong)** — individual OCM contributors are also maintainers in those adjacent projects, but the OCM project does not contribute to them upstream as a project. Slide-10 split (a/b) also fixes a layout overflow problem in the rendered Marp draft.

---

## 7. Phase-2 readiness — consolidated open items

After the 2026-06-17 grilling pass and follow-ups, all major decisions are locked. **No structural blockers remain for Phase 2 to begin** with the internal-sponsor variant. Items below are minor and can be carried as placeholders into early Phase 2 review, or resolved before the first variant build.

**Resolved (locked into the docs):**
- Hero: B-orig (*"Three minutes from now, you'll know what your supply chain doesn't"* + the auditor/operator/regulator subtitle) — applied to `NARRATIVE.md`, `NARRATIVE-AT-A-GLANCE.md`, comparison column in `NARRATIVE-INTERNAL-SPONSOR.md`.
- Slide 3: Option 3 ("Meet OCM. One identity, every boundary.") — hub-and-spoke diagram landed at `decks/exec-phase1/diagrams/03-meet-ocm-hub-and-spoke.svg`. Three regulatory regimes: DORA, NIS2, CRA (GDPR dropped, CRA added per regime-research subagent). Footer line names FedRAMP/FISMA, BSI C5, SecNumCloud. Cluster headers: *EVERY ARTIFACT TYPE / EVERY REGIME / EVERY DEPLOYMENT BOUNDARY*. *"… any artifact type"* pill added. EU + US flag glyphs on boundary spokes; Sovereign Cloud uses the cloud-with-lock motif from slide 6 (was slide 5 pre-renumbering).
- Slide 5 (new): comparator slide — *"OCM doesn't replace your tools. It gives them something to sign together."* Three columns: keyless/key-based signing; SBOM tool or format; OCI + Sigstore + scripts. Eyebrow *HOW OCM COMPOSES*.
- Slide 9 internal-sponsor outcomes: four adoption examples named (Hyperspace, Gardener, CSI, Konfidence).
- Slide 10 internal-sponsor peer wall: **split into 10a (open peers — CSI / Gardener / Kyma / Konfidence / OCP) and 10b (internal SAP — Hyperspace, RBSC)**. The "OCM contributes upstream to kro/ESO" framing was dropped as factually wrong (contributors are also maintainers in those projects, but the OCM project itself does not contribute upstream there).
- Slide 11 internal-sponsor CTA: SAP Slack `#sap-tech-ocm` only. No Zulip on the internal deck.
- ROI-led variant: deferred. No real numbers available.
- First Phase-2 build: internal-sponsor variant.

**Still open — minor, can be carried as placeholders:**
- External variants still need a concession line locked. Candidates in §4.2 (this doc): (1) "OCM is overkill if you ship into one cloud, with one stack, with no sovereignty pressure"; (2) v2 maturity caveat; (3) cosign/SBOM-composition framing. *Recommend: pick one before risk-led variant build starts.*
- External slide 11 CTA wording: first chief's Option A ("30-min reading / 2-hour PoC / white-glove") vs the current "Try it / Build with us / Talk to us." *Recommend: pick one before risk-led variant build.*
- The new `03-meet-ocm-hub-and-spoke.svg` is not yet wired into `build_pptx.py` — currently slide 3 uses `03-fragmented.svg`. Wiring is downstream and not part of Phase 1.

---

## Summary scorecard — where this review diverges from the first chief

The first chief's actual scorecard (in `MARKETING-CRITIQUE-EXEC.md` lines 218–229) graded the *current deck* against a *target*, dimension by dimension. This second-chief review does not regrade those same numbers — instead it surfaces where the first chief's *recommendations* should be revised. Below: per-area divergence, in plain text, sourced to the first chief's actual claims.

| Area | First chief's recommendation (sourced) | Second-chief divergence |
|---|---|---|
| Slide-1 hero | "Replace slide 1 hero with a stake-led variant" (top-5 list, line 232) — risk-led recommended as canonical | Risk-led canonical *only when paired with comparator slide*. First chief did not name the dependency. See §2.1. |
| Slide-2/3 collapse | First chief recommends "collapsing 2 and 3 into one diagnosis slide and add an OCM-as-answer slide right after" (line 233) | Aligned. Option C in `EXEC-DECK-REWORK-OPTIONS.md` is the cleanest realization. |
| Slide-4 SBoD | First chief recommends three-beat repetition (Option A) for canonical | Aligned for external. Internal-sponsor reframes as "the category SAP led the definition of." See §3.3. |
| Slide-5 enrichment | First chief recommends Option A (Sigstore proof line) + C (Sign as hero bullet) | Aligned but incomplete: missing concession line (Gap 2) and adoption-cost link (Gap 1). See §4.1, §4.2. |
| Slide-6 sovereignty | First chief recommends Option A (3 bullets + conformance proof) | Conformance scenario is fine; *production proof* (BwI / SAP NS2 deployments) is stronger and absent from the first chief's options. |
| Slide-7 ODG | First chief recommends Option A (4 bullets + dashboard thumbnail) | Aligned. Dashboard screenshot dependency is real and unresolved (per `DIAGRAM-OPTIONS.md` line 117). |
| Slide-8 outcome tiles | First chief recommends Option A (outcome reframing) for canonical, B (ROI numbers) when defensible | Outcome reframing is right; ROI numbers are placeholders. See §2.2 / §5.5. |
| Slide-9 adopters | First chief recommends Option D (logos + quote + scale number) | Doesn't address upstream-ecosystem leverage (Gap 3). For internal-sponsor, this slide carries the strategic-fit argument and needs a different shape. |
| Slide-10 CTA | First chief recommends Option A (single specific ask, three escalation tiers) | First chief's options are external-only. Internal-sponsor needs a different CTA shape ("sponsor / scale / standardize"). See §3.3. |
| Cost-of-inaction beat | First chief proposes new slide between 7 and 8, three options (A/B/C) | First chief's options are right but the *adoption-cost* beat (Gap 1) is the bigger structural miss — what does it cost *to act*, not just what costs to *not* act. |
| **Internal-sponsor audience** | **Not considered by first chief at all.** | Distinct lead axis required (strategic fit + ecosystem leverage), separate sibling narrative document, distinct deck. See §3 and §5.1. |

Five things — if fixed — would lift the deck and the variant set the most:

1. Author `NARRATIVE-INTERNAL-SPONSOR.md` (Gap §3, Recommendation §5.1).
2. Add adoption-cost / what-stays-unchanged beat (Gap 1, Recommendation §5.2).
3. Add one concession line (Gap 2, Recommendation §5.3).
4. Pair risk-led with comparator slide (§2.1, Recommendation §5.4).
5. Decide ROI-led numbers sourcing (§2.2, Recommendation §5.5).

Stop here. Do not start Phase 2 until these are converged with the user.
