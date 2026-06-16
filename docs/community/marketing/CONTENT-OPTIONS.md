# Exec Deck — Content Options for Discussion

Multiple variants per slide. Browse, compare, mark the ones you like, and we'll converge.

Every variant is meant to be **read aloud at a slow pace** — these are exec slides, not docs. Lines are deliberately short.

The structure is: existing line first (for reference), then 3-5 alternatives. **No option below has been applied to the deck yet** — these are draft proposals only.

---

## Slide 2 — "Why now"

The current deck supports 3 framings (V1 / V2 / V3). I'm not proposing changes to which framing, only to wording.

### V1 title — "Sovereignty is no longer optional"

| # | Title | Reads as |
|---|---|---|
| 0 | Sovereignty is no longer optional. | Current. Direct, declarative. |
| 1 | Sovereignty is no longer a choice. | Slightly softer; "choice" instead of "optional". |
| 2 | Where sovereignty is required, delivery has to follow. | Implication-led; ties sovereignty back to delivery. |
| 3 | The boundary moved. Software has to move with it. | Mirrors the column-1 body's "wherever the law puts the boundary." |
| 4 | Software now has to ship with its sovereignty. | Ownership framing — sovereignty as a property of the artifact. |

### Column 1 — Sovereignty pressure

| # | Body | Notes |
|---|---|---|
| 0 | Wherever the law puts the boundary — by jurisdiction, sector, or air-gap — software must be deliverable, verifiable, and operable inside it. | Current. 28 words. Strong but long. |
| 1 | Wherever the law sets the boundary, software must arrive, verify, and run inside it. | Tighter (15 words). Same structure. |
| 2 | EU jurisdictions. Regulated sectors. Air-gapped systems. Each defines its own boundary. Software must run inside each. | Three-clause stab; lands the boundaries as concrete things. |
| 3 | Boundaries used to be physical. Now they're contractual. Software still has to honour them. | Insight-led — frames the cultural shift. |

### Column 2 — Regulation tightening

| # | Body |
|---|---|
| 0 | EU DORA · NIS2 · GDPR. Provable supply-chain control, not best effort. |
| 1 | DORA in force from January 2025. NIS2 transposed across the EU. Provable control, not best effort. |
| 2 | Three regimes, one demand: prove your supply chain. Best effort is now non-compliance. |
| 3 | DORA, NIS2, GDPR — provable supply-chain control is the new audit floor. |

### Column 3 — Supply-chain attacks

| # | Body |
|---|---|
| 0 | SolarWinds. xz. log4shell. Signatures must survive the journey, or compliance is theatre. |
| 1 | SolarWinds. xz. log4shell. If signatures don't survive transit, compliance is theatre. |
| 2 | SolarWinds. xz. log4shell. Without proof at the destination, signing is paperwork. |
| 3 | Three years, three landmark breaches. Each broke the chain in transit. |

---

## Slide 3 — "The pain"

### Title

| # | Title |
|---|---|
| 0 | Software delivery is fragmented. Compliance retrofits don't scale. |
| 1 | Fragmented delivery, bolted-on compliance. |
| 2 | One delivery, ten stacks, no through-line. |
| 3 | Each stack has its own signing. Each compliance regime adds its own bolt-on. |
| 4 | Stacks don't compose. Neither do their compliance retrofits. |

### Body / proof point

The subagent flagged that the current proof point ("OCM Coordinates") is good but **buried**. Three placement options:

**A. Keep the body as-is, add Coordinates as a punchline.** (current shape)
> Many teams, many stacks. Signatures break in transit. SBOMs were never built for delivery — they were built for inventory. Each compliance regime adds its own bolt-on. None of it composes.
>
> *Proof:* OCM gives every component a globally unique, technology- and location-agnostic identity — its OCM Coordinates. One identity, one signature, one audit trail.

**B. Lead with Coordinates as the answer.** (subagent's recommendation)
> OCM Coordinates give every component one identity across the whole lifecycle — the correlation ID across signing, scanning, deployment, and reporting.
>
> *Proof:* One identity, one signature, one audit trail. Today's stack-by-stack tooling can't deliver that — every transit breaks the link.

**C. Two-column variant.** Pain on left, OCM answer on right (mirror layout).
> **The pain:** Many teams, many stacks. Signatures break in transit. Each compliance regime bolts on its own metadata.
>
> **OCM Coordinates:** One globally unique identity per component. Carries through every registry, every transfer, every audit.

---

## Slide 4 — "SBoD vs SBOM"

### Body

| # | Body | Source |
|---|---|---|
| 0 | An SBOM tells you what's in your software. It was built for inventory. A Software Bill of Delivery (SBoD) tells you what you delivered, how to verify it, how to transport it, and how to operate it. It was built for delivery. The SBoD contains the SBOM. OCM doesn't replace your SBOM tooling — it gives the SBOM an envelope that's compliance-native, signed once, and travels intact across any boundary. | Current. NARRATIVE.md. |
| 1 | An SBOM tells you what's inside. An SBoD tells you what you delivered — built, signed, transported, deployed. The SBoD contains the SBOM. OCM gives your SBOM the envelope that travels intact. | Tighter (38 words vs 80). Borrows verb chain from `ocm_v2_announcement.md:232`. |
| 2 | SBOM = inventory. SBoD = delivery. Built, signed, transported, deployed — the SBoD records all of it, with the SBOM as one payload item among many. OCM doesn't replace your SBOM tooling. It puts an envelope around it. | Lean / definitional. Visual: equation-like opening. |
| 3 | Your SBOM lists ingredients. Your SBoD records the delivery. Built. Signed. Transported. Deployed. One verb chain. One signed envelope. One audit trail across every boundary. | Punchier rhythm. Suited to slow read-aloud. |

### Proof line (none on current slide — could add as third paragraph)

| # | Proof |
|---|---|
| A | Your existing SBOM tools keep working — OCM only adds the envelope around them. |
| B | The SBoD contains the SBOM. Same data, in a structure built for delivery, not inventory. |
| C | Drop OCM into your existing pipeline. Your SBOM tooling is unchanged; the delivery story finally composes. |

---

## Slide 5 — "Pack · Sign · Transport · Deploy"

### Title — keep current, no proposed alternatives.

### Body bullets (current 4) + optional proof line

The subagent suggested adding "**native OCI compatibility**" as a one-liner. Three placements to consider:

**A. Add as a fifth bullet:**
> Pack · Sign · Transport · Deploy · **plus** — components are natively OCI-compliant; `docker pull` and `helm pull` work directly.

**B. Replace the existing "no lock-in" proof line:**
> ~~Works with what you already ship — OCI, Helm, npm, GitHub, S3. OCM doesn't replace your registries; it gives them one signed envelope.~~
>
> Native OCI. Native Helm. Native npm. Pull components with the tools you already use. OCM gives them one signed envelope without forcing a parallel stack.

**C. Add the Sigstore beat to the Sign bullet:**
> Sign — one signature covers every artifact, by digest. Bring your existing PKI (RSA), your team's GPG keys, or go keyless with Sigstore. No long-lived secrets.

I recommend **B + C** combined. They both add credibility without lengthening the slide.

---

## Slide 6 — "Sovereign-ready / Trust, but verify"

### Title

| # | Title |
|---|---|
| 0 | Trust, but verify. | Current. Reagan reference, well-known. |
| 1 | Sign once. Verify anywhere. | Mechanism-led, OCM-specific. |
| 2 | Identity travels. So does proof. | Property-led; pairs with the diagram. |
| 3 | One signature. Every boundary. Every hop. | Repetition for rhythm. |

### Bullet tightening (current is 4 bullets, ~80 words total — long)

Subagent flagged: the day-2 / subscription bullet is the strongest beat after location-independent signatures, and it's currently 3rd of 4. Here's a re-ordered + tighter version:

**Variant A — re-order, no rewrite:**
1. Identity is location-independent. *(unchanged)*
2. **Day-2 ops happen inside the boundary. Subscribe to the component and pull upgrades on your schedule, scale across regions, all without reaching back upstream.** *(promoted from 3rd)*
3. Signatures are location-independent. *(unchanged, demoted)*
4. On transfer, a component carries every artifact it needs. *(unchanged)*

**Variant B — tighten to 3 bullets:**
1. **Identity travels.** A component's name is the same in every registry, every region.
2. **Signatures travel with it.** Sign at source; verify at destination, or any hop in between. No upstream callback.
3. **Day-2 ops stay inside the boundary.** Subscribe. Upgrade. Scale across regions. The destination needs nothing more.

**Variant C — single sentence:**
> One identity, one signature, one closed-loop. Each boundary is a perimeter the component runs inside on its own.

### Proof — conformance scenario (subagent: strongest credibility lever, currently invisible)

Three placements:

| # | Proof line | Where |
|---|---|---|
| A | Validated end-to-end in OCM's open-source sovereign conformance scenario. | Footer-style, below bullets |
| B | We test this end-to-end. The project ships a sovereign conformance scenario in the monorepo — the closed-loop is exercised on every release. | Standalone proof paragraph |
| C | This isn't aspirational. The closed-loop is exercised in the project's sovereign conformance scenario, on every release. | Punchier, "this isn't aspirational" framing |

---

## Slide 7 — "Scan / ODG / Compliance"

### Title

| # | Title |
|---|---|
| 0 | Compliance as a system property — not a quarterly project. | Current. |
| 1 | Compliance, by component identity. | Mechanism-led. |
| 2 | One dashboard. Every component. Every signal. | Outcome-led. |
| 3 | Every compliance signal correlates by OCM Coordinates. | Direct, technical, builds on slide 3. |
| 4 | Audit-ready by construction. | Slogan-style. |

### Bullet rewrite — current 5 → tightened to 4 (subagent rec)

The subagent flagged that bullets 4 and 5 say roughly the same thing. Here's a 4-bullet version:

**Variant A — straightforward tighten:**
1. Open Delivery Gear (ODG) is OCM's compliance automation engine.
2. Compliance Dashboard: every component, every finding, every signature in one view.
3. Continuous async scans — even after release. Findings rescore against contextual risk.
4. **All signals correlate by OCM Coordinates.** Auditors get evidence, not spreadsheets.

**Variant B — DORA-aligned (subagent rec: tie in DORA metrics):**
1. Open Delivery Gear (ODG) is OCM's compliance automation engine.
2. Compliance Dashboard: every component, every finding, every signature in one view.
3. **DORA-aligned by construction.** Per-component delivery metrics; continuous async scans.
4. Findings rescore against contextual risk. Auditors get evidence, not spreadsheets.

**Variant C — "shift left → shift continuous":**
1. Compliance is no longer a release-time gate. ODG runs continuous scans on every component.
2. Compliance Dashboard: one entry point for every component, every finding, every signature.
3. CVE rescoring, not raw CVE counts. Patches go where context says they matter.
4. All signals correlate by OCM Coordinates — audit evidence, not spreadsheets.

### Visual proof — Compliance Dashboard screenshot (currently absent)

The subagent strongly recommended including a thumbnail. **Action: I will fetch the IPCEI deck slides 5–6 and propose a sanitized thumbnail.** That's a separate workstream — flagged here for visibility.

---

## Slide 8 — "What OCM unlocks" (the 5-step / 4-step bridge problem)

This is the slide you flagged. The header strip says **5 steps** (Pack · Scan · Ship · Deploy · Scale Out) — but slide 5 says **4 steps** (Pack · Sign · Transport · Deploy). An exec audience clocks the inconsistency without articulating it.

Five options to fix this:

### Option A — Bridge in the header strip *(subagent recommendation)*

Replace the bare 5-step header with a one-line bridge that explicitly relates the two:

> **THE 4-STEP CORE EXTENDS TO A FULL LIFECYCLE: PACK · SCAN · SHIP · DEPLOY · SCALE OUT**

Pros: keeps both framings, lowest cost. Cons: the line is heavy; might land as setup.

### Option B — Drop the lifecycle frame entirely

Replace the strip with: **"OUTCOMES ACROSS THE LIFECYCLE."** Six tiles speak for themselves.

Pros: cleanest. Cons: loses the IPCEI continuity for SAP-internal viewers who recognise that framing.

### Option C — Use the 4-step everywhere, drop "Scan" and "Scale Out"

Slide 8 strip becomes: **"PACK · SIGN · TRANSPORT · DEPLOY — ONE MODEL, END TO END."**

Pros: total consistency with slide 5. Cons: Scan and Scale-Out are real product capabilities; demoting them feels weak.

### Option D — Promote slide 5 to 5 steps (the inverse fix)

Change slide 5 title to: **"Pack · Sign · Transport · Deploy · Scale Out"**. Add a fifth bullet:
> **Scale Out** — same model handles day-2 ops, regional scale, multi-cluster fleets.

Pros: every slide aligns. Cons: slide 5's title gets long; "Sign" disappears as a verb (implicit in Pack).

### Option E — Two slides, two stories

Slide 5 stays at **Pack · Sign · Transport · Deploy** (the *mechanics*). Slide 8 keeps **Pack · Scan · Ship · Deploy · Scale Out** (the *lifecycle outcomes*). Add a header on slide 8: **"BEYOND THE MECHANICS — WHAT OCM UNLOCKS ACROSS THE LIFECYCLE."**

Pros: each frame keeps its own audience. Cons: longest setup line, requires the speaker to verbalise the bridge.

**My recommendation:** **A** for low-cost wins, **B** for cleanest deck, **C** if you want maximum consistency. Avoid D (slide 5 was designed around 4 mechanics).

### Tile content — minor revisions

The subagent rated all 6 tile concepts as defensible. Two minor copy options:

**Tile 4 — "Asynchronous security scans"**

| # | Body |
|---|---|
| 0 | Continuous scanning, even after release; findings tied to component identity. |
| 1 | Continuous scanning. Findings rescored as the world changes — not as a release-time gate. |
| 2 | Scans run async, even after release. Findings stay correlated to the component, no matter where it runs. |

**Tile 5 — "One source of truth"**

| # | Body |
|---|---|
| 0 | Rebuild any landscape from a single signed descriptor. |
| 1 | One signed descriptor; every landscape rebuildable from it. |
| 2 | Lose your environment? Rebuild from the descriptor. The descriptor is the truth. |

---

## Slide 9 — "Adopters / NeoNephos"

### Title

| # | Title |
|---|---|
| 0 | Aligned with NeoNephos. | Current. |
| 1 | Open. Governed. In production. | Three-beat slogan. |
| 2 | Trusted in production, governed in the open. | Combines current eyebrow + structural claim. |
| 3 | Where OCM is already shipping. | Plain. |

### Section labels

| # | Tier 1 (regulated) | Tier 2 (OSS) |
|---|---|---|
| 0 | ADOPTED BY ENTERPRISES SHIPPING INTO REGULATED ENVIRONMENTS | BUILT INTO THE OPEN-SOURCE ECOSYSTEM |
| 1 | SHIPPING INTO REGULATED ENVIRONMENTS | EMBEDDED IN OPEN-SOURCE INFRASTRUCTURE |
| 2 | IN PRODUCTION ACROSS REGULATED INDUSTRIES | UPSTREAM IN THE OPEN-SOURCE ECOSYSTEM |

### Proof point under logos

| # | Proof |
|---|---|
| 0 | An open standard, neutrally governed — your stack stays portable, your dependencies stay yours. |
| 1 | Stewarded under NeoNephos / Linux Foundation Europe. Your dependencies stay open, your stack stays portable. |
| 2 | Open spec, neutral governance, production adoption. Three-of-three for an exec audience. |
| 3 | A spec moving toward a Community Specification License. Adoption that doesn't require you to bet on a vendor. |

### Optional addition: **conformance scenario citation**

If we want to land "this is real" hard:

> Validated by an open-source sovereign conformance scenario in the project's monorepo — exercised on every release.

---

## Slide 10 — CTA

### Title

| # | Title |
|---|---|
| 0 | Start delivering with confidence. | Current. |
| 1 | Start delivering. End the mess. | Punchy, contrasts with slide 3. |
| 2 | Pack. Sign. Ship. Today. | Verb-led, calls back to slide 5. |
| 3 | Your next deck → into a sovereign environment. | Implication-led ("imagine this is your next release"). |

### CTA links (subagent rec: replace generic "community channels" with Zulip)

| # | List |
|---|---|
| 0 (current) | Try it — ocm.software · Build with us — github.com/open-component-model · Talk to us — community channels on the website |
| 1 (named Zulip) | Try it — ocm.software · Build with us — github.com/open-component-model · Join us on Zulip — linuxfoundation.zulipchat.com (channel: open-component-model) |
| 2 (4-line, with mailing list) | Try it — ocm.software · Build with us — github.com/open-component-model · Chat on Zulip — channel: open-component-model · Subscribe — lists.neonephos.org |
| 3 (per-audience split) | **For engineers:** github.com/open-component-model · **For architects:** ocm.software/docs/concepts · **For execs:** ocm.software/blog · **Talk to us:** Zulip / open-component-model |

---

## Cross-deck additions to consider

These don't fit a single slide — flagging for discussion.

### A. A "Section Divider" between slides 3 and 4 ("From pain to model")

The deck moves from the pain (slide 3) directly into "SBoD vs SBOM" (slide 4) — a conceptual jump for execs. Inserting a section divider with **"OCM is the model"** or **"How OCM solves it"** could give the audience a beat.

### B. A second Section Divider between 6 and 7 ("From mechanism to system")

Slides 4–6 are about *how OCM works*. Slide 7 (ODG) is about *what the system enables*. A divider with **"From mechanism to system"** or **"From components to compliance"** would reset the cognitive frame.

### C. A "what's new in v2" paragraph somewhere

`ocm_v2_announcement.md` has a strong "OCM v2 is here" beat. Currently invisible in the deck. Could go as a footer-style line on slide 5 or a standalone slide between 8 and 9: "OCM v2 — natively OCI-compliant, simpler CLI, the same identity model."

### D. A speaker's-notes companion

For the exec to hand to a deputy. Each slide gets 2–3 sentences of "what to say" plus 1–2 sentences of "what an exec might ask."

### E. Per-vertical hero variants

- Hero (default): "Secure Delivery for Sovereign Clouds"
- Hero (financial services): "Audit-Ready Delivery, by Construction" — DORA-led
- Hero (defense / public): "Software That Crosses Every Boundary You Have" — air-gap-led
- Hero (platform team): "One Model. Every Stack. End to End." — fragmentation-led

---

## What's NOT in this options doc

- Diagram alternatives — being produced by separate workstreams (background agents). Will land as `DIAGRAM-OPTIONS.md` and a primitives library.
- Tile icon alternatives — being produced by separate workstream. Will land as `TILE-ICON-OPTIONS.md`.
- Visuals (Compliance Dashboard thumbnail, etc.) — flagged in slide 7 above; needs separate fetch + sanitization step.
- The hero slide — your hand-saved version. Not touching unless you ask.

---

*Generated 2026-06-16 from cross-reference of NARRATIVE.md, NARRATIVE-AT-A-GLANCE.md, ~/dies-und-das/OCM/ (whitepaper, IPCEI-CIS GA pitch, OCM-Adoption Plan), website blog (`ocm_v2_announcement.md`), website overview, and concepts.*
