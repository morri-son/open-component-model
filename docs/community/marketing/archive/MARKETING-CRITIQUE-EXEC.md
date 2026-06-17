# Marketing Critique — Exec Deck

Reading the current 10-slide exec deck the way a senior B2B marketing strategist would. The audience: CIO, CISO, CTO, board, regulated-industry buying committees. Time budget: 12–15 minutes presented, 90 seconds skimmed in a meeting prep packet.

The deck is **technically accurate, narratively coherent, and currently underselling the product**. The biggest issues are not what it says but what it doesn't make the audience *feel*. Below: the critique. Companion doc with reworked options is `EXEC-DECK-REWORK-OPTIONS.md`.

---

## 1. The deck doesn't open with a stake

Slide 1 ("Secure Delivery for Sovereign Clouds") is a brand promise, not a stake. An exec opens the deck with a question: *"why am I in this room?"* The current hero answers what the project does — not why now, not what it costs to ignore, not what they'd fail to do without it.

Compare to how marketing-mature B2B decks open:
- "$2.7B average cost of a software supply-chain breach in 2025."
- "DORA goes into force this quarter. Here's what it asks of you."
- "Three of your suppliers had software signed by tools that don't talk to each other."

A stake creates urgency. A brand promise creates polite attention.

**Severity:** high. **Slide(s):** 1 (and partly 2).

---

## 2. Slides 2 and 3 say the same thing twice

Slide 2 ("Why now: sovereignty, regulation, supply-chain attacks") and slide 3 ("Software delivery is fragmented, compliance retrofits don't scale") both inhabit the **diagnosis** quadrant of the narrative arc. An exec audience doesn't need two diagnosis slides — it needs *one sharp diagnosis* and an immediate move into *what now*.

Currently:
- Slide 2 lists three pressures (sovereignty, regulation, attacks)
- Slide 3 lists more pressures (fragmented delivery, broken signatures, SBOMs not built for delivery)

These are the same fire viewed from two angles. The deck spends 25–30% of its airtime on diagnosis without yet showing what OCM is.

**Severity:** high. **Slide(s):** 2 and 3 — recommend collapsing or repurposing.

---

## 3. The audience meets "OCM" as a noun on slide 5 — too late

Slide 1 mentions OCM in the org line. Slide 4 explains SBoD. Slide 5 finally says what OCM **does** (Pack · Sign · Transport · Deploy). By that point, an exec has been waiting for the answer for 40% of the deck.

Marketing rule of thumb: introduce the *product name as a verb* by slide 3, not slide 5. "OCM **packs**, **signs**, **transports**, and **deploys** every component as a single signed unit" — that should be a slide-3 line, not a slide-5 framing.

**Severity:** high. **Slide(s):** 1–5 — the whole intro arc.

---

## 4. SBoD is product-marketing jargon that needs more selling than it gets

The SBoD vs SBOM distinction is one of the strongest IP positions OCM has — a *new category name* that the project literally owns. But slide 4 introduces it like a definition, not like a category claim.

How marketing should treat a category name you're trying to coin:
- Repeat the contrast 3×: SBOM lists, SBoD delivers. SBOM = ingredients, SBoD = delivery. SBOM = inventory, SBoD = audit trail.
- Earn it with concrete examples (one specific delivery, one specific SBoD payload).
- Tie it to a regulatory or industry artifact analogy ("a manifest is to a shipping container what an SBoD is to a software delivery").

The current slide does (1) lightly, doesn't do (2), doesn't do (3).

**Severity:** medium-high. **Slide(s):** 4.

---

## 5. The "what OCM unlocks" tile grid (slide 8) is feature-listing, not benefit-selling

Tiles like "Code signing across stacks", "Asynchronous security scans", "One source of truth" describe **mechanisms**, not **outcomes the buyer cares about**. Exec audiences make decisions in the language of:

- Cost (audit prep hours, breach insurance, headcount)
- Risk (regulatory penalty, incident exposure, vendor lock-in)
- Time (release velocity, time-to-compliance, time-to-recover)
- Strategic optionality (sovereign cloud entry, EU market access, M&A integration)

The tile grid currently sells features. Reworked as outcomes:
- "Cut audit-prep from weeks to hours"
- "Ship into a sovereign region next quarter, not next year"
- "Eliminate the per-stack signing-tool sprawl your security team is chasing"
- "Stop paying compliance retrofits as recurring tax"

**Severity:** high. **Slide(s):** 8.

---

## 6. Slide 7 (ODG / Compliance Dashboard) has zero visual evidence

This is the slide where execs decide whether the project is **real**. Five bullets and no screenshot is not enough. Senior buyers want to see a UI, an artifact, a real component descriptor — *something* that says "this exists outside a slide deck."

The IPCEI deck has Compliance Dashboard screenshots that we already know are usable. They should be on this slide.

**Severity:** high. **Slide(s):** 7.

---

## 7. Slide 9 (adopters) is the weakest credibility play in the deck

Six logos, two tiers, no proof of *what those orgs actually do with OCM*. An exec sees logos like "SAP / BwI / SAP NS2" and asks *"are they running OCM in production, or do they just have a CFP?"*

What's missing:
- A **per-logo one-liner**: "BwI uses OCM to ship into Bundeswehr-grade air-gapped environments." "Gardener uses OCM to manage its component graph." (Even if generic.)
- **A scale number**: components delivered, deployments per month, regions, percentage of releases.
- **Quote / testimonial**: even one line, attributed by role not name, raises credibility 10×.

Logos alone are wallpaper. Logos with proof are positioning.

**Severity:** high. **Slide(s):** 9.

---

## 8. The CTA (slide 10) is generic and doesn't ask for a small, specific action

"Try it. Build with us. Talk to us." is three competing CTAs, none specific. An exec leaves with no idea what the *next 30 minutes* of action looks like for them or their team.

Better CTA structures for an exec deck:
- **Single specific ask + escalation path:** "Pick one regulated component. Pack it as an OCM component this sprint. We'll help."
- **Self-serve evaluation tier:** "30-minute reading: ocm.software/start. 2-hour PoC: github.com/open-component-model/poc-template. White-glove session: contact us."
- **Peer pressure CTA:** "Join the SAP / BwI / Gardener cohort already running OCM in production."

**Severity:** medium-high. **Slide(s):** 10.

---

## 9. The deck has no business outcomes anywhere

Search the current deck for words like "revenue", "cost", "time-to-market", "regulatory exposure", "EUR", "headcount", "ROI", "weeks → hours", "audit", "incident". Most don't appear. The few that do appear as backdrop, not as quantified business claims.

Exec decks need at least 2–3 quantified business claims, even if they're directional. Examples:
- "Audit prep: weeks of manual evidence → hours of automated correlation."
- "Air-gap delivery: months of bespoke tooling → reuses your existing pipeline."
- "Compliance per release: from N tools to 1 model."

**Severity:** medium. **Slide(s):** 5, 6, 7, 8.

---

## 10. The deck is missing a "what's at risk if you don't" slide

This is a B2B marketing staple often skipped by engineering-led decks. After diagnosis, after the OCM model, before the close — a slide that crystallises the *cost of inaction*. For OCM:

- DORA/NIS2 audit fines (real numbers exist, ~€10M / 2% revenue)
- Sovereign cloud market access locked away (BSI C5, ENS, FedRAMP equivalents)
- M&A integration friction (every acquired team's signing scheme has to be retired)
- Per-stack tooling cost compounds annually

This is one of the most underused slide-types in technical-product marketing.

**Severity:** medium. **Slide(s):** new slide between current 7 and 8.

---

## 11. The hero's gradient noun is wrong for the audience

"Sovereign Clouds" with the cyan→blue gradient looks great. But for a board audience, the *most pressing* word might not be **Sovereign**. It might be **Compliance**, or **Trust**, or **Audit**. Different audiences = different gradient noun.

The current single-version hero loses an opportunity.

**Severity:** low (but interesting). **Slide(s):** 1.

---

## 12. The deck doesn't differentiate from the obvious comparators

Senior buyers will mentally compare OCM to:
- "Don't we already have cosign + SBOM tools?"
- "Isn't this what GitOps already does?"
- "Couldn't OCI Distribution + Sigstore + a script accomplish this?"

The deck never names these comparators or addresses them. The first time a buyer thinks "we have cosign already," the deck should be ahead of them: "OCM doesn't replace cosign. It uses your cosign keys, plus signs the *whole delivery* (every artifact, every metadata, every reference) by digest. Cosign signs containers. OCM signs deliveries."

**Severity:** medium-high. **Slide(s):** new slide between 4 and 5, OR strengthened bullets on 5.

---

## 13. The deck is silent on cost / pricing / open-source

For an open-source project moving toward enterprise adoption, exec audiences want to know:
- How much does this cost?
- Is it really free? What's the catch?
- What kind of governance prevents it from going Elasticsearch / HashiCorp / Redis?

The current slide 9 mentions NeoNephos governance but doesn't translate it to "your dependencies stay yours, here's how we ensure that." Slide 9 is the natural home for this beat — currently underused.

**Severity:** medium. **Slide(s):** 9.

---

## 14. There's no "what we ship in v2 vs v1 vs v3 next" beat

OCM v2 just shipped (per `ocm_v2_announcement.md`). Exec buyers care about *roadmap maturity* — they don't want to bet on a project that just had its first major rev. A single line "OCM v2 shipped 2026; native OCI compliance, simpler CLI, the same identity model. v3 roadmap public" would land hard.

**Severity:** low. **Slide(s):** could be 5 footer, 9 sidebar, or new mini-slide.

---

## 15. The closing CTA backdrop competes with the message

Slide 10 (CTA) uses the dark Brand Blue Night background — same as the hero. Visually, this loops the deck back to the start, which weakens the *act-now* feeling. CTA slides should feel different from openers — more decisive, more "the meeting ends here."

**Severity:** low. **Slide(s):** 10.

---

## What's good about the current deck (don't lose this in rework)

To balance the critique:

✅ **The Pack · Sign · Transport · Deploy frame on slide 5** is the strongest single slide. Verb chain, repeatable, sticks. Don't touch the structure; only enrich.

✅ **The "Trust, but verify" tagline on slide 6** is pitch-perfect for the audience. Reagan-era reference, immediately understood.

✅ **The locked-narrative tension between SBOM and SBoD** is a genuinely defensible category positioning. Just under-sold (see #4).

✅ **The visual language of the .potx** (eyebrow, big black title, three-column with blue rules, grey-soft tiles) is on-brand and exec-credible. The rework should not touch this.

✅ **The 4-step → 5-step lifecycle bridge** issue we discussed earlier — once fixed — is actually a *strength* (can speak to two audience registers).

---

## Summary scorecard

| Dimension | Current | Target |
|---|---|---|
| Hook strength (slide 1) | 4/10 | 8/10 |
| Diagnosis crispness (2+3) | 6/10 | 8/10 |
| Mental model clarity (4+5) | 7/10 | 9/10 |
| Mechanism-to-outcome translation (8) | 4/10 | 9/10 |
| Visual credibility (7) | 3/10 | 8/10 |
| Adoption proof (9) | 5/10 | 8/10 |
| Close / CTA (10) | 5/10 | 8/10 |
| Comparator differentiation | 2/10 | 7/10 |
| Quantified business claims | 2/10 | 6/10 |
| Cost-of-inaction beat | 0/10 | 7/10 |

Five things — if fixed — would lift the deck the most:
1. Replace slide 1 hero with a stake-led variant
2. Collapse 2 and 3 into one diagnosis slide and add an OCM-as-answer slide right after
3. Reframe slide 8 tiles as outcomes, not features
4. Add a Compliance Dashboard screenshot (or any UI artifact) to slide 7
5. Rewrite slide 10 CTA as a single specific ask

See `EXEC-DECK-REWORK-OPTIONS.md` for concrete rework variants.

*Generated 2026-06-16.*
