# Speaker Notes — Internal Sponsor Deck (`OCM-Sovereign-Delivery-Internal-Sponsor.pptx`)

**Audience.** Internal SAP sponsors — LoB heads, board sponsors, technology officers who decide whether OCM gets engineering capacity, headcount, and political cover for the next budget cycle. They already know SAP. They don't need to be sold on sovereign-cloud as a market — they need to be sold on **why SAP should keep stewarding OCM rather than letting it drift**.

**Talk length.** ~13 minutes. Same as external, but the rhythm is different — less "let me convince you this matters", more "here's where we are, here's the choice in front of us".

**Tone.** Honest. Internal. You can name the elephant: every LoB has rebuilt delivery mechanics separately, and that's expensive. You can be candid about the disinvestment risk — that's the actual decision the sponsor is being asked to weigh in on. No marketing-speak. No "industry-leading". They'll spot it instantly and switch off.

**Posture.** You're a peer making a case to a peer. You believe SAP should keep investing because the work is real and the leverage is bigger than a single LoB's budget. State that, don't perform it.

**Slide count.** 14 presented slides + appendix glossary + 2 hidden trademark slides (not presented). Final deck after dropping SBOD variants and NATIVE PPT shape variants.

---

## SLIDE 1 — HERO  (00:00 — 00:45, ~45 sec)

**On screen.** Two parallel stop-sentences: "Every LoB ships." (white) / "Separately, every time." (gradient). Subtitle: "OCM is the shared standard. Each LoB still ships — on the same model."

**Speaker notes.**

Open with the observation, no preamble.

> "I want to start with something we all already know but don't usually say out loud. Every line of business at SAP ships its own delivery — separately, every release cycle. Signing. Transport. Sovereign-cloud readiness. Compliance reporting. Each LoB has built its own version of all of that, and each one operates it independently."

Pause. Let it land. This is a true statement; if the room nods, you've earned the next ten minutes.

> "OCM is the shared standard for that work. Open source, governed by NeoNephos, stewarded by SAP. Each LoB still ships its own products — what changes is that they ship on the same model. Same vocabulary. Same signing primitive. Same transport story. Same compliance evidence."

> "Today I want to walk you through why that matters now, where we already are, and what the choice in front of us is."

Move on.

---

## SLIDE 2 — WHY NOW  (00:45 — 02:30, ~105 sec)

**On screen.** Three columns: ECOSYSTEM VELOCITY · THE WINDOW · DISINVESTMENT COST. Subtitle: "Compliance and sovereignty are given. Our strategic position is a choice."

Each column is two parallel stop-sentences: an observation, then a consequence-if-no-action.

**Speaker notes.**

Don't read the columns. Frame the choice.

> "The subtitle is the whole pitch in one line: compliance and sovereignty are given. We're not arguing about whether DORA, NIS2, sovereign-cloud delivery are real — they are. They're table stakes for the markets we serve. The strategic question is what shape SAP shows up in."

**Column 1 — Velocity.** "The peer ecosystem is converging. Gardener, Kyma, OpenControlPlane, Konfidence, Platform Mesh — all aligned around the OCM primitive. SAP is currently the biggest contributor, by a comfortable margin. And the biggest contributor shapes the standard. That's true today, and it'll be true in two years — about whoever the biggest contributor is *then*."

**Column 2 — Window.** "The rails are being laid right now. NeoNephos governance is forming. CRA enforcement starts. The sovereign-cloud market is taking shape. Late entrants pay migration cost. Early stewards keep optionality and shape the standard around their use cases."

**Column 3 — Disinvestment.** "And here's the real number — walking away costs more than staying. Each LoB that builds its own retrofit pays the cost OCM was supposed to amortise. The standard gets shaped without us. Competitors who keep investing get the standard built around their preferences."

> "That's the choice. Not 'should we adopt OCM' — we already did. The choice is whether we keep the steering position or hand it to someone else."

---

## SLIDE 3 — THE ANSWER  (02:30 — 03:30, ~60 sec)

**On screen.** Hub-and-spoke diagram. OCM in the centre. Artifacts left, deployment boundaries right, compliance frameworks bottom.

**Speaker notes.**

Brief. The audience knows what OCM is — they need a refresh, not an introduction.

> "Quick refresher. This is what OCM ties together. On the left, every artifact type — images, charts, npm, binaries, config. On the right, every deployment boundary — EU, US, sovereign cloud, customer-owned. Underneath, every compliance regime — DORA, NIS2, CRA."

> "One identity. Every boundary. That's the model."

Move on.

---

## SLIDE 4 — THE SHIFT, SBOM INSIDE SBOD  (03:30 — 04:15, ~45 sec)

**On screen.** SBOD diagram: artifact list (Docker images, Helm charts, K8s manifests, config files, SBOM) on the left, signature bracket on the right with "One digest covers all." Component identity at the top.

**Speaker notes.**

Show the picture first; the explanation follows on the next slide.

> "Visually: this is the SBOD. Container image, chart, manifests, config, the SBOM itself. One signed envelope. One identity at the top — `github.com/acme/webshop:v1.0.0`. Everything that was delivered, with one signature covering all of it."

Pause.

> "Internally, this picture is what every LoB needs. Today, every LoB has its own version of it. With OCM, they share the picture."

---

## SLIDE 5 — THE SHIFT (bullets)  (04:15 — 05:15, ~60 sec)

**On screen.** Title: THE SHIFT. Subtitle: "SBOM lists. SBOD delivers." Four bullets.

**Speaker notes.**

> "There's a category shift happening — SBOMs were built for inventory, what's-in-the-software. SBODs — Software Bill of Delivery — are built for delivery, what-was-shipped-where-and-how-to-verify. The SBOD contains the SBOM."

**Bullet 4 specifically — the political one.** "SBOD is the category SAP defined. Now standardised through NeoNephos. That's the kind of position the disinvestment slide was talking about — a place where SAP is the one defining the vocabulary, and the industry is adopting it. That position has value, and it's worth protecting."

> "OCM doesn't replace your SBOM tooling, by the way. It gives the SBOM an envelope — signed once, transports intact, audit-ready at every hop."

---

## SLIDE 6 — HOW OCM COMPOSES  (05:15 — 06:30, ~75 sec)

**On screen.** Three columns: SIGNING / TRANSPORT / COMPLIANCE. Each two parallel lines — [what you have today] / [what OCM adds].

**Speaker notes.**

Internal twist: emphasise that this isn't competing with what LoBs already have — it's the connective tissue.

> "Whenever I show this internally, the first reaction is 'we already have signing, we already have registries, we already have scanners.' Right. Of course you do. OCM doesn't replace any of that. OCM composes around what each LoB already has."

**Walk through the columns. Slide gives setup; you deliver the punchlines.**

> "Signing: you sign artifacts. OCM signs the release as a whole — one signature, every digest. So when audit shows up, you don't track twelve signatures across twelve artifacts — you track one."

> "Transport: your registries differ — by type, by location, by LoB. OCM moves the release across them all. Same identity. Same signature."

> "Compliance: your scanners see one artifact at a time. OCM correlates findings to the release. Compliance becomes continuous, not a quarterly project that each LoB runs separately."

> "What this means for SAP specifically: instead of every LoB owning its own signing-transport-compliance pipeline, every LoB plugs into the same primitive. Investment compounds across LoBs. That's the leverage."

---

## SLIDE 7 — OCM IN ONE PICTURE  (06:30 — 08:00, ~90 sec)

**On screen.** Pack · Sign · Transport · Deploy → Sovereign Cloud diagram. Four tiles plus a Sovereign Cloud destination.

**Speaker notes.**

Same flow as external, but with internal framing.

> "The whole flow on one slide. Four verbs."

**PACK.** "Bundle every artifact your software needs into one named, versioned component. One source of truth."

**SIGN.** "One signature covers every artifact in the bundle by digest."

**TRANSPORT.** "Move the bundle across registry boundaries — cloud to cloud, region to region, into an air-gapped archive — without breaking the signature."

**DEPLOY.** "At the destination, verify the signature, unpack, deploy. GitOps or OCM K8s controllers — your team's call. No callback upstream."

> "Every LoB at SAP has built some version of this. Some are mature, some are partial, some are still spreadsheets. With OCM, they're all on the same picture — and the work to mature one LoB's version helps every other LoB."

---

## SLIDE 8 — SOVEREIGN-READY  (08:00 — 09:00, ~60 sec)

**On screen.** Title: SOVEREIGN-READY. Subtitle: "Trust, but verify." Four bullets, each anchor + characterisation + consequence.

**Speaker notes.**

> "Sovereign-ready isn't a checkbox. It's a property of the delivery model. Four things have to be true:"

**Bullet 1 — Identity.** "Location-independent. The component carries its name regardless of registry."

**Bullet 2 — Signatures.** "Location-independent. Sign once at source, verify anywhere downstream. No callback upstream."

**Bullet 3 — Day-2 ops.** "Happen inside the boundary. Subscribe to the component, pull upgrades, scale across regions. Still no callback."

**Bullet 4 — Transfer.** "Self-contained. Every artifact travels with the component."

> "Several SAP LoBs are already shipping into sovereign environments today — those four properties are how they get away with it."

---

## SLIDE 9 — SOVEREIGN-READY — AIR-GAP  (09:00 — 10:00, ~60 sec)

**On screen.** Air-gap diagram. Source side (left), trust boundary (middle), sovereign target (right) with three green checks (Local registry / K8s cluster / Auditor). Footer: "SAME IDENTITY · SAME SIGNATURE · ANY LOCATION".

**Speaker notes.**

Reinforce visually.

> "Source side, left. Pack and sign. Public registry or your dev environment, doesn't matter."

> "Trust boundary, middle. The air gap. The sovereign-cloud edge. The regulated network perimeter."

> "Sovereign target, right. Component lands. Local registry receives it. Verification happens locally — same signature, same identity. K8s cluster pulls from local. Auditor signs off based on the component's own evidence."

> "Same identity. Same signature. Any location."

---

## SLIDE 10 — SCAN  (10:00 — 10:45, ~45 sec)

**On screen.** Title: SCAN. Subtitle: "Compliance as a system property — not a quarterly retrofit." Four bullets (no ODG definition — internal audience knows ODG).

**Speaker notes.**

Brief stop here — internally everyone knows ODG, you don't need to introduce it.

> "Open Delivery Gear is the OCM-native compliance engine. ODG dashboard is the entry point — every component, every finding, one view. Continuous scans run asynchronously, even after release. Findings get rescored against contextual risk — the team only patches what actually matters, not the noise. Every signal correlates by component identity — auditors get answers, not spreadsheets."

> "What this gets us internally: when a CVE drops, the question 'which SAP product is affected' isn't a fire drill across LoBs. It's a query. The OCM coordinate system answers it."

---

## SLIDE 11 — WHAT OCM UNLOCKS FOR SAP  (10:45 — 11:45, ~60 sec)

**On screen.** Six tiles, internal-outcomes framing: Faster sovereign delivery · Compliance leverage across LoBs · Integration after acquisition · Cross-LoB security correlation · One source of truth · Ecosystem stewardship.

**Speaker notes.**

This is the slide the sponsor came for. Pace it.

> "Six outcomes from one shared primitive. Internally."

**Tile by tile, brief.**

> "**Faster sovereign delivery.** Pack once, ship everywhere. Sovereign Cloud across all SAP products on one mechanism."

> "**Compliance leverage across LoBs.** Report from one shared primitive. ODG correlates findings across products — auditors see SAP, not eight separate stories."

> "**Integration after acquisition.** When SAP acquires, the new company's delivery mechanism is rarely SAP's. With OCM, both converge onto one model. Faster integration, less rework."

> "**Cross-LoB security correlation.** When something drops at 11pm, the blast-radius question is one query. Answered via the OCM coordinate system."

> "**One source of truth.** One signed descriptor per delivery. Rebuild any landscape."

> "**Ecosystem stewardship.** The investment compounds with the open-peer ecosystem. SAP gets the standard built around its preferences — because SAP is the steward."

> "Six things. One model. Cross-LoB by construction."

---

## SLIDE 12 — WHERE OCM IS SHIPPING — OPEN ECOSYSTEM  (11:45 — 12:15, ~30 sec)

**On screen.** Logo wall: Gardener · Kyma · OpenControlPlane · Konfidence — each with a substantive caption ("Managed Kubernetes" / "Cloud-native runtime" / "Control-plane framework" / "Reproducible delivery"). "Aligned with NeoNephos" at the footer.

**Speaker notes.**

Quick tour. Don't dwell.

> "Outside SAP, here's where OCM is shipping. Gardener — production for over five years, the managed Kubernetes layer. Kyma — the cloud-native runtime. OpenControlPlane — the control-plane framework. Konfidence — reproducible delivery, ApeiroRA-aligned. All aligned with NeoNephos, which now governs the standard."

> "This is the velocity I mentioned at the start. It's real, and it's accelerating."

---

## SLIDE 13 — WHERE OCM IS SHIPPING — SAP  (12:15 — 12:45, ~30 sec)

**On screen.** Bullet list, parallel short form: Hyperspace · RBSC · CSI · Steampunk · Greenhouse.

**Speaker notes.**

Internal evidence. Be specific.

> "Inside SAP — five pieces of delivery infrastructure already on OCM."

> "Hyperspace — internal Dev Portal and product delivery. RBSC — the Release-Based Shipment Channel, customer shipments. CSI — Common Service Infrastructure, the shared internal services platform. Steampunk for ABAP development. Greenhouse for cloud ops."

> "This isn't theoretical. SAP is already running on it. The question is whether SAP keeps stewarding the standard or hands the steering wheel over."

---

## SLIDE 14 — CTA — SPONSOR · SCALE · STANDARDIZE  (12:45 — 13:30, ~45 sec)

**On screen.** "Sponsor. Scale. Standardize." Three action lines.

**Speaker notes.**

Close with the actual ask. Plain, no posturing.

> "Three asks."

> "**Sponsor.** Allocate engineering capacity to OCM stewardship in your LoB. Concretely: name a person, name the percentage, write it into the next quarter's plan."

> "**Scale.** Pack one regulated component as an OCM component this quarter. Pick something that's already going through compliance friction — that's where the early payoff is."

> "**Standardize.** Bring your LoB into the OCM steering conversation. SAP Slack, channel `#sap-tech-ocm`. The earlier your LoB's voice is in the room, the more the standard reflects your delivery reality."

> "Sponsor. Scale. Standardize. That's the ask."

> "Thank you."

(Take questions.)

---

## TIMING TOTAL

| Slide | Topic | Duration |
|---|---|---|
| 1 | Hero — Every LoB ships. Separately, every time. | 0:45 |
| 2 | WHY NOW (Velocity / Window / Cost) | 1:45 |
| 3 | THE ANSWER — hub-and-spoke | 1:00 |
| 4 | SBOM INSIDE SBOD (diagram) | 0:45 |
| 5 | THE SHIFT (bullets) | 1:00 |
| 6 | HOW OCM COMPOSES | 1:15 |
| 7 | OCM IN ONE PICTURE | 1:30 |
| 8 | SOVEREIGN-READY (bullets) | 1:00 |
| 9 | AIR-GAP (diagram) | 1:00 |
| 10 | SCAN / ODG | 0:45 |
| 11 | WHAT OCM UNLOCKS FOR SAP | 1:00 |
| 12 | OPEN ECOSYSTEM | 0:30 |
| 13 | SAP delivery infrastructure | 0:30 |
| 14 | CTA | 0:45 |
| **Total** | | **13:30** |

A bit longer than the external — the disinvestment-cost framing on WHY NOW and the six-outcomes tile slide need the extra weight. If pressed, slide 9 can drop to 30 sec; otherwise sit on it, the sovereign-cloud picture is what compliance officers need to see.

---

## Q&A PREP — internal questions that come up

- **"Why NeoNephos and not CNCF?"** → NeoNephos was created specifically for sovereign-cloud governance — the regulated-industry adoption story matters here, and CNCF doesn't carry that frame. SAP and partners have a stronger steering position at NeoNephos than they would at CNCF. (slide 12)
- **"What's the engineering cost to standardise on OCM in my LoB?"** → Mid-single-digit person-quarters typically — most LoBs already have a delivery layer; the work is mapping it onto OCM, not rebuilding it. (slide 14)
- **"Why don't we just use [LoB X's internal delivery system]?"** → Because LoB Y has its own, and LoB Z has its own, and that's the disinvestment cost on slide 2. The point is shared mechanics. (slide 2)
- **"What if the open community pulls OCM in a direction we don't want?"** → That's the whole point of stewardship. SAP has the most engineering investment, the most adopters, and the steering committee seat. The community shapes the standard with us, not against us — but only as long as SAP stays in. (slide 2 / slide 12)
- **"What happens if we walk away?"** → The standard moves to whoever fills the steering position. Likely a US hyperscaler. SAP becomes a consumer of someone else's standard, with all the migration and lock-in cost that implies. (slide 2)
- **"Show me the migration path from [LoB X's bespoke delivery] to OCM."** → That's the architect-deck conversation — different audience, different depth. Happy to set that up. (off-prompt)

---

## NOTE — what to leave OUT of this deck even if asked

- **Specific tooling names** like Sigstore, Trivy, S3, OCI registries. Internal architects know them; for sponsors they're noise.
- **Spec details.** Component descriptors, plugin system. Architect material.
- **Roadmap.** Sponsors care about the steering position, not next quarter's commit log.
- **Headcount asks.** The ask is "allocate capacity in your LoB" — concrete numbers belong in the follow-up conversation, not the pitch.

---

## DELIVERY NOTES

- **The disinvestment frame on slide 2 is the load-bearing argument.** If you only have 5 minutes, you can deliver slide 2, slide 11, slide 13, slide 14 and nothing else. Everything else is supporting.
- **The "biggest contributor shapes the standard" line on slide 2 column 1 is the rhetorical engine.** It says "SAP is currently in front" without sounding triumphant, and it implies "staying in front is an active choice" without sounding alarmist. Pause for half a beat after you say it.
- **Don't apologise for the technical detail in slides 6-9.** Sponsors at SAP have technical literacy; what they don't have is the time to assemble the picture themselves. You're saving them work.
- **Stay calm on slide 11.** The "WHAT OCM UNLOCKS FOR SAP" tiles are the slide where everyone wants to interject with their LoB's specific need. Acknowledge ("yes, that's exactly tile 4 / tile 6 / etc.") and keep moving — full conversation belongs in follow-up.
- **Stop-sentence rhythm.** Hero ("Every LoB ships. / Separately, every time."), slide 2 column subtitles, CTA — all use the stop-and-go rhythm. Honour the pauses; don't rush them. The whole deck is built on this beat.
