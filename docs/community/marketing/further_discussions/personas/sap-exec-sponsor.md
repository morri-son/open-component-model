# SAP Executive Sponsor (LoB Head / Board Sponsor)

**One-sentence identity:** SAP LoB head or senior technology sponsor deciding whether OCM gets engineering capacity next budget cycle, needs to understand strategic position, not the mechanic.

## Role / Background / Seniority

- Senior director / VP / C-level at SAP
- Decides engineering allocation, headcount, political cover
- Already knows sovereign-cloud, NIS2, DORA, CRA as market context; skeptical of "why OCM matters" framing
- Primary question: "Should SAP keep stewarding OCM or let the community own it?"
- Secondary question: "What lift and payoff for my LoB?"

## What They Care About

1. **Strategic position**, Is stewarding OCM defensible vs. consuming from community?
2. **Disinvestment cost**, What happens if we walk away?
3. **Cross-LoB leverage**, Does this compound investment across LoBs or siloed effort?
4. **Vendor independence**, Can we avoid lock-in by staying on a standard we help shape?
5. **Ecosystem velocity**, Is the open peer community accelerating around OCM?

## What They Push Back On

- **"Why not let the community handle OCM?"**
  - Concern: Let open-source community standardize; SAP consumes; saves budget
  - Response (from exec-internal-sponsor deck): "The peer ecosystem is converging. SAP is the biggest contributor by a comfortable margin. The biggest contributor shapes the standard. Walking away costs more than staying."

- **"Prove this is production-ready, not research."**
  - Concern: Is this vaporware or do we have real deployments?
  - Response: "Five SAP LoBs shipping today: Hyperspace, RBSC, CSI, Steampunk, Sovereign Services & Delivery. Four SAP open-source projects aligned: Gardener, Kyma, Open Control Plane, Konfidence. Production, not research."

- **"What's the concrete business outcome?"**
  - Concern: Cross-LoB leverage is abstract; needs LoB-relevant answer
  - Response (from exec deck Slide 11, "Six outcomes"): Faster sovereign delivery. Compliance leverage across LoBs. Integration after acquisition. Cross-LoB security correlation. One source of truth. Ecosystem stewardship.

- **"Isn't compliance already automated?"**
  - Concern: Doesn't want yet another compliance tool
  - Response: "OCM correlates findings across products via the coordinate system. When a CVE drops, 'which SAP product is affected' is one query, not a fire drill."

## Language and Tone They Respond To

- **Strategic framing**, "Steering position" vs. "consumption"; positioning in the ecosystem
- **Disinvestment math**, "Walking away costs more than staying"
- **Concrete proof**, Named adopters (Hyperspace, RBSC, CSI, Steampunk, SS&D)
- **Peer momentum**, Gardener, Kyma, Open Control Plane, Konfidence
- **Cross-LoB compounding**, Work in one LoB benefits every other LoB
- **No mechanic-speak**, Doesn't want descriptor / signature / transport details

## Anchor questions to test messaging against

- "Why are we investing SAP capacity vs. letting the community do it?"
- "Who else is shipping OCM today?"
- "What's the cross-LoB compounding effect?"
- "What if we stop investing, what breaks?"
- "How does this help me pass the next NIS2 / CRA audit?"

## Sources

- `decks/exec-internal-sponsor/deck.pptx`, the canonical audience artefact
- `SPEAKER-NOTES-EXEC-INTERNAL-SPONSOR.md`, verbatim tone reference
