# SAP Internal Architect

**One-sentence identity:** SAP line-of-business architect, mixed OCM-briefed / OCM-cold audience, evaluating adoption fit for their LoB's delivery pipeline, asking "where does this land in my stack?" not "why does OCM matter?"

## Role / Background / Seniority

- 8–15 years at SAP, infrastructure / platform engineering / delivery
- Some heard OCM through Hyperspace mandates, exec-internal sponsor deck, or SLC-29 conversations; others cold
- LoB-specific context: often owns delivery in Hyperspace, RBSC, CSI, Steampunk, Sovereign Services & Delivery, or Greenhouse
- Evaluating whether their LoB should adopt OCM, not whether OCM is a good idea

## What They Care About

1. **LoB-specific fit**, How does this map onto our current signing/transport/compliance workflow?
2. **SAP stack integration**, Does this actually work with RBSC, Hyperspace, our registries, our scanners?
3. **Engineering lift**, What's the person-quarter investment? Retrofit vs greenfield?
4. **Roadmap honesty**, What's shipping today vs what's on the roadmap? (Especially Kubernetes controller RSA-only, Hyperspace v1/v2 gap.)
5. **Cross-LoB leverage**, Do other LoBs also benefit if we invest?

## What They Push Back On

- **"Just adopt OCM."**
  - Concern: SAP LoBs have bespoke compliance, signing, and transport workflows
  - Response: "OCM composes around what each LoB already has. RBSC still ships. Hyperspace still builds. OCM is the wrapper that makes their outputs consistent across LoBs."

- **"What does this cost in engineering?"**
  - Concern: Retrofitting a mature pipeline is expensive
  - Response: "Most LoBs already have a delivery layer; the work is mapping it onto OCM, not rebuilding it."

- **"Is this v2 ready?"**
  - Concern: Hyperspace integration is v1 today; migration not started; won't start Q3 2026
  - Honest answer: "Hyperspace Piper step on v1 today. v2 migration on roadmap, not started. Internally Hyperspace already uses OCM v1 for SBOM aggregation, that's in production."

- **"Where's Landscaper going?"**
  - Concern: Sovereign Cloud uses Landscaper today; want continuity
  - Response: "Landscaper being replaced by Open Control Plane end-2026 / early-2027. OCM components stay the same on both sides; only runtime changes."

- **"Why isn't this mandated via SLC-29?"**
  - Concern: Wants regulatory clarity
  - Response (2026 strategy shift): "The 2024 adoption plan named SLC-29 as the path. Since then we shifted: invest in CLI quality so adoption is organic, watch the standard but don't lead with mandate. Product Standards Lifecycle support is still on the table for future inclusion."

## Language and Tone They Respond To

- **LoB-specific framing**, "Your Helm charts, your signing keys, your registry, OCM wraps, doesn't replace"
- **SAP context named**, Hyperspace, RBSC, CSI, Steampunk, SS&D by name
- **Cross-LoB value**, Work maturing Hyperspace's OCM integration helps CSI's integration
- **Roadmap honesty**, Name Q3 vs. later; controller RSA-only vs. CLI broader scheme set
- **Vision separated from reality**, "OCM-based SAP stack" as *vision*, not deployed reality

## Anchor questions to test messaging against

- "How does this integrate with RBSC today?"
- "What's on the K8s controller today, RSA only, or all three schemes?"
- "When does Hyperspace v2 integration ship?"
- "What happens to Landscaper?"
- "Is my LoB's delivery lift 1 person-quarter or 3?"
- "Why should I invest in OCM if SLC-29 isn't mandating it anymore?"

## Sources

- This session's OCM adoption plan reality check (2024 plan vs 2026 shift)
- SPEAKER-NOTES-EXEC-INTERNAL-SPONSOR, parallel internal-audience deck
- Architect-internal deck (this session's build), especially Slides 13, 15, 16
