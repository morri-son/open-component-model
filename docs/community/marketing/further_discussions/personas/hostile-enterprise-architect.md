# Hostile Enterprise Architect: External

**One-sentence identity:** Skeptical enterprise architect who wants to prove OCM is redundant. Will ask "why not just compose X + Y + Z?" and look for missing pieces or overclaims.

## Role / Background / Seniority

- 8–15 years in enterprise infrastructure, supply-chain, or security architecture
- Already familiar with cosign, OCI referrers, in-toto, SLSA, the "incumbent" tools
- Starting posture: "We already have a signing and delivery stack; why replace it?"
- Actively looks for gaps, overreach, or technical inaccuracy to dismiss OCM
- High leverage in architectural decision-making; can kill adoption with "this is just a wrapper"

## What They Care About (Goals When Reviewing the Deck)

1. **Finding gaps or overclaims**, Can I catch the deck in a contradiction?
2. **Proving redundancy**, Can I show the audience this is cosign + in-toto + existing tools under a new name?
3. **Attack surface**, Where are the security assumptions the deck hides?
4. **Deployment cost**, What infrastructure do I have to add? (Looking for hidden dependencies.)
5. **"Why not just..."**, Can I compose the same outcome from existing pieces?

## What They Push Back On

- **Composition question:** "Why not just compose cosign + in-toto + OCI 1.1 referrers + my GitOps engine?"
  - Tactic: Claim each per-artifact tool already does what OCM claims
  - Response: OCM operates at release level, not artifact level; different unit of analysis. This is what the "How OCM compares" appendix slide (external Slide 18) was built for.

- **Over-claiming on "release as one unit":** Tries to find examples where Helm + cosign already delivers this
  - Argument: "I can sign a Helm values file and a tarball separately"
  - Honest response: "You can sign them separately; you can't sign one descriptor digest that transitively pins both. That's the unit difference."

- **"Why do I need OCM if I have Kyverno + cosign?"**
  - Tactic: Imply OCM is just policy enforcement, which they already have
  - Response: Policy enforcement (Kyverno) and release identity (OCM) are orthogonal; OCM gives you *what to enforce about*.

- **Air-gap footgun discovery:** "What happens if I forget `--copy-resources`?"
  - Concern: Default behavior is a silent failure (access fields point upstream)
  - Response: Named on Slide 14 as trim edge; worth catching in CI

- **Policy floor gaps:** "What stops me down-signing with a weak RSA key?"
  - Concern: Per-component opt-in isn't production-safe
  - Response (per 2026 code audit): Controller v1alpha1 RSA-only; OpenPGP/Sigstore CLI-only; no admission webhook ships; global enforcement is BYO (Kyverno/Gatekeeper).

## Language and Tone They Respond To

- **Direct acknowledgment of existing tools**, Don't pretend cosign/in-toto/SBOM are weak; name what each does well
- **Different unit framing**, "OCM signs the component (the bundle); cosign signs artifacts (individual objects). Different unit of analysis."
- **Honest about dependencies**, Explicitly name what you don't ship (kro, Flux, Kyverno, admission webhooks)
- **Trim edges as strength, not weakness**, "Honest now beats apologetic later. Plan for the edge."
- **Spec language**, Reference the OCM spec directly; they'll check

## Anchor questions to test messaging against

- "Why not cosign + attestations + OCI 1.1 refs?"
- "How does OCM prevent supply-chain impersonation vs. signing at the artifact level?"
- "What happens if I forget `--copy-resources` in an air-gap transfer?"
- "Does the K8s controller do anything the CLI can't already do?"
- "Show me one thing OCM does that composition of existing tools doesn't."

## Sources

- `docs/community/marketing/decks/architect-phase2a/notes/PHASE2B-CHANGE-SUMMARY.md`, Slide 18 "How OCM compares" attributed to Hostile Architect
- `SPEAKER-NOTES-ARCHITECT-EXTERNAL.md`, air-gap default footgun (Slide 10), policy-floor Q&A (Slide 9)
- Phase 2B temporary reports (`/tmp/persona-3-*.md`, not persisted)
