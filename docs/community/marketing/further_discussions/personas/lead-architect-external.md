# Lead Architect: External (CNCF-adjacent, Senior)

**One-sentence identity:** Senior software architect at a CNCF-adjacent organization, evaluating OCM as a potential delivery standard; skeptical of marketing claims, grounded in technical reality.

## Role / Background / Seniority

- Typically 10+ years in infrastructure or platform engineering
- Familiar with CNCF landscape: Kubernetes, OCI registries, Helm, cosign/sigstore
- Has built or maintained delivery systems for regulated environments
- Often holds architectural decision-making power or strong influence
- Evaluating OCM for production adoption, not research

## What They Care About (Goals When Reviewing the Deck)

1. **Correctness and composability**, Does OCM actually solve a real problem, or is it redundant?
2. **Technical depth**, What are the actual mechanisms? How do digest pinning, signatures, and composition interact?
3. **Production readiness**, Is this mature enough to run day-2 operations? What breaks?
4. **Security properties**, Is the trust model sound? Per-component vs. per-release signing implications?
5. **Interoperability**, How does this coexist with their existing signing / registry / deployment tools?

## What They Push Back On

- **Uniqueness arbitration:** "Who prevents `github.com/microsoft/azure-cli` squatting?"
  - Concern: DNS-prefix model doesn't prevent supply-chain impersonation
  - Response: "Uniqueness is delegated to DNS. Two parties claiming `acme.org/helloworld` is prevented the same way two parties claiming `acme.org` is prevented, by DNS delegation, not by OCM."

- **Name-spoofing attacks:** "What if someone forges a perfectly-signed component under my name?"
  - Concern: Per-component trust anchoring doesn't scale to org-wide name-prefix policies
  - Response: "Trust is per-component, the verifier knows what trust anchor to apply to the descriptor in front of it. Per-name-prefix trust-anchor binding is not in the spec or the controllers today."

- **Composition safety:** How do referenced components stay trustworthy when you bump a version? (Led to Slide 8 & 12 focus on transitive digest pinning.)

- **Verification defaults:** Does the controller verify signatures by default? (Phase 2B changed Slide 11 speaker notes to explicitly state verification is opt-in.)

## Language and Tone They Respond To

- **Technical precision**, Use "descriptor digest", not "component identity" when discussing what's signed
- **Honest about trim edges**, They *expect* a limitations slide; distrust decks without one
- **YAML over prose**, Show the data structure, walk through fields, let them parse the shape
- **Peer-to-peer**, Don't explain basics (registries, SemVer, digests); assume they know
- **Backed by spec**, Reference the OCM spec when asked; they'll verify

## Anchor questions to test messaging against

- "How is 'globally unique' actually enforced?"
- "What breaks if I re-sign a referenced component?"
- "Does the K8s controller verify signatures by default?"
- "How does OCM coexist with the cosign attestations we already produce?"
- "What's the migration cost from Helm-based delivery to OCM-wrapped delivery?"

## Sources

- `docs/community/marketing/decks/architect-phase2a/notes/PHASE2B-CHANGE-SUMMARY.md`, Slides 3, 6, 8, 9, 14 changes attributed to Lead Architect feedback
- `docs/community/marketing/decks/architect-phase2a/notes/SPEAKER-NOTES-ARCHITECT-EXTERNAL.md`, Q&A backups (Slides 3, 6, 8)
- Phase 2B temporary reports (`/tmp/persona-1-*.md`, not persisted)
