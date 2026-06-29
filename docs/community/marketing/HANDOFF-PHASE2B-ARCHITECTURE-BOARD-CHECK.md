# Handoff — Architecture-Board Final Content Challenge

## What this next session is for

**Subject.** Three OCM decks have reached a stable shape:

- **OCM External Architect** (~30 min, technical, the one this session built and tightened)
- **OCM External Exec** (C-suite framing, prior session)
- **OCM Internal Sponsor** (internal-stakeholder framing, prior session)

Before any of them goes in front of a real architecture board, we want a **final content challenge** — *not* a layout/visuals/typography pass. The visuals are locked. The story arcs are locked. What's being challenged is whether the *content holds up against the people who will actually sit in the room*.

**Three personas. One session.** You play each in turn as a fresh-eyes critic, not as a co-author:

1. **OCM Domain Expert / OCM Lead Architect.** Full knowledge of the OCM v2 codebase, the OCM specification, the website docs, the conformance scenarios, and the architectural decisions behind every concept the decks reference. You can quote `bindings/go/...` paths and `ocm-spec/...` paths from memory; you know which features are GA, which are roadmap, which are experimental; you know the difference between the constructor and the descriptor and why the access field is excluded from the signature. Your job is to find **technical claims that are wrong, oversimplified to the point of misleading, or use terminology that drifts from the canonical spec/docs.**

2. **Marketing/Communications Expert specialised in high-impact technical slide decks.** You've shipped dozens of decks for CNCF keynotes, developer-relations talks at major conferences, and architect-track sessions at enterprise events. You know what lands with senior architects: information hierarchy, dramatic structure, where the eye should fall, when the speaker is carrying too much vs when the slide is doing the work. **You do NOT know OCM in detail** — you evaluate craft, not correctness. The previous session ran this persona once already (for the architect deck only); this session re-runs it across all three decks and looks specifically at *consistency of voice across the three audiences* and whether the deck shape is right for an architecture-board review.

3. **Senior Enterprise Architect — Software Lifecycle Specialist (HOSTILE).** You've spent 20 years in software supply chain, configuration management, release engineering, and platform engineering. You know cosign, sigstore, SLSA, in-toto, OCI 1.1 referrers, Helm, Flux, Argo, kro, the OSS supply chain attack surface from XZ to log4shell. You've watched many "new package format" pitches come and go. **You are pre-disposed to skepticism.** You want to know: (a) what does this replace that I already use, (b) what does this NOT do that I will have to keep using my existing tools for, (c) where are the seams between OCM and the tools I already trust, (d) what's the cost of adopting this if I'm wrong about the value, and (e) what evidence do I have that this isn't just yet another organisation pushing yet another acronym. You read every slide critically. You raise your hand in Q&A.

## What the personas have access to

Place these in each persona's reading list (with role-specific selection — see below):

### Decks (the artifacts under review)

Located in `~/Downloads/OCM/`:

- `OCM-Story-Architect-External.pdf` — 16 pages (15 main + 1 appendix), render-order: 1 Pain / 2 Diagnosis / 3 The Hinge / 4 Where OCM Sits / 5 Constructor / 6 Descriptor / 7 The Four Moves / 8 Compose / 9 Sign / 10 Transport / 11 Deploy / 12 Day 2 / 13 Adoption / 14 What's Sharp / 15 CTA / 16 Appendix Replication
- `OCM-Story-Exec-External.pdf` — C-suite framing, external audience
- `OCM-Story-Exec-Internal-Sponsor.pptx` — internal-sponsor framing. **This one is `.pptx`, not `.pdf`** — unzip and read the XML (`unzip -d /tmp/exec-internal-pptx <file>`; the slide XML is in `ppt/slides/slide*.xml`). The previous session used this pattern when extracting from a `.pptx`; the same approach works.

### OCM project context (the truth references)

Located in the worktree:

- `website/content/docs/` — full documentation. Especially:
  - `concepts/signing-and-verification-concept.md`
  - `concepts/component-identity.md`
  - `concepts/transfer-concept.md`
  - `concepts/ocm-controllers.md`
  - `concepts/kubernetes-deployer.md`
  - `overview/core-model.md`
  - `overview/how-ocm-works.md`
  - `reference/input-and-access-types.md`
  - `reference/component-constructor.md`
  - `reference/kubernetes-api/*.md`
  - `getting-started/*.md`
  - `tutorials/signing/*.md`
  - `how-to/Sign and Verify/*.md`
  - `how-to/transfer-helm-charts.md`
  - `how-to/air-gap-transfer.md`
- `website/content/blog/` — blog posts, framing for the wider audience. **Note the singular `blog`, not `blogs`.**
- `bindings/go/...` — the implementation. The signing-experimental and Sigstore stability findings from the previous session live in this tree (`bindings/go/rsa/signing/v1alpha1/encoding_policy_pem.go:33` carries the `Experimental:` marker; `bindings/go/sigstore/signing/v1alpha1/` has no equivalent marker; both ship under `v1alpha1`).

### OCM spec (parallel checkout)

`/Users/D032990/github/github.com/morri-son/ocm-spec/doc/` — the canonical OCM specification. Especially `01-model/`, `04-extensions/01-artifact-types/`, `04-extensions/02-access-types/`, `05-guidelines/02-contract.md`. This is the source of truth above the website docs.

### Legacy OCM v1 codebase

`/Users/D032990/github/github.com/morri-son/ocm/` — the v1 line. Relevant when the decks reference roadmap items that v1 shipped and v2 hasn't yet (npm/maven access types in `api/ocm/extensions/accessmethods/{npm,maven}/`).

### Out-of-website background reading (for the architect persona only)

Located in `~/dies-und-das/OCM/`:

- `whitepaper.pdf` — the OCM whitepaper. **Highest-value document.** Likely the canonical positioning + technical framing the decks should be aligned with.
- `OCM-Adoption Plan.pdf` — the project's own adoption thinking. Use this to challenge slide 13 (Adoption) — does the deck's "two paths" framing match the project's actual adoption strategy?
- `2024-05-28_OCM_Delivery_and_Compliance_Automation.pdf` — older Delivery & Compliance Automation framing (May 2024). Useful for tracking how the OCM story has evolved; the architect deck should be the *current* story, not an echo of older positioning.
- `20250327 IPCEI-CIS GA OCM-ODG – Kopie.pdf` — IPCEI-CIS GA framing (March 2025). NeoNephos / sovereign-cloud positioning context. Useful for understanding the wider regulatory and standards context the decks reference (NeoNephos Foundation, IPCEI).

## Reading list per persona

| Document / Path | OCM Architect | Marketing Expert | Senior Architect (Hostile) |
|---|---|---|---|
| All three decks (PDFs + the PPTX) | ✓ all three | ✓ all three (focus on craft) | ✓ all three (focus on the architect deck most carefully) |
| Speaker notes (`docs/community/marketing/decks/architect-phase2a/build-pptx/speaker_notes.py`) | ✓ | ✓ | ✗ (latecomer/audience persona doesn't have speaker notes) |
| Speaker notes long-form (`docs/community/marketing/decks/architect-phase2a/notes/SPEAKER-NOTES-ARCHITECT-EXTERNAL.md`) | ✓ | ✓ | ✗ |
| `website/content/docs/**/*.md` | ✓ (verify decks against docs) | ✗ (don't need to know OCM) | ✓ (cross-check what the docs say vs what the decks say) |
| `website/content/blog/**/*.md` | ✓ | optional | optional |
| `~/dies-und-das/OCM/whitepaper.pdf` | ✓ (read end-to-end first) | ✗ | ✓ (skim, focus on positioning sections) |
| `~/dies-und-das/OCM/OCM-Adoption Plan.pdf` | ✓ | ✗ | ✓ (critical: cross-check slide 13) |
| `~/dies-und-das/OCM/2024-05-28_OCM_Delivery_and_Compliance_Automation.pdf` | ✓ (skim for drift) | ✗ | optional |
| `~/dies-und-das/OCM/20250327 IPCEI-CIS GA OCM-ODG – Kopie.pdf` | ✓ (NeoNephos framing context) | optional (positioning context) | optional |
| OCM v2 code (`bindings/go/`) | ✓ (verify GA-status claims, access-type lists, signing surface) | ✗ | ✗ |
| OCM spec (`/Users/D032990/github/github.com/morri-son/ocm-spec/doc/`) | ✓ (the source of truth) | ✗ | ✓ (where claims should be traceable to) |
| OCM v1 code (`/Users/D032990/github/github.com/morri-son/ocm/`) | ✓ (compare v1 vs v2 shipping surface) | ✗ | optional |

## What was already decided in the previous session — out of scope to re-litigate

These were settled. Don't spend persona tokens on them:

- **Slide 4 noun list** keeps "SBOMs, npm, maven" (free-form `type:` field justifies it; speaker notes carry the roadmap nuance for npm/maven access bindings)
- **Slide 7 placement** stays between slide 5/6 (the static artifact) and slides 8–11 (the mechanics). Not moved before slide 5.
- **Slide 7 eyebrow** is "THE FOUR MOVES" (no qualifier like "in lifecycle")
- **Slide 11 title verb** is "verify and apply" (not "deploy")
- **Replication moved to appendix slide 16** — not on slide 11's main chain
- **Slide 12 footer color** is brand blue (matches the diff highlights on day-2)
- **"Coordinates" terminology** renamed to "Component identity" across slides 3, 5, 6 and speaker notes
- **Sigstore docs PR** (removing the early-access callout in `signing-and-verification-concept.md`) is gating delivery — must be merged before the talk. The deck claims "all three GA on the v1alpha1 surface today" for RSA / GPG / Sigstore. PEM stays experimental — flagged on slide 14 as one of the three honest edges. *Don't re-litigate this; it's resolved.*
- **Slide 14 third edge** is "Helm-deploy adds kro + Flux" (replaced the older PEM-experimental edge)
- **Slide 15 CTA** reshape to architect-arc: Evaluate · Pilot · Engage (matches exec deck's pattern)
- **Slide-7 card design** (rounded rect, brand-blue top stripe, soft shadow, no border, Aptos labels mid-blue 30pt bold) is the deck-wide card family. Slide 11 and slide 16 also use it (slide 16 with grey-toned variant for the dimmed chain). Don't propose alternative card designs.

If a persona finds a new flaw on or near these decisions, surface it; just don't re-litigate the decision itself.

## What to challenge

### Persona 1 — OCM Lead Architect (technical hostile)

Read every technical claim on every slide AND in the speaker notes (both `speaker_notes.py` and the long-form `.md`). For each claim, classify and quote the supporting / contradicting evidence with `file:line` citations:

- **CONTRADICTED** — the docs, code, or spec disagree with the slide.
- **OVERSIMPLIFIED** — true but misleading at the slide's altitude; a careful architect would push back.
- **TERMINOLOGY DRIFT** — meaning is right but the wording differs from the canonical spec/docs vocabulary.
- **SOPHIST / HAND-WAVING** — rhetorically strong but technically vacuous; would not survive Q&A.
- **MISSING** — the slide should disclose something an architect WILL find on day 1 and feel deceived about.

Push hard on:

- Slide 3 / slide 4 / slide 6 / slide 9 / slide 11 / slide 12 / slide 14 — the technically-load-bearing slides.
- **Consistency with the whitepaper.** Does the architect deck contradict, simplify, or evolve away from the whitepaper's framing? If so, is that drift intentional?
- **Cross-deck consistency.** Do the three decks (Architect / Exec External / Exec Internal Sponsor) agree on what OCM is, what it replaces, what it composes with? Where do they drift? Drift across audience is fine if intentional; accidental drift is a credibility risk.
- **What the OCM Adoption Plan says vs what slide 13 says.** Slide 13 promises "two paths to a first OCM component in production." Does the project's own adoption plan agree this is the recommended path?
- **Things the decks should disclose but don't.** Read `whitepaper.pdf` and `bindings/go/` and look for caveats / known limitations / experimental features that don't appear on any slide and aren't in any speaker note.

Output: a ranked findings list — CRITICAL / SUBSTANTIVE / NITPICK — same format as the previous session.

### Persona 2 — Marketing Expert (craft critique, all three decks)

The previous session ran this persona on just the architect deck. This session, **run it across all three** with a specific lens: **does the three-deck portfolio read as one coherent OCM story, or as three disconnected pitches?**

- Same per-slide structural critique as last time (information hierarchy, cognitive load, dramatic structure, bookend alignment, density rhythm, color discipline) — but applied to all three decks.
- **Cross-deck:**
  - Do the three decks share a recognisable visual language?
  - Do they say the same thing about *what OCM is* in their opening slides?
  - Do their CTAs hand off the audience to the right next step for each persona?
  - Is the architect deck's "Evaluate / Pilot / Engage" CTA aligned with the exec deck's CTA in a way that makes the two decks feel like a single sales motion, or do they fight each other?
- **For an architecture-board review specifically:** is the architect deck the right shape for that meeting, or would an architecture board want something different (more comparative? more decision-tree? more "show me the risks and the trade-offs"?)? Some architecture boards expect a recommendation slide. The current deck doesn't have one explicit. Should it?

Output: ranked findings list — HIGH-IMPACT / WORTH DOING / POLISH / DOES WELL — plus an arc-level read of each deck and a cross-deck consistency assessment.

### Persona 3 — Senior Enterprise Architect (HOSTILE, audience-shaped)

You walk into the architecture board meeting fresh. You sit down at the table. The deck is shown to you. **You have access to nothing else** — no website docs, no speaker notes, no whitepaper. Just the rendered slides.

For the architect deck specifically:

- **Slide by slide, what did you understand and what made you skeptical.** Be honest about confusion: if `componentReferences` is shown on slide 8 without context, say "I have no idea what that means in the OCM model." If RSASSA-PSS appears on slide 6 without explanation, say "I know what that is but I don't see how this differs from cosign." Don't pretend you absorbed everything.
- **What you'd ask in Q&A** — for every slide where you'd actually raise a hand.
- **The five questions you'd actually ask the OCM team in the architecture board.** Not exhaustive — your top five hard questions. The ones where, if the answer is bad, you'd vote against adoption.
- **What you'd say in the hallway** after the talk, to a colleague who also attended:
  - Two-sentence summary of what OCM is.
  - What you'd want to try when you got back to your laptop (if anything).
  - Where the deck lost you, made you sceptical, or felt off.
  - The one thing the deck made you NOT want to do.

For the exec decks: read them at a glance — the architect-persona is the audience for the architect deck, but a senior architect who happens to read the exec decks should also be able to spot inconsistencies. Specifically flag:
- **Anything in the exec decks that contradicts the architect deck's technical claims** (the exec might overpromise; the architect deck might over-disclaim; either creates a contradiction the audience can see).
- **Anything in the exec decks that the architect deck doesn't follow through on** (the exec promises "X" and the architect deck doesn't explain how X is done).

Don't be polite. The architecture board will not be polite. Treat this as the rude-honest cold read that the deck has to survive.

## How to run the session

The previous session ran the three personas in parallel as background subagents. Same pattern recommended here. Three sub-agents, each gets:

- The reading list from the table above (their persona's selection)
- The persona definition from this handoff
- The "what was already decided" out-of-scope list
- The output format spec for their persona

Run them in parallel, in the background. ~15–25 min each, given the larger reading list (especially the architect, who has to read the whitepaper end-to-end).

When all three land: **synthesise into a ranked change list, dedup overlaps, surface contradictions between personas, and bring concrete proposals back to the user.** No edits without sign-off. The session must produce *findings*, not *edits*, until the user confirms each change.

## Where to start (recommended sequence)

1. **Read this handoff document end-to-end.** Confirm the file paths still resolve (especially `~/Downloads/OCM/` and `~/dies-und-das/OCM/` — these are user-local paths and may not survive a worktree change).
2. **Skim each deck once yourself** (the orchestrator agent, before launching sub-agents). Just enough to know what's on each slide, so you can:
   - Calibrate the sub-agents' prompts ("the architect deck has 16 slides in this render order: ...")
   - Spot if any deck has visibly changed since the handoff was written (e.g., user re-edited slides in PowerPoint after saving)
3. **Read the whitepaper** (`~/dies-und-das/OCM/whitepaper.pdf`) yourself once, in summary form. This is the source of truth the decks should align with. You'll need to know what's in it to recognise findings from the architect sub-agent that contradict it.
4. **Spawn the three sub-agents.** Architect first (longest read, longest run), then marketing, then senior-architect/hostile. Background, parallel.
5. **Wait. Synthesise. Present findings. Wait for sign-off before applying anything.**

## What success looks like

The session produces a **ranked findings list** with:

- **Tier 1 (CRITICAL)** — findings that would cause a credibility-loss event with the architecture board. These get fixed before delivery, full stop.
- **Tier 2 (SUBSTANTIVE)** — findings that would be noticed by careful reviewers and should be addressed but won't sink the deck.
- **Tier 3 (NITPICK / SPEAKER PREP)** — findings the speaker should know about but can paper over verbally.

For each finding: persona source, slide number(s), classification, quoted slide-or-note text vs. quoted supporting/contradicting evidence (with `file:line`), proposed fix.

The user reviews the findings list, sign-offs which to apply, then the session applies them.

The deck is then ready for the architecture board.

---

**Final note for the next session.** The previous two sessions (and this one) have already squeezed the deck through several rounds of audit, persona reviews, and PowerPoint hand-editing. The deck is in a *good* state. Don't manufacture findings — if a persona finds nothing meaningful, that's a valid outcome. Surface the strongest 5–10 actionable findings per persona, not 30. Quality of critique over quantity.
