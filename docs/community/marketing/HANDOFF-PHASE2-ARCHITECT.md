# Phase 2 Handoff — Architect Deck (and later: Engineer/Community)

**Written at:** end of session 2026-06-22
**By:** assistant (Sonnet/Opus) working with @D032990 on `marketing/deck` worktree
**Status of Phase 1:** Exec + Internal-Sponsor decks shipped. Both `.pptx` files in `docs/community/marketing/decks/exec-phase1/` are the editable source of truth; build scripts (`build_pptx.py`, `build_pptx_internal_sponsor.py`) regenerate the same text/structure but the user edits the `.pptx` directly going forward (hybrid model — see "Working model" below).
**Next session goal:** Architect deck — first draft of slide sequence and text, working with the user iteratively (the way the exec decks were built).

---

## Read first — before any drafting

You're an expert in marketing and technical communication. Your task is to draft the first version of the architect deck, working with the user iteratively in PowerPoint. The deck's job is to convince architects that OCM is a good architectural primitive for sovereign delivery. It should inherit the rhetorical patterns and design language of the Phase-1 exec decks, but shift the content and voice to meet the architect audience's needs.

If you're picking this up cold, the cheapest-to-correctness path is:

1. **The two Phase-1 decks** — open both `.pptx` in PowerPoint or Keynote and click through them. Don't skim. The hero, slide 2 ("WHY NOW" pattern), slide 7 ("HOW OCM COMPOSES" 2-line columns), slide 12 ("TRUSTED IN PRODUCTION" 4 stop-sentences) are the *rhetorical templates* the architect deck should inherit. Same designer voice; different audience.
   - `docs/community/marketing/decks/exec-phase1/OCM-Sovereign-Delivery-Exec.pptx` (external, cold-start)
   - `docs/community/marketing/decks/exec-phase1/OCM-Sovereign-Delivery-Internal-Sponsor.pptx` (internal SAP sponsors)
2. **The Phase-1 speaker notes** — same directory, `notes/SPEAKER-NOTES-EXEC-EXTERNAL.md` and `notes/SPEAKER-NOTES-EXEC-INTERNAL-SPONSOR.md`. The "DELIVERY NOTES" section at the bottom of each captures the rhetorical decisions that survived the iteration.
3. **The phase-2 starting point — read but don't trust**: `docs/community/marketing/phase-2-technical/TECHNICAL-DECK-OUTLINE.md` and `TECHNICAL-DECK-CONTENT.md`. The user's explicit instruction: *"das sollten wir nur als idee nehmen und darauf iterieren"*. Treat as a brainstorm seed — borrow what works, drop what doesn't. **Do not** import its 22-slide structure wholesale; the Phase-1 work taught us that shorter is better (13-14 slides, not 22).
4. **The website content** — for any architect topic you propose, verify the OCM project actually does what you're claiming. The website is canonical:
   - `website/content/docs/overview/` — explanation-oriented intro (4 files: benefits, core-model, how-ocm-works)
   - `website/content/docs/concepts/` — the architecture surface (11 files including ownership, plugin-system, signing-and-verification-concept, transfer-concept, resolvers, kubernetes-deployer, etc.) **← this is the primary source for architect content**
   - `website/content/docs/how-to/` — 15 task-oriented guides (air-gap-transfer, configure-credentials-ocm-controllers, custom-rbac, transfer-helm-charts, sign-and-verify, etc.) **← these are concrete proof-points the architect audience will want to see**
   - `website/content/docs/tutorials/` — learning paths (advanced-component-constructor, configure-resolvers, credential-resolution, deploy-helm-chart-bootstrap, signing/, working-with-oci/)
   - `website/content/docs/getting-started/` — install + first-component (4 files: cli installation, create-component-version, deploy-helm-chart, setup-controller-environment)
   - `website/content/blog/2026-03-16-ocm-controllers-differences.md` — recent reference, useful for the controller-mechanics slides
   - `website/content/blog/ocm_v2_announcement.md` — the v2 spec evolution, useful for the "stable surfaces vs evolving surfaces" slide
5. **The Diátaxis framing** — `overview/_index.md`, `concepts/_index.md`, `how-to/_index.md` each declare which Diátaxis quadrant they live in. Use the same vocabulary if the architect deck has to position itself relative to docs the audience already navigates.

---

## What worked in Phase 1 — patterns to inherit

These are the rhetorical and structural decisions that survived multiple iterations with the user. If you don't have a strong reason to change them, keep them.

### Stop-sentence rhythm

The strongest moments in both decks are **two-or-three-word sentences stacked**, each ending with a period. Examples:
- Hero internal: *"Every LoB ships. / Separately, every time."*
- Hero external: *"Your supply chain has / blind spots."*
- Slide 12 external title: *"SAP stewards. NeoNephos governs. / Production-grade. Sovereign-ready."*
- CTA: *"Sponsor. Scale. Standardize."*

Why it works: each sentence is one observation. The audience scans them as a list of claims, not as prose. The speaker is responsible for the connective tissue — the slide doesn't try to argue.

For the architect deck this pattern transfers directly. Architects scan even faster than execs.

### Anchor-word + half-sentence bullets

For lists, this format won out over both "single anchor word" (too cryptic for cold-start) and "full sentence" (too verbose):

> ▪ **Identity** — location-independent. The component carries its name regardless of registry.

Slot 1 (Identity) is the scannable anchor. Slot 2 (location-independent) characterises it in 2-3 words. Slot 3 elaborates with 5-10 words. The reader can stop at slot 1, slot 2, or read all three depending on time.

Architects need slot 3 more than execs did, because the architectural claim *does* require unpacking. Don't drop slot 3.

### Two-line comparison columns

For "what you have today / what OCM adds" claims (slide 6 in both decks), a 3-column layout with **exactly two lines per column** beats everything else:

```
SIGNING
You sign artifacts.
OCM signs the release.
```

The first line names the status quo (short, present-tense, no judgement). The second line names the OCM contribution (parallel structure, no marketing). The audience reads the differential automatically. The speaker delivers the punchline ("one signature, every digest") verbally.

For the architect deck this maps to comparison slides — OCM vs cosign+SBOM, OCM vs OCI Distribution, OCM vs Argo/Flux. Same pattern. Don't get clever.

### Logo wall discipline

Captions under logos are either **substantive characterisations** (Phase-1 internal slide 12: "Managed Kubernetes / Cloud-native runtime / Control-plane framework / Reproducible delivery") or **nothing at all** for wordmark logos (Phase-1 external slide 12: BWI, SAP NS2, Gardener, Platform Mesh display unlabeled; only Kyma and OpenControlPlane carry name-captions because they're icon-only).

What we explicitly rejected: caption = logo name. That's pure doubling.

For the architect deck this matters less (architects don't need the "trusted in production" beat at the same volume — they want technical credibility, not social proof). But if you do include a logo wall, follow the same caption discipline.

### Kill variants and duplicates

Phase 1 had three SBOD-diagram variants (A/B/C), two "WHAT OCM UNLOCKS" slides (capability list + SAP outcomes), and three NATIVE PPT-shape variants of diagrams. **All variants were killed.** Each variant in a deck buys complexity without adding clarity. If two slides answer the same question for the same audience, the deck has too many slides. Cut one.

For the architect deck the temptation will be even stronger — there are more legitimate ways to frame the same OCM concept for architects than for execs. Pick the strongest framing and commit. Variants belong in the iteration backlog, not the live deck.

---

## The Architect deck — open questions for the next session

Before drafting, the next session needs explicit user input on three things. **Do not draft past slide 5 without these answers.**

### Q1 — One architect deck or two (external + internal)?

Phase 1 has two exec decks (external + internal-sponsor) because the audience asks **different questions**:
- External: *"Should my organisation invest in OCM?"* → cold-start, vendor-neutral, NeoNephos-led credibility
- Internal: *"Should SAP keep stewarding OCM?"* → warm-start, disinvestment-cost framing, LoB-shared-mechanics story

For the architect tier the equivalent split would be:
- **External architect** — *"Should my team standardise on OCM as our delivery primitive?"* — cold-start, audience evaluates OCM against cosign, SBOMs, OCI Distribution, GitOps, ArgoCD/Flux. Needs more comparison content, more "what we know is sharp" candor (TECHNICAL-DECK-OUTLINE slide 17 "Gotchas and edges").
- **Internal architect** — *"How does my LoB migrate from its bespoke delivery layer to OCM?"* — warm-start, audience knows OCM exists and already feels organisational push (from the sponsor pitch). Needs migration-path content, internal-tooling integration (Hyperspace, RBSC, CSI), and the "investment-amortise across LoBs" frame.

**Two decks is the safer bet** — the audiences ask such different questions that one deck would dilute both. But it's more work, and the next session should confirm rather than assume. **Ask the user explicitly.**

If the answer is "one deck, both audiences", start with the **external** framing as the trunk and add a 2-3 slide "internal-context" appendix that the speaker un-hides for SAP audiences. (This is the same pattern the Engineer/Community deck will probably need — one trunk, audience-specific toggles.)

### Q2 — What's the architect audience's prior?

The Phase-1 exec decks defined "cold-start" precisely: the audience does **not** know what OCM is, does **not** know what an SBOD is, does **not** distinguish a component descriptor from a SLSA attestation. The hero slide gives them three minutes to find out.

The architect audience is harder to position. They might be:
- (a) **Aware of OCM from the exec deck or a colleague**, never opened the docs — they need a quick refresh, then the architectural detail.
- (b) **Read the website's overview** but not the concepts pages — they have terminology but no mental model. Most slides need to land a concept *and* defuse a misconception in the same beat.
- (c) **Read the concepts and the v2 announcement blog** — they have a working mental model and want to argue trade-offs. Slides need to be more contrastive (OCM vs X) and less didactic.
- (d) **Have already used OCM** in a prototype — they want the migration ramp, day-2 ops, plugin extension points. Mechanics-heavy.

The Phase-2 starting point (TECHNICAL-DECK-CONTENT.md) implicitly assumes (b) leaning (c). **Confirm with the user which prior is realistic for the typical room.** It changes slide 1 (hook), slide 3 (concept introduction), and slide 17 (gotchas — only valuable if audience is (c) or (d)).

### Q3 — What's the desired length and pacing?

Phase 1 settled at 13 slides (external) and 14 (internal), with 12:45 and 13:30 talk lengths. The starting point (TECHNICAL-DECK-OUTLINE) proposes 22 slides for a 35-45 min talk.

22 slides for 45 minutes is ~2 min per slide — too slow for engaged architects, too fast for the dense ones (slides 7-13 in the outline carry 5-10 minutes of material each). **Recommend the user pick one of:**
- **Talk format, ~15 slides, ~30 min** — assumes a live audience that can absorb dense material in spoken form. Keeps mechanics tight.
- **Read format, ~20 slides, no fixed timing** — designed for self-service review by an architect who'll spend 45 min with the PDF. Allows more density per slide.
- **Both** — one structure, two presentations. The harder but probably correct answer if the deck has to do double duty.

The user's working pattern in Phase 1 was **talk-first, PDF-fallback**. Default to that unless they signal otherwise.

---

## The Architect deck — what we already know

These are decisions where Phase 1 directionally points; you don't need to re-relitigate them, but record any deviation.

### The mental-model migration thesis

The Phase-2 outline (TECHNICAL-DECK-OUTLINE.md) opens with: *"The audience already has working mental models (cosign, SBOM, OCI, GitOps); the deck's job is to graft OCM onto those models, then show where OCM replaces, contains, or bridges them."* That framing is sound and survives the Phase-1 lessons. **Inherit it.**

Specifically:
- **"What OCM contains"** — SBOMs, signatures, OCI artifacts, Helm charts. Already established in exec slide 4. Architect deck should make this concrete with the component descriptor YAML.
- **"What OCM replaces"** — almost nothing. OCM is connective tissue. Architects will probe this hard — the slide that handles it has to be honest, not defensive.
- **"What OCM bridges"** — cross-registry transport, cross-toolchain signing, GitOps-and-controller dual deployment. The bridging is the value prop.

### The hinge concept

Phase 1 established *"One identity, every boundary"* as the deck-defining phrase. The architect equivalent is **location-independent identity** — the technical machinery that makes the hinge true.

The phase-2-technical content (slide 9 in the outline: *"Why signatures survive transport"*) names this the single most important slide. Phase-1 lessons say: **don't have a "most important slide"**. Have a deck where every slide is load-bearing. If slide 9 is the most important, the other 21 slides are decoration.

**Reframe**: instead of "the most important slide is X", design the deck so the answer to "if you only have 5 minutes" is a coherent sub-deck (3-4 slides), not "skip to slide 9". Phase 1's "5-minute version" is hero → WHY NOW → WHAT OCM UNLOCKS → CTA. The architect equivalent might be hero → diagnosis → mechanics-summary → CTA.

### Where the comparison slides go

The phase-2-technical outline puts comparison late (slides 14-17 of 22). Phase 1 puts the comparator-pattern earlier — slide 6 of 13 ("HOW OCM COMPOSES"). For architects this is a real decision:

- **Comparison early** (slide 5-6 of ~15) — defuses skepticism before the audience commits attention. Good for cold (b) audiences.
- **Comparison late** (slide 10-12 of ~15) — earns the comparison after establishing OCM's own model first. Good for warm (c)/(d) audiences who already know "what OCM is" and want "why instead of X".

Recommend **early** for the cold-start variant, **late** for the warm-start variant. If only one deck, default to early.

### What to drop from the phase-2-technical outline

These slides in TECHNICAL-DECK-OUTLINE.md should probably go or merge:
- **Slide 4 "Eight words to learn"** — terminology-list slides are scan-stoppers. Better to introduce terms in context (slide 3 already names them; slide 5 shows them).
- **Slide 13 "Plugins"** — true but architect-deck-tail material. Could be appendix or skipped entirely; plugins are an extension point most architects won't touch in evaluation.
- **Slide 21 "Governance"** — Phase 1 already handles governance via the "Aligned with NeoNephos" footer on TRUSTED IN PRODUCTION. A dedicated governance slide for architects is overkill unless the user signals otherwise.

These should probably stay but be tightened:
- **Slide 14-17 comparison** — keep all four (cosign+SBOM, OCI Distribution, Argo/Flux, gotchas), but use the Phase-1 two-line column format. 16 lines total across 4 slides if you use the comparator pattern; readable in 5 minutes.
- **Slide 18-19 adoption ramp** — keep, but make concrete. Phase 1 settled on "pack one regulated component this quarter" as the smallest useful step for sponsors. Architect equivalent might be the 30-minute air-gap CTF round-trip from outline slide 18.

These are probably right and should survive:
- **Slide 5 component descriptor** — show the YAML. Architects expect to see the artifact.
- **Slides 7-11 mechanics** (Pack/Sign/Transport/Deploy/Day-2) — necessary if the audience leans (c) or (d). Trim to 4 slides if pacing is tight.
- **Slide 20 maturity curve** — *"stable surfaces vs evolving surfaces"* is exactly the kind of candor that wins architects. Don't drop this even if you drop slide 17.

---

## Working model — how to collaborate with the user

The user's working pattern through Phase 1, distilled:

1. **They want to think alongside, not be presented to.** Show options with trade-offs, name your recommendation, then let them call it. Examples: SBOD diagram variants (3 options, user picked Option A), caption strategy on logo walls (5 options, user picked C), hero wording (4 variants, user picked the two-sentence stop-sentence form).
2. **They iterate in PowerPoint, not in code.** The build scripts are the *historic* truth, the `.pptx` is the *live* truth. When you make a suggestion, give it as text the user can paste into PowerPoint. Don't generate a new `.pptx` unless explicitly asked.
3. **They send screenshots from `~/Downloads/OCM/`.** PowerPoint exports go there; that's the channel for visual review. Reading the `.pptx` text-only via XML extract is fine for verifying *content*; screenshots are necessary for verifying *layout*.
4. **They name things in German and English freely.** Read German prompts; reply in German if they prompt in German. Technical terms stay English.
5. **They challenge wording sharply.** When they say "this is too long" or "this is wrong", probe **what specifically is wrong** before rewriting. Phase 1 example: user pushed back on "every LoB rebuilds the delivery stack" because "rebuild" implied a from-scratch build, which doesn't match reality. The real phenomenon was "ships separately, every release". Right diagnosis, right fix.
6. **They reject SAP marketing voice.** "Industry-leading", "revolutionary", "best-in-class" — don't. The audience will smell it and switch off. Phase 1 explicit feedback: *"Honest. Internal. … No marketing-speak. No 'industry-leading'."*
7. **They use Caveman mode signal when context is tight.** If the user starts compressing their language ("ok, weiter"), match the brevity. Don't reply with a 500-word essay when "going to do X" is enough.
8. **They want commits and pushes only when asked.** Same as the global CLAUDE.md rule. Phase 1 finished without a push; the user does it themselves.

### What to ask for at session start

When the user opens the next session, before drafting anything:

1. *"One architect deck or two (external + internal)?"* (Q1 above)
2. *"What prior does the typical architect audience have?"* (Q2 above) — give them the four options (a)-(d).
3. *"Talk-first ~15 slides, or PDF-first ~20 slides, or both?"* (Q3 above)
4. *"Should slide 4 of the exec deck (THE SHIFT) carry over verbatim or be rewritten?"* — the SBOM/SBOD distinction is foundational; for architects it might need to be longer (with the component descriptor YAML) or shorter (already accepted, just refresh). User's call.

After these four answers you have enough to draft slide 1 and slide 2. Don't draft past slide 5 before showing the user the early structure.

---

## Engineer / Community deck — deferred but signposted

Per the audience tier model carried over from Phase 1:

| Trunk | Status | External/Internal | Phase |
|---|---|---|---|
| Exec / LoB-head | done | external + internal-sponsor (forks) | 1 |
| **Architect** | **next** | external + internal (probably forks) | **2a** |
| Engineer / OSS-community | after | one trunk, OSS-community slides toggled per venue | 2b |

The Engineer/Community deck is **not** part of the next session's scope. But: design decisions in the architect deck should consider what the engineer deck will inherit. Specifically:
- **Hero pattern** — if the architect hero works for engineers too, reuse it
- **Component descriptor presentation** — engineers will want the same YAML, more verbose
- **CLI commands** — architects see `ocm add cv`, engineers want `ocm add cv --help` output

Don't draft the engineer deck. Just leave the architect deck *forkable* into the engineer one.

---

## File layout for the next session

```
docs/community/marketing/decks/
  exec-phase1/                              # Phase 1, complete
    OCM-Sovereign-Delivery-Exec.pptx        # ← live truth (hand-edited)
    OCM-Sovereign-Delivery-Internal-Sponsor.pptx
    OCM-Master.potx
    build-pptx/build_pptx.py                # ← scripts synced to live truth
    build-pptx/build_pptx_internal_sponsor.py
    notes/SPEAKER-NOTES-EXEC-EXTERNAL.md    # ← updated for current decks
    notes/SPEAKER-NOTES-EXEC-INTERNAL-SPONSOR.md
    diagrams/                               # SVG sources, plus PowerPoint-native versions in build scripts
    theme/                                  # OCM-Banner.png, brand row logos
    assets/                                 # adopter logos, LICENSING.md
  architect-phase2/                         # ← create this when drafting starts
    (mirror layout — build_pptx_architect.py, notes/SPEAKER-NOTES-ARCHITECT.md, etc.)

docs/community/marketing/phase-2-technical/
  TECHNICAL-DECK-OUTLINE.md                 # ← 22-slide v0.1 brainstorm. Idea source, not blueprint.
  TECHNICAL-DECK-CONTENT.md                 # ← 677 lines slide-content drafts. Mine for fragments.

docs/community/marketing/archive/
  HANDOFF-PHASE2-ARCHITECT-ENGINEER.md      # ← prior handoff (this file supersedes it)
  HANDOFF-*.md                              # other historic handoffs; reference only

website/content/docs/                       # ← canonical content. Source of architectural truth.
  overview/                                 # 4 files — high-level intro
  concepts/                                 # 11 files — architecture, use for slide content
  how-to/                                   # 15 files — concrete proof-points
  tutorials/                                # learning paths
  getting-started/                          # CLI install + first-component
```

---

## Open issues / known unknowns

- **`OCM-Master.potx` SharePoint round-trip** — user reported it broke on upload to SharePoint, then later said it works. If it breaks again in the next session, the diagnostic steps (font embedding, content-type swap in `open_template_as_pptx()`, OOXML gradient surgery) are in the prior session's task #3.
- **PowerPoint spellcheck red lines** — "NeoNephos", "OpenControlPlane", "LoB", "GitOps", "Reproducible delivery" all trigger the red squiggle. Add to PowerPoint Custom Dictionary before any screenshot or PDF export. Mentioned in passing throughout Phase 1; never centrally cleaned up.
- **Konfidence vs Platform Mesh selection** — Internal deck uses Konfidence on slide 12 (SAP-ApeiroRA-aligned, internal credibility), Exec deck uses Platform Mesh (broader appeal). Deliberate split. Architect deck has to make the same choice — recommend matching Exec deck conventions (Platform Mesh for external, Konfidence for internal) for consistency.
- **SBOD Option B** — was in the hand-edited `.pptx` files at session close, now removed (user confirmed). Build scripts already reflect this. If user re-adds it for any reason, the build scripts will diverge again.

---

## Definition of done for the next session

A successful next session ends with:
- **A first-pass slide sequence** for the architect deck (titles + one-line purposes per slide), agreed with the user
- **Full text drafts** for slides 1-5 (hero, hook/diagnosis, OCM-in-context, component descriptor introduction, mechanics overview)
- **Open questions** flagged for slides 6+ (the user will iterate on these in subsequent sessions)
- **No PowerPoint output yet** — the working flow is: agree on text first, user creates the `.pptx` themselves, then iterate via screenshots like Phase 1

Avoid the mistake of generating a complete deck on first pass. Phase 1 went through ~5 substantial iterations to get to the final form. Plan for the same with the architect deck — the first draft is the *seed*, not the *answer*.
