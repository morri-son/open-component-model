# Phase 2a Architect Deck — Autonomous Loop Handoff

**Written:** 2026-06-23
**Worktree:** `marketing/deck`
**Mode:** Autonomous build-and-iterate loop. Coordinator spawns subagents, monitors progress, restarts on failure. Stop criterion baked in.
**Supersedes nothing.** Companion to `HANDOFF-PHASE2A-SESSION-01.md` (decisions) and `HANDOFF-PHASE2-ARCHITECT.md` (Phase-1 lessons).

This document tells a fresh agent everything needed to **autonomously finish the external architect deck trunk** in a single working loop.

---

## 1. Your identity for this work

You are simultaneously:

1. **A marketing expert** skilled at impactful presentations and speaker notes. Phase 1's design principles (stop-sentence rhythm, anchor-word bullets, two-line columns, no marketing-speak) are inherited.
2. **The OCM lead architect** with `./website/content/` memorised. When YAML, terminology, or claims need verification, the website is canonical.
3. **A domain expert** in software lifecycle management, software logistics, and Kubernetes-native delivery. Stack literacy is high.

You **read every slide as the future presenter** would, imagining the architect audience. If a slide doesn't convince *you*, fix it. This is not a pixel-shifting task — content and ASCII diagrams are sufficient. Story first; geometry second.

---

## 2. The task

Produce a clean, presentable, technically correct external-architect deck — **trunk only, 15 slides, no warm-ups, no appendix, no hidden trademarks** (those exist already and the user copies them across).

**Done means:** the user opens the `.pptx`, flips through 15 slides, and every slide tells a coherent piece of the larger story without geometry overlaps, technical inaccuracies, or filler.

---

## 3. Working environment

| Path | Role |
|---|---|
| `/Users/D032990/github/github.com/morri-son/open-component-model/.claude/worktrees/marketing-deck/` | Worktree root |
| `docs/community/marketing/decks/architect-phase2a/` | Architect-deck home (created in prior session) |
| `docs/community/marketing/decks/architect-phase2a/OCM-Master.potx` | Master template (symlink to exec-phase1) |
| `docs/community/marketing/decks/architect-phase2a/build-pptx/build_pptx_architect_external.py` | Existing build script — extend/rewrite |
| `docs/community/marketing/decks/architect-phase2a/build-pptx/icon_strokes.py` | Icon helpers (symlink) |
| `docs/community/marketing/decks/architect-phase2a/OCM-Sovereign-Delivery-Architect-External.pptx` | Output `.pptx` (overwrite each iteration) |
| `docs/community/marketing/decks/architect-phase2a/_verify/` | Render scratch dir for PDFs + PNGs |
| `docs/community/marketing/decks/architect-phase2a/notes/SPEAKER-NOTES-ARCHITECT-EXTERNAL.md` | Speaker notes file to produce |
| `docs/community/marketing/decks/exec-phase1/build-pptx/build_pptx.py` | Phase-1 reference — read for patterns |
| `docs/community/marketing/decks/exec-phase1/notes/SPEAKER-NOTES-EXEC-EXTERNAL.md` | Phase-1 speaker-notes example |
| `website/content/docs/concepts/` | Canonical OCM architecture docs |
| `website/content/docs/getting-started/create-component-version.md` | Source for slides 5+6 YAML (ground truth) |
| `conformance/scenarios/sovereign/` | Source for slide 12 (composition + day-2) |

**Tools:**
- `python3` (system) — has `python-pptx 1.0.2`, `lxml 6.1.1`, `Pillow 11.3.0`
- `rsvg-convert` at `/opt/homebrew/bin/rsvg-convert` (homebrew librsvg)
- `soffice` at `/Applications/LibreOffice.app/Contents/MacOS/soffice` and `/opt/homebrew/bin/soffice`
- `pdftoppm` at `/opt/homebrew/bin/pdftoppm`

**Render command (use this verbatim):**

```bash
cd docs/community/marketing/decks/architect-phase2a && \
  rm -rf _verify && mkdir _verify && \
  soffice --headless --convert-to pdf OCM-Story-Architect-External.pptx --outdir _verify && \
  pdftoppm -r 100 _verify/OCM-Sovereign-Delivery-Architect-External.pdf _verify/slide -f 1 -l 15 -png
```

After this, `_verify/slide-1.png` … `slide-15.png` exist. Read them with the Read tool.

---

## 4. The locked story arc — 15 trunk slides

This is the agreed sequence. **Do not re-debate the order.** Iterate on content within each slot.

| # | Beat | Title | Purpose |
|---|---|---|---|
| 1 | Pain | *You ship pieces. / Nothing carries the release.* | Hero. Two-line gradient title. Subtitle: "Identity stops at the artifact. So does everything you do with it." Footer: "Open Component Model — open source, NeoNephos Foundation." Banner + brand row. |
| 2 | Cause | *In every existing tool, identity is bound to location.* | Three bullets (locked): OCI image / Helm chart / SBOM. Subtitle: "You can't sign a delivery once and have it survive transit — there is no 'delivery' identifier to sign." |
| 3 | Insight | *Identity that travels with the artifact.* | Three bullets (Coordinates / Digest / Access) + ASCII diagram on the right (coordinate chip travelling across registries). Subtitle: "Move the artifact; the digest stays; only the access changes. That's the trick." |
| 4 | Positioning | *One wrapper. All artifacts. Signed once.* | Three columns (ARTIFACT FORMATS / LOCATION / TRUST). Subtitle: "Architects came in with three tools. They leave with one unit." |
| 5 | **Constructor (Input)** | *What you write.* | 18-line YAML from `getting-started/create-component-version.md` (verbatim). Two right-side callouts: `input:` (by value) / `access:` (by reference). |
| 6 | **Descriptor (Output)** | *What gets signed and travels.* | ~22-line YAML (trimmed descriptor + signed). Callouts on `digest:` (signed, content identity) and `access:` (rewritten on transfer). Signature `value:` shown as `<256-byte signature>` placeholder, not hex. |
| 7 | Overview | *Pack · Sign · Transport · Deploy.* | Reuse exec-deck `05-pack-sign-transport-deploy-v2.svg`. The visual anchor before the four mechanic slides. |
| 8 | Pack | *Bundle once. Name once.* | Mechanic detail. CLI in speaker notes (`ocm add cv`). Slide stays clean. |
| 9 | Sign | *One signature shape. Three trust models.* | RSA · PEM (early access) · Sigstore (early access). Three-column layout. |
| 10 | Transport | *Three patterns, one command.* | Registry → Registry · Registry → CTF · CTF → Registry (air-gap). The "signature survives transport" payoff lands here. |
| 11 | Deploy | *Repository → Component → Resource → Deployer.* | 4-CR controller chain. One sentence in speaker notes: "If your platform team already runs Argo CD for the dashboard, point Argo at the Resource CRs — your team gets the deploy in the UI they're used to. The reconciliation can be OCM's built-in deployer, Flux, or Argo itself." |
| 12 | Composition + Day 2 | *One product. Three components. One line to upgrade.* | Composition tree (acme.org/sovereign/product:1.0.0 → notes + postgres) + YAML callout (`spec.version: 1.1.0   # was: 1.0.0`). Speaker explains the conformance scenario. Subtitle: "Composition is a first-class primitive. Upgrade is one line." |
| 13 | What's sharp | *Three honest edges.* | Sigstore signing — early access. PEM encoding — early access. Controllers apply raw manifests only (no Kustomize/Helm rendering at deploy time). |
| 14 | Adoption | *Two paths to a first OCM component in production.* | Two columns: FROM ZERO (CTF round-trip, 30 min) / ON YOUR EXISTING PLATFORM (OpenControlPlane service-provider, one openMCP resource). |
| 15 | CTA | *Build with us.* | Three doors: Try it (`ocm.software`) / Build with us (`github.com/open-component-model`) / Talk to us (community channels). |

**Note on slides 1–6:** these were partially built in the prior session. Re-check that they still fit the locked story. Slides 1, 2, 3 were rendered visually-verified. Slides 4 and the rest need fresh implementation.

---

## 5. Layout cheat sheet (from `OCM-Master.potx`)

| Layout | idx=1 (eyebrow/hero-line1) | idx=2 (title/hero-line2) | idx=3 (hero-subtitle) | idx=4 (hero-footer) | idx=10 (body/col1) | idx=11/12/13/14/15 (cols) |
|---|---|---|---|---|---|---|
| Hero | y=180 h=160 w=1700 (sz=132pt default — **architect override: sz=115pt, w=1824**) | y=345 h=160 w=1700 (same override) | y=560 h=90 | y=690 h=60 | n/a | n/a |
| Plain | y=255 h=48 (Eyebrow) | y=308 h=200 (Title sz=74pt) | n/a | n/a | y=580 h=400 (Body) | n/a |
| Plain / Compact | y=255 h=48 | y=308 h=200 | n/a | n/a | y=520 h=460 | n/a |
| Content / 3-Column | y=255 h=48 | y=308 h=200 | n/a | n/a | y=536 h=56 (Col1 Header) | y=604 h=460 (Col1 Body), etc. |
| Content / 2-Column | y=255 h=48 | y=308 h=200 | n/a | n/a | y=520 h=460 (Left Body) | y=520 h=460 (Right Body, x=980) |
| Content / Diagram | y=75 h=48 | y=128 h=80 | n/a | n/a | (varies — picture placeholder) | n/a |

**Geometry hazard:** the Plain layout title at sz=74pt wraps long titles (>~35 chars) to 3 lines, busting the 200px title box and overlapping the body slot at y=580. For slides 3, 6, 11, 13, 14 either:
- Keep titles ≤35 chars per line and ≤2 lines, OR
- Inline-patch the Plain layout title sz from 7400 to ~5500 (55pt) for those slides specifically, OR
- Use Plain / Compact (body at y=520 gives less buffer but title still wraps), OR
- Use Content / 2-Column when the body has a natural left/right split.

**Hero font-size override** (already implemented in the build script via `customize_hero_for_architect(prs)`). Pattern is reusable for other layouts — wrap as `customize_plain_for_architect(prs)` if needed.

---

## 6. Working method — Coordinator + Subagent Loop

### Coordinator (you, the main agent)

1. Read this handoff.
2. Read `HANDOFF-PHASE2A-SESSION-01.md` for prior decisions.
3. Read the current build script and run it once to establish baseline. Render. Read all current PNGs.
4. Build TaskList of remaining work — one task per slide that needs construction/iteration, one task per cross-cutting concern (speaker notes, content review).
5. Spawn subagents per the parallel-block strategy in §3 of `HANDOFF-PHASE2A-SESSION-01.md`. Specifically:

   **Wave 1 (parallel, three subagents):**
   - **Block A — Slides 1–5 review and finalisation** (Pain/Cause/Insight/Positioning/Constructor)
   - **Block B — Slides 6–11 construction** (Descriptor/PSTD-Overview/Pack/Sign/Transport/Deploy)
   - **Block C — Slides 12–15 construction** (Composition+Day2/What's-sharp/Adoption/CTA)

   Each subagent gets its own edit window in the same `build_pptx_architect_external.py`. Coordinator merges sequentially to avoid Python-level conflicts.

   **Wave 2 (sequential):**
   - Build + render + visually verify all 15 slides (read every PNG).
   - Fix geometry/content issues found.
   - Rebuild and reverify.
   - Max 5 iterations of build/render/fix. If issues remain after 5, write a final report listing them and stop.

   **Wave 3 (sequential):**
   - Generate `SPEAKER-NOTES-ARCHITECT-EXTERNAL.md` matching the style of the exec-deck notes file.
   - Final content review by a fresh subagent: read every slide PNG + the speaker notes, check against website docs, flag inaccuracies, suggest sharpenings.
   - Apply fixes from review.

6. **Restart-on-failure:** if a subagent times out, returns garbled output, or fails to follow instructions, spawn a fresh subagent for the same task. Track restart count; after 3 restarts on the same task, escalate by simplifying the task scope and trying once more.

### Subagent contract

Every subagent invocation must:
- Receive **explicit file paths**, never relative or "find the right one"
- Receive **the locked slide-text content** (from §4 here), not "draft something"
- Be told what to **return** (e.g., "DONE: edited <path>") with no commentary
- Be limited to ONE concrete output (edit the script, OR generate notes, OR render+verify)

### Stop criterion (final)

The loop stops when EITHER:

- (a) All 15 slides render cleanly: no title-body overlap, no text cutoff, content matches the locked story, ASCII diagrams readable, AND
- (b) Speaker notes generated AND content review subagent returns ≤ 3 minor findings (no critical inaccuracies),
- (c) Max 5 build/render/fix iterations reached — write a final report listing open issues even if (a) or (b) not fully met.

---

## 7. Decisions already locked (do not re-debate)

From `HANDOFF-PHASE2A-SESSION-01.md` and the latest grilling:

- Two forked decks (external + internal). **This loop = external only.**
- No v1/v2 distinction. OCM is OCM.
- 15-slide trunk (not 14 — Constructor + Descriptor are separate slides).
- Story arc: Pain → Cause → Insight → Positioning → Constructor → Descriptor → PSTD-Overview → Pack → Sign → Transport → Deploy → Composition+Day 2 → What's sharp → Adoption → CTA.
- Clean deck for presenting, prose speaker notes, deep dives go to the website.
- ASCII diagrams are acceptable. Real SVGs come later in a separate iteration.
- No YAML on slides except 5 and 6.
- No CLI on slides — CLI in speaker notes only.
- "OCM vs cosign+SBOM" comparator deleted.
- "OCM vs OCI" reframed as positioning (slide 4), not vs-comparison.
- GitOps reframed as Deployer-tier pluggability — one sentence in slide 11 speaker notes.
- OpenControlPlane integration → slide 14, second column.
- Day-2 anchored in `conformance/scenarios/sovereign/` story (product → notes + postgres; spec.version 1.0.0 → 1.1.0).

### Locked text for slides 1–4 (from prior session — review but don't re-debate)

**Slide 1 — Hero:**
- Title L1 (white): "You ship pieces."
- Title L2 (gradient): "Nothing carries the release."
- Subtitle (cyan): "Identity stops at the artifact. So does everything you do with it."
- Footer (white): "Open Component Model — open source, NeoNephos Foundation."

**Slide 2 — Diagnosis:**
- Eyebrow: DIAGNOSIS
- Title: "In every existing tool, identity is bound to location."
- Bullets:
  - "OCI image — identified by registry/repo:tag. Mirror to another registry, the reference changes."
  - "Helm chart — identified by repository URL + name. Mirror the repo, the reference changes."
  - "SBOM — linked to its subject artifact by path or naming convention. Repackage or relocate the artifact, the association breaks."
- Caption: "You can't sign a delivery once and have it survive transit — there is no \"delivery\" identifier to sign."

**Slide 3 — The Hinge:**
- Eyebrow: THE HINGE
- Title: "Identity that travels with the artifact."
- Left bullets:
  - "Coordinates — a component has a name (github.com/acme/widget) and a version (v1.4.2). Globally unique. Location-agnostic."
  - "Digest — every resource inside the component carries a content hash. Computed once."
  - "Access — where the resource currently lives. Rewritten on transfer. Digest stays."
- Right diagram: ASCII art of coordinate chip travelling across EU/US/Air-gap registries
- Caption: "Move the artifact; the digest stays; only the access changes. That's the trick."

**Slide 4 — Positioning:**
- Eyebrow: WHERE OCM SITS
- Title: "One wrapper. All artifacts. Signed once."
- Col 1 (ARTIFACT FORMATS): "You keep yours.\nHelm, OCI, SBOM, npm — every kind is a resource."
- Col 2 (LOCATION): "Identity travels.\nThe component carries its name across registries."
- Col 3 (TRUST): "One signature.\nCovers every digest. Survives transport."
- Caption: "Architects came in with three tools. They leave with one unit."

### To-draft text for slides 5–15

See §4 above for purpose-level guidance. Subagent must draft the actual text within each slot's purpose, then coordinator reviews against the architect-audience criteria below.

---

## 8. Audience criteria for the convince-yourself test

When reading each slide as the presenter, check:

1. **Does the slide make a single claim?** If two unrelated claims, split or cut.
2. **Is the claim technically defensible to an architect who skims the OCM website later?** No marketing inflation. Verify against website docs.
3. **Does the slide presume vocabulary the audience hasn't seen?** Slide 3 introduces coordinates/digest/access; later slides may rely on those terms. Slides 5+ rely on slides 1–4 having established the frame.
4. **Does the speaker have a natural punchline to deliver verbally?** If the slide says everything, the speaker has nothing. Slide carries setup; speaker delivers the closing line.
5. **Is the visual rhythm coherent with Phase-1?** Stop-sentence rhythm (X. Y. Z.), anchor-word bullets, two-line columns, no walls of text.
6. **Honesty check** — anything early-access flagged explicitly? Anything that would make a security architect parse "early access" and trust the rest *more*?

If a slide fails any criterion: rewrite, rebuild, reverify.

---

## 9. Open issues to be aware of

1. **Hero subtitle overlap** — in the current build, slide 1's subtitle at y=560 may be visually overlapped by the title rendering at 115pt. User said: "Slide 1 is OK for now, I'll fix in PowerPoint." Coordinator: leave geometry as-is for slide 1, do not iterate on it during this loop.

2. **Plain layout title wrapping** — slides 3 and 6 in the current build show 3-line title wrapping when title > ~35 chars. Two options:
   - (a) Keep current build behaviour, accept the wrap; user will fix in PowerPoint master.
   - (b) Inline-patch Plain layout title size like the Hero patch.
   - **Default: (a).** User said this loop is about content, not pixels.

3. **Slide 6 (was current build slide 6) is now COMPOSITION + DAY 2** — but the position changed (slide 6 in old build was at position 6; in new arc, COMPOSITION + DAY 2 is at position 12). Coordinator must reorder the build script's slide-emission order to match the new arc. Old "slide 6" content (composition tree + YAML callout) moves to position 12.

4. **Speaker notes have not been generated yet.** Phase-1's `SPEAKER-NOTES-EXEC-EXTERNAL.md` is the structural reference: per-slide section with "On screen" + "Speaker notes" + timing budget + anticipated questions. The coordinator's wave-3 subagent produces the equivalent file.

5. **API errors during long subagent runs.** If a subagent fails mid-task, the coordinator restarts. If the same task fails 3 times, simplify scope (e.g., split a "draft slides 6–11" subagent into "draft slides 6–8" + "draft slides 9–11"), and try again.

---

## 10. First-action checklist for the fresh agent

1. Verify environment:
   - `python3 -c "import pptx, lxml, PIL"` — passes
   - `which soffice rsvg-convert pdftoppm` — all return paths
   - `ls docs/community/marketing/decks/architect-phase2a/` — file exists
2. Read this handoff in full.
3. Read `HANDOFF-PHASE2A-SESSION-01.md`.
4. Read the current `build_pptx_architect_external.py`.
5. Run it once. Render. Read all current PNGs.
6. Confirm: which slides exist in the current build, which need to be added, which need to be reordered.
7. Create TaskList for the new work.
8. Spawn Wave 1 subagents.

When ready, start the loop. The user has explicitly said: **iterate as many times as needed; max 5 build/render/fix cycles before reporting.**

---

## 11. Phase-1 patterns to honour (inherited)

These survived the Phase-1 iteration and are non-negotiable for the architect deck:

- **Stop-sentence rhythm.** Two-or-three-word sentences stacked, each ending in a period.
- **Anchor-word + half-sentence bullets.** `**Anchor** — characterisation. Consequence.`
- **Two-line comparison columns.** Status quo / OCM contribution, parallel structure.
- **Kill variants and duplicates.** Phase 1 had three SBOD-diagram variants — all killed. One slide, one claim.
- **No marketing voice.** No "industry-leading", "revolutionary", "best-in-class".
- **Speaker carries the colour, slide carries the structure.** The slide says less than the speaker.

---

## 12. What "done" looks like

Coordinator returns to the user with:

- `OCM-Sovereign-Delivery-Architect-External.pptx` — 15 trunk slides, no warm-ups, no appendix, no trademarks.
- `notes/SPEAKER-NOTES-ARCHITECT-EXTERNAL.md` — full prose speaker notes, one section per slide.
- A short final report:
  - All 15 slides confirmed rendering cleanly? Y/N
  - Content review findings? (≤ 3 minor = pass; more = list)
  - Number of build/render/fix iterations used (out of 5 max)
  - Any open issues for the user to handle manually

That's the loop complete. Internal-architect deck, SVG diagrams, and per-audience refinements are separate future loops.

---

**End of handoff.**
