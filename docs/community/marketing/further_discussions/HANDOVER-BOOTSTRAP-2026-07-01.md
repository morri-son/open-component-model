# Handover: OCM Deck Consultant Workspace

**Last update:** 2026-07-02 (early afternoon)
**Status:** Workspace + skill functional. Four PPTX files refreshed from SharePoint. AI-slop audits and em-dash sweeps applied across all four decks. One paste-ready file partially deployed. Skill not yet live-tested.

## What changed since the 2026-07-01 handover

- User applied all AI-slop audit proposals to Architect-External, Architect-Internal, and Exec-External speaker notes on SharePoint.
- User applied all em-dash sweep proposals to slide text and speaker notes on the same three decks.
- User applied the Exec-External Slide 12 rewrite (`WHAT YOU GET`, concretising pattern). Slide title further refined to `Six outcomes. One model.` (crisper than the June draft).
- User applied the exec-internal `speaker-notes-paste-ready.md` to SharePoint, but only Slides 1-11 landed. Slides 12-15 are still empty (Slides 16-17 are trademark and intentionally note-free).
- User re-uploaded the four updated PPTX to SharePoint. Copies also live in `~/Downloads/OCM/` and in the workspace as of today.
- Notes and slide-texts markdown files re-extracted from the updated PPTX. The old June extractions are gone.
- The isolated `speaker-notes-slide12-rewrite.md` scratch file was not preserved because its content is now in the PPTX itself. No longer needed.

## Notes coverage as of now

| Deck | Slides | With notes | Missing |
|---|---|---|---|
| Architect-External | 18 | 17 | Slide 18 (glossary appendix, no notes needed) |
| Architect-Internal | 18 | 17 | Slide 18 (glossary appendix, no notes needed) |
| Exec-External | 17 | 13 | Slides 1, 15, 16, 17 (title + appendix + trademarks, intentional) |
| Exec-Internal-Sponsor | 17 | 15 | Slides 16-17 (trademarks, intentional) |

All decks fully deployed. Nothing more to paste.

## What sits ready to use

```
further_discussions/
├── README.md                             orientation
├── SKILL-CHARTER.md                      THE anchor, 25 locked decisions
├── HANDOVER-BOOTSTRAP-2026-07-01.md      this file
│
├── decks/
│   ├── architect-external/
│   │   ├── deck.pptx                     REFRESHED 2026-07-02 (audit + em-dash applied)
│   │   ├── slide-texts.md                re-extracted 2026-07-02
│   │   ├── speaker-notes.md              re-extracted 2026-07-02
│   │   ├── speaker-notes-audit.md        historical, all proposals now applied
│   │   └── em-dash-sweep.md              historical, all proposals now applied
│   ├── architect-internal/               (same, refreshed 2026-07-02)
│   ├── exec-external/
│   │   └── (refreshed, audit + em-dash + Slide 12 rewrite applied)
│   └── exec-internal-sponsor/
│       ├── (refreshed, but Slides 12-15 notes gap)
│       └── speaker-notes-paste-ready.md        Slides 12-15 still to be pasted
│
├── personas/                             5 audience personas
├── ocm-knowledge/                        4 files, domain grounding
├── design-principles/                    8 files (voice-guide, marketing-canon, story-arcs, conventions)
├── decks/decks_as_pdf/                   4 full PDFs + README
├── decks/decks_as_images/                55 JPEGs (deduped) + README
├── references/                           empty
├── notes/                                user scratch space
└── summary_other_docs/                   user scratch space
```

Skill entry: `~/.claude/skills/deck-consultant/SKILL.md`

## 25 anchors locked

Full list in SKILL-CHARTER.md. Load-bearing anchors from 2026-07-01:

- A22: No em dashes anywhere in workspace prose, slide text, or speaker notes.
- A23: `Anchor: Description` is the standard bullet pattern.
- A24: Concretising over reading-aloud on payoff slides.
- A25: Payoff-slide title convention (WHAT YOU GET / WHAT SAP GETS + "Six things / Six outcomes from one model").

## Next steps for you

One remaining.

### Step 1: Skill live-test in a fresh session (30-60 min)

This is the critical remaining step. The skill has never worked without the bootstrap session's memory. A fresh session is the real test.

Open a new Claude Code session in this repo. Type verbatim:

> Read further_discussions/SKILL-CHARTER.md and work as deck-consultant from now on. I want to review slide 12 of the Architect-External deck through the Marketing-Comms and Hostile-Enterprise-Architect persona lenses.

Watch for:
- Does the skill load charter, voice-guide, marketing-canon, both personas, deck slide-texts and speaker-notes in that order? (Charter defines the load order, session-start protocol.)
- Does output cite specific marketing lenses (narrative / cognitive / sticky / design), not vague "this could be clearer"?
- Does it read in voice-guide voice? No AI courtesies, no MBA vocabulary, no em dashes?
- Does it respect anchors? A14 (SS&D not Greenhouse), A7 (K8s controller RSA only), A22 (no em dashes), A24 (concretising)?
- If asked to draft a rewrite, does the output read like a human wrote it? Or does the AI-slop drift back in?

If any check fails, log the drift in a new session, name the anchor that got violated, and update either SKILL-CHARTER.md (if the anchor needs sharpening) or the underlying design-principles file (if the voice-guide missed a pattern). This is calibration, not failure.

### Optional low-priority

- **`references/` folder.** Summaries of `~/dies-und-das/OCM/` PDFs with freshness caveats. Not urgent; a session that needs them can read the PDFs directly.
- **`changelog.md`** for anchor drift. When anchors get updated, log the change with date + reason.
- **Re-review at scale.** You applied all audit + em-dash proposals mechanically. If in a real presentation the notes still feel AI-generated in aggregate, run the six meta-tests per slide (Vorlesen-Test, Sprechzeit-Test, Q&A-Realitätstest, Landing-Test, Persona-Realitätstest, Fakten-Audit gegen Code) and produce paste-ready rewrites for the slides that fail.

## Known unknowns

- **Skill discovery.** The skill entry sits at `~/.claude/skills/deck-consultant/SKILL.md`. It should surface via `/deck-consultant` in a fresh session, or via natural triggers. If a fresh session doesn't pick it up, `.claude/skills/` at repo level may be needed.
- **Voice at scale.** Voice-guide is proven for one paste-ready file (exec-internal) plus the workspace docs themselves (30+ files, 500+ em dashes removed). Not yet proven for slide-by-slide reviews in a fresh session.

## What "done" looks like

You have a workspace and skill that ground consistent, high-impact deck discussions across future sessions. That grounding is:
- 25 explicit anchors
- 4 audience personas
- 4 story-arc files (per-slide narrative role)
- Voice-guide with em-dash ban and AI-slop patterns
- Marketing-canon with four review lenses
- OCM domain knowledge with 2026 freshness
- Four deck extractions matching the current SharePoint state
- One full paste-ready rewrite as reference pattern
- Audit and sweep files as historical record of what got fixed

Steps 1 and 2 above are the last two things you owe the workspace. After that, the skill is ready for real-world use, and the next session should be one where the skill DOES work rather than where the workspace GETS BUILT.

## Session budget

Four sessions across 2026-07-01 and 2026-07-02 built this workspace. Combined output: ~40 markdown files, 25 charter anchors, 4 audit files, 4 sweep files, 2 paste-ready notes files, 1 skill entry, refreshed PPTX + PDF + JPEG state.

Successor sessions should be much cheaper. The workspace is now a stable ground truth to review against, not something being built from scratch.
