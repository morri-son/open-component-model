# OCM Deck Consultant: Discussion Workspace

This directory grounds an LLM for **consistent, high-impact discussions about OCM slide decks**, across sessions, without the LLM re-inventing conclusions we've already reached.

## What lives here

```
further_discussions/
├── SKILL-CHARTER.md              ← THE anchor. Read this first, every session.
├── README.md                     ← This file. Orientation only.
│
├── decks/                        ← One folder per deck.
│   ├── architect-external/
│   │   ├── deck.pptx: Source PowerPoint (user maintains)
│   │   ├── deck.pdf: Optional (user exports)
│   │   ├── slides-jpeg/: Optional per-slide JPEG (user exports)
│   │   ├── speaker-notes.md: Extracted from PPTX
│   │   └── slide-texts.md: Extracted from PPTX
│   ├── architect-internal/
│   ├── exec-external/
│   └── exec-internal-sponsor/
│
├── personas/                     ← Audience personas we test messaging against.
│   ├── lead-architect-external.md
│   ├── hostile-enterprise-architect.md
│   ├── marketing-comms.md
│   ├── sap-internal-architect.md
│   └── sap-exec-sponsor.md
│
├── ocm-knowledge/                ← OCM domain knowledge with freshness dates.
│   ├── glossary.md: Canonical terms (SBOD, ODG, OCP, RBSC…)
│   ├── technical-primitives.md: Component, descriptor, signature, transport
│   ├── sap-adoption-2026.md: 2026 reality (Landscaper sunset, renames, etc.)
│   └── website-pointers.md: "For X, see website/content/docs/…"
│
├── design-principles/            ← Slide-design rules this skill enforces.
│   ├── high-impact-decks.md
│   ├── architect-deck-conventions.md
│   ├── exec-deck-conventions.md
│   └── card-family.md
│
├── references/                   ← External docs, summarised with freshness caveats.
│   └── (populated later: OCM adoption plan 2024, whitepaper, IPCEI framing)
│
├── notes/                        ← User's scratch space. LLM does not write here.
└── summary_other_docs/           ← User's scratch space for extracted summaries.
```

## How to use in a session

1. Invoke the skill (`/deck-consultant`) or manually tell the LLM: "read `further_discussions/SKILL-CHARTER.md` first."
2. Tell it which deck (or "new deck") and which persona lens (or "no persona").
3. The skill loads the right files and engages.

## When to update

- **Slide edits in PowerPoint:** Re-drop the PPTX in the right `decks/*/` folder; ask a session to re-extract `speaker-notes.md` and `slide-texts.md`.
- **New locked decisions:** Add to `SKILL-CHARTER.md` anchor table.
- **New personas:** Add file to `personas/`, one per audience.
- **New deck:** Create `decks/<slug>/`, drop the PPTX, ask a session to extract.

## Why this exists

We had a Phase 2B pass in the summer of 2026 where the LLM landed on a specific set of decisions, Slide 7 mnemonic, Slide 14 honest edges, verifier semantics, adopter list, CTA verbs. Every new session that ignored those anchors re-invented worse versions. This folder makes the anchors durable.

The charter is the contract. The persona and design-principle files are the reasoning. The deck files are the current state. Together they let a session in a year still produce a review consistent with what a session today would produce.
