# Speaker-Notes Audit — Exec Internal-Sponsor Deck

**Purpose.** Audit AI-slop patterns in the speaker notes. Propose rewrites in the voice defined at `design-principles/voice-guide.md`.

**Status:** The extracted `speaker-notes.md` shows all 17 slides marked `(no notes)`. Either the SharePoint version of this deck ships without notes at all, or the notes exist in the SharePoint copy but were not embedded in the PPTX that was placed here for extraction.

## What needs to happen

If the deck ships without notes intentionally: no audit is possible, no audit is needed. The speaker carries everything from memory / the exec-external deck's parallel notes.

If the deck ships with notes and they should have been extracted: replace `decks/exec-internal-sponsor/deck.pptx` with a version that has notes populated, re-run the extraction, then re-run this audit.

For context, the exec-external deck's `speaker-notes.md` has notes on 13/17 slides. If the internal-sponsor deck was expected to inherit those notes (with audience-shaped rewrites for the internal audience), the extraction gap needs to be closed before the audit can run.

## Per-slide entries

| Slide | State | Action |
|---|---|---|
| 1 | (no notes) | Audit N/A — see status note above |
| 2 | (no notes) | Audit N/A |
| 3 | (no notes) | Audit N/A |
| 4 | (no notes) | Audit N/A |
| 5 | (no notes) | Audit N/A |
| 6 | (no notes) | Audit N/A |
| 7 | (no notes) | Audit N/A |
| 8 | (no notes) | Audit N/A |
| 9 | (no notes) | Audit N/A |
| 10 | (no notes) | Audit N/A |
| 11 | (no notes) | Audit N/A |
| 12 | (no notes) | Audit N/A |
| 13 | (no notes) | Audit N/A |
| 14 | (no notes) | Audit N/A |
| 15 | (no notes) | Audit N/A |
| 16 | (no notes) | Audit N/A |
| 17 | (no notes) | Audit N/A |

## Recommendation for the next session

Before working with this deck further, confirm with the user:

- Are the notes intentionally empty (speaker carries the deck from memory)?
- Or should the deck have notes that the current PPTX lost or never had?

If the answer is "should have notes":
- Look at the sibling `exec-external/speaker-notes.md` — most of that content probably applies with audience-shaped tweaks for the sponsor lens.
- Look at `personas/sap-exec-sponsor.md` for tone anchors.
- Look at `design-principles/story-arc-exec.md` for the arc analysis of this deck.
- Draft new notes from those inputs; audit them for AI-slop before shipping.
