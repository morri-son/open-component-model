# Deck PDFs

**Purpose.** Full-deck visual references. Each PDF is a self-contained snapshot of one PPTX exported at a specific date.

## Files

```
decks_as_pdf/
├── OCM-Story-Architect-External.pdf         (18 pages, 412 KB)
├── OCM-Story-Architect-Internal.pdf         (18 pages, 556 KB)
├── OCM-Story-Exec-External.pdf              (15 pages, 996 KB)
└── OCM-Story-Exec-Internal-Sponsor.pdf      (15 pages, 628 KB)
```

## About the overlap

The paired decks (external + internal within the same audience) share content by design. Text-level overlap analysis:

- **Architect pair:** 14 of 19 pages are text-identical. Divergent pages are 1 (opener), 15 (adopter proof, only in internal), 16 (CTA, different verbs), 17 (renumbered replication appendix in internal), 18 (comparison matrix vs glossary).
- **Exec pair:** Only 1 of 16 pages is text-identical (Slide 16 legal / appendix). Slide 15 is 90% text-similar (CTA, both use action-path pattern, verbs differ). The whole content arc diverges, external opens with "Three Blind Spots," internal opens with "Why Now / Compliance and sovereignty are given."

Despite the architect overlap, all four PDFs are kept as self-contained references. Reasons:

1. **PDFs are whole artifacts.** Unlike per-slide JPEGs, splitting a PDF into unique-only pages creates confusion ("why does this PDF only have 5 pages?") and is fragile against re-exports.
2. **The overhead is small**, ~500 KB per redundant deck.
3. **Skill navigation is simpler**, when a session needs slide 5 of the internal architect deck, it opens the internal PDF directly; no redirect logic needed.

## When to update

Each time the source PPTX changes:
1. Re-export from PowerPoint (File → Export → Create PDF/XPS).
2. Replace the corresponding PDF here.
3. The JPEG folder (`../decks_as_images/`) will drift out of sync, re-export those too and re-run the byte-level de-dup script (see `../decks_as_images/README.md`).

## How the skill uses these

When the skill needs to reason about visual layout of a specific slide:
1. Prefer the per-slide JPEG in `../decks_as_images/<Deck-Name>/SlideN.jpg`, faster, targeted.
2. Fall back to the PDF when comparing slide sequences, checking pagination flow, or looking at spread-level pacing.
3. Never rely on the extracted `speaker-notes.md` or `slide-texts.md` alone for visual questions, text extraction loses layout, colour, card-family, and typography.

Also useful for offline reading (train, plane, without local Claude Code): open the PDF, review, come back with notes.
