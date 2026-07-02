# Slide Images (JPEG per slide)

**Purpose.** Visual ground-truth for the LLM. Every session that discusses a deck should reference the JPEG for the slide under discussion, not just the extracted text.

## Layout

```
decks_as_images/
├── OCM-Story-Architect-External/    (18 slides)
├── OCM-Story-Architect-Internal/    (5 slides: see de-dup note below)
├── OCM-Story-Exec-External/         (17 slides)
└── OCM-Story-Exec-Internal-Sponsor/ (15 slides: see de-dup note below)
```

## Byte-identical de-duplication

The paired decks (external + internal within the same audience) share many identical JPEGs by slide number. To save space and reduce redundancy, byte-identical files are removed from the *internal* deck. **Refer to the external deck's JPEG for those slide numbers.**

### Architect pair: deduplicated slides

Slides **2–14** of the internal deck are byte-identical to the external deck. If you need the JPEG for architect-internal Slide 5, use:

```
decks_as_images/OCM-Story-Architect-External/Slide5.jpg
```

Only these slides remain in `OCM-Story-Architect-Internal/`:

| Slide | Reason unique |
|---|---|
| 1 | Different opener ("What's the release" vs "You ship pieces") |
| 15 | Adopter Proof (only in internal deck) |
| 16 | Different CTA verbs (Pilot·Standardize·Steward vs Evaluate·Pilot·Engage) |
| 17 | Renumbered replication appendix, but likely also identical content to external Slide 16; kept to be safe until visually confirmed |
| 18 | Glossary (only in internal deck) |

### Exec pair: deduplicated slides

Only slides **16 and 17** are byte-identical between external and internal exec decks. The arcs diverge significantly (external Slide 2 is "Three Blind Spots"; internal Slide 2 is "Why Now") so nearly every JPEG is unique. Files remaining in `OCM-Story-Exec-Internal-Sponsor/`: Slides 1–15.

If you need Slide 16 or 17 of exec-internal, use:

```
decks_as_images/OCM-Story-Exec-External/Slide16.jpg
decks_as_images/OCM-Story-Exec-External/Slide17.jpg
```

## When to update

Every time the source PPTX changes:
1. Re-export the JPEGs from PowerPoint (File → Export → As Pictures).
2. Drop into the correct folder.
3. Re-run the de-dup check (see script below) to remove new byte-identical duplicates.

## De-dup check (bash + python)

Run from `decks_as_images/`:

```bash
python3 << 'EOF'
import hashlib
from pathlib import Path

pairs = [
    ("OCM-Story-Architect-External", "OCM-Story-Architect-Internal"),
    ("OCM-Story-Exec-External", "OCM-Story-Exec-Internal-Sponsor"),
]
base = Path(".")
for ext, int_ in pairs:
    ext_dir = base / ext
    int_dir = base / int_
    for f_ext in sorted(ext_dir.glob("Slide*.jpg"), key=lambda p: int(p.stem.replace("Slide",""))):
        f_int = int_dir / f_ext.name
        if not f_int.exists():
            continue
        h1 = hashlib.md5(f_ext.read_bytes()).hexdigest()
        h2 = hashlib.md5(f_int.read_bytes()).hexdigest()
        if h1 == h2:
            print(f"duplicate: {f_int} == {f_ext}")
            # f_int.unlink()  # uncomment to actually delete
EOF
```

## Why this matters

The LLM builds mental models of the decks from text extraction, but visual layout, colour, card family, spacing, and typography are all part of the deck's message. A session that reasons only from text will miss visual issues. When a session is asked "how does Slide N look?" it should read the JPEG, not describe from text alone.
