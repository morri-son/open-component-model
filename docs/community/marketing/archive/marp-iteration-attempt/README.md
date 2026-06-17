# Marp content playground

This directory is the **content-iteration tool** for the OCM exec deck. It is
not a parallel build pipeline — the brand-correct PPTX is still built by
`../build-pptx/build_pptx.py` against `../OCM-Master.potx`.

## Why Marp here

- Edit copy in plain markdown, see results in seconds.
- Diff variants side-by-side without scrolling through Python.
- Hand a `.md` to a colleague to edit copy without onboarding them to python-pptx.

## Why not Marp for the final PPTX

Marp's PPTX export is lossy: it can't honor `OCM-Master.potx`, doesn't fill
the named placeholders, and discards layout metadata. Use Marp for HTML/PNG
review only. When copy is locked, port it into `build_pptx.py`.

## Layout

```
marp/
├── .marprc.yml          marp-cli config (HTML output only)
├── build.sh             ./build.sh [slides.md] [html]
├── theme/
│   └── ocm-master.css   1920×1080 theme aligned with OCM-Master.potx tokens
├── slides.md            baseline 12-slide deck (mirrors current build_pptx.py)
└── dist/                rendered HTML + per-slide PNG previews
```

## Token alignment

`theme/ocm-master.css` mirrors `build_potx.py` exactly:

| Token         | Value                                       |
|---------------|---------------------------------------------|
| Canvas        | 1920 × 1080 px                              |
| Margins       | x=120, content width 1680                   |
| Eyebrow       | y=255 h=48 · 28pt blue · ALL CAPS · no wrap |
| Title         | y=308 h=200 · 64pt Aptos Display · lh 0.9   |
| Body (Compact)| y=520 (1-line title)                        |
| Body (Plain)  | y=580 (2-line title)                        |
| Footer        | bottom 22px · 12pt grey                     |
| Bullet marker | blue ▪ · 22pt body                          |
| Palette       | #0F6BFF · #0A3A99 · #5CD6FF · #0A1530 ...   |

If a token drifts in `build_potx.py`, update both.

## Variants

```
slides.md             baseline (current narrative)
slides-risk.md        risk-led variant
slides-roi.md         ROI-led variant
slides-peer.md        peer-led variant
slides-regulator.md   regulator-led variant
```

Render any of them: `./build.sh slides-risk.md`

Variant content lives in `../EXEC-DECK-REWORK-OPTIONS.md` (the menu) and
`../MARKETING-CRITIQUE-EXEC.md` (the strategist read).

## Build

```bash
./build.sh                       # baseline → dist/slides.html + PNGs
./build.sh slides-risk.md        # variant
./build.sh slides-risk.md html   # HTML only, skip PNG render
```

Open `dist/slides.html` in a browser. Marp serves at the canvas's native
1920×1080 — zoom out to fit the viewport.

## When copy is locked

1. Pick the winning variant per slide.
2. Port the copy into `../build-pptx/build_pptx.py` (or a per-variant
   `build_pptx_<variant>.py`).
3. Rebuild the PPTX from the .potx — that's the deliverable.
