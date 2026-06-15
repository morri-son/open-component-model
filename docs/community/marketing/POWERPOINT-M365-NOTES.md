# PowerPoint M365 Build Notes (macOS)

Pre-answers for gotchas while building the master from `POWERPOINT-MASTER-SPEC.md`. PowerPoint M365 macOS, current channel 2026.

> External web search was unavailable during research, so these draw on consolidated PowerPoint M365 / OOXML knowledge, not fresh citations. Confidence flagged per section. Verify menu paths on your installed build before committing to the full master.

---

## 1. Gradient text on a substring

**Confidence: high.** Substring gradient text fills work; one quirk.

- **Yes**, you can apply a different fill to a selected character run inside a text box.
- **Menu path (macOS):** highlight characters in edit mode → right-click → **Format Text Effects…** (or Format pane → **Text Options** → **Text Fill & Outline** A icon) → **Text Fill** → **Gradient fill**. Type = **Linear**, direction = **Linear Left** (0°). Three stops: White at 0%, Cyan `#5CD6FF` at 35%, Brand Blue `#0F6BFF` at 75%.
- **Quirk — selection scope:** if the *shape* (frame) is selected, the gradient applies to all text. You must be in text-edit mode with characters highlighted. Re-opening the pane sometimes resets to whole-shape — re-highlight before each change.
- **Quirk — colour swatch:** on macOS the per-stop swatch occasionally fails to open the picker on first click. Click again, or Tab into/out of the percentage field.
- **0° = left-to-right** is consistent across PowerPoint, Keynote, LibreOffice. PDF export preserves the gradient as a vector pattern (no rasterisation, no colour shift in sRGB).
- **Mac vs Windows:** identical feature; Windows pins the Format Shape pane, Mac floats it.

---

## 2. 3-px top rule on tile shapes

**Confidence: high.** Use a separate rectangle, not a one-side border.

- **PowerPoint shapes don't support per-side borders.** "Format Shape → Line" is uniform on all four sides. No reliable workaround.
- **Approach:** draw a thin rectangle 570 × 3 px, fill = Brand Blue `#0F6BFF`, no line, snap to top edge of the 570 × 280 tile. Group (Cmd+Option+G) tile + rule. Define this on the slide-master layout, not per slide.
- **Custom hex:** Fill colour → **More Colors…** → **Color Sliders** → **RGB Sliders** → enter `15, 107, 255`, or paste `#0F6BFF` into the hex field at the bottom of the macOS colour wheel (Big Sur+). Doesn't need to be in the theme palette.
- **3 px on export:** PowerPoint stores positions in EMUs, so 3 px @ 96 dpi = 28,575 EMU. PDF export is vector — no snapping. PNG at 1920×1080 keeps it 3 px; lower resolutions can round to 2 px, so export at native or higher.

---

## 3. SVG import with editable strokes

**Confidence: medium-high.** Editable SVG works in M365; Tabler icons need one extra step.

- **Insert path:** **Insert → Pictures → Picture from File…** → select the `.svg`. Native since 2019.
- **Convert to Shape:** still required as of 2026. Right-click → **Convert to Shape**. Confirm the prompt. Result: a group of vector shapes.
- **Tabler quirk — stroke vs fill:** Tabler outline icons use `stroke` (not `fill`) on `<path>` with `stroke="currentColor"`. After Convert to Shape, strokes become **shape outlines, not fills**. Recolour: Cmd+click into the group (or Ungroup with Cmd+Shift+G), then **Format Shape → Line → Color → More Colors → `#0F6BFF`**. Setting the *fill* does nothing visible — outline icons have `fill="none"`.
- **Multi-path:** group is preserved; recolour all paths at once via group line colour. If it resists, ungroup once, regroup after.
- **Pre-flatten:** for icons with mixed stroke+fill (e.g., `tabler-icon-filled-*`), unify in a text editor or run through `svgo` before import.
- **Theme colour shortcut:** once Brand Blue is a theme colour (§4), pick it from the picker's top row instead of typing hex each time.

---

## 4. Custom theme colours (8-colour brand palette)

**Confidence: high.** Mac and Windows menu paths diverge slightly.

- **Menu path (macOS):** **Design** tab → click the small dropdown arrow on the right of the theme gallery → **Colors** → **Customize Colors…**. (Windows is Design → Variants → Colors → Customize Colors.) Exit Slide Master view first if you don't see it.
- **Slot labels (12 slots):** Text/Background — Dark 1, Light 1, Dark 2, Light 2; Accent 1–6; Hyperlink; Followed Hyperlink. Theme colours appear in the top row of every colour picker.
- **Suggested mapping:**

  | Slot | OCM colour | Hex |
  |---|---|---|
  | Text/Bg — Dark 1 | Brand Black | `#333333` |
  | Text/Bg — Light 1 | White | `#FFFFFF` |
  | Text/Bg — Dark 2 | Brand Blue Night | `#0A1530` |
  | Text/Bg — Light 2 | Grey Soft | `#F3F4F6` |
  | Accent 1 | Brand Blue | `#0F6BFF` |
  | Accent 2 | Brand Blue Deep | `#0A3A99` |
  | Accent 3 | Accent Cyan | `#5CD6FF` |
  | Accent 4 | Grey Mid | `#6B7280` |
  | Accent 5–6 | (free; reuse Brand Blue / Deep, or leave default) | |
  | Hyperlink | Brand Blue | `#0F6BFF` |
  | Followed Hyperlink | Brand Blue Deep | `#0A3A99` |

- **Save:** name the scheme **"OCM"** → Save. Persists at `~/Library/Group Containers/UBF8T346G9.Office/User Content.localized/Themes.localized/Theme Colors/OCM.xml`. Also embedded in any `.pptx` saved with it active — distributing the master is enough for collaborators.

---

## 5. Layout-level banner image

**Confidence: high** for layout-vs-slide; **medium** on locking (macOS lacks the Windows shape-Lock UI as far as I know).

- **Put the banner on the layout, not the master root.** **View → Slide Master**. Click the **Hero layout** (right-click → Rename Layout to "Hero"). Insert the banner here — it appears on every Hero slide, won't bleed onto other layouts.
- **Static picture, not Picture Placeholder.** A placeholder would prompt authors to swap the image; you want it fixed. **Insert → Pictures → Picture from File…** at layout level, position 0,0, size 1920×648.
- **Gradient overlay:** rectangle 1920 × 432 at y=648, linear gradient 90° (top-to-bottom), stop 1 = `#0A1530` at 0% opacity, stop 2 = `#0A1530` at 100% opacity (same colour, transparent at top). Order: above banner, below text placeholders — use **Arrange → Bring Forward**.
- **Locking:** PowerPoint M365 macOS does **not** have a per-shape Lock toggle UI (Windows added one in 2022; Mac as of 2026 hasn't shipped parity — verify on your build). Workaround: layout objects can't be moved from Normal view; authors would need to enter Slide Master to disturb them. That's the strongest "lock" available without document-level protection.

---

## 6. Footer line on every content slide

**Confidence: high.**

- **Use a manual text box on each layout, not Insert → Header & Footer.** The Header & Footer dialog has only Date / Footer / Slide-number slots with limited styling — no per-slot ALL-CAPS, letter-spacing, or font weight. The dialog's Footer slot also strips letter-spacing on save in some macOS builds.
- **Where:** Slide Master view → on each content layout (Title+Content, Two-Col, Three-Col, Tile-Grid, etc.), text box at x=60, y=1020, width=1800, height=20. Type `OPEN COMPONENT MODEL · OCM.SOFTWARE`. Don't put it on the master root unless you also want it on Hero — spec says content slides only.
- **Letter-spacing (+6%):** PowerPoint expresses this as **"Spacing: Expanded by N pt"**, not a percentage. Path: select text → **Format → Font → Character Spacing tab** (older builds) or **Format pane → Text Options → Text Box → Character Spacing**. Convert: at 9 pt, +6% ≈ 0.54 pt → use **0.5 pt expanded**. (For 14 pt eyebrow at +8%: **1.1 pt expanded**.) Sticks per text box.
- **Font/colour:** Aptos Regular, 9 pt, ALL-CAPS via **Format → Font → All Caps** (preferred over typing capitals — keeps source string editable in mixed case), colour Grey Mid `#6B7280`.

---

## Open / unverified items

- **Mac shape-locking UI:** medium confidence Mac M365 still lacks per-shape Lock. If parity has landed, ignore the §5 workaround. Verify by right-clicking any shape and looking for **Lock**.
- **Letter-spacing UI label:** the exact label shifted between 2024–2025 builds; both reach `<a:rPr spc="...">`, so whichever path your build exposes is fine.
- **Substring gradient fallback:** if Format Text Effects refuses to scope the fill to selected characters on your build, split the title into two text boxes — gradient on the operative-noun box, plain white on the rest.
