# Handover — Phase 2: Build the remaining variant decks (python-pptx path)

**Repo root:** `/Users/D032990/.cline/worktrees/marketing-recovery/open-component-model`
**Working dir:** `docs/community/marketing/`
**Branch:** `marketing/spike-deck`
**Picks up from:** 2026-06-17, end of Phase 1
**Supersedes:** earlier draft of this doc that referenced Marp. Marp was abandoned mid-Phase-1 — the Marp playground is archived at `archive/marp-iteration-attempt/`. **The build path is python-pptx.**

---

## What this session is about

Phase 1 of the OCM exec-deck rework is complete. Narratives are locked, two variant decks are built (external base + internal-sponsor) via python-pptx against the brand-correct `OCM-Master.potx`. The folder is reorganised; a meeting landing page is in place.

**Phase 2 is variant authoring for the remaining external decks.** Each variant gets its own python-pptx script, cloned from `build_pptx.py` (the external base) and edited to apply per-variant copy. Output is a brand-correct PPTX in `decks/exec-phase1/` that opens cleanly in PowerPoint with proper layouts.

Read this whole document before touching any file. **Do not redo Phase 1.** The narrative is locked. The structural decisions are locked. Your job is to clone the base build script, change copy, run it, iterate.

---

## What's already done (do not redo)

**Folder structure:**
- `narratives/NARRATIVE.md` — external locked master narrative (11-beat skeleton; comparator slide added as new slide 5).
- `narratives/NARRATIVE-INTERNAL-SPONSOR.md` — internal-sponsor sibling narrative (14-slide skeleton with 10a/10b split, Slack-only CTA, no kro/ESO).
- `narratives/NARRATIVE-AT-A-GLANCE.md` — one-page summary.
- `decks/exec-phase1/diagrams/03-meet-ocm-hub-and-spoke.svg` — new "Meet OCM" hub-and-spoke diagram. Three regulatory regimes (DORA, NIS2, CRA), EU+US flag glyphs, cloud-with-lock for Sovereign Cloud, "… any artifact type" pill, FedRAMP/FISMA/BSI C5/SecNumCloud footer.
- `decks/exec-phase1/build-pptx/build_pptx.py` — external base build script (13 slides). Already updated to match the locked Phase-1 narrative.
- `decks/exec-phase1/build-pptx/build_pptx_internal_sponsor.py` — internal-sponsor variant build script (14 slides). Reference example for cloning.
- `decks/exec-phase1/OCM-Sovereign-Delivery-Exec.pptx` — rendered external base (rebuilt 2026-06-17).
- `decks/exec-phase1/OCM-Sovereign-Delivery-Internal-Sponsor.pptx` — rendered internal-sponsor variant.

**Locked decisions** — see `README.md` "What's locked" section. Highlights: external hero is *"Three minutes from now, you'll know what your supply chain doesn't"* + auditor/operator/regulator subtitle; comparator slide ("How OCM composes") is locked into all variants; CRA replaced GDPR everywhere; ROI-led variant deferred (no real numbers); kro/ESO upstream-contribution claim dropped (factually wrong).

---

## What this session needs to produce

Build three more python-pptx variants. Each is a clone of `build_pptx.py` (the external base), edited to apply per-variant hero, slide 2, slide 9 outcomes, and slide 11 CTA. **Slides 4–8 mostly inherit unchanged** — the SBoD category claim, the comparator slide, the mechanic, and sovereign-ready are audience-independent.

| Variant | Audience | Source for hero/slide-2 | Build order |
|---|---|---|---|
| **build_pptx_cold_room.py** | External small-to-mid regulated-industry boards/CTOs (canonical cold-room) | Already in `build_pptx.py` — this *is* the cold-room canonical. No new script needed unless variant tweaks are wanted. | First — confirm with user whether any tweaks to `build_pptx.py` are needed for cold-room, or if it stands as-is. |
| **build_pptx_regulator_led_fsi_eu.py** | EU FSI CISO / risk officer | `archive/EXEC-DECK-REWORK-OPTIONS.md` Slide 1 Option B (DORA-frame). Slide 8 (ODG) gets DORA-aligned title per the same doc. | Second |
| **build_pptx_peer_led_event.py** | Industry-event keynote with adopters in the room | `archive/EXEC-DECK-REWORK-OPTIONS.md` Slide 1 Option C ("SAP, BwI, Gardener — and now you?") | Third (lowest priority) |

The fourth axis — ROI-led — is **deferred**. The user cannot deliver real numbers, and ROI-led without numbers is paper. Do not build it.

---

## How to build a variant

```bash
cd docs/community/marketing/decks/exec-phase1/build-pptx
cp build_pptx.py build_pptx_<variant>.py
# Edit OUTPUT_PPTX at line ~48 to a variant-specific name
# Edit slide constructors as needed
python3 build_pptx_<variant>.py
```

The output lands in `decks/exec-phase1/<OUTPUT_FILENAME>.pptx`. Open in PowerPoint to verify.

**Helpers available in the script** (do not modify):
- `set_text(slide, idx, text, *, color=None)` — set placeholder text
- `set_split_gradient_title(slide, idx, prefix, noun)` — hero second line with gradient noun
- `set_blue_box_bullets(slide, idx, list_of_strings)` — body bullets in the brand-blue box
- `add_diagram(slide, svg_path, x_px, y_px, max_w_px, max_h_px)` — embed an SVG diagram (rasterized at build time)
- `add_tile_icon(slide, tile_x_px, tile_y_px, icon_name)` — tile icon
- `add_logo_row(slide, [paths], y_px)` — horizontal logo row
- `add_label_at(slide, y_px, text)` / `add_centred_proof(slide, y_px, text)` — inline text helpers for slide 10

Layouts available in `OCM-Master.potx`:
`Hero, CTA, Content / 3-Column, Content / Diagram, Content / Tiles, Content / 2-Column, Section Divider, Plain, Plain / Compact`.

---

## What's still open (resolve with the user before each external variant)

1. **External concession line wording** — three candidates in `archive/MARKETING-PEER-REVIEW.md` §4.2:
   - (1) *"OCM is overkill if you ship into one cloud, with one stack, with no sovereignty pressure."*
   - (2) *"OCM v2 just shipped. Expect surface-area changes through 2026."*
   - (3) *"OCM does not replace cosign or your SBOM tooling. It composes with both."*
   Pick one; bake into slide 6 footer or slide 8 sub-bullet.

2. **External CTA wording** — current `build_pptx.py` slide 11 says *"Try it / Build with us / Talk to us. Community channels on the website."* First chief's recommendation in `archive/EXEC-DECK-REWORK-OPTIONS.md` slide 10 Option A: *"Pick one component this sprint. Pack it. We'll help."* + 30-min reading / 2-hour PoC / white-glove. Pick one; or keep current.

3. **External slide 10 (adopters wall)** — currently uses generic *"TRUSTED IN PRODUCTION / Aligned with NeoNephos"* + the 6-logo wall (SAP / BwI / SAP NS2 + Gardener / Konfidence / Platform Mesh). May want stronger per-logo proof per first chief's `archive/EXEC-DECK-REWORK-OPTIONS.md` Slide 9 Option D, but that requires real attributable quotes which the user said cannot be sourced. Leave as-is unless user objects.

4. **Cold-room concession line** — same as (1) above. The cold-room variant is *already* `build_pptx.py`; deciding whether to add the concession line involves editing that base script directly.

---

## Constraints (do not violate)

- **Slides are EITHER text OR diagram, never both.** This is why slides 4 and 7 split into a/b pairs. Confirmed with user; design constraint of the .potx layouts.
- **Eyebrow never wraps to 2 lines.** Keep eyebrow text terse.
- **1-line vs 2-line title use different layouts** (Plain / Compact at body y=520 vs Plain at y=580). Use the right layout per slide.
- **Design is frozen.** No layout, color, font, or coordinate changes. If a variant truly needs a new layout, ask the user first.
- **Acronym discipline.** First mention spells out (e.g., "Cyber Resilience Act (CRA)"); subsequent mentions use acronym only. The diagram canvas uses acronyms only — visual cleanliness wins.
- **CRA replaced GDPR everywhere.** Do not reintroduce GDPR on regulatory regime lists. GDPR is data-protection, off-thesis for software supply chain.
- **No fabricated numbers.** The user cannot deliver real numbers. Do not add metric claims to any variant.
- **kro and ESO are NOT OCM upstream contributions.** Cross-pollination happens at the contributor level (OCM contributors are also maintainers there), not the project level. Do not reintroduce a "OCM contributes upstream to kro/ESO" line.
- **BwI capitalization.** Bundeswehr Informationstechnik = "BwI" (lowercase w). Not "BWI".

---

## Suggested approach for variant authoring

1. **Read the three narratives in `narratives/` first** (~25 min total).
2. **Open `decks/exec-phase1/build-pptx/build_pptx_internal_sponsor.py`** as your reference. This shows what slide-by-slide variant edits look like.
3. **Read `archive/MARKETING-PEER-REVIEW.md` §1, §2, §7** (~15 min). §2 has the per-framing critique that explains *why* each variant exists. §7 is the consolidated open-items list.
4. **Build the regulator-led FSI-EU variant** first — most technically distinct from the cold-room canonical (different hero, different slide 8 title). Get user feedback. Iterate.
5. **Then peer-led** — smallest delta from cold-room (only hero changes; rest of deck identical). Cheap to build.
6. **Don't build cold-room as a separate file** unless user requests tweaks to `build_pptx.py`. Right now `build_pptx.py` *is* the cold-room canonical.

Per the original Phase-1 handoff: **don't write all variants up-front.** Build the highest-leverage one, get user feedback, then expand.

---

## Files in scope for Phase 2 (modify)

- `decks/exec-phase1/build-pptx/build_pptx_regulator_led_fsi_eu.py` (new)
- `decks/exec-phase1/build-pptx/build_pptx_peer_led_event.py` (new)
- Optionally: tweaks to `build_pptx.py` (cold-room canonical) if user requests
- Their corresponding `.pptx` outputs in `decks/exec-phase1/`

## Files NOT in scope (do not modify without asking)

- `narratives/*` — locked
- `decks/exec-phase1/build-pptx/build_potx.py` — generates the brand template; do not touch
- `decks/exec-phase1/diagrams/*.svg` — diagrams locked unless user requests revision
- `assets/*` — brand logos and banners, locked
- `archive/*` — process artifacts (including the abandoned Marp playground); reference only

---

## What was settled in the previous session

These are decisions reached during 2026-06-17 grilling that are now locked into the docs and the build scripts. **Do not relitigate.**

| Decision | Locked value |
|---|---|
| External canonical hero | *"Three minutes from now, you'll know what your supply chain doesn't"* + auditor/operator/regulator subtitle |
| Internal-sponsor lead axis | Loss-frame: "what we lose by walking away" |
| Internal-sponsor concession line | *"OCM's value is strategic — ecosystem leverage, sovereignty positioning, standardization. The transactional case is built per-LoB, with your team."* (lives on slide 6 footer or slide 9 ecosystem beat) |
| Internal-sponsor slide 9 outcomes | Six tiles, no per-tile project pointers (italic pointers were AI slop and were dropped) |
| Internal-sponsor slide 10 ecosystem | Split into 10a (open peers — CSI, Gardener, Kyma, Konfidence, OCP) + 10b (internal SAP — Hyperspace, RBSC). No upstream-contribution section. |
| Internal-sponsor CTA | SAP Slack `#sap-tech-ocm` only. No Zulip. No GH issues. |
| Slide 3 reframe | "Meet OCM. One identity, every boundary." Hub-and-spoke diagram. |
| Slide 5 (new) | Comparator slide "How OCM composes" — three columns: keyless/key-based signing; SBOM tool or format; OCI + Sigstore + scripts. |
| Regulatory regimes | DORA, NIS2, CRA. GDPR dropped. |
| Number sourcing | User cannot deliver. ROI-led variant deferred. |
| Build path | python-pptx + `OCM-Master.potx`. Marp abandoned (archived). |
| Slide size | 20" × 11.25" (50.8 × 28.58 cm). Matches .potx exactly; do not change. |

---

## Open questions to confirm with the user before Phase 2 work begins

1. **Has the user reviewed the rendered `OCM-Sovereign-Delivery-Exec.pptx` (external base) and `OCM-Sovereign-Delivery-Internal-Sponsor.pptx`?** If they have feedback on these, address before building the external variants — the same patterns recur.
2. **The four open items in §7 of `archive/MARKETING-PEER-REVIEW.md`** — pick concession line, pick external CTA, confirm comparator-on-all-variants, decide whether external slide 10 stays generic or names public adopters with proof.
3. **Naming convention for variant `.pptx` files** — current pattern is `OCM-Sovereign-Delivery-<variant>.pptx`. Confirm or override.

---

*Generated 2026-06-17. Replaces an earlier Marp-based draft. Successor to `archive/HANDOFF-CONTENT-VARIANTS.md` (the original Phase-1 handoff). The folder structure described in `README.md` is in place; this handover doc lives in `archive/` because it's a process artifact, not meeting-discussion material.*
