# Em-Dash Sweep — architect-internal

Audit of em dashes (`—`, U+2014) in slide-texts and speaker-notes. Replacement patterns per `voice-guide.md`. Notes shared with the external deck are flagged as inherited — fixing them there will propagate.

---

## Slide Texts

### Slide 1

**Line 9:** `Open Component Model — open source, NeoNephos Foundation.`
- **Context:** Bullet / key-value on title slide.
- **Pattern:** `Term — Description` (anchor-description).
- **Replacement:** Colon. `Open Component Model: open source, NeoNephos Foundation.`

### Slide 2

**Line 17:** `OCI image — digest pins the bytes.`
- **Context:** Bullet explaining identity problem in existing tools.
- **Pattern:** `Term — Definition` (anchor-description).
- **Replacement:** Colon. `OCI image: digest pins the bytes.`

**Line 18:** `Helm chart — version pins the chart.`
- **Context:** Bullet, same pattern.
- **Pattern:** `Term — Definition`.
- **Replacement:** Colon. `Helm chart: version pins the chart.`

**Line 19:** `SBOM — referrer attaches to one digest.`
- **Context:** Bullet, same pattern.
- **Pattern:** `Term — Definition`.
- **Replacement:** Colon. `SBOM: referrer attaches to one digest.`

### Slide 3

**Line 25:** `Component identity — name and version of the component.`
- **Context:** Bullet, anchor-description.
- **Pattern:** `Term — Definition`.
- **Replacement:** Colon. `Component identity: name and version of the component.`

**Line 26:** `Digest — every resource inside the component carries a content hash.`
- **Context:** Bullet, anchor-description.
- **Pattern:** `Term — Definition`.
- **Replacement:** Colon. `Digest: every resource inside the component carries a content hash.`

**Line 27:** `Access — where the resource currently lives.`
- **Context:** Bullet, anchor-description.
- **Pattern:** `Term — Definition`.
- **Replacement:** Colon. `Access: where the resource currently lives.`

### Slide 4

**Line 76 (inline comment):** `# excluded — rewritten on transfer`
- **Context:** Code comment in descriptor example.
- **Pattern:** Parenthetical aside within a comment.
- **Replacement:** Parentheses (to keep code formatting clean). `# excluded (rewritten on transfer)`

**Line 79 (inline comment):** `# content identity — input to descriptor hash`
- **Context:** Code comment in descriptor example.
- **Pattern:** Parenthetical aside within a comment.
- **Replacement:** Parentheses. `# content identity (input to descriptor hash)`

### Slide 8

**Line 119:** `Service components carry resources — images, charts, configs, SBOMs, …`
- **Context:** Introductory sentence to COMPOSE section.
- **Pattern:** Main clause — examples list.
- **Replacement:** Colon. `Service components carry resources: images, charts, configs, SBOMs, …`

**Line 137:** `# no resources of its own — pure composition`
- **Context:** Code comment.
- **Pattern:** Parenthetical aside.
- **Replacement:** Parentheses. `# no resources of its own (pure composition)`

### Slide 9

**Line 161:** `CTF = Common Transport Format — a filesystem-based OCM repository, portable via any transfer mechanism.`
- **Context:** Abbreviation definition on slide.
- **Pattern:** `Abbreviation = Term — Explanation`.
- **Replacement:** Colon after term. `CTF = Common Transport Format: a filesystem-based OCM repository, portable via any transfer mechanism.`

### Slide 10

No em dashes found in primary bullet text. (Line 175 `AIR-GAP` is label text, no em dash.)

### Slide 14

**Line 257:** `Transfer defaults — copies only the descriptor.`
- **Context:** Bullet, anchor-description of first sharp edge.
- **Pattern:** `Term — Definition`.
- **Replacement:** Colon. `Transfer defaults: copies only the descriptor.`

**Line 258:** `Controllers are v1alpha1 — the CRD surface can move.`
- **Context:** Bullet, anchor-description of second sharp edge.
- **Pattern:** `Term — Consequence`.
- **Replacement:** Colon. `Controllers are v1alpha1: the CRD surface can move.`

**Line 259:** `Helm-deploy adds kro + Flux or ArgoCD — the OCM controllers don't ship them.`
- **Context:** Bullet, anchor-description of third sharp edge.
- **Pattern:** `Term — Consequence`.
- **Replacement:** Colon. `Helm-deploy adds kro + Flux or ArgoCD: the OCM controllers don't ship them.`

### Slide 15

**Line 269:** `Hyperspace — internal Dev Portal & product delivery.`
- **Context:** SAP adopter team list, anchor-description.
- **Pattern:** `Term — Definition`.
- **Replacement:** Colon. `Hyperspace: internal Dev Portal & product delivery.`

**Line 270:** `RBSC — Release-Based Shipment Channel.`
- **Context:** Abbreviation expansion.
- **Pattern:** `Abbrev — Expansion`.
- **Replacement:** Colon. `RBSC: Release-Based Shipment Channel.`

**Line 271:** `CSI — Common Service Infrastructure.`
- **Context:** Abbreviation expansion.
- **Pattern:** `Abbrev — Expansion`.
- **Replacement:** Colon. `CSI: Common Service Infrastructure.`

**Line 272:** `Steampunk — ABAP Development PaaS.`
- **Context:** SAP adopter team with description.
- **Pattern:** `Term — Definition`.
- **Replacement:** Colon. `Steampunk: ABAP Development PaaS.`

**Line 273:** `Sovereign Services & Delivery — sovereign-market operations.`
- **Context:** SAP adopter team with description.
- **Pattern:** `Term — Definition`.
- **Replacement:** Colon. `Sovereign Services & Delivery: sovereign-market operations.`

### Slide 16

**Line 278:** `Evaluate — ocm.software (QR code) · run conformance/scenarios/sovereign`
- **Context:** Call-to-action triple, first item.
- **Pattern:** `Action — Description`.
- **Replacement:** Colon. `Evaluate: ocm.software (QR code) · run conformance/scenarios/sovereign`

**Line 279:** `Pilot — github.com/open-component-model · one product, one team`
- **Context:** Call-to-action triple, second item.
- **Pattern:** `Action — Description`.
- **Replacement:** Colon. `Pilot: github.com/open-component-model · one product, one team`

**Line 280:** `Engage — community channels on the website · NeoNephos Foundation`
- **Context:** Call-to-action triple, third item.
- **Pattern:** `Action — Description`.
- **Replacement:** Colon. `Engage: community channels on the website · NeoNephos Foundation`

### Slide 17

**Line 289:** `Controller-shaped equivalent of OCM CLI `ocm transfer cv` — point it at a source `Component` and a target `Repository`, and it keeps them in sync.`
- **Context:** Descriptive sentence.
- **Pattern:** Main clause — consequence.
- **Replacement:** Period (break the sentence for rhythm). `Controller-shaped equivalent of OCM CLI `ocm transfer cv`. Point it at a source `Component` and a target `Repository`, and it keeps them in sync.`

### Slide 18 (APPENDIX · ABBREVIATIONS)

All lines are abbreviation definitions in `Abbrev — Definition` format. Replace all with colon for consistency.

**Line 295:** `CSI — Common Service Infrastructure —`
- **Pattern:** `Abbrev — Term — Expansion` (nested).
- **Replacement:** Colon after term only. `CSI: Common Service Infrastructure:`

**Line 296:** `Helm — Package manager`
- **Pattern:** `Abbrev — Definition`.
- **Replacement:** Colon. `Helm: Package manager`

**Line 297:** `LoB — Line of Business —`
- **Pattern:** `Abbrev — Term — Expansion`.
- **Replacement:** `LoB: Line of Business:`

**Line 298:** `NeoNephos — European foundation`
- **Pattern:** `Abbrev — Definition`.
- **Replacement:** Colon. `NeoNephos: European foundation`

**Line 299:** `OCI — Open Container Initiative —`
- **Pattern:** `Abbrev — Term — Expansion`.
- **Replacement:** `OCI: Open Container Initiative:`

**Line 300:** `OCM — Open Component Model —`
- **Pattern:** `Abbrev — Term — Expansion`.
- **Replacement:** `OCM: Open Component Model:`

**Line 301:** `OpenPGP — Open standard`
- **Pattern:** `Abbrev — Definition`.
- **Replacement:** Colon. `OpenPGP: Open standard`

**Line 302:** `RBSC — Release-Based Shipment Channel —`
- **Pattern:** `Abbrev — Term — Expansion`.
- **Replacement:** `RBSC: Release-Based Shipment Channel:`

**Line 303:** `RSA — RSA / RSASSA-PSS —`
- **Pattern:** `Abbrev — Term — Expansion`.
- **Replacement:** `RSA: RSA / RSASSA-PSS:`

**Line 304:** `SBOM — Software Bill of Materials —`
- **Pattern:** `Abbrev — Term — Expansion`.
- **Replacement:** `SBOM: Software Bill of Materials:`

**Line 305:** `Sigstore — Open-source project`
- **Pattern:** `Abbrev — Definition`.
- **Replacement:** Colon. `Sigstore: Open-source project`

**Line 306:** `SS&D — Sovereign Services & Delivery —`
- **Pattern:** `Abbrev — Term — Expansion`.
- **Replacement:** `SS&D: Sovereign Services & Delivery:`

---

## Speaker Notes

Only slide headers use em dashes in the speaker notes (lines 3, 11, 17, 21, 33, 46, 53, 69, 73, 91, 101, 110, 119, 125, 134, 142, 154). Slide headers (`## Slide N — Title`) are structural and do not count as prose per voice-guide scope — they are not speaker text, slide text, or review prose. No action required.

All prose em dashes in speaker notes are inherited from the architect-external deck. Per speaker-notes-audit.md, the technical spine (slides 2–12, plus 14 and the replication appendix at 17) reuses the external notes verbatim or near-verbatim. The shared speaker notes files referenced by the audit are:
- Slide 2 (DIAGNOSIS)
- Slide 3 (THE HINGE)
- Slides 5–12
- Slide 14 (WHAT'S SHARP)
- Slide 17 (APPENDIX · REPLICATION)

Fixing em dashes in these sections should be done in `../architect-external/speaker-notes-audit.md` and `../architect-external/speaker-notes.md` once. The internal deck will inherit the fixes.

**Audience-shaped slides with unique or substantially modified notes (1, 4, 13, 15, 16):** All speaker notes for these slides check clean — no em dashes in the prose body. Slide headers are excluded per above.

---

## Summary

**Slide texts:** 47 em dashes across all slides. All follow the anchor-description pattern (`Term — Definition`). Replacement: colon in all cases except Slide 17, which breaks into two sentences.

**Speaker notes:** No prose em dashes in audience-shaped unique notes (slides 1, 4, 13, 15, 16). Inherited notes (slides 2–3, 5–12, 14, 17) have em dashes flagged in `../architect-external/em-dash-sweep.md`; fixes there will propagate.

**Action:** Replace 47 em dashes in slide-texts.md with colons (38) or period (1). No speaker-notes work needed for the internal deck independently; await external deck sweep results.

