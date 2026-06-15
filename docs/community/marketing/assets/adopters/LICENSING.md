# Adopter Logos — Sources and Licensing

This directory holds adopter logos used on slide 9 ("Open and governed") of the
OCM marketing deck. Each logo was fetched from the source listed below.

**General rule:** All third-party trademarks and logos remain the property of
their respective owners. Inclusion here is for editorial/factual use to
illustrate adoption of OCM. Before publishing the deck externally, confirm the
usage is consistent with each owner's brand and trademark policies.

---

## Tier 1 — Enterprises shipping into regulated environments

### SAP

- **File:** `sap/sap-horizontal-color.svg`
- **Source URL:** <https://upload.wikimedia.org/wikipedia/commons/5/59/SAP_2011_logo.svg>
- **Wikimedia file page:** <https://commons.wikimedia.org/wiki/File:SAP_2011_logo.svg>
- **Licence:** Public domain on Wikimedia (PD-textlogo / simple shapes — below
  the threshold of originality).
- **TRADEMARK:** "SAP" is a registered trademark of SAP SE. The Wikimedia entry
  carries the standard trademark warning: *"This work includes material that
  may be protected as a trademark in some jurisdictions."* Editorial/factual
  use to indicate that SAP is an OCM adopter is generally fine; do not use the
  mark in a way that suggests endorsement of a third-party product.
- **Caveat:** This is the corporate SAP wordmark. Internal SAP teams ship OCM,
  so this is the right mark for slide 9.

### BwI (BWI GmbH — Bundeswehr IT)

- **Files:**
  - `bwi/bwi-horizontal-color.svg` — primary, "BWI · IT für Deutschland" lockup
    from <https://commons.wikimedia.org/wiki/File:BWI_Logo_IT-fuer-Deutschland.svg>
  - `bwi/bwi-gmbh-logo.svg` — alternate plain "BWI GmbH" mark from
    <https://commons.wikimedia.org/wiki/File:BWI_GmbH_logo.svg>
  - `bwi/bwi-700px.jpg` — JPG fallback fetched directly from BWI press page
    <https://www.bwi.de/fileadmin/images/start/Logo-BWI_700px.jpg> (linked from
    <https://www.bwi.de/presse>)
- **Licence:** Wikimedia versions are tagged public domain (PD-textlogo).
- **TRADEMARK:** "BWI" is a trademark of BWI GmbH (German federal IT
  subsidiary). Wikimedia's standard trademark warning applies. The press-kit
  JPG is provided by BWI for press use; verify their press conditions before
  external publication.
- **Caveat:** Two horizontal variants are present — pick the
  `bwi-horizontal-color.svg` ("IT für Deutschland") if you want context, or the
  plain `bwi-gmbh-logo.svg` for a cleaner mark.

### SAP NS2 (SAP National Security Services)

- **File:** `sap-ns2/sap-corporate-fallback.svg` (copy of the SAP corporate
  wordmark — see SAP entry above)
- **Source URL:** Wikipedia's SAP NS2 article uses the SAP corporate logo as
  the company mark — <https://en.wikipedia.org/wiki/SAP_NS2>.
- **Licence / Trademark:** Same as SAP entry above. SAP NS2 is a wholly-owned
  SAP subsidiary; it does not appear to publish a distinct, freely-available
  "NS2" wordmark.
- **⚠ NEEDS USER DECISION:** No standalone "SAP NS2" logo SVG/PNG was found on
  Wikimedia Commons, seeklogo, the public sapns2.com site (returns HTTP 403 to
  scrapers), or as a recognisable mark in the `sap-ns2` GitHub org avatar (the
  avatar is a default GitHub identicon, not a real logo). Options:
  1. Use the SAP corporate wordmark with a "NS2" caption underneath.
  2. Reach out to SAP NS2 directly for an official asset.
  3. Render a simple typeset "SAP NS2" lockup inline in the slide.

---

## Tier 2 — Built into the open-source ecosystem

### Gardener

- **Files:**
  - `gardener/gardener-horizontal-color.svg` (preferred)
  - `gardener/gardener-horizontal-color.png`
- **Source URL:** <https://github.com/neonephos/artwork/tree/main/projects/gardener/horizontal/color>
- **Licence:** Per `https://github.com/neonephos/artwork/blob/main/LICENSE.md`,
  all artwork in the neonephos/artwork repo is made available under the Linux
  Foundation trademark usage guidelines:
  - <https://www.linuxfoundation.org/hubfs/lfeu_policies_exhibitb_051024b.pdf>
  - <https://www.linuxfoundation.org/legal/trademark-usage/>
- **Caveat:** None — neonephos is the home of the canonical Gardener artwork.

### Konfidence

- **File:** `konfidence/konfidence-avatar.png` (icon only, 460×460)
- **Source URL:** <https://avatars.githubusercontent.com/u/219007561?v=4&s=512>
  (GitHub avatar of the `konfidence-project` org —
  <https://github.com/konfidence-project>)
- **Licence:** Unclear. The org's `repository-template` README identifies
  Konfidence as an SAP open source project ("Default templates of SAP's
  repositories. Provides template files including LICENSE…"). The icon itself
  has no published licence file; treat as **TRADEMARK: not redistributable
  outside the deck — fetched for evaluation only.**
- **⚠ NEEDS USER DECISION:** This is *icon-only* (a stylised orange "C"
  sphere), not a horizontal lockup. The org has no other artwork, no
  neonephos/artwork entry, and no website. Options:
  1. Use the icon at ~80×80 inside a tile that contains the wordmark
     "Konfidence" set in the deck typeface.
  2. Pad the icon onto a 250×80 canvas with the wordmark beside it.
  3. Drop Konfidence from the wall if no horizontal mark exists.

### Platform Mesh

- **Files:**
  - `platform-mesh/platform-mesh-horizontal-color.svg` (preferred)
  - `platform-mesh/platform-mesh-horizontal-color.png`
- **Source URL:** <https://github.com/neonephos/artwork/tree/main/projects/platform-mesh/horizontal/color>
- **Licence:** Same as Gardener — Linux Foundation trademark usage guidelines
  via the neonephos/artwork repo licence.
- **Caveat:** None.

---

## Summary of items needing user decision before slide 9 is authored

1. **SAP NS2** has no public horizontal wordmark; pick one of the three options
   in that section.
2. **Konfidence** has only an icon mark; pick one of the three options in that
   section.
3. **BwI** has two valid horizontal variants — confirm which one to use.
