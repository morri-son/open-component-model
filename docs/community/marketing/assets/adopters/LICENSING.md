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

- **File:** `sap-ns2/sap-ns2-getlogovector.png` (preferred — distinct SAP NS2
  lockup, 900×500 PNG with transparency)
- **Fallback:** `sap-ns2/sap-corporate-fallback.svg` (copy of the SAP corporate
  wordmark, retained as a backup)
- **Source URL:** <https://getlogovector.com/wp-content/uploads/2023/04/sap-ns2-logo-vector.png>
- **Licence / Trademark:** "SAP NS2" is a trademark of SAP National Security
  Services, Inc., a wholly-owned SAP subsidiary. The getlogovector source
  redistributes brand marks for editorial/reference use; treat as
  **TRADEMARK: editorial use only — do not imply endorsement.** Verify usage
  with SAP NS2 brand owners before external publication.

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

- **Files:**
  - `konfidence/konfidence-horizontal-light.svg` (preferred — horizontal
    lockup, light-mode variant suitable for white slide backgrounds)
  - `konfidence/konfidence-horizontal-dark.svg` (alternate — dark-mode variant)
  - `konfidence/konfidence-avatar.png` (legacy icon, 460×460, kept as backup)
- **Source URL:** <https://konfidence.cloud/assets/logo/full/SVG/400_konfidence_logo_light.svg>
  and `…_dark.svg` from the konfidence.cloud project site.
- **Licence:** Konfidence is an SAP-supported project distributed via
  konfidence.cloud. No explicit logo licence is published; treat as
  **TRADEMARK: editorial use only — do not imply endorsement.** Verify with
  the Konfidence project before external publication.

### Platform Mesh

- **Files:**
  - `platform-mesh/platform-mesh-horizontal-color.svg` (preferred)
  - `platform-mesh/platform-mesh-horizontal-color.png`
- **Source URL:** <https://github.com/neonephos/artwork/tree/main/projects/platform-mesh/horizontal/color>
- **Licence:** Same as Gardener — Linux Foundation trademark usage guidelines
  via the neonephos/artwork repo licence.
- **Caveat:** None.

### OpenControlPlane (OCP)

- **File:** `open-control-plane/opencontrolplane-icon-color.svg`
- **Source URL:** <https://open-control-plane.io/img/opencontrolplane-icon-color.svg>
- **Licence:** No explicit logo licence published on the project site at fetch
  time. Project is the open-source rebrand of openMCP (rename triggered by
  licensing concerns prior to OSS release). Treat as **TRADEMARK: editorial
  use only — do not imply endorsement.** Verify with the OpenControlPlane
  project before external publication.
- **Caveat:** Icon-only mark (no horizontal lockup available at fetch time).
  Reads slightly smaller than the horizontal logos in a row, acceptable
  trade-off until a horizontal variant is published.

### Kyma

- **File:** `kyma/kyma-icon-color.svg`
- **Source URL:** <https://kyma-project.io/assets/logo_icon.svg>
- **Licence:** Kyma is an SAP-originated open-source project. No explicit
  separate logo licence published; project assets are part of the public site.
  Treat as **TRADEMARK: editorial use only — do not imply endorsement.**
- **Caveat:** Icon-only mark (the kyma-project.io site uses this as its
  primary navigation logo). No horizontal wordmark variant identified.

### NeoNephos Foundation

- **File:** `neonephos/neonephos-foundation-horizontal-color.svg`
  (copied from `assets/neonephos/`, where the same SVG is used for the slide
  brand row — kept under `adopters/` for consistency with the adopter-wall
  convention)
- **Source URL:** Vendored alongside the OCM brand assets; canonical source is
  the NeoNephos Foundation (Linux Foundation Europe project).
- **Licence:** Linux Foundation trademark usage guidelines apply
  (<https://www.linuxfoundation.org/legal/trademark-usage/>). Editorial use
  to indicate adoption is consistent with those guidelines.
- **Caveat:** None.

---

## Decisions taken (slide 9 authoring)

1. **SAP NS2** — using `sap-ns2-getlogovector.png` (distinct SAP NS2 lockup
   from getlogovector.com).
2. **Konfidence** — using `konfidence-horizontal-light.svg` (horizontal lockup
   from konfidence.cloud).
3. **BwI** — using `bwi-horizontal-color.svg` (Wikimedia "IT für Deutschland"
   lockup).
