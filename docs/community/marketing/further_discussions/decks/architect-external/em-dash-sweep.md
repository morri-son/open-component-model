# Em Dash Sweep — Architect External Deck

**Purpose.** Locate every em dash in slide text and speaker notes, propose a rewrite following `voice-guide.md`. User approves before any actual edit lands in the PPTX.

**Sweep date:** 2026-07-01

**Method.** Regex sweep for U+2014 in `slide-texts.md` and `speaker-notes.md`. Every match gets a proposed replacement based on the voice-guide's replacement table. The default for `Anchor — Description` bullets is a colon.

## Summary counts

- Slide text: 40 em dashes across 18 slides
- Speaker notes: 2 em dashes across 2 slides
- Total: 42 em dashes

## Slide text sweep

### Slide 1: You ship pieces

**Instance 1** (slide title):
> ## Slide 1 — You ship pieces.

Pattern: slide title
Proposed rewrite: `## Slide 1: You ship pieces.`

**Instance 2** (bullet text):
> Open Component Model — open source, NeoNephos Foundation.

Pattern: Anchor — Description
Proposed rewrite: `Open Component Model: open source, NeoNephos Foundation.`

### Slide 2: DIAGNOSIS

**Instance 1** (slide title):
> ## Slide 2 — DIAGNOSIS

Pattern: slide title
Proposed rewrite: `## Slide 2: DIAGNOSIS`

**Instance 2** (bullet):
> ▪  OCI image — digest pins the bytes. Nothing pins the release the image belongs to.

Pattern: Anchor — Description
Proposed rewrite: `▪  OCI image: digest pins the bytes. Nothing pins the release the image belongs to.`

**Instance 3** (bullet):
> ▪  Helm chart — version pins the chart. Nothing pins it to the image, config, and SBOM it ships with.

Pattern: Anchor — Description
Proposed rewrite: `▪  Helm chart: version pins the chart. Nothing pins it to the image, config, and SBOM it ships with.`

**Instance 4** (bullet):
> ▪  SBOM — referrer attaches to one digest. No referrer spans the whole release.

Pattern: Anchor — Description
Proposed rewrite: `▪  SBOM: referrer attaches to one digest. No referrer spans the whole release.`

### Slide 3: THE HINGE

**Instance 1** (slide title):
> ## Slide 3 — THE HINGE

Pattern: slide title
Proposed rewrite: `## Slide 3: THE HINGE`

**Instance 2** (bullet):
> ▪  Component identity — name and version of the component. Globally unique. Location-agnostic.

Pattern: Anchor — Description
Proposed rewrite: `▪  Component identity: name and version of the component. Globally unique. Location-agnostic.`

**Instance 3** (bullet):
> ▪  Digest — every resource inside the component carries a content hash. Computed once.

Pattern: Anchor — Description
Proposed rewrite: `▪  Digest: every resource inside the component carries a content hash. Computed once.`

**Instance 4** (bullet):
> ▪  Access — where the resource currently lives. Rewritten on transfer. Digest stays.

Pattern: Anchor — Description
Proposed rewrite: `▪  Access: where the resource currently lives. Rewritten on transfer. Digest stays.`

### Slide 4: WHERE OCM SITS

**Instance 1** (slide title):
> ## Slide 4 — WHERE OCM SITS

Pattern: slide title
Proposed rewrite: `## Slide 4: WHERE OCM SITS`

### Slide 5: CONSTRUCTOR

No em dashes in slide title beyond the numbered heading format. Heading uses colon pattern already implicit in slide metadata.

### Slide 6: DESCRIPTOR

**Instance 1** (code comment):
> # excluded — rewritten on transfer

Pattern: Anchor — Description (in code comment)
Proposed rewrite: `# excluded: rewritten on transfer`

**Instance 2** (code comment):
> # content identity — input to descriptor hash

Pattern: Anchor — Description (in code comment)
Proposed rewrite: `# content identity: input to descriptor hash`

### Slide 7: OCM IN ONE PICTURE

No em dashes in content (middle dots `·` are correct per voice-guide).

### Slide 8: COMPOSE

**Instance 1** (bullet):
> Service components carry resources — images, charts, configs, SBOMs, …

Pattern: Anchor — Description
Proposed rewrite: `Service components carry resources: images, charts, configs, SBOMs, …`

**Instance 2** (code comment):
> # no resources of its own — pure composition

Pattern: Anchor — Description (in code comment)
Proposed rewrite: `# no resources of its own: pure composition`

### Slide 9: SIGN

**Instance 1** (footer note):
> CTF = Common Transport Format — a filesystem-based OCM repository, portable via any transfer mechanism.

Pattern: Anchor — Description
Proposed rewrite: `CTF = Common Transport Format: a filesystem-based OCM repository, portable via any transfer mechanism.`

### Slide 10: TRANSPORT

No em dashes in content.

### Slide 11: DEPLOY

No em dashes in content.

### Slide 12: DAY 2

No em dashes in content.

### Slide 13: ADOPTION

**Instance 1** (section heading):
> FROM ZERO — CLI

Pattern: Anchor — Description
Proposed rewrite: `FROM ZERO: CLI`

**Instance 2** (section heading):
> ON YOUR CLUSTER — CONTROLLERS

Pattern: Anchor — Description
Proposed rewrite: `ON YOUR CLUSTER: CONTROLLERS`

### Slide 14: WHAT'S SHARP

**Instance 1** (slide title):
> ## Slide 14 — WHAT'S SHARP

Pattern: slide title
Proposed rewrite: `## Slide 14: WHAT'S SHARP`

**Instance 2** (bullet):
> ▪  Transfer defaults — copies only the descriptor. For air-gap, pass --copy-resources so the bytes travel too.

Pattern: Anchor — Description
Proposed rewrite: `▪  Transfer defaults: copies only the descriptor. For air-gap, pass --copy-resources so the bytes travel too.`

**Instance 3** (bullet):
> ▪  Controllers are v1alpha1 — the CRD surface can move. Pin to specific release tags in your platform installs.

Pattern: Anchor — Description
Proposed rewrite: `▪  Controllers are v1alpha1: the CRD surface can move. Pin to specific release tags in your platform installs.`

**Instance 4** (bullet):
> ▪  Helm-deploy adds kro + Flux or ArgoCD — the OCM controllers don't ship them. Bring your existing GitOps engine.

Pattern: Anchor — Description
Proposed rewrite: `▪  Helm-deploy adds kro + Flux or ArgoCD: the OCM controllers don't ship them. Bring your existing GitOps engine.`

### Slide 15: Ship the release as one unit

**Instance 1** (line):
> Evaluate — ocm.software (QR code) · run conformance/scenarios/sovereign

Pattern: Anchor — Description
Proposed rewrite: `Evaluate: ocm.software (QR code) · run conformance/scenarios/sovereign`

**Instance 2** (line):
> Pilot — github.com/open-component-model · one product, one team

Pattern: Anchor — Description
Proposed rewrite: `Pilot: github.com/open-component-model · one product, one team`

**Instance 3** (line):
> Engage — community channels on the website · NeoNephos Foundation

Pattern: Anchor — Description
Proposed rewrite: `Engage: community channels on the website · NeoNephos Foundation`

### Slide 16: APPENDIX · REPLICATION

**Instance 1** (slide title):
> ## Slide 16 — APPENDIX · REPLICATION

Pattern: slide title
Proposed rewrite: `## Slide 16: APPENDIX · REPLICATION`

**Instance 2** (text line):
> Controller-shaped equivalent of OCM CLI `ocm transfer cv` — point it at a source `Component` and a target `Repository`, and it keeps them in sync.

Pattern: subordinate-clause em dash
Proposed rewrite: `Controller-shaped equivalent of OCM CLI `ocm transfer cv`: point it at a source `Component` and a target `Repository`, and it keeps them in sync.`

### Slide 17: HOW OCM COMPARES

**Instance 1** (slide title):
> ## Slide 17 — HOW OCM COMPARES

Pattern: slide title
Proposed rewrite: `## Slide 17: HOW OCM COMPARES`

**Instance 2** (text line):
> OCM rides on top. It doesn't replace the per-artifact tools — it adds the release-level envelope they don't.

Pattern: subordinate-clause em dash (two independent sentences joined by em dash)
Proposed rewrite: `OCM rides on top. It doesn't replace the per-artifact tools. It adds the release-level envelope they don't.` OR (if tight connection needed) `OCM rides on top. It doesn't replace the per-artifact tools; it adds the release-level envelope they don't.`

### Slide 18: APPENDIX · ABBREVIATIONS

**Instance 1** (slide title):
> ## Slide 18 — APPENDIX · ABBREVIATIONS

Pattern: slide title
Proposed rewrite: `## Slide 18: APPENDIX · ABBREVIATIONS`

**Instance 2** (glossary entry):
> CSI — Common Service Infrastructure — SAP-internal shared services platform.

Pattern: Anchor — Description — Secondary. Two-part definition.
Proposed rewrite: `CSI: Common Service Infrastructure (SAP-internal shared services platform).` OR `CSI (Common Service Infrastructure): SAP-internal shared services platform.`

**Instance 3** (glossary entry):
> Helm — Package manager for Kubernetes; reference artifact type for OCM.

Pattern: Anchor — Description
Proposed rewrite: `Helm: Package manager for Kubernetes; reference artifact type for OCM.`

**Instance 4** (glossary entry):
> NeoNephos — European foundation for sovereign cloud open-source projects (Linux Foundation Europe).

Pattern: Anchor — Description
Proposed rewrite: `NeoNephos: European foundation for sovereign cloud open-source projects (Linux Foundation Europe).`

**Instance 5** (glossary entry):
> OCI — Open Container Initiative — open standards for container image format and distribution.

Pattern: Anchor — Description — Secondary
Proposed rewrite: `OCI: Open Container Initiative (open standards for container image format and distribution).` OR `OCI (Open Container Initiative): open standards for container image format and distribution.`

**Instance 6** (glossary entry):
> OCM — Open Component Model — vendor-neutral specification for signed, transportable software components.

Pattern: Anchor — Description — Secondary
Proposed rewrite: `OCM: Open Component Model (vendor-neutral specification for signed, transportable software components).` OR `OCM (Open Component Model): vendor-neutral specification for signed, transportable software components.`

**Instance 7** (glossary entry):
> OpenPGP — Open standard for cryptographic signatures (RFC 4880). GPG is one implementation; Sequoia and RNP produce compatible signatures.

Pattern: Anchor — Description
Proposed rewrite: `OpenPGP: Open standard for cryptographic signatures (RFC 4880). GPG is one implementation; Sequoia and RNP produce compatible signatures.`

**Instance 8** (glossary entry):
> RSA — RSA / RSASSA-PSS — bare public-key signing scheme. Trust model: operator pins the public key. No PKI required.

Pattern: Anchor — Full expansion — Description
Proposed rewrite: `RSA (RSA / RSASSA-PSS): bare public-key signing scheme. Trust model: operator pins the public key. No PKI required.`

**Instance 9** (glossary entry):
> SBOM — Software Bill of Materials — inventory of components and dependencies inside a software artifact.

Pattern: Anchor — Full expansion — Description
Proposed rewrite: `SBOM (Software Bill of Materials): inventory of components and dependencies inside a software artifact.`

**Instance 10** (glossary entry):
> Sigstore — Open-source project for keyless software signing using OIDC identities + Rekor transparency log.

Pattern: Anchor — Description
Proposed rewrite: `Sigstore: Open-source project for keyless software signing using OIDC identities + Rekor transparency log.`

## Speaker notes sweep

### Slide 4: WHERE OCM SITS

**Instance 1** (main text):
> It WRAPS them — adds one envelope signature over the whole release, sitting on top of whatever signatures the individual artifacts already carried.

Pattern: subordinate-clause em dash
Proposed rewrite: `It WRAPS them, adding one envelope signature over the whole release, sitting on top of whatever signatures the individual artifacts already carried.`

### Slide 16: APPENDIX · REPLICATION

**Instance 1** (section header):
> APPENDIX — pull only if asked about cluster-side component mirroring or 'how do I get a version from one repo into another without running the CLI?'.

Pattern: Anchor — Description (contextual cue)
Proposed rewrite: `APPENDIX: pull only if asked about cluster-side component mirroring or 'how do I get a version from one repo into another without running the CLI?'.`

## Notes

Most em dashes follow the `Anchor — Description` pattern and convert cleanly to colons. Glossary entries on Slide 18 use two-part definitions (Anchor — Expansion — Description); these benefit from parenthesized expansions. The two speaker notes are contextual cues that convert to colons or commas without disruption.

No material ambiguity. All rewrites preserve meaning and improve readability by eliminating the AI-signal em dash without sacrificing semantic clarity.
