# OCM Glossary: Canonical Terms

The definitive short-form glossary. When a session uses one of these terms, this is the meaning. When multiple names exist for the same object (SBOD vs descriptor), both are here with the aliasing spelled out.

## Core OCM primitives

**Component**, the OCM unit. A named, versioned, signed bundle of one or more artifacts, packaged with a descriptor. Location-independent. This is what the deck calls out consistently across all four decks.

**Component identity**, the DNS-style path plus SemVer, e.g. `github.com/acme/webshop:v1.2.0`. Globally unique via DNS delegation. NOT called "coordinates" anywhere in the decks (that was a rejected term).

**Component descriptor**, the machine-readable YAML/JSON describing a component: identity, provider, resources, componentReferences, signatures. This is what gets signed and what travels. In marketing framing it's also called the SBOD (see below).

**SBOD (Software Bill of Delivery)**, marketing-positioning term against SBOM. Refers to the same object architects call the component descriptor. Both terms are OK; on the wire the object is a descriptor.

**Resource**, an artifact inside a component. Has a type (`OCIImage/v1`, `Helm/v1`, `LocalBlob/v1`, `File/v1`), an access (how to fetch it), and a digest (SHA-256 of the bytes).

**Component reference**, a pointer from one component to another. The referencing component's signature transitively pins the referenced component's descriptor digest.

**Access**, the "where to find it" pointer on a resource. Rewritten during transport. Excluded from signature calculation on purpose.

**Digest**, SHA-256 over resource bytes. Computed at pack time. Input to the descriptor hash.

**Descriptor hash / descriptor digest**, SHA-256 of the canonicalized descriptor. This is what gets signed. One signature covers every resource digest via this hash.

## Signing schemes

**RSA / RSA-PSS / RSASSA-PSS**, bare public-key signing. Trust model: operator pins the public key. No PKI. Implemented in both CLI and v1alpha1 K8s controller.

**OpenPGP**, signature standard (RFC 4880). Trust model: key pinning via keyring. GPG is one implementation; Sequoia and RNP produce compatible signatures. Slide header uses **OpenPGP**, not GPG. CLI-only today; K8s controller support on roadmap.

**Sigstore**, keyless signing via OIDC + Rekor transparency log. Trust anchor: OIDC issuer + Fulcio CA. CLI-only today; K8s controller support on roadmap.

**PEM + X.509 cert chain**, a fourth option (RSA + certificate chain). Experimental; the CLI prints `experimental` warnings on every sign/verify.

## Transport

**CTF (Common Transport Format)**, local archive format: blobs + index. Hand-carryable. Air-gap-compatible.

**Three transport patterns:**
- Registry → Registry (promotion / cross-cloud)
- Registry → CTF (archive out)
- CTF → Registry (air-gap import)

All three: `ocm transfer cv <src> <dst>`. Same command; access rewritten; digests stay.

## Kubernetes Controller CRs

**Component CR**, declares which component version(s) to resolve. Has an optional `verify:` field. Verification is opt-in.

**Component CR `verify:` field**, list of `{signature-name, public-key}` pairs. Pins by name+key, NOT by scheme. Empty list = no verification (opt-in). K8s controller v1alpha1 implements RSA only; OpenPGP/Sigstore CLI-only.

**Repository CR**, declares where to fetch components from.

**Resource CR**, picks one artifact from a verified component.

**Deployer CR**, applies the resource to the cluster.

**Deploy chain:** Repository → Component → Resource → Deployer.

## SAP tools & names (2026-current)

**Hyperspace**, SAP-internal developer portal + product delivery infrastructure. Includes the Piper CI system. OCM v1 integration today; v2 migration on 2026 roadmap. Internally uses OCM v1 for **SBOM aggregation** (production, not planned).

**RBSC (Release-Based Shipment Channel)**, SAP-internal customer shipment channel. OCM v2 CLI plugin works today. Products described in OCM, shipped via RBSC.

**CSI (Common Service Infrastructure)**, SAP-internal shared services platform. Adopter of OCM.

**Steampunk**, SAP-internal ABAP Development PaaS. Adopter.

**Sovereign Services & Delivery (SS&D)**, SAP organisation operating products in sovereign markets. Adopter, replaced Greenhouse in the exec-internal adopter slide.

**Greenhouse**, Cloud ops platform (still exists at SAP; removed from the internal adopter list in favour of SS&D).

**ODG (Open Delivery Gear)**, the OCM compliance-automation engine. Formerly called "OCM Gear." Lives in the OCM GitHub org. Open source.

**OCP (Open Control Plane)**, declarative deployment runtime. Formerly called "MCP" / "Managed Control Plane." Open source. Replaces Landscaper for Sovereign Cloud deployment end-2026 / early-2027.

**Landscaper**, being sunset. OCM-based components will migrate from Landscaper to Open Control Plane.

## OCM open-source ecosystem (peer projects, aligned with NeoNephos Foundation)

- **Gardener**, managed Kubernetes (SAP-origin).
- **Kyma**, cloud-native runtime (SAP-origin).
- **Open Control Plane**, control-plane framework (SAP-origin, OCM-native).
- **Konfidence**, reproducible-delivery tooling.

**NeoNephos Foundation**, European foundation for sovereign-cloud open-source projects, hosted under Linux Foundation Europe. Governs OCM.

## Regulatory framing (backdrop, not deck subject)

**NIS2**, EU Network and Information Security Directive 2.
**DORA**, Digital Operational Resilience Act (EU financial-services ICT risk regulation).
**CRA**, Cyber Resilience Act (EU cybersecurity regulation for products with digital elements).
**FedRAMP**, US federal risk / cloud security assessment.
**FISMA**, US federal information security modernization act.
**SecNumCloud**, French cloud security qualification (ANSSI).
**BSI C5**, German cloud computing compliance catalogue (Bundesamt für Sicherheit in der Informationstechnik).

## Compliance references

**SBOM (Software Bill of Materials)**, inventory of what's inside a software artifact. ISO/IEC 5962 (SPDX). Does NOT describe delivery; the deck's positioning is SBOM lists inventory, SBOD (OCM) describes delivery.
**SPDX**, Software Package Data Exchange, ISO/IEC 5962 standard format for SBOM data.
**SWID tags**, Software Identification Tags, ISO/IEC 19770-2 standard.

## Deprecated / redirected terms

| Old term | Current term |
|---|---|
| OCM Gear | Open Delivery Gear (ODG) |
| MCP / Managed Control Plane | Open Control Plane (OCP) |
| "Coordinates" | Component identity |
| GPG | OpenPGP (GPG is one implementation) |
| "descriptor.yaml" | Component descriptor |

## What this glossary is NOT

- It's not the OCM spec. For spec-level detail, see `~/github/github.com/morri-son/ocm-spec/doc/` and `website/content/docs/`.
- It's not stable long-term. Rename these as the project renames things; add a date-of-last-check when you do.

**Last full sweep:** 2026-07-01.
