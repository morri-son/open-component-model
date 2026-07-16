# Slide Texts

## Slide 1: Every LoB ships

[IMAGE]
Every LoB ships
Separately, every time.
OCM is the shared standard. Each LoB still ships. On the same model.
Open Component Model. Open source. NeoNephos Foundation. Stewarded by SAP.
[IMAGE]
[IMAGE]

## Slide 2: WHY NOW

WHY NOW
Compliance and sovereignty are given.
Our strategic position is a choice.
ECOSYSTEM VELOCITY
The peer ecosystem is converging.
The biggest contributor shapes the standard.

THE WINDOW
The rails are being laid now.
Late entrants pay migration cost.
DISINVESTMENT COST
Walking away costs more than staying.
The standard gets shaped without us.

## Slide 3: THE ANSWER

THE ANSWER
Meet OCM. One identity, every boundary.
EVERY ARTIFACT TYPE
OCI
Helm
npm
Binary
Config
EVERY DEPLOYMENT BOUNDARY
EU
US
Sovereign
Cloud
EVERY COMPLIANCE FRAMEWORK
DORA
NIS2
CRA
v1.0.0

## Slide 4: THE SHIFT

THE SHIFT
SBOM lists. SBOD delivers.
▪  SBOM: What's inside your software. Built for inventory.
▪  A Software Bill of Delivery (SBOD): what you delivered, how to verify, transport, operate. Built for delivery.
▪  SBOD contains SBOM. OCM doesn't replace your SBOM tooling. OCM gives the SBOM an envelope.
▪  SBOD is the category SAP defined. Now governed through NeoNephos.

## Slide 5: THE SHIFT · SBOM INSIDE SBOD

THE SHIFT · SBOM INSIDE SBOD
What the envelope holds.
github.com/acme/webshop:v1.0.0
Location-independent name. Same identity, every registry.
[IMAGE]
[IMAGE]
ARTIFACTS
What you delivered.  How to verify it · how to operate it. 

[IMAGE]
Docker Images
[IMAGE]
Helm Charts
[IMAGE]
Kubernetes Deployment Manifests
[IMAGE]
Configuration Files
[IMAGE]
SIGNATURE
One digest covers all.
SOFTWARE BILL OF DELIVERY (SBOD)
[IMAGE]
SBOM
[IMAGE]

## Slide 6: HOW OCM COMPOSES

HOW OCM COMPOSES
Composes around your existing stack.
SIGNING
You sign artifacts.
OCM signs the release.
TRANSPORT
 Your registries differ.
OCM moves the release across them.
COMPLIANCE
Your scanners see one artifact at a time.
OCM correlates findings to the release.

## Slide 7: OCM IN ONE PICTURE

OCM IN ONE PICTURE 
Pack · Sign · Transport · Deploy
[IMAGE]
PACK
Bundle your software.
One source of truth.
[IMAGE]
SIGN
One signature covers
all artifacts.
[IMAGE]
TRANSPORT
Across any boundary.
Even air-gapped.
[IMAGE]
DEPLOY
Verify · Unpack · DeployOCM K8s Controllers.
[IMAGE]
SOVEREIGN
CLOUD
Verify at destination.
No callback upstream.

## Slide 8: SOVEREIGN-READY

SOVEREIGN-READY
The component is the trust boundary.
▪  Identity: location-independent. The component carries its name regardless of registry.
▪  Signatures: location-independent. Sign once at source, verify anywhere downstream. No callback upstream.
▪  Transfer: self-contained. Every artifact travels with the component. 
▪  Day-2 ops: happen inside the boundary. Subscribe, pull upgrades, scale across regions. Still no callback.

## Slide 9: SOVEREIGN-READY · AIR-GAP

SOVEREIGN-READY · AIR-GAP
Trust travels with the component.
SOURCE
Pack · Sign
[IMAGE]
Public registry
TRUST BOUNDARY
SOVEREIGN TARGET
Verify · Deploy
AIR-GAPPED ENVIRONMENT
[IMAGE]
Local registry
[IMAGE]
K8s cluster
[IMAGE]
Auditor
Verify locally. Day-2 ops included.
Transport

## Slide 10: SCAN

SCAN
Continuous compliance. Not quarterly audits.
▪  Open Delivery Gear (ODG): the OCM compliance automation engine, built on the same primitives. 
▪  The Compliance Dashboard: every component, every finding, one view. 
▪  Continuous scans: asynchronous, even post-release. 
▪  Contextual rescoring: patch what matters, not the noise. 
▪  Identity-correlated evidence: auditors get answers, not spreadsheets.

## Slide 11: WHAT SAP GETS

WHAT SAP GETS
Six outcomes from one shared primitive.
Faster sovereign delivery
Pack once, ship everywhere.
Sovereign Cloud for all products.
Compliance leverage across LoBs
Report from one shared primitive.
ODG correlates all findings.
Integration after acquisition
Acquired companies converge onto one model.
Cross-LoB security correlation
Blast radius is one query.
Answered via the OCM coordinate system.
One source of truth
One signed descriptor per delivery.
Rebuild any landscape.
Ecosystem stewardship
SAP investment compounds with
the open-peer ecosystem.
[IMAGE]
[IMAGE]
[IMAGE]
[IMAGE]
[IMAGE]
[IMAGE]

## Slide 12: WHERE OCM IS SHIPPING · OPEN ECOSYSTEM

WHERE OCM IS SHIPPING · OPEN ECOSYSTEM
Peer in the open ecosystem.
[IMAGE]
[IMAGE]
Kyma
[IMAGE]
OpenControlPlane
[IMAGE]

## Slide 13: STRATEGIC POSITION

STRATEGIC POSITION
OCM is one piece of the EU sovereign cloud stack.
▪  ApeiroRA: EU-funded reference architecture for the sovereign cloud-edge continuum. 17 open-source projects across three layers.
▪  OCM sits in the Cloud OS layer. Alongside Gardener, Konfidence, OpenControlPlane, Platform Mesh, all names from the previous slide.
▪  Funded through NextGenerationEU and BMWK under IPCEI-CIS. Housed in NeoNephos (Linux Foundation Europe) for long-term neutrality.
▪  SAP is the lead partner. The steering position is funded and governed.
[IMAGE]
is part of
[IMAGE]

## Slide 14: WHERE OCM IS SHIPPING · SAP

WHERE OCM IS SHIPPING · SAP
Five SAP teams. Already running on OCM.
▪  Hyperspace: internal Dev Portal & product delivery.
▪  Release-Based Shipment Channel (RBSC): customer shipment channel.
▪  Common Service Infrastructure (CSI): shared internal services platform.
▪  Steampunk: ABAP Development PaaS.
▪  Sovereign Services & Delivery: operates SAP products in sovereign clouds.

## Slide 15: Sponsor. Scale. Standardize.

Sponsor. Scale. Standardize.
Sponsor: Allocate engineering capacity to OCM stewardship in your LoB.
Scale: Pack one regulated component as an OCM component this quarter.
Standardize: Bring your LoB into the OCM steering conversation. SAP Slack #sap-tech-ocm.
[IMAGE]
[IMAGE]
[IMAGE]

## Slide 16: APPENDIX · ABBREVIATIONS

APPENDIX · ABBREVIATIONS
Quick reference for the acronyms used in this deck.
BSI C5: Bundesamt für Sicherheit in der Informationstechnik. Cloud Computing Compliance Criteria Catalogue.
BTP: SAP Business Technology Platform.
CRA: Cyber Resilience Act. EU regulation on cybersecurity for products with digital elements.
DORA: Digital Operational Resilience Act. EU regulation on ICT risk management in financial services.
FedRAMP: Federal Risk and Authorization Management Program. US standardised cloud security assessment.
FISMA: Federal Information Security Modernization Act. US federal information security mandate.
Grype: Open-source vulnerability scanner for container images and filesystems (Anchore).
Helm: Package manager for Kubernetes. Reference artifact type for OCM.
LoB: Line of Business. SAP organisational unit owning a product portfolio.
NeoNephos: European foundation for sovereign cloud open-source projects, hosted under the Linux Foundation.
NIS2: Network and Information Security Directive 2. EU baseline for cybersecurity of essential entities.
OCI: Open Container Initiative. Open standards for container image format and distribution.
OCM: Open Component Model. Vendor-neutral specification for signed, transportable software components.
ODG: Open Delivery Gear. OCM-native compliance automation engine and dashboard.
OSS: Open Source Software.
PKI: Public Key Infrastructure. Framework for managing certificates and signing keys.
SBOD: Software Bill of Delivery. The OCM component descriptor, signed and traceable. Contains all artifacts and metadata for delivery and deployment.
SBOM: Software Bill of Materials. Inventory of components and dependencies inside a software artifact.
SecNumCloud: French cloud security qualification scheme operated by ANSSI.
Sigstore: Open-source project for keyless software signing using OIDC identities.
SPDX: Software Package Data Exchange. ISO/IEC 5962 standard format for SBOM data.
SWID: Software Identification Tags. ISO/IEC 19770-2 standard for software inventory.
Trivy: Open-source security scanner for containers, IaC, and code (Aqua Security).

## Slide 17: TRADEMARK & LICENSE NOTICES (1/2)

TRADEMARK & LICENSE NOTICES (1/2)
Logos and trademarks named for technical reference.
▪  SAP, SAP NS2: trademarks of SAP SE / SAP National Security Services. Editorial use only; no endorsement implied. sap.com · sapns2.com
▪  BWI: trademark of BWI GmbH (Bundeswehr-IT). Editorial use of the Wikimedia public-domain wordmark; verify against BWI press conditions before external publication. bwi.de
▪  Gardener, Platform Mesh, NeoNephos Foundation: Linux Foundation Europe artwork; usage governed by the Linux Foundation trademark usage guidelines (linuxfoundation.org/legal/trademark-usage). gardener.cloud · platform-mesh.io · neonephos.org
▪  Konfidence: SAP-supported open project; logo from konfidence.cloud. Editorial use only; verify with the Konfidence project before external publication. konfidence.cloud

## Slide 18: TRADEMARK & LICENSE NOTICES (2/2)

TRADEMARK & LICENSE NOTICES (2/2)
Logos and trademarks named for technical reference.
▪  OpenControlPlane: open-source project at open-control-plane.io. Editorial use only; verify with the project before external publication. open-control-plane.io
▪  Kyma: SAP-originated open-source project at kyma-project.io. Editorial use only. kyma-project.io
▪  Hyperspace, RBSC, CSI, Greenhouse, Steampunk: internal SAP delivery infrastructure named for context. Not third-party marks.
▪  Trivy, Grype, Sigstore, Helm, OCI, Kubernetes, kro, Flux, Argo CD: third-party trademarks named for technical reference. Ownership remains with their respective projects and organisations.

