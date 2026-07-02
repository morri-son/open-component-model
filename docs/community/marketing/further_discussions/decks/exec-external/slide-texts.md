# Slide Texts

## Slide 1: Your supply chain has

[IMAGE]
Your supply chain has
blind spots.
Three minutes from now, you'll know what they are.
Open Component Model. Open source. NeoNephos Foundation.
[IMAGE]
[IMAGE]

## Slide 2: THREE BLIND SPOTS

THREE BLIND SPOTS
What today's delivery model can't see.
IDENTITY DRIFT
You signed the artifact at source.
Each transfer changes its reference. Downstream verifies a reference you never signed.
NO RELEASE ENVELOPE
You sign artifacts. You don't sign the release.
Twelve pieces, twelve signatures -  if you're lucky.
UNVERIFIED ARRIVAL
Sovereign zones forbid upstream traffic.
Verification ships with the release - or it doesn't happen.

## Slide 3: WHY NOW

WHY NOW
Sovereignty is no longer optional
SOVEREIGNTY PRESSURE
The law draws boundaries - jurisdiction, sector, air-gap.
Software must be deliverable inside each one.
REGULATION TIGHTENING
EU DORA · NIS2 · CRA. Provable supply-chain control, not best effort.
SUPPLY-CHAIN ATTACKS ARE REAL
SolarWinds. xz. log4shell. Signatures must survive the journey, or compliance is theatre.

## Slide 4: THE ANSWER

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

## Slide 5: THE SHIFT

THE SHIFT
SBOM lists. SBOD delivers.
▪  SBOM: what's inside your software. Built for inventory.
▪  A Software Bill of Delivery (SBOD): what you delivered, how to verify, transport, operate. Built for delivery.
▪  SBOD contains SBOM. OCM doesn't replace your SBOM tooling. OCM gives the SBOM an envelope.


## Slide 6: THE SHIFT - SBOM INSIDE SBOD

THE SHIFT - SBOM INSIDE SBOD
What the envelope holds.
github.com/acme/app:v1.0.0
Location-independent name. Same identity, every registry.
[IMAGE]
[IMAGE]
ARTIFACTS
What you delivered.  How to verify it · how to operate it. 

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

## Slide 7: HOW OCM COMPOSES

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

## Slide 8: OCM IN ONE PICTURE

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
Verify · Unpack · DeployOCM K8s Controllers.
[IMAGE]
SOVEREIGN
CLOUD
Verify at destination.
No callback upstream.

## Slide 9: SOVEREIGN-READY

SOVEREIGN-READY
Trust, but verify.
▪  Identity: location-independent. The component carries its name regardless of registry.
▪  Signatures: location-independent. Sign once at source, verify anywhere downstream. No callback upstream.
▪  Transfer: self-contained. Every artifact travels with the component. 
▪  Day-2 ops: happen inside the boundary. Subscribe, pull upgrades, scale across regions. Still no callback.

## Slide 10: SOVEREIGN-READY - AIR-GAP

SOVEREIGN-READY - AIR-GAP
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

## Slide 11: SCAN

SCAN
Compliance as a system property -
not a quarterly retrofit.
▪  The Compliance Dashboard: every component, every finding, one view. 
▪  Continuous scans: asynchronous, even post-release. 
▪  Contextual rescoring: patch what matters, not the noise. 
▪  Identity-correlated evidence: auditors get answers, not spreadsheets.

## Slide 12: WHAT YOU GET

WHAT YOU GET
Six outcomes. One model.
Artifact signing across stacks
Sign once at source. Verify everywhere, with no per-stack tooling.
Air-gapped delivery
Walk a complete component across an air gap. Verify at destination.
Kubernetes-native deployment
OCM controllers deploy components directly into clusters.
Asynchronous security scans
Continuous scanning, even after release. Findings tied to component identity.
One source of truth
Rebuild any landscape from a single signed descriptor.
Automated compliance reporting
Reports composed from SBOD metadata - no spreadsheet drift.
[IMAGE]
[IMAGE]
[IMAGE]
[IMAGE]
[IMAGE]
[IMAGE]

## Slide 13: TRUSTED IN PRODUCTION

TRUSTED IN PRODUCTION
SAP stewards. NeoNephos governs. Production-grade. Sovereign-ready.
[IMAGE]
[IMAGE]
[IMAGE]
[IMAGE]
[IMAGE]
Kyma
[IMAGE]
OpenControlPlane

## Slide 14: Start delivering with confidence.

Start delivering with confidence.
Try it - ocm.software (QR code)
Build with us - github.com/open-component-model
Talk to us - community channels on the website
[IMAGE]
[IMAGE]
[IMAGE]

## Slide 15: APPENDIX - ABBREVIATIONS

APPENDIX - ABBREVIATIONS
Quick reference for the acronyms used in this deck.
BSI C5  -  Bundesamt für Sicherheit in der Informationstechnik - Cloud Computing Compliance Criteria Catalogue.
BTP  -  SAP Business Technology Platform.
CRA  -  Cyber Resilience Act - EU regulation on cybersecurity for products with digital elements.
DORA  -  Digital Operational Resilience Act - EU regulation on ICT risk management in financial services.
FedRAMP  -  Federal Risk and Authorization Management Program - US standardised cloud security assessment.
FISMA  -  Federal Information Security Modernization Act - US federal information security mandate.
Grype  -  Open-source vulnerability scanner for container images and filesystems (Anchore).
Helm  -  Package manager for Kubernetes; reference artifact type for OCM.
NeoNephos  -  European foundation for sovereign cloud open-source projects, hosted under the Linux Foundation.
NIS2  -  Network and Information Security Directive 2 - EU baseline for cybersecurity of essential entities.
OCI  -  Open Container Initiative - open standards for container image format and distribution.
OCM  -  Open Component Model - vendor-neutral specification for signed, transportable software components.
ODG  -  Open Delivery Gear - OCM-native compliance automation engine and dashboard.
OSS  -  Open Source Software.
PKI  -  Public Key Infrastructure - framework for managing certificates and signing keys.
SBOD  -  Software Bill of Delivery - the OCM component descriptor, signed and traceable. Containing all artifacts and metadata for delivery and deployment.
SBOM  -  Software Bill of Materials - inventory of components and dependencies inside a software artifact.
SecNumCloud  -  French cloud security qualification scheme operated by ANSSI.
Sigstore  -  Open-source project for keyless software signing using OIDC identities.
SPDX  -  Software Package Data Exchange - ISO/IEC 5962 standard format for SBOM data.
SWID  -  Software Identification Tags - ISO/IEC 19770-2 standard for software inventory.
Trivy  -  Open-source security scanner for containers, IaC, and code (Aqua Security).

## Slide 16: TRADEMARK & LICENSE NOTICES (1/2)

TRADEMARK & LICENSE NOTICES (1/2)
Logos and trademarks named for technical reference.
▪  SAP, SAP NS2 - trademarks of SAP SE / SAP National Security Services. Editorial use only; no endorsement implied. sap.com · sapns2.com
▪  BWI - trademark of BWI GmbH (Bundeswehr-IT). Editorial use of the Wikimedia public-domain wordmark; verify against BWI press conditions before external publication. bwi.de
▪  Gardener, Platform Mesh, NeoNephos Foundation - Linux Foundation Europe artwork; usage governed by the Linux Foundation trademark usage guidelines (linuxfoundation.org/legal/trademark-usage). gardener.cloud · platform-mesh.io · neonephos.org
▪  Konfidence - SAP-supported open project; logo from konfidence.cloud. Editorial use only; verify with the Konfidence project before external publication. konfidence.cloud

## Slide 17: TRADEMARK & LICENSE NOTICES (2/2)

TRADEMARK & LICENSE NOTICES (2/2)
Logos and trademarks named for technical reference.
▪  OpenControlPlane - open-source project at open-control-plane.io. Editorial use only; verify with the project before external publication. open-control-plane.io
▪  Kyma - SAP-originated open-source project at kyma-project.io. Editorial use only. kyma-project.io
▪  Hyperspace, RBSC, CSI, Greenhouse, Steampunk - internal SAP delivery infrastructure named for context; not third-party marks.
▪  Trivy, Grype, Sigstore, Helm, OCI, Kubernetes, kro, Flux, Argo CD - third-party trademarks named for technical reference; ownership remains with their respective projects and organisations.


