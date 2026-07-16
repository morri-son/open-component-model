# Slide Texts

## Slide 1: You ship pieces

[IMAGE]
You ship pieces.
The release isn't one of them.
The model that makes it one. The mechanic. The honest edges.
Open Component Model. Open source. NeoNephos Foundation.
[IMAGE]
[IMAGE]

## Slide 2: DIAGNOSIS

DIAGNOSIS
Every tool identifies one artifact. Nothing identifies the release.
▪  OCI image: the digest identifies the image's bytes. Nothing says which release it belongs to.
▪  Helm chart: the version identifies the chart. Nothing says which release the chart is part of.
▪  SBOM and signatures: each covers one artifact. Nothing links them to the release those artifacts form.
You can't sign, ship, or audit what you can't name.

## Slide 3: THE HINGE

THE HINGE
Identity that travels with the release.
▪  Component identity: name and version of the component. Globally unique. Location-agnostic.
▪  Digest: every resource inside the component carries a content hash. Computed once.
▪  Access: where the resource currently lives. Rewritten on transfer. Digest stays.
Move the artifact. The digest stays. Only the access changes.

## Slide 4: WHERE OCM SITS

WHERE OCM SITS
Wraps every artifact. Signs the whole release.
ANY FORMAT
OCI, Helm, configs, SBOMs, npm, maven, binaries.
Artifact type is free-form; access types are pluggable.
ANY LOCATION
Component identity travels.
The component carries its name across registries.
ONE SIGNATURE
Covers every digest in the component.
Survives transport.

## Slide 5: CONSTRUCTOR

CONSTRUCTOR
What you write.
components:
- name: github.com/acme.org/helloworld
  version: 1.0.0
  provider:
    name: acme.org
  resources:
    - name: mylocalfile
      type: blob
      input:                  # Embed by value
        type: File/v1
        path: ./my-local-resource.txt
    - name: image
      type: ociImage
      version: 1.0.0
      access:                 # Reference external artifact
        type: OCIImage/v1
        imageReference: ghcr.io/stefanprodan/podinfo:6.9.1

## Slide 6: DESCRIPTOR

DESCRIPTOR
What gets signed and travels.
component:                                # (fields trimmed)
  name: github.com/acme.org/helloworld
  version: 1.0.0
  resources:
    - name: image
      type: ociImage
      access:                             # excluded. Rewritten on transfer.
        type: OCIImage/v1
        imageReference: ghcr.io/stefanprodan/podinfo@sha256:8fa5691d768ef456...
      digest:                             # content identity. Input to descriptor hash.
        hashAlgorithm: SHA-256
        value: 262578cde928d5c9eba3bce0...
signatures:			                     # signature: one hash over the canonicalized descriptor
  - name: acme-release-key				
    digest:                              # of the descriptor
      hashAlgorithm: SHA-256
      value: a4b1c2d3e4f5...
    signature:
      algorithm: RSASSA-PSS
      value: <hex-encoded signature>

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

## Slide 8: COMPOSE

COMPOSE
Service carries resources. Product carries references.
Service components carry resources: images, charts, configs, SBOMs, ...
A product component composes other components. One release unit, transferable, signable end-to-end.
components:
  - name: acme.org/sovereign/notes
    version: 1.0.0
    resources:
      - name: image       # OCI image
        # type, access, digest trimmed 
      
components:
  - name: acme.org/sovereign/product
    version: 1.0.0
    componentReferences:
      - name: notes
        componentName: acme.org/sovereign/notes
        version: 1.0.0
      - name: postgres
        componentName: acme.org/sovereign/postgres
        version: 1.0.0
# no resources of its own. Pure composition.
SERVICES
PRODUCT
components:
- name: acme.org/sovereign/postgres
    version: 1.0.0
    resources:
      - name: image       # OCI image
        # type, access, digest trimmed      - name: chart       # Helm chart
 		# type, access, digest trimmed

## Slide 9: SIGN

SIGN
One signed object, three ways to prove the key.
RSA
Bare public-key pinning.
If you already rotate a signing key.
OpenPGP
OpenPGP keys, ASCII-armored.
If your team runs a keyring.
SIGSTORE
Keyless via OIDC + Rekor.
If you already trust your identity provider.
CTF = Common Transport Format. A filesystem-based OCM repository, portable via any transfer mechanism.

## Slide 10: TRANSPORT

TRANSPORT
Same command, three shapes.
REGISTRY → REGISTRY
Promote across stages.
Source registry to target registry.
REGISTRY → CTF
Export to a local archive.
Hand-carry across the boundary.
CTF → REGISTRY
Air-gap import.
Verify on arrival. No callback to source.
AIR-GAP

## Slide 11: DEPLOY

DEPLOY
OCM controllers verify and apply.
REPOSITORY
Where component versions live.
COMPONENT
Pulls one version.
Verifies its signature (when a trust anchor is configured).
RESOURCE
One artifact, by digest.
DEPLOYER
Applies it to the cluster.

## Slide 12: DAY 2

DAY 2
Bump the product version and the references follow.
component:
  name: acme.org/sovereign/product
  version: 1.0.0
  componentReferences:
    - name: notes
      componentName: acme.org/sovereign/notes
      version: 1.0.0
      digest:          			# of the referenced component
		hashAlgorithm: SHA-256		value: 7a1b2c3d4e...
    - name: postgres
      componentName: acme.org/sovereign/postgres
      version: 1.0.0
      digest:
		hashAlgorithm: SHA-256
		value: f5e4d3c2b1...signatures:
  - name: acme-release-key
    signature:
      algorithm: RSASSA-PSS
      value: a4b1c2d3e5f6789abc012345def04691...
component:
  name: acme.org/sovereign/product
  version: 1.1.0
  componentReferences:
    - name: notes
      componentName: acme.org/sovereign/notes
      version: 1.1.0
      digest: 				# of the referenced component
        hashAlgorithm: SHA-256
        value: 9b8a7c6d5e...
    - name: postgres
      componentName: acme.org/sovereign/postgres
      version: 1.0.0
      digest:
        hashAlgorithm: SHA-256
        value: f5e4d3c2b1...
signatures:
  - name: acme-release-key
    signature:
      algorithm: RSASSA-PSS
      value: 9c2af18b3e7d52914a8c6b0f1d2e8f37...
bumpversion
Every digest pinned by the signature. The cluster cannot drift.

## Slide 13: ADOPTION

ADOPTION
Two paths to a first OCM component.
FROM ZERO · CLI
Pack one component. Sign it.
Air-gap CTF round-trip.
Verify on the other side.
ON YOUR CLUSTER · CONTROLLERS
Helm-install the OCM controllers.
Point them at your registry.
Deploy a component.

## Slide 14: WHAT'S SHARP

WHAT'S SHARP
Three honest edges.
▪  Transfer defaults: copies only the descriptor. For air-gap, pass --copy-resources so the bytes travel too.
▪  Controllers are v1alpha1: the CRD surface can move. Pin to specific release tags in your platform installs.
▪  Helm-deploy adds kro + Flux or ArgoCD. The OCM controllers don't ship them. Bring your existing GitOps engine.

## Slide 15: ADOPTER PROOF

ADOPTER PROOF
Open ecosystem on the left. SAP teams on the right.
SAP OPEN-SOURCE PROJECTS
[IMAGE]
[IMAGE]
SAP-INTERNAL TEAMS
Hyperspace: internal Dev Portal & product delivery.
RBSC: Release-Based Shipment Channel.
CSI: Common Service Infrastructure.
Steampunk: ABAP Development PaaS.
Sovereign Services & Delivery: sovereign-market operations.

## Slide 16: Ship the release as one unit.

Ship the release as one unit.
Pilot: pack one product this quarter, in your team's pipeline.
Standardize: make OCM the default in your LoB, bottom-up, not mandate.
Steward: Slack #sap-tech-ocm, steering meets every four weeks.
[IMAGE]
[IMAGE]
[IMAGE]

## Slide 17: APPENDIX · REPLICATION

APPENDIX · REPLICATION
Alongside the chain. Not within it.
Controller-shaped equivalent of OCM CLI ocm transfer cv. Point it at a source Component and a target Repository, and it keeps them in sync.

## Slide 18: APPENDIX · ABBREVIATIONS

APPENDIX · ABBREVIATIONS
Quick reference for terms used in this deck.
CSI: Common Service Infrastructure. SAP-internal shared services platform.
Helm: Package manager for Kubernetes. Reference artifact type for OCM.
LoB: Line of Business. SAP organisational unit owning a product portfolio.
NeoNephos: European foundation for sovereign cloud open-source projects (Linux Foundation Europe).
OCI: Open Container Initiative. Open standards for container image format and distribution.
OCM: Open Component Model. Vendor-neutral specification for signed, transportable software components.
OpenPGP: Open standard for cryptographic signatures (RFC 4880). GPG is one implementation; Sequoia and RNP produce compatible signatures.
RBSC: Release-Based Shipment Channel. SAP-internal customer shipment channel.
RSA: RSA / RSASSA-PSS. Bare public-key signing scheme. Trust model: operator pins the public key. No PKI required.
SBOM: Software Bill of Materials. Inventory of components and dependencies inside a software artifact.
Sigstore: Open-source project for keyless software signing using OIDC identities + Rekor transparency log.
SS&D: Sovereign Services & Delivery. SAP organisation operating products in sovereign markets.

