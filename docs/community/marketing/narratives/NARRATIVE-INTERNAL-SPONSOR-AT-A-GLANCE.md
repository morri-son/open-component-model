# OCM Marketing Deck — Internal-Sponsor At a Glance

*Summary of the internal-sponsor executive deck. Derived from `NARRATIVE-INTERNAL-SPONSOR.md`.*

---

**Audience:** SAP LoB heads (primary) + chief architects (secondary, objections handled inline).

**Thesis:** OCM is SAP's leverage point in the open-source supply-chain ecosystem — and the standardization window is closing. Compounding the leverage costs less than retrofitting it later.

---

**1. Hero** — *Why OCM matters more now —*
*and what we lose by walking away.*
Compounding strategic position in the open standard for regulated delivery. Stewarded by SAP.

**2. Why now — internal** — *Compliance and sovereignty are given. The strategic position is not.*
Three columns: **Ecosystem velocity** (OCM-shaped abstractions are landing in adjacent OSS projects; the peer ecosystem already shares the primitive) · **The window is closing** (NeoNephos governance, CRA enforcement, sovereign-cloud market formation — the rails are being laid now; late entrants pay migration cost) · **Disinvestment has a cost** (each LoB that builds its own retrofit pays the cost OCM was supposed to amortize; competitors who keep investing get the standard built around their preferences).

**3. Meet OCM — one identity, every boundary** — *The answer.*
Hub-and-spoke: OCM bridges every artifact type, every regulatory regime (DORA · NIS2 · CRA), every deployment boundary (EU · US · Sovereign Cloud). Footer: plus FedRAMP/FISMA, BSI C5, SecNumCloud — and the regimes specific to your sector.

**4. The shift — SBoD** — *SBOM lists. SBoD delivers.*
Software Bill of Delivery: signed, verifiable record of everything you delivered + how to access it. SBOM lives inside it. *Internal-sponsor footer: SBoD is the category SAP led the definition of — now standardised through NeoNephos governance.*

**5. How OCM composes** — *OCM doesn't replace your tools. It gives them an envelope to compose around.*
Comparator slide, three axes: **Signing** (keyless or key-based PKI signs one artifact at a time — OCM gives them the complete SBoD to sign). **Transport** (Helm registries, S3, OCI move artifacts — OCM moves a signed envelope across any boundary, including air-gap, signatures travel intact). **Compliance** (Trivy, Grype, SBOM tools scan in isolation — OCM via ODG correlates findings by component identity).

**6. OCM in one picture** — *Pack · Sign · Transport · Deploy.*
One source of truth for the whole landscape. Bring your own GitOps. *Internal-sponsor concession line in the footer: This deck argues OCM strategically — the transactional case is built per-LoB, with your team.*

**7. Sovereign-ready** — *Trust, but verify. Anywhere — including behind the air gap.*
Location-independent identity and signatures. Day-2 ops inside the boundary. Proof: validated end-to-end in OCM's open-source sovereign conformance scenario, plus production deployments in BwI / SAP NS2.

**8. Scan — Compliance-native with Open Delivery Gear** — *Compliance as a system property — not a quarterly retrofit.*
ODG + Compliance Dashboard reads SBoD metadata directly. Continuous scans, contextual rescoring, automated reporting. *Internal-sponsor sub-bullet: every SAP LoB gets compliance correlation by component identity, without each LoB building its own retrofit.*

**9. What OCM unlocks for SAP** — *Six outcomes from one shared primitive.*
Faster sovereign delivery · compliance leverage across LoBs · integration after acquisition · cross-LoB security correlation (which deployments contain OCM component X?) · one source of truth · ecosystem stewardship.

**10a. Where OCM is shipping — open ecosystem** — *Peer in the open ecosystem.*
Open peer projects: Gardener · Kyma · Konfidence (development and delivery framework) · Open Control Plane (a platform for managing Kubernetes-based ControlPlanes). Forthcoming: every NeoNephos foundation project.

**10b. Where OCM is shipping — internal SAP** — *Backbone of internal SAP delivery.*
Internal SAP projects converging on OCM: **Hyperspace** (internal Dev Portal, lifecycle, shipment/delivery) · **RBSC** (Release-Based Shipment Channel) · **CSI** (Common Service Infrastructure — largest internal-services footprint) · **Greenhouse** (cloud operations platform for large-scale distributed infrastructure) · **Steampunk** (internal name for SAP BTP ABAP Environment, large user of OCM and ODG).
*Italic centred manifesto:* Stewardship is leverage. Disinvestment forfeits it. The window for shaping the open standard for regulated delivery is closing — what compounds for SAP today migrates elsewhere if we step back.

**11. Call to action** — *Sponsor. Scale. Standardize.*
**Sponsor** — allocate engineering capacity to OCM stewardship in your LoB. **Scale** — pack one regulated component delivery as an OCM component this quarter. **Standardize** — bring your LoB's signing/compliance/delivery patterns into the OCM steering conversation. Channel: SAP Slack `#sap-tech-ocm`.

---

**14-slide deck:** 1, 2, 3, 4a, 4b, 5, 6, 7a, 7b, 8, 9, 10a, 10b, 11.
**Lead axis:** strategic-fit + ecosystem-leverage, framed as loss (what we lose by walking away).
**Out of scope:** SAP board / CTO office — they have context already, or politics don't run through this deck.
**No real numbers in this deck:** the user cannot deliver per-LoB ROI numbers; the deck argues strategy, not transactions.
