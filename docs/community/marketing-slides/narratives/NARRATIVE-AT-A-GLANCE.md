# OCM Marketing Deck — At a Glance

*Summary of the executive deck. Derived from `NARRATIVE.md`*

---

**Thesis:** Modern software delivery faces two non-negotiables — prove compliance continuously, and operate on your own terms. OCM is the open standard that resolves both at once.

---

**1. Hero** — *Your supply chain has blind spots.*
Three minutes from now, you'll know what they are.

**2. Why now** — *Compliance is rising. Sovereignty makes it harder. Trust must travel with the artifact.*
EU DORA · NIS2 · CRA · supply-chain attacks · sovereign deployment pressure.

**3. Meet OCM — one identity, every boundary** — *The answer.*
Hub-and-spoke: OCM bridges every artifact type, every regulatory regime, every deployment boundary. The "pain" beat from prior versions is now absorbed into slide 2 column 3.

**4. The shift — SBoD** — *SBOM lists. SBoD delivers.*
Software Bill of Delivery: signed, verifiable record of everything you delivered + how to access it. SBOM lives inside it.

**5. How OCM composes** — *OCM doesn't replace your tools. It gives them an envelope to compose around.*
Comparator slide, three axes: **Signing** (keyless or key-based PKI signs one artifact at a time — OCM gives them the complete SBoD to sign). **Transport** (Helm registries, S3, OCI move artifacts — OCM moves a signed envelope across any boundary, including air-gap, signatures travel intact). **Compliance** (Trivy, Grype, SBOM tools scan in isolation — OCM via ODG correlates findings by component identity).

**6. OCM in one picture** — *One model. One flow. Any artifact, any registry, any boundary.*
Pack · Sign · Transport · Deploy. One source of truth for the whole landscape. Bring your own GitOps (Argo, Flux, KRO).

**7. Sovereign-ready** — *Trust, but verify. Anywhere — including behind the air gap.*
Location-independent identity and signatures. Day-2 ops inside the boundary — subscribe and pull, scale across regions, no callback upstream.

**8. Scan — Compliance-native with Open Delivery Gear** — *Compliance as a system property — not a quarterly retrofit.*
ODG + Compliance Dashboard reads SBoD metadata directly. Continuous scans, contextual rescoring, automated reporting.

**9. What OCM unlocks** — *One model unlocks all of this.*
Header strip: *Pack · Scan · Ship · Deploy · Scale Out — one model, end to end.*
Code signing across stacks · air-gapped delivery · Kubernetes-native deployment · async security scans · one source of truth · automated compliance reporting.

**10. Open and governed** — *Trusted in production. Aligned with NeoNephos.*
Enterprises shipping into regulated environments: SAP · BwI · SAP NS2.
Built into the open-source ecosystem: Gardener · Konfidence · Platform Mesh.

**11. Call to action** — *Start delivering with confidence.*
ocm.software · github.com/open-component-model · community channels.

---

**Audience model:** one master narrative, three depths — boardroom cut · mixed-audience cut · Phase 2 technical cut.
**Lead axis:** compliance + sovereignty as one argument, not pick-one.
**Three opener variants for slides 1–2** (sovereignty-led / supply-chain-led / fragmentation-led) — same body, different first-page voice.
