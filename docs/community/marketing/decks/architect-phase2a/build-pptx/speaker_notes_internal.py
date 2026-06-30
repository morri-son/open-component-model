# -*- coding: utf-8 -*-
"""Speaker-notes overrides for the internal-architect deck.

The external deck's speaker_notes.SPEAKER_NOTES dict provides the
technical-spine notes verbatim (slides 2, 3, 5, 6, 7, 8, 9, 10, 11, 12,
14, 17 in the internal numbering). This module overrides ONLY the
audience-shaped slides:

  1   PAIN          — reframed opener for pre-briefed audience
  4   POSITIONING   — drop CNCF Q&A; add SAP-stack equivalents
  13  ADOPTION      — Pack & Ship / Deploy & Operate (SAP-shaped)
  15  ADOPTER PROOF — NEW slide
  16  CTA           — Pilot · Standardize · Steward
  18  GLOSSARY      — NEW appendix

Slide-number keys match the internal deck's final order. Build script
merges these into the external dict at import time so unchanged slides
inherit the external notes verbatim.

Audience assumptions baked in:
  - They know the noun OCM (from Hyperspace mandate, exec sponsor deck,
    SLC-29 framing, or internal product-standards conversations).
  - They have a deployed delivery stack (Hyperspace, RBSC, Sovereign
    Cloud, Open Control Plane in flight). The question is not "what is
    OCM" but "where does this fit my stack."
  - They are pre-briefed on the sovereign-cloud / NIS2 / DORA / CRA
    regulatory frame. Don't re-litigate; reference and move on.
  - They have NOT seen the architect-external deck verbatim. They may
    have seen the exec-internal sponsor deck.
"""

SPEAKER_NOTES_OVERRIDES = {
    1: (
        "Open with the question, not the noun. Internal architects in the first 60 seconds are silently asking: 'what's a release, as one signed unit?' Stating that question on the slide instead of pitching OCM gives both groups in the room the same starting point — the briefed half recognises the question they've been working on; the un-briefed half gets handed the frame they'll need anyway.\n"
        "The subtitle trails the three concrete content beats this hour delivers: the model (descriptor, component identity, composition — slides 2-8), the mechanic (signature, transport, deploy, day-2 ops — slides 9-12), and the honest edges (what's still sharp — slide 14). That's the deck. Don't promise more.\n"
        "Specifically don't promise 'the SAP stack' or 'where it fits in your pipeline.' OCM + ODG + OCP exist; an OCM-based SAP delivery stack does not yet. Saying it would land as overclaim. Slide 13 names two SAP-shaped adoption paths; slide 15 names the teams running OCM. That's the honest scope.\n"
        "One sentence to land: 'For the next 30 minutes we're walking the model behind one signed unit — what it is, how it travels, and what's still sharp.' Then slide 2."
    ),

    4: (
        "OCM does NOT replace OCI, Helm, cosign, sigstore, your SBOM tooling. It WRAPS them — adds one envelope signature over the whole release.\n"
        "• Any format - any artifact you produce becomes a resource. OCI, Helm, configs, SBOMs, npm, maven, binaries.\n"
        "• Any location - identity is location-independent; the same component travels across registries unchanged.\n"
        "• One signature - covers every digest in the component. The whole release is one signed unit.\n"
        "Q&A backup on SAP-stack equivalents (the question this room actually asks): RBSC ships products; OCM describes the product so RBSC can ship it consistently. Hyperspace builds artifacts; OCM is the metadata wrapper added on top — the existing Piper steps stay. Open Delivery Gear (formerly OCM Gear) handles compliance automation on top of OCM components. None of these are replaced. OCM is the shared primitive they all align on.\n"
        "Q&A backup on SBOMs (still relevant): SBOMs go INTO the component as resources. OCM does not generate SBOMs — it carries them, signs them as part of the release, and lets compliance tools query 'every SBOM in every shipped product' via the OCM coordinate system.\n"
        "A component is the unit you sign, transport, and deploy. Hold the noun."
    ),

    13: (
        "Two SAP-shaped paths. The external deck offers 'CLI laptop / Helm controllers' for an audience evaluating OCM from zero. This room is not at zero.\n"
        "PACK & SHIP: OCM CLI v2 produces component descriptors. RBSC integration with the v2 CLI is live — the existing OCM RBSC plugin works against v2. The 30-minute laptop hands-on is the first half of this card; the production shape is wiring it into the team's release pipeline.\n"
        "DEPLOY & OPERATE: Open Delivery Gear runs the compliance automation engine on the OCM coordinate system. Open Control Plane (the open-source successor to Managed Control Plane / MCP) is the declarative deployment runtime — the long-term replacement for Landscaper.\n"
        "Q&A backup on Landscaper sunset (Sovereign Cloud audience will ask): Landscaper deploys type-A services (IAS, Audit Log) today in Sovereign Cloud. The migration to Open Control Plane is planned for end-of-year / early next year. OCM components are the SAME on both sides of the migration — only the runtime changes. That is the whole point of the model.\n"
        "Q&A backup on Hyperspace Piper step (someone will ask if it's not on the slide): Hyperspace integration exists today on OCM v1. The v2 migration is on the 2026 roadmap, not started yet. Internally, Hyperspace already uses OCM for SBOM aggregation. This is why it's on the adopter-proof slide but not as an adoption path — the path is still being built.\n"
        "Q&A backup on the renames: OCM Gear → Open Delivery Gear (ODG), now inside the OCM GitHub org. Managed Control Plane → Open Control Plane, also open source. We hardened the naming when we hardened the projects."
    ),

    15: (
        "Adopter proof, two columns. The exec-internal deck splits this across two slides; we combine into one for the architect-track audience.\n"
        "LEFT — four SAP-internal projects that are also open source: Gardener (managed Kubernetes), Kyma (cloud-native runtime), Open Control Plane (control-plane framework, open-source successor to MCP / Managed Control Plane), Konfidence (reproducible delivery). Gardener and Konfidence are recognised by their wordmark logos; Kyma and OpenControlPlane carry a name label below the icon. All aligned with the NeoNephos Foundation.\n"
        "RIGHT — five SAP-internal teams running on OCM: Hyperspace, RBSC, CSI, Steampunk, Sovereign Services & Delivery. These are SAP-only; no public logos.\n"
        "Hyperspace caveat (audience WILL ask): Hyperspace integration today runs on OCM v1. The v2 migration is on the 2026 roadmap. Internally, Hyperspace ALREADY uses OCM for SBOM aggregation — that is in production. The Piper-step v2 integration is the in-flight piece.\n"
        "Sovereign Services & Delivery operates SAP products in sovereign markets — the Sovereign Cloud delivery use case is the cleanest current OCM end-to-end story (pack, sign, ship via Landscaper today, will move to Open Control Plane).\n"
        "Q&A backup on conspicuous absences: ACD, Hana Cloud / SGSC traceability — these were in the 2024 plan but have not made the same progress. We don't claim them as adopters; we claim them as 'considering / in conversation.' Better to under-claim than over-claim."
    ),

    16: (
        "Pilot. Standardize. Steward. Three verbs, three concrete next-quarter actions for an architect in this room.\n"
        "PILOT: Pack one product as an OCM component, in your team, this quarter. Not a laptop demo — a real product, in your existing pipeline. RBSC is the cleanest first wire-up if you ship via RBSC today.\n"
        "STANDARDIZE: Make OCM the default for component delivery IN YOUR LoB. This is the key reframe: we are NOT mandating OCM via SLC-29 or via a top-down product standard. The 2024 plan named that path; the 2026 strategy is different. We invest in the CLI quality so that OCM becomes the standard because it's the best tool for the job — bottom-up. The Elton Mathias support from Product Standards Lifecycle is still on the table for future inclusion, but it's not the lever we're pulling first.\n"
        "STEWARD: Bring your LoB into the OCM steering conversation. Slack #sap-tech-ocm. We meet every two weeks; cross-LoB design decisions land there. If your LoB has a stake in component-delivery architecture, you should be in the room.\n"
        "Final stop-sentence rhythm: 'One primitive. Your stack. Your call.' Then pause. Don't trail into the appendix."
    ),

    18: (
        "Appendix only. Pull on demand if the audience stalls on a term. Don't narrate.\n"
        "Scope discipline: every entry on this slide also appears in the slide text of an earlier slide. If someone asks about a term that's NOT on this glossary (ODG, OCP, SBOD, NIS2, CRA, DORA, SLC-29, SPDX, SWID, SecNumCloud, TG, …), it lives in the speaker notes — answer from there.\n"
        "Spot-checks worth knowing: OCM = Open Component Model (the spec). RBSC = Release-Based Shipment Channel. CSI = Common Service Infrastructure. SS&D = Sovereign Services & Delivery. NeoNephos = the foundation, hosted under Linux Foundation Europe."
    ),
}
