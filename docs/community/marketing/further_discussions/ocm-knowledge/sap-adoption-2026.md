# SAP OCM Adoption: 2026 Reality

**Freshness date:** 2026-07-01. This document was recalibrated from the 2024 adoption plan (`~/dies-und-das/OCM/OCM-Adoption Plan.pdf`, June 2024) after 2 years of drift. Where the 2024 plan is stale, that is called out inline.

**Purpose.** Every deck session works from THIS document for SAP-adoption realities, not from the 2024 plan directly. The 2024 plan is a historical reference; the 2026 reality below is the operational truth.

---

## Strategy shift: 2024 → 2026

The 2024 adoption plan had **three pillars for success**:

1. Introduce an ecosystem for OCM to support its value proposition
2. Convince & support stakeholders with OCM adoption
3. Introduce OCM to (mandatory) product standards

**Pillar 3 (mandatory standardization) has been intentionally deprioritized in 2026.** The current strategy is:

> *Invest in OCM CLI quality until adoption becomes organic, not mandated top-down.*

Concretely:
- TG (Technical Guideline) product standard: **withdrawn**.
- SLC-29 inclusion: **stuck**, not actively pursued.
- The Elton Mathias / Product Standards Lifecycle support (2024 quote about "OCM mandatory... under SAP Innovation Cycle") is **still valid in principle** but the timing has shifted. First we make the CLI good; then we consider standardization.

**Deck implication:** never claim OCM is mandated at SAP. Frame standardization as bottom-up team standard, not top-down policy. The internal-architect deck CTA `Pilot · Standardize · Steward` uses "Standardize" in this bottom-up sense.

## Adopters: SAP-internal teams (2026-current)

Per the internal-architect deck's adopter slide + the exec-internal deck's adopter slide:

**Five SAP-internal teams running on OCM today (or on-roadmap):**

| Team | 2024 plan | 2026 reality |
|---|---|---|
| **Hyperspace** | Piper step (first version ready, planned general-purpose) | v1 integration in production. **v2 migration on 2026 roadmap, not started.** Internally Hyperspace uses OCM v1 for **SBOM aggregation** (production). |
| **RBSC** | Plugin for OCM CLI existed | v2 CLI plugin **works today**. Products described in OCM, shipped via RBSC. |
| **CSI (Common Service Infrastructure)** | "considering" | Confirmed adopter. |
| **Steampunk** | Not mentioned | ABAP Development PaaS. Adopter. |
| **Sovereign Services & Delivery (SS&D)** | Not by that name in 2024 | Operates SAP products in sovereign markets. Replaced Greenhouse in the exec-internal deck. |

**Removed from adopter lists (do not claim as current):**
- **ACD (Dirk Bössmann's team)**, Dirk gone. Priority removed.
- **SGSC E2E traceability**, "not much progress" in 2026.
- **Hana Cloud, IAS, Destination Service**, 2024 plan called them "considering." 2026 status: unclear / not verified. Do NOT claim as adopters until verified.
- **Greenhouse**, cloud ops platform, still exists at SAP but removed from the internal adopter list in favour of SS&D.

## Adoption shapes (Pack&Ship / Deploy&Operate): 2026 architecture

The internal-architect deck's Slide 13 uses two cards. The 2024 plan's four adoption shapes were remapped:

**PACK & SHIP** (mapping 2024 pillars 1a + 1c):
- OCM CLI v2 produces component descriptors
- RBSC integration ships them via the customer channel
- Air-gap-safe by construction (transport signed, no callbacks)

**DEPLOY & OPERATE** (mapping 2024 pillars 1b + Sovereign Cloud):
- Open Delivery Gear (ODG), OCM compliance-automation engine
- Open Control Plane (OCP), declarative deployment runtime (open source, replaces Landscaper end-2026 / early-2027)
- Sovereign-cloud-ready
- Day-2 ops on the same primitive

**Not a card:** Hyperspace Piper step, because it's v1 today, migration not started. Named as a footnote / adopter but not as an adoption *path*.

## Renames since 2024 (must-remember)

| 2024 name | 2026 name | Location |
|---|---|---|
| OCM Gear | **Open Delivery Gear (ODG)** | OCM GitHub org |
| Managed Control Plane / MCP | **Open Control Plane (OCP)** | Open source |
|, (implicit "MCP") | **Landscaper** (being sunset) | Sovereign Cloud today; replaced by OCP end-2026 |

## The "OCM-based SAP delivery stack" question

**Reality:** There is NO integrated OCM-based SAP delivery stack today. OCM + ODG + OCP exist as components. An integrated stack is a **vision**, not a deployment.

**Deck implication:** Never claim "the SAP stack" as if it exists. If it belongs anywhere on a deck, it's an **outlook** slide showing the vision, and even then labeled as such. Do not put "The SAP stack." as a subtitle promising something the deck doesn't deliver. (This is why the internal-architect deck's Slide 1 subtitle went through three drafts.)

## Peer ecosystem (SAP OSS projects that align with OCM)

- **Gardener**, managed Kubernetes (SAP-origin, CNCF)
- **Kyma**, cloud-native runtime (SAP-origin)
- **Open Control Plane**, control-plane framework (SAP-origin)
- **Konfidence**, reproducible-delivery tooling

All aligned with the **NeoNephos Foundation** (European sovereign-cloud open-source foundation, hosted by Linux Foundation Europe).

## Adoption CTA verbs by audience

- **Architect external:** Evaluate · Pilot · Engage
- **Architect internal:** Pilot · Standardize · Steward (bottom-up standardization, not SLC-29)
- **Exec external:** (see external exec deck)
- **Exec internal:** Sponsor · Scale · Standardize (top-down engineering-capacity language)

## Freshness: how to keep this document accurate

The 2024 plan is 2 years out of date on several claims. This document is a snapshot as of 2026-07-01.

**Refresh triggers (update this doc if any is true):**
- A SAP team is added or removed from the adopter list
- A rename happens (Open Delivery Gear was itself a rename in early 2026)
- SLC-29 or TG standardization status changes (re-added, formally shelved, etc.)
- Landscaper sunset timing shifts
- Hyperspace v2 migration starts
- A new OSS project joins the NeoNephos alignment list

When you update, bump the freshness date at the top and note the change here.

---

**Update log:**
- 2026-07-01, Initial calibration from 2024 plan + this session's user input.
