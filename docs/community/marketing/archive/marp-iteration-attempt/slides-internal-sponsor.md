---
marp: true
theme: ocm-master
paginate: false
---

<!-- Slide 1 — HERO (loss-frame, internal-sponsor) -->
<!-- _class: hero -->

<div class="hero-bg"></div>
<div class="hero-stack">
  <h1>Why OCM matters more now —<br/><span class="gradient-headline">and what we lose by walking away</span></h1>
  <p class="subtitle">Compounding strategic position in the open standard for regulated delivery.</p>
  <p class="org-line">Open Component Model — open source, NeoNephos Foundation. Stewarded by SAP.</p>
</div>
<div class="brand-row">
  <img class="ocm-mark" src="../../../assets/ocm/ocm-horizontal-white.svg" alt="OCM" />
  <img class="nn-mark"  src="../../../assets/neonephos/neonephos-foundation-horizontal-white.svg" alt="NeoNephos Foundation" />
</div>

---

<!-- Slide 2 — WHY NOW (3-column, internal lens) -->
<!-- _class: three-col -->

<p class="eyebrow">Why now — internal</p>
<h1 class="title">Compliance and sovereignty are given. The strategic position is not.</h1>

<div class="columns">
<div>

### Ecosystem velocity is real

kro and ESO are converging on OCM-shaped abstractions. NeoNephos is operationalizing. The peer ecosystem (Gardener, Kyma, Konfidence, OCP, Hyperspace, RBSC, CSI) shares the primitive.

</div>
<div>

### The standardization window is closing

Adjacent ecosystems are moving toward OCM-shaped solutions. Late entrants pay migration cost; early stewards keep optionality.

</div>
<div>

### Disinvestment has a cost

Stewardship migrating elsewhere = SAP loses a position it spent years building. Competitors gain leverage in the same window.

</div>
</div>

<p class="footer">Open Component Model · internal-sponsor cut</p>

---

<!-- Slide 3 — MEET OCM (hub-and-spoke diagram) -->
<!-- _class: diagram -->

<p class="eyebrow">The answer</p>
<h1 class="title">Meet OCM. One identity, every boundary.</h1>

<div class="stage">
  <img src="../diagrams/03-meet-ocm-hub-and-spoke.svg" alt="OCM bridges every artifact type, every regulatory regime, every deployment boundary" />
</div>

<p class="footer">Open Component Model · internal-sponsor cut</p>

---

<!-- Slide 4a — THE SHIFT (text, internal positioning) -->
<!-- _class: compact -->

<p class="eyebrow">The shift</p>
<h1 class="title">SBOM lists. SBoD delivers.</h1>

<ul class="bullets body">
  <li>An SBOM tells you what's in your software. It was built for inventory.</li>
  <li>A Software Bill of Delivery (SBoD) tells you what you delivered, how to verify it, how to transport it, and how to operate it. It was built for delivery.</li>
  <li>The SBoD contains the SBOM. OCM doesn't replace your SBOM tooling — it gives the SBOM an envelope that's compliance-native, signed once, and travels intact across any boundary.</li>
  <li><em>SBoD is the category SAP led the definition of — now standardised through NeoNephos governance.</em></li>
</ul>

<p class="footer">Open Component Model · internal-sponsor cut</p>

---

<!-- Slide 4b — THE SHIFT (diagram) -->
<!-- _class: diagram -->

<p class="eyebrow">The shift — SBOM inside SBoD</p>
<h1 class="title">An envelope, not a list.</h1>

<div class="stage">
  <img src="../diagrams/04-sbom-inside-sbod.svg" alt="SBOM inside SBoD" />
</div>

<p class="footer">Open Component Model · internal-sponsor cut</p>

---

<!-- Slide 5 — HOW OCM COMPOSES (comparator slide, NEW) -->
<!-- _class: three-col -->

<p class="eyebrow">How OCM composes</p>
<h1 class="title">OCM doesn't replace your tools. It gives them something to sign together.</h1>

<div class="columns">
<div>

### Keyless (Sigstore) / key-based (your PKI)

*Only signs one artifact.* OCM gives them the complete SBoD to sign. **One signature, covering every artifact in the delivery, by digest.** Your existing keys still work.

</div>
<div>

### Your SBOM tool or format (Syft, CycloneDX, SPDX)

*Lists what's in your software.* The SBoD contains or references it. Your SBOM tool is unchanged; the SBOM now travels with the signature.

</div>
<div>

### A bit of OCI + Sigstore + your own scripts

*Can almost get you there, in pieces.* OCM is the standardised version, openly governed, with conformance tests and the SBoD vocabulary your auditors are starting to expect.

</div>
</div>

<p class="footer">Open Component Model · internal-sponsor cut</p>

---

<!-- Slide 6 — OCM IN ONE PICTURE (diagram + concession footer) -->
<!-- _class: diagram -->

<p class="eyebrow">OCM in one picture</p>
<h1 class="title">Pack · Sign · Transport · Deploy</h1>

<div class="stage">
  <img src="../diagrams/05-pack-sign-transport-deploy-v2.svg" alt="Pack, sign, transport, deploy" />
</div>

<p class="footer"><em>This deck argues OCM strategically. The transactional case is built per-LoB, with your team.</em></p>

---

<!-- Slide 7a — SOVEREIGN-READY (text) -->
<!-- _class: compact -->

<p class="eyebrow">Sovereign-ready</p>
<h1 class="title">Trust, but verify.</h1>

<ul class="bullets body">
  <li>Identity is location-independent. A component carries its name regardless of which registry it lives in.</li>
  <li>Signatures are location-independent. Sign once at source; verify at the destination, or at any hop in between, with no callback upstream.</li>
  <li>Day-2 ops happen inside the boundary. Subscribe to the component and pull upgrades on your schedule, scale across regions, all without reaching back upstream.</li>
  <li>On transfer into a sovereign environment, a component can carry every artifact it needs along with it. The destination needs nothing more.</li>
</ul>

<p class="footer">Open Component Model · internal-sponsor cut</p>

---

<!-- Slide 7b — SOVEREIGN-READY AIR-GAP (diagram) -->
<!-- _class: diagram -->

<p class="eyebrow">Sovereign-ready — air-gap</p>
<h1 class="title">Trust travels with the component.</h1>

<div class="stage">
  <img src="../diagrams/06-sovereign-airgap.svg" alt="Sovereign air-gap delivery" />
</div>

<p class="footer">Open Component Model · internal-sponsor cut</p>

---

<!-- Slide 8 — SCAN (Compliance-native, internal sub-bullet) -->
<!-- _class: plain -->

<p class="eyebrow">Scan — compliance-native with open delivery gear</p>
<h1 class="title">Compliance as a system property —<br/>not a quarterly retrofit.</h1>

<ul class="bullets body">
  <li>Open Delivery Gear (ODG) is OCM's compliance automation engine.</li>
  <li>The Compliance Dashboard is your entry point: every component, every finding, every signature in one view.</li>
  <li>Continuous scans run asynchronously — even after release.</li>
  <li>Findings get rescored against contextual risk, so your team patches what actually matters.</li>
  <li>Every compliance signal correlates by component identity. Auditors get evidence, not spreadsheets.</li>
  <li><strong>Every SAP LoB gets compliance correlation by component identity, without each LoB building its own retrofit.</strong></li>
</ul>

<p class="footer">Open Component Model · internal-sponsor cut</p>

---

<!-- Slide 9 — WHAT OCM UNLOCKS (tiles, internal-sponsor outcomes) -->
<!-- _class: tiles -->

<p class="eyebrow">What OCM unlocks for SAP</p>
<h1 class="title">Six outcomes from one shared primitive.</h1>

<div class="tile-grid">
  <div class="tile">
    <p class="tile-label">Faster sovereign delivery</p>
    <p class="tile-outcome">Pack a complete component once. From source into a regulated sovereign environment — every operator, every region, every air-gap — without bespoke pipelines per destination.</p>
  </div>
  <div class="tile">
    <p class="tile-label">Compliance leverage across LoBs</p>
    <p class="tile-outcome">Each LoB gets DORA-aligned reporting from one shared primitive — not built N times.</p>
  </div>
  <div class="tile">
    <p class="tile-label">M&amp;A integration efficiency</p>
    <p class="tile-outcome">Acquired teams' signing schemes converge on one mechanism. The retire-list shrinks every quarter.</p>
  </div>
  <div class="tile">
    <p class="tile-label">Cross-LoB security correlation</p>
    <p class="tile-outcome">An incident's blast radius is one query — "which deployments contain library X?" — across every LoB on OCM.</p>
  </div>
  <div class="tile">
    <p class="tile-label">One source of truth</p>
    <p class="tile-outcome">One signed descriptor per delivery. Rebuild any landscape. Audit prep is composition, not archaeology.</p>
  </div>
  <div class="tile">
    <p class="tile-label">Ecosystem stewardship</p>
    <p class="tile-outcome">SAP investment in OCM compounds with the open-peer ecosystem (Gardener, Konfidence, OCP, NeoNephos). Stewardship is leverage, not a cost.</p>
  </div>
</div>

<p class="footer">Open Component Model · internal-sponsor cut</p>

---

<!-- Slide 10a — OPEN-PEER ECOSYSTEM (logo wall) -->
<!-- _class: logos -->

<p class="eyebrow">Where OCM is shipping — open ecosystem</p>
<h1 class="title">Peer in the open ecosystem.</h1>

<p class="section-label" style="top: 510px;">Open peer projects</p>
<p class="proof" style="top: 580px; font-size: 28px;">
  Common Service Infrastructure (CSI) · Gardener · Kyma · Konfidence · Open Control Plane (OCP)
</p>

<p class="proof" style="top: 720px; font-size: 22px;"><em>And forthcoming: every NeoNephos foundation project as it lands.</em></p>

<p class="footer">Open Component Model · internal-sponsor cut</p>

---

<!-- Slide 10b — INTERNAL SAP TRACTION (text) -->
<!-- _class: compact -->

<p class="eyebrow">Where OCM is shipping — internal SAP</p>
<h1 class="title">Backbone of internal SAP delivery.</h1>

<ul class="bullets body">
  <li><strong>Hyperspace</strong> — hosts the internal Dev Portal, lifecycle processes, and the shipment / delivery of SAP products. Direct OCM consumer.</li>
  <li><strong>Release-Based Shipment Channel (RBSC)</strong> — internal SAP delivery infrastructure converging on OCM.</li>
</ul>

<p class="proof" style="top: 880px; font-size: 22px;"><em>Stewardship is leverage. Disinvestment forfeits it. The window for shaping the open standard for regulated delivery is closing — what compounds for SAP today migrates elsewhere if we step back.</em></p>

<p class="footer">Open Component Model · internal-sponsor cut</p>

---

<!-- Slide 11 — CTA (sponsor / scale / standardize) -->
<!-- _class: cta -->

<h1 class="title">Sponsor. Scale. Standardize.</h1>

<ul class="actions">
  <li><span class="action">Sponsor</span> — Allocate engineering capacity to OCM stewardship in your LoB. Name the engineer who owns the OCM relationship.</li>
  <li><span class="action">Scale</span> — Pick one regulated component delivery your LoB ships. Pack it as an OCM component this quarter. We'll help.</li>
  <li><span class="action">Standardize</span> — Bring your LoB's signing / compliance / delivery patterns into the OCM steering conversation. SAP Slack <code>#sap-tech-ocm</code>.</li>
</ul>
