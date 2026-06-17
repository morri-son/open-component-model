---
marp: true
theme: ocm-master
paginate: false
---

<!-- Slide 1 — HERO -->
<!-- _class: hero -->

<div class="hero-bg"></div>
<div class="hero-stack">
  <h1>Secure Delivery for<br/><span class="gradient-headline">Sovereign Clouds</span></h1>
  <p class="subtitle">Deliver and deploy your software securely. Anywhere, at any scale.</p>
  <p class="org-line">Open Component Model — open source, NeoNephos Foundation.</p>
</div>
<div class="brand-row">
  <img class="ocm-mark" src="../../../assets/ocm/ocm-horizontal-white.svg" alt="OCM" />
  <img class="nn-mark"  src="../../../assets/neonephos/neonephos-foundation-horizontal-white.svg" alt="NeoNephos Foundation" />
</div>

---

<!-- Slide 2 — WHY NOW (3-column) -->
<!-- _class: three-col -->

<p class="eyebrow">Why now</p>
<h1 class="title">Sovereignty is no longer optional</h1>

<div class="columns">
<div>

### Sovereignty pressure

Wherever the law puts the boundary — by jurisdiction, sector, or air-gap — software must be deliverable, verifiable, and operable inside it.

</div>
<div>

### Regulation tightening

EU DORA · NIS2 · GDPR. Provable supply-chain control, not best effort.

</div>
<div>

### Supply-chain attacks are real

SolarWinds. xz. log4shell. Signatures must survive the journey, or compliance is theatre.

</div>
</div>

<p class="footer">Open Component Model · ocm.software</p>

---

<!-- Slide 3 — THE PAIN (diagram) -->
<!-- _class: diagram -->

<p class="eyebrow">The pain</p>
<h1 class="title">Software delivery is fragmented.<br/>Trust breaks at every boundary.</h1>

<div class="stage">
  <img src="../diagrams/03-fragmented.svg" alt="Fragmented delivery" />
</div>

<p class="footer">Open Component Model · ocm.software</p>

---

<!-- Slide 4a — THE SHIFT (text) -->
<!-- _class: compact -->

<p class="eyebrow">The shift</p>
<h1 class="title">SBOM lists. SBoD delivers.</h1>

<ul class="bullets body">
  <li>An SBOM tells you what's in your software. It was built for inventory.</li>
  <li>A Software Bill of Delivery (SBoD) tells you what you delivered, how to verify it, how to transport it, and how to operate it. It was built for delivery.</li>
  <li>The SBoD contains the SBOM. OCM doesn't replace your SBOM tooling — it gives the SBOM an envelope that's compliance-native, signed once, and travels intact across any boundary.</li>
</ul>

<p class="footer">Open Component Model · ocm.software</p>

---

<!-- Slide 4b — THE SHIFT (diagram) -->
<!-- _class: diagram -->

<p class="eyebrow">The shift — SBOM inside SBoD</p>
<h1 class="title">An envelope, not a list.</h1>

<div class="stage">
  <img src="../diagrams/04-sbom-inside-sbod.svg" alt="SBOM inside SBoD" />
</div>

<p class="footer">Open Component Model · ocm.software</p>

---

<!-- Slide 5 — OCM IN ONE PICTURE (diagram) -->
<!-- _class: diagram -->

<p class="eyebrow">OCM in one picture</p>
<h1 class="title">Pack · Sign · Transport · Deploy</h1>

<div class="stage">
  <img src="../diagrams/05-pack-sign-transport-deploy-v2.svg" alt="Pack, sign, transport, deploy" />
</div>

<p class="footer">Open Component Model · ocm.software</p>

---

<!-- Slide 6a — SOVEREIGN-READY (text) -->
<!-- _class: compact -->

<p class="eyebrow">Sovereign-ready</p>
<h1 class="title">Trust, but verify.</h1>

<ul class="bullets body">
  <li>Identity is location-independent. A component carries its name regardless of which registry it lives in.</li>
  <li>Signatures are location-independent. Sign once at source; verify at the destination, or at any hop in between, with no callback upstream.</li>
  <li>Day-2 ops happen inside the boundary. Subscribe to the component and pull upgrades on your schedule, scale across regions, all without reaching back upstream.</li>
  <li>On transfer into a sovereign environment, a component can carry every artifact it needs along with it. The destination needs nothing more.</li>
</ul>

<p class="footer">Open Component Model · ocm.software</p>

---

<!-- Slide 6b — SOVEREIGN-READY AIR-GAP (diagram) -->
<!-- _class: diagram -->

<p class="eyebrow">Sovereign-ready — air-gap</p>
<h1 class="title">Trust travels with the component.</h1>

<div class="stage">
  <img src="../diagrams/06-sovereign-airgap.svg" alt="Sovereign air-gap delivery" />
</div>

<p class="footer">Open Component Model · ocm.software</p>

---

<!-- Slide 7 — SCAN (Compliance-native) -->
<!-- _class: plain -->

<p class="eyebrow">Scan — compliance-native with open delivery gear</p>
<h1 class="title">Compliance as a system property —<br/>not a quarterly project.</h1>

<ul class="bullets body">
  <li>Open Delivery Gear (ODG) is OCM's compliance automation engine.</li>
  <li>The Compliance Dashboard is your entry point: every component, every finding, every signature in one view.</li>
  <li>Continuous scans run asynchronously — even after release.</li>
  <li>Findings get rescored against contextual risk, so your team patches what actually matters.</li>
  <li>Every compliance signal correlates by component identity. Auditors get evidence, not spreadsheets.</li>
</ul>

<p class="footer">Open Component Model · ocm.software</p>

---

<!-- Slide 8 — WHAT OCM UNLOCKS (tiles) -->
<!-- _class: tiles -->

<p class="eyebrow">What OCM unlocks</p>
<h1 class="title">One model unlocks all of this.</h1>

<div class="tile-grid">
  <div class="tile">
    <p class="tile-label">Code signing across stacks</p>
    <p class="tile-outcome">Sign once at source; verify everywhere, with no per-stack tooling.</p>
  </div>
  <div class="tile">
    <p class="tile-label">Air-gapped delivery</p>
    <p class="tile-outcome">Walk a complete component across an air gap; verify at destination.</p>
  </div>
  <div class="tile">
    <p class="tile-label">Kubernetes-native deployment</p>
    <p class="tile-outcome">OCM controllers deploy components directly into clusters.</p>
  </div>
  <div class="tile">
    <p class="tile-label">Asynchronous security scans</p>
    <p class="tile-outcome">Continuous scanning, even after release; findings tied to component identity.</p>
  </div>
  <div class="tile">
    <p class="tile-label">One source of truth</p>
    <p class="tile-outcome">Rebuild any landscape from a single signed descriptor.</p>
  </div>
  <div class="tile">
    <p class="tile-label">Automated compliance reporting</p>
    <p class="tile-outcome">Reports composed from SBoD metadata — no spreadsheet drift.</p>
  </div>
</div>

<p class="footer">Open Component Model · ocm.software</p>

---

<!-- Slide 9 — TRUSTED IN PRODUCTION (logo wall) -->
<!-- _class: logos -->

<p class="eyebrow">Trusted in production</p>
<h1 class="title">Aligned with NeoNephos.</h1>

<p class="section-label" style="top: 510px;">Adopted by enterprises shipping into regulated environments</p>
<div class="logo-row" style="top: 560px;">
  <img src="../../../assets/adopters/sap/sap-horizontal-color.svg" alt="SAP" />
  <img src="../../../assets/adopters/bwi/bwi-horizontal-color.svg" alt="BWI" />
  <img src="../../../assets/adopters/sap-ns2/sap-ns2-getlogovector.png" alt="SAP NS2" />
</div>

<p class="section-label" style="top: 740px;">Built into the open-source ecosystem</p>
<div class="logo-row" style="top: 790px;">
  <img src="../../../assets/adopters/gardener/gardener-horizontal-color.svg" alt="Gardener" />
  <img src="../../../assets/adopters/konfidence/konfidence-horizontal-light.svg" alt="Konfidence" />
  <img src="../../../assets/adopters/platform-mesh/platform-mesh-horizontal-color.svg" alt="Platform Mesh" />
</div>

<p class="proof">An open standard, neutrally governed — your stack stays portable, your dependencies stay yours.</p>

<p class="footer">Open Component Model · ocm.software</p>

---

<!-- Slide 10 — CTA -->
<!-- _class: cta -->

<h1 class="title">Start delivering with confidence.</h1>

<ul class="actions">
  <li><span class="action">Try it</span> — ocm.software</li>
  <li><span class="action">Build with us</span> — github.com/open-component-model</li>
  <li><span class="action">Talk to us</span> — community channels on the website</li>
</ul>
