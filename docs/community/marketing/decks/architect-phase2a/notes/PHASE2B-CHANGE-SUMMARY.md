# Phase 2B — Per-Slide Change Summary for PPTX Hand-Edit

**Source for all changes:** Persona pass (Lead Architect / Marketing-Comms / Hostile Enterprise Architect) — full reports at `/tmp/persona-{1,2,3}-*.md`.

**Slide-numbering convention used below:** the **rendered PDF order** (matches what you see in PowerPoint).

**No main-arc renumbering.** The "How OCM compares" slide was originally planned as slide 4b (insert between current slides 4 and 5). After reviewing where it would actually fit, it's been moved to a **post-CTA appendix slide (slide 18)** instead — pulled on demand if a hostile architect asks "why not just compose the existing CNCF stack?" The main arc (slides 1–16) keeps its current numbering and ordering.

---

## SLIDE 1 — PAIN

**Slide text:** No change.

**Speaker notes — what to copy in:** replace the existing thirty-minutes line with:
> "By the end of the deck you'll have a thirty-minute path to your first OCM component — laptop or cluster. Until then, here's why that matters."

---

## SLIDE 2 — DIAGNOSIS

**Slide text — replace the three bullets** with Option B wording (concedes the digest reality before naming the gap):

| Old | New |
|---|---|
| **OCI image** — identified by registry/repo:tag. Mirror it; every downstream reference is invalidated. | **OCI image** — digest pins the bytes. Nothing pins the release the image belongs to. |
| **Helm chart** — identified by repo URL + name + version. Mirror the repo; pulls fail. | **Helm chart** — version pins the chart. Nothing pins it to the image, config, and SBOM it ships with. |
| **SBOM** — linked to its subject by file path or naming convention. Move the artifact; the link dangles. | **SBOM** — referrer attaches to one digest. No referrer spans the whole release. |

**Speaker notes:** updated to walk the new bullets — concedes digest pinning is the norm, then names the release-level gap. See `SPEAKER-NOTES-ARCHITECT-EXTERNAL.md` slide 2 section.

---

## SLIDE 3 — THE HINGE

**Slide text:** No change.

**Speaker notes — add two Q&A backup paragraphs:**

1. *"'Globally unique' inherits from DNS-prefix naming — same model as Go import paths. We don't run a registry that arbitrates conflicts; uniqueness is delegated to DNS. Two parties claiming `acme.org/helloworld` is prevented the same way two parties claiming `acme.org` is prevented."*

2. *"Q&A on squatting: trust is per-component — the verifier knows what trust anchor to apply to the descriptor in front of it. A regulated environment relies on (a) controlling which registry the controllers are configured to pull from, and (b) per-component verifier config. Per-name-prefix trust-anchor binding is not in the spec or the controllers today."*

---

## SLIDE 4 — POSITIONING

**Slide text:** No change.

**Speaker notes — add one SBOD Q&A backup:**
> *"If the audience knows OCM at all, they may have heard 'Software Bill of Delivery' — SBOD — in earlier presentations or on the website. It's our positioning term against SBOM. Technically an SBOD is the same object architects call **the component descriptor**: the serialized form of an OCM component version. Different words, one object."*

---

## SLIDE 5 — CONSTRUCTOR

No changes.

---

## SLIDE 6 — DESCRIPTOR

**Slide text:** No change.

**Speaker notes — add two Q&A backup paragraphs:**

1. *"Q&A backup on the trust model (one per scheme, all configurable): RSA-PSS uses bare public-key pinning. Sigstore uses OIDC issuer + Fulcio short-lived cert + Rekor transparency log. OpenPGP uses an OpenPGP keyring. Algorithm is configurable per signature; the signed object is the canonicalized descriptor regardless of algorithm."*

2. *"Q&A backup on composition: the signature transitively pins `componentReferences` (introduced on slide 8). The product signature covers every reference's descriptor digest — so re-signing or re-publishing a referenced component breaks the product signature. Verifier policy is per-component."*

---

## SLIDE 7 — THE FOUR MOVES

No changes.

---

## SLIDE 8 — COMPOSE

**Slide text:** No change.

**Speaker notes — add one Q&A backup paragraph:**
> *"Q&A on transitive trust: `componentReferences` are pinned by digest of the referenced component's descriptor. The product signature covers each reference's digest — re-signing a referenced component breaks the product signature. At deploy time the verifier checks each component against the public key pinned for its signature name. In v1alpha1 the Component CR's `verify:` entries pin signature **name → public key** (RSA today; OpenPGP and Sigstore are CLI-only and on the controller roadmap). Per-component-name anchor binding beyond that is not in the controller; global enforcement is BYO Kyverno/Gatekeeper."*

---

## SLIDE 9 (SIGN)

### ★ SLIDE TEXT CHANGE — column header rename

**Middle column header:** change **`GPG`** → **`OpenPGP`**

(The column body text stays as-is. GPG is one implementation; OpenPGP is the standard. Sequoia and RNP produce compatible signatures.)

**Speaker notes — add one Q&A backup paragraph (the policy-floor question is the hardest in this slot).** The earlier draft of this paragraph was technically wrong on three points and has been corrected against the controller source (`kubernetes/controller/api/v1alpha1/component_types.go`, `kubernetes/controller/internal/resolution/workerpool/workerpool.go`):

- The Component CR `verify:` entry pins a signature **name + public key**, not a scheme or trust anchor — re-worded accordingly.
- The v1alpha1 controller implements **RSA only** today; OpenPGP and Sigstore are CLI-only and on the roadmap — the answer now says so plainly rather than implying all three are wired in.
- No admission webhook ships with OCM — the "Production installs SHOULD pin policy via admission" sentence has been re-framed as BYO Kyverno/Gatekeeper/custom rather than implying an OCM-native option exists.

The corrected note text lives in `build-pptx/speaker_notes.py` key `9` (canonical) and in `notes/SPEAKER-NOTES-ARCHITECT-EXTERNAL.md` slide 9 section (prose, updated in parallel). Copy from there into PowerPoint — do **not** paste the earlier policy-floor paragraph that referenced "scheme/anchor pinning on the Component CR" or "implicit fall-through to a weakest scheme."

---

## SLIDE 10 (TRANSPORT)

**Slide text:** No change.

**Speaker notes — add two Q&A backups:**

1. *"Q&A on the air-gap default footgun: default `ocm transfer` copies only the descriptor — the access fields still point back at the source registry. For air-gap (CTF → Registry) you MUST pass `--copy-resources` so the bytes travel with the descriptor. Slide 14 names this as one of the three honest edges. Worth catching in a CI step the first time someone runs an air-gap export."*

2. *"Q&A on Sigstore air-gap specifically: Sigstore verification at the destination is offline IF the trusted-root file (Fulcio CA + Rekor public key for the configured issuer) has been distributed into the destination once, out of band. After that, `ocm verify cv` runs without contacting Rekor or Fulcio. RSA and OpenPGP need only their pinned public keys — no trusted-root file."*

---

## SLIDE 11 (DEPLOY)

**Slide text:** No change. (We considered adding the verification-opt-in disclosure to the COMPONENT card body, but kept the card discipline; disclosure lives in speaker notes.)

**Speaker notes — three updates:**

1. **Replace the COMPONENT-card walk-through** (so verification-opt-in is named):
> *"Component. Pulls one version. Verifies its signature against a trust anchor you give it — the public key, the OpenPGP keyring, or the Sigstore identity policy. **Verification is opt-in**: without a `verify:` entry on the Component CR pointing at a key or secret, the controller resolves and pulls but does not check signatures. Production installs should require verification via admission policy. If verification *is* configured and fails, nothing downstream sees a verified descriptor — the chain stops here."*

2. **Replace the kro/Flux foreshadow paragraph** (so slide 14 doesn't land retroactively, and so Argo CD is included):
> *"Honest layering, foreshadowed so slide 14 doesn't feel retroactive: the four-card chain on its own deploys raw Kubernetes manifests via the Deployer. For the Helm-deploy reference flow the chain feeds a `ResourceGraphDefinition` that kro reconciles, with Flux (or Argo CD) applying the resulting `HelmRelease`. The OCM controllers don't ship kro, Flux, or Argo CD — bring your own. Slide 14 names this as one of three honest edges."*

3. **Add an Argo CD Q&A backup line:**
> *"Q&A on Argo CD: tabs for Argo CD are landing in the website how-tos before the deck ships. Until then, the documented Helm-deploy path is kro + Flux; the Argo CD path is symmetrical."*

---

## SLIDE 12 (DAY 2)

No changes.

---

## SLIDE 13 (ADOPTION)

### ★ SLIDE TEXT CHANGE — drop the "Thirty minutes" closing line on both cards

| Card | Old final line | New final line |
|---|---|---|
| FROM ZERO — CLI | *Thirty minutes on a laptop.* | **Delete this line entirely.** End the card on *Verify on the other side.* |
| ON YOUR CLUSTER — CONTROLLERS | *Thirty minutes on any cluster.* | **Delete this line entirely.** End the card on *Deploy a component.* |

Slide becomes honest without marketing numbers. The cards now end on the action verb.

**Speaker notes — full slide-13 section rewritten.** Key new content:
> *"On the slide: no marketing minutes. The honest numbers live here so the speaker can land them when asked."*
> *"CLI cold-start budget: about thirty minutes — CLI install plus the simple `helloworld` pack/sign/verify walked in the website tutorial."*
> *"Cluster cold-start budget: an afternoon — kind cluster bootstrap + Helm-install OCM controllers + kro + Flux or Argo CD + Helm-deploy of the simple component documented in the getting-started tutorial."*

---

## SLIDE 14 (WHAT'S SHARP)

### ★ SLIDE TEXT CHANGE — third bullet rewrite

| Old | New |
|---|---|
| **Helm-deploy adds kro + Flux** — the OCM controllers don't ship them. Bring your existing GitOps engine. | **Helm-deploy adds kro + Flux or Argo CD** — the OCM controllers don't ship them. Bring your existing GitOps engine. |

Rationale: minimal change — preserves the statement / em-dash / explanation rhythm of the other two bullets. Just adds the Argo CD path. The "kro is needed for more than Helm-deploy" nuance lives in speaker notes.

**Speaker notes:** slide-14 section rewritten. Key new content for the third bullet:
> *"The four-card chain on its own deploys raw Kubernetes manifests via the Deployer. For the Helm-deploy reference flow, the Deployer feeds a `ResourceGraphDefinition` that kro reconciles, with your GitOps engine — Flux today, Argo CD path landing in the docs before this deck ships — applying the resulting `HelmRelease`. The OCM controllers don't ship kro, Flux, or Argo CD; you bring them. Three installs for Helm-deploy. Plan for it. Nuance for Q&A: kro is actually required for any non-raw-manifest deploy path; the GitOps engine is the Helm-deploy-specific add."*

---

## SLIDE 15 (CTA)

No changes.

---

## SLIDE 16 (APPENDIX · REPLICATION)

No changes.

---

## ★ SLIDE 18 — APPENDIX · HOW OCM COMPARES (Q&A backup, NOT in main flow)

**Position:** post-CTA appendix slide, after slide 16 (Replication appendix). Pulled ON DEMAND if a hostile architect asks "why not just compose cosign + in-toto + OCI 1.1 referrers + my GitOps engine?" Otherwise never shown.

**Rationale:** This deck is for architects coming from different areas trying to find out what OCM *is*, not for an architecture-decision board. A comparative slide in the main arc would either sit too early (before the audience knows what's being compared) or interrupt the closing posture after slide 14–15. It belongs nowhere in the main arc — but it earns its keep as the answer to one specific Q&A question.

**Slide file:** `OCM-Story-Architect-External-Slide-4b.pptx` in the deck folder. The filename keeps the original "4b" tag since that was the design iteration tag; it now lives as slide 18 in the deck.

**On screen.** Eyebrow: HOW OCM COMPARES. Title: "Composes with what's there." A three-row bordered table containing the per-artifact tools, with the OCM row sitting *outside* the box below it:

```
                       WHAT IT SIGNS              LOCATION-      AIR-GAP
                                                  INDEPENDENT    NATIVE
┌────────────────────┬────────────────────────┬──────────┬───────────┐
│ cosign / sigstore  │ one OCI artifact       │ no       │ no        │
│ SLSA / in-toto     │ one build's provenance │ no       │ partial   │
│ SBOM / OCI 1.1 refs│ one artifact's contents│ partial  │ no        │
└────────────────────┴────────────────────────┴──────────┴───────────┘

OCM                     a component (the bundle)   yes        yes
```

The "out of the table" placement of OCM is the slide's whole argument made visual: the per-artifact tools form one comparison group; OCM is a *different unit* of analysis, not just a row in the same group.

Bottom caption (mid-blue): *"OCM rides on top. It doesn't replace the per-artifact tools — it adds the release-level envelope they don't."*

**Speaker notes** are embedded in the slide and also live as the `18:` entry in `speaker_notes.py`. Full Q&A-grade walk-through is in `SPEAKER-NOTES-ARCHITECT-EXTERNAL.md` under "SLIDE 18 — APPENDIX · HOW OCM COMPARES."

---

## Quick reference — locked decisions for context

These were settled in this Phase 2B pass; do not re-litigate during the PPTX edit:

- Sigstore "GA" claim on slide 9 (SIGN) is **gated by the website PR** removing the early-access callout. Don't ship the deck until that PR merges. (No deck-side edit; just timing.)
- The `ociImage` (artifact type) vs `OCIImage/v1` (access type) casing on slides 5 + 6 is **intentionally different** per spec — these are two different nouns. The deck is correct as-is.
- No new "Our recommendation" slide. The deck is for architects evaluating OCM, not an architecture-decision board.
- No comparative footer added to slide 9 (SIGN). Policy-floor disclosure is speaker-notes-only — and the disclosure was rewritten to match the v1alpha1 controller reality (RSA-only today; `verify:` pins name + public key, not scheme/anchor; production global enforcement is BYO Kyverno/Gatekeeper, no OCM-native admission webhook ships).
- CTAs across decks don't ladder, but external vs internal decks are explicitly distinct audiences — no anchor-line added.
- Day-2 visual diff pointers already exist (changed values are in brand blue) — no further change.
- The comparison slide ("How OCM compares") lives as a post-CTA Q&A backup at slide 18 — not in the main arc. Main-arc slides keep their current numbering.

---

## Files touched in the repo

- `docs/community/marketing/decks/architect-phase2a/build-pptx/speaker_notes.py` — main-arc slide notes updated (1, 2, 3, 4, 6, 8, 9, 10, 11, 13, 14); appendix slide-18 notes added as a dict entry.
- `docs/community/marketing/decks/architect-phase2a/notes/SPEAKER-NOTES-ARCHITECT-EXTERNAL.md` — long-form notes updated; new SLIDE 18 appendix section added after SLIDE 16.
- `docs/community/marketing/decks/architect-phase2a/build-pptx/build_slide_4b_compare.py` — generates the slide-18 PPTX (filename keeps the 4b tag).
- `docs/community/marketing/decks/architect-phase2a/OCM-Story-Architect-External-Slide-4b.pptx` — the slide-18 PPTX, ready to insert.
- This file: `docs/community/marketing/decks/architect-phase2a/notes/PHASE2B-CHANGE-SUMMARY.md` — the hand-edit reference you're reading.

No main deck PPTX was touched. All slide-text and slide-insertion changes are listed above for manual PowerPoint application against the SharePoint copy.
