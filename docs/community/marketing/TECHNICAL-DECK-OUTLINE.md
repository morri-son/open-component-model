# OCM Technical Deck — Outline

**Status:** v0.1 draft
**Audience:** Platform architects, SREs, security engineers, lead/principal devs evaluating OCM for adoption.
**Pre-requisite:** Audience has seen (or could see) the exec deck. This deck assumes the positioning and dives into *how*.
**Target length:** 22 slides + cover + back-matter = 24 total. Designed for a 35–45 min talk + Q&A, or a self-read PDF.

---

## Why this arc

Practitioner decks fail in two ways: (1) they re-tell the exec story slower, or (2) they list features without a thread. We solve both by making the deck a **migration of mental models**. The audience already has working mental models (cosign, SBOM, OCI, GitOps); the deck's job is to graft OCM onto those models, then show where OCM *replaces*, *contains*, or *bridges* them. Every section ends with an explicit "what this means for your stack" line — the question every architect is silently asking.

The arc is **Pain → Diagnosis → Model → Mechanics → Day-2 → Comparison → Adoption → Governance → CTA**. Mechanics (slides 7–13) is the deck's center of gravity. Comparison (slides 14–17) is the credibility lever. Adoption (slides 18–20) is what they came for.

We deliberately reject the temptation to lead with a feature tour. The audience has heard enough feature tours. We lead with **a thing that hurts** and earn the right to keep talking.

---

## Slide-by-slide

| # | Title | One-line purpose |
|---|---|---|
| 1 | **The wall every platform team hits at scale** | Hook — the artifact-graph-with-no-spine problem they recognise. |
| 2 | **Diagnosis: identity is bound to location** | Name the root cause sharper than they have. |
| 3 | **What "location-independent identity" actually means** | The hinge concept. Everything else hangs off this. |
| 4 | **Eight words to learn** | Component · Version · Resource · Source · Reference · Descriptor · Repository · Coordinates. |
| 5 | **A Component Descriptor, in full** | Show the artifact. Read it line by line. |
| 6 | **From SBOM to SBoD — what the envelope adds** | Bridge to the exec story without retreading it. |
| 7 | **Pack — what `ocm add cv` actually does** | Mechanics 1/4 — show the CLI, show the bytes. |
| 8 | **Sign — three trust models, one signature shape** | Mechanics 2/4 — RSA, PEM, Sigstore; what gets signed and what doesn't. |
| 9 | **Why signatures survive transport** | The `access` vs `digest` split. The single most important slide in the deck. |
| 10 | **Transport — Registry · CTF · Air gap** | Mechanics 3/4 — three patterns, one command, one CTF. |
| 11 | **Deploy — controllers, localization, kro** | Mechanics 4/4 — Repository → Component → Resource → Deployer. |
| 12 | **Day-2 — subscribe, upgrade, drift, prune** | What the controllers do once you stop watching. |
| 13 | **Plugins — extend OCM without forking it** | Process boundary, capability negotiation, registry-as-component. |
| 14 | **OCM vs cosign + SBOM** | Comparison 1/4 — the most common conflation. |
| 15 | **OCM vs OCI Distribution alone** | Comparison 2/4 — "isn't OCI enough?" |
| 16 | **OCM vs Argo / Flux / GitOps** | Comparison 3/4 — what OCM *adds*, not replaces. |
| 17 | **Gotchas and edges** | Failure modes, anti-patterns, what we know is sharp. |
| 18 | **The 30-minute PoC** | Smallest useful proof; one product, one CTF, one verify. |
| 19 | **Adoption ramp — week 1 to quarter 1** | What "champion adoption" looks like as a calendar. |
| 20 | **Where OCM is on the maturity curve** | Stable surfaces vs evolving surfaces. Practitioner candor. |
| 21 | **Governance — TSC, SIGs, NeoNephos, Community Spec License** | Why your bet doesn't depend on one vendor. |
| 22 | **Build with us** | CTA — repo, Zulip, conformance scenario, mailing list. |

Cover and back-matter aside, mechanics gets 7 slides (7–13), comparison gets 4 (14–17), adoption gets 3 (18–20). That weighting is deliberate: practitioners need *enough mechanics to argue internally*, *enough comparison to defuse pushback*, and *a concrete path forward*.

---

## Trade-offs we made

- **No live demo slot.** Demos belong in the PoC, not the deck. Slide 7 shows CLI output in-line so a non-demo room still gets the texture.
- **No vendor logos for compared tools.** We name them in the body but don't put logos on slides — keeps the deck portable across audiences and avoids a "vs" framing the project doesn't want.
- **Sigstore is treated as first-class but flagged "early access"** — matches `signing-and-verification-concept.md:311`. Don't oversell.
- **ODG / Compliance Dashboard appears only in passing on slide 12.** This is the *technical* deck; ODG has its own surface and audience. Keep this deck about the runtime.
- **No slide for the spec / OCM Specification v2.** Folded into governance (slide 21). Practitioners care that it exists; they don't need a tour.

---

## Open questions for the project owner

1. **Slide 17 (gotchas).** Are we comfortable putting a "what's sharp" slide in a technical deck? It's the credibility lever, but some orgs prefer to keep edges off the page. Recommend keeping it.
2. **Slide 20 (maturity curve).** Should "Sigstore: early access" and "PEM encoding: early access" be named explicitly, or grouped as "newer surfaces"? Recommend explicit — the audience reads the docs and will catch the dodge.
3. **Slide 18 (PoC).** I default to **air-gapped CTF round-trip** as the smallest useful PoC because it's the demo with the highest "aha" per minute. Alternative: a Helm-chart Deploy via controllers. Pick one — both is too much for a 30-min PoC.
4. **Slide 14 vs 15 ordering.** I lead with cosign+SBOM because that's where the audience is. Argument for swapping: OCI is the more *technical* misunderstanding. Defaulting to current order; flag for review.
