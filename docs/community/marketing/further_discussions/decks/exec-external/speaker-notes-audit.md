# Speaker Notes Audit — Exec External

Purpose. Read `speaker-notes.md` against `design-principles/voice-guide.md` and flag every place the prose still reads like an LLM wrote it. Per slide: the pattern, why it costs the delivery, a rewrite that matches the voice. Clean slides get a one-liner. Slides without notes get one line and no audit.

The audit itself is written in the target voice. If it hedges, sycophants, or reaches for MBA vocabulary, it fails its own test.

Exec-external has 13 slides with notes and 4 without. The notes are in better shape than the architect-external set — the voice already lands most of the time. The findings below are the residual drift, not a rewrite of the whole file.

---

## Slide 1 — Your supply chain has

No notes. No audit needed.

## Slide 2 — THREE BLIND SPOTS

Mostly clean. Three columns, each with a concrete mechanism — location-as-part-of-the-name, twelve-signatures-and-an-explanation, verification-ships-with-the-release. That's the voice working.

One drift. **"Discharge the contract -> Deliver on the promise you just made on slide 1."** Stage-direction gloss is fine, but "discharge the contract" is consultant-speak for something the next clause already says plainly. Cut the first phrase; keep the second.

**Proposed:** `Deliver on the promise from slide 1. Three picturable failures the audience can recognise in their own delivery chain. The slide is intentionally sparse — let the audience read; you fill in the colour.`

Impact: minor. One line of consultant residue in an otherwise sharp opener.

## Slide 3 — WHY NOW

Clean. The column framings are anchored — jurisdictions, DORA/NIS2/CRA, SolarWinds/xz/log4shell. Named things, not adjectives. The close — *Not faster pipelines. Different mechanics.* — is the voice at its best.

No changes.

## Slide 4 — THE ANSWER

Mostly clean. The wait-two-seconds direction is right. The four quoted lines each carry a concrete claim (artifact types, boundaries, compliance regimes, headline).

One soft spot. **"OCM gives you the evidence model the regulators are asking for."** *Evidence model* is on the edge of vague. It's saveable — the mechanism is the signed descriptor and the digest tree — but as-written it drifts toward the outcome-not-mechanism failure mode voice-guide names. Not urgent to fix at exec altitude; flag it if you tighten this deck later.

## Slide 5 — THE SHIFT

Clean. The SBOM/SBOD contrast is doing real work, and the *lists / delivers / lives inside* triad is prose, not a template. The paraphrase instruction — read the third bullet only if the audience is reading it — is exactly the kind of stage direction the voice wants.

No changes.

## Slide 6 — THE SHIFT — SBOM INSIDE SBOD

Clean and short. *The diagram is the point. Don't talk over it.* is the whole rule. *If you take one thing from this talk, take this picture* earns its place because the previous slide set it up.

No changes.

## Slide 7 — HOW OCM COMPOSES

Clean. The objection-handling frame is honest — *we already have signing, registries, scanners* — and each column names the mechanism OCM adds, not a slogan. *Same tools. New connective tissue.* lands.

One tiny drift. **"I want to disarm something."** Fine as-is; slightly stagey. Optional to trim to `Disarm something first.` if you want the beat tighter. Not worth changing on its own.

## Slide 8 — OCM IN ONE PICTURE

Clean. Four verbs, four sentences, each with the digest/signature/registry mechanism underneath. *That's OCM in operation.* is a landing, not a summary.

No changes.

## Slide 9 — SOVEREIGN-READY

Clean. The four bullets each carry the same shape — anchor + characterisation + consequence — but the content varies enough that it doesn't read templated. *The component is the trust boundary — not the registry, not the network.* is the load-bearing sentence and it earns the position.

No changes.

## Slide 10 — SOVEREIGN-READY — AIR-GAP

Clean. Left / middle / right walkthrough, each anchored in what physically happens (pack-and-sign, no traffic crosses, verification happens locally). *Same identity. Same signature. Any location.* closes without hyperbole.

No changes.

## Slide 11 — SCAN

Clean, and this is one of the sharper slides in the deck. The *CVE-something-2026 drops at 11pm* line is the voice being witty on purpose — an absurd situation gets a beat of dryness, which is what voice-guide asks for. *Compliance becomes a property of the system. Not a Q3 deliverable.* is a real observation, not a slogan.

No changes.

## Slide 12 — WHAT OCM UNLOCKS

Drift here. The slide title uses `UNLOCKS` — MBA vocabulary that voice-guide flags explicitly. The speaker notes then say **"Six things you get from one shared model"** which is the honest version. So the notes recover from the title, but the title-echo through the deck still costs something.

Second drift. The single long quoted sentence — *Code signing across the whole stack, not per-tool. Air-gapped delivery as a built-in, not a workaround. Kubernetes-native deployment via OCM controllers. Continuous async security scans. A single signed source of truth you can rebuild any landscape from. And compliance reporting that flows from the SBOD itself — no spreadsheets.* — is six fragments in identical `X, not Y` / `X via Y` shape. That's the AI-slop enumeration pattern voice-guide calls out. Content is fine; shape is templated.

**Proposed rewrite of the quoted line:**

> "Code signing across the whole stack. Air-gap delivery is built in — no workaround shelf. Kubernetes-native deploy through the OCM controllers if you want it; GitOps if you don't. Async scans keep running after release. One signed source of truth you can rebuild any landscape from. Compliance reports fall out of the SBOD — no spreadsheets."

Same six items. Different lengths, different shapes. Reads like a person talking.

Slide-title fix (out of scope for the notes file, flag for the slide): `WHAT YOU GET` or `SIX THINGS FROM ONE MODEL`. Not `UNLOCKS`.

Impact: moderate. The tile is the payoff slide of the deck. Templated cadence there undercuts everything the middle of the deck built.

## Slide 13 — TRUSTED IN PRODUCTION

Clean. *OCM isn't a research project.* is the right first line — direct, no throat-clearing. Named adopters (BWI, SAP NS2) with one clause each of what they actually do. Peer projects with one clause of what each is for. *Aligned with NeoNephos. Open source. Production-grade.* closes without oversell.

No changes.

## Slide 14 — Start delivering with confidence.

Mostly clean. Three asks, each anchored in a specific action — *pick one regulated delivery you're already shipping*, *have your platform-engineering and security leads brief you*, *bring your delivery problem to the steering conversation*. That's the voice.

One drift. **"The signal is in their faces, not in the slides."** Nice line, but it's doing the same rhetorical job as *the reality is* — a filler-as-emphasis. It's borderline. Keep it if you like it; if you want the tighter version:

**Proposed:** `Have your platform-engineering and security leads brief you on what they found. If the model fits your delivery, they'll come back saying so without prompting.`

Impact: minor. The line survives; it just isn't required.

Second, smaller thing. **"ocm.software for the entry point — github dot com slash open-component-model for the code — community Slack and steering meetings linked from the website."** Reading the URL aloud with `dot` and `slash` is exec-friendly delivery, fine as-is. Kept for the record; no change.

## Slide 15 — APPENDIX — ABBREVIATIONS

No notes. No audit needed.

## Slide 16 — TRADEMARK & LICENSE NOTICES (1/2)

No notes. No audit needed.

## Slide 17 — TRADEMARK & LICENSE NOTICES (2/2)

No notes. No audit needed.

---

## Summary

Two real findings, both on slide 12: the `UNLOCKS` title echo and the six-item templated cadence in the speaker-note payoff line. Fix those and the deck's speaker notes are in voice end-to-end.

The rest are minor — one consultant phrase on slide 2, one soft *evidence model* on slide 4, one optional trim on slide 14. Take them or leave them.

Slides 1, 15, 16, 17 have no notes. Not a gap — the appendix and legal slides don't need speaker prose.
