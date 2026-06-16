# Tile Icon Audit and Alternatives

Slide 8 of the OCM exec deck uses six tiles, each with a Tabler outline icon
(MIT licensed, https://tabler.io/icons). This document audits each icon's fit
to its tile concept and proposes alternatives.

Verdicts:
- keep — icon fits the concept directly
- acceptable — works but a stronger metaphor exists
- replace — wrong metaphor; swap

All alternatives below were verified to exist at
`https://raw.githubusercontent.com/tabler/tabler-icons/main/icons/outline/{name}.svg`.

---

## Tile 1 — Code signing across stacks

**Current:** `lock.svg` — acceptable

A plain padlock reads as "secured / locked" rather than "signed". It is
generic; the link to *signing* (cryptographic attestation, not access
control) is left to the tile copy. Works, but a more specific glyph is
available.

**Recommended:** `signature` — already present in this folder; an actual
signing-mark glyph is the most literal metaphor and reads instantly.

**Alternatives:**
- `key` — signing-key metaphor; clean and unambiguous when paired with the
  word "signing".
- `shield-lock` — combines the protection halo with a lock; good if we want
  the tile to lean toward "trust" rather than "signature".
- `certificate` — explicit "signed certificate" reading; slightly busy at
  small sizes.

**Action:** none required for this round. Flag for follow-up: consider
swapping `lock.svg` for `signature.svg` (already in repo) so the tile
matches the concept exactly.

---

## Tile 2 — Air-gapped delivery

**Current:** `cloud-upload.svg` — replace

Wrong metaphor. Air-gap means *disconnected from the network*; a cloud
upload glyph communicates the opposite — pushing into the cloud. The icon
contradicts the tile copy.

**Recommended:** `package-export` — a sealed package leaving the system
boundary. Reads as "ship the artifact out (to be carried across the gap)"
without implying any network. Matches OCM's actual story: a CTF / OCI
archive that can be transported and re-imported on the other side.

**Alternatives considered:**
- `archive` — sealed archive; good "self-contained bundle" reading but
  loses the directionality / delivery aspect.
- `briefcase-2` — physical transport metaphor; a bit too "business
  travel", reads weaker than `package-export` in a software context.
- `transfer-out` — arrow-out-of-box; correct directionality but more
  abstract than `package-export`.
- `usb` / `device-floppy` — overly literal "sneakernet" props; risk
  looking dated next to the other tiles.
- `plug-x` — disconnected plug; communicates "no network" but loses the
  *delivery* half of the concept.

**Action taken:** fetched `package-export.svg` from Tabler outline set
and saved it next to the other tile icons in this directory. SVG validated
with `xmllint`.

---

## Tile 3 — Kubernetes-native deployment

**Current:** `rocket.svg` — acceptable

A rocket reads as "deploy / launch" generically. It is not wrong, but it
does not say *Kubernetes-native*. Every CI tool on Earth uses a rocket.

**Recommended:** `topology-star-3` — the clustered-nodes topology glyph is
the closest non-trademarked stand-in for the K8s control-plane-and-workers
shape. Communicates "orchestrated cluster deployment" without using the
Kubernetes wheel logo.

**Alternatives:**
- `topology-ring-3` — same family; ring layout reads slightly more as
  "service mesh" than "deployment target". Use if `topology-star-3` is
  visually too busy at tile size.
- `cube-send` — a container being shipped; reinforces the
  "ship containerized workloads" angle and pairs well with `package-export`
  on tile 2.
- `affiliate` — connected-nodes glyph; cleaner at small size but more
  generic.
- `world-cog` — "platform / runtime"; weaker fit, drops the cluster idea.

**Trademark note:** avoid the actual Kubernetes wheel/helm logo — it is a
CNCF mark with usage restrictions. Tabler does not ship it; do not draw it
in.

---

## Tile 4 — Asynchronous security scans

**Current:** `radar.svg` — keep

Radar is a strong metaphor for *continuous, sweeping, asynchronous*
detection — it scans on its own schedule, not on demand. Fits the tile
concept directly.

**Alternatives** (only if the deck ends up with two radar-like glyphs and
we need to differentiate):
- `shield-search` — security-flavoured magnifier; explicitly says
  "security scan" but loses the asynchronous / continuous reading.
- `radar-2` — same family, denser sweep lines; visually noisier.
- `scan` — barcode-style scan glyph; reads as "one-shot scan", which
  contradicts *asynchronous*.
- `bug` — finding-oriented; weaker — implies the result, not the activity.

---

## Tile 5 — One source of truth

**Current:** `source-of-truth.svg` — keep

This is a custom glyph already named for the concept. Assumed to be on-brand
and on-message; no swap needed unless visual style drifts from the rest of
the Tabler set.

**Alternatives** (if we decide to fall back to a stock Tabler icon for
visual consistency with the other five tiles):
- `database` — canonical "single store"; safe and instantly readable.
- `book-2` — "the book of record"; literary metaphor, fits "truth".
- `git-merge` — "all branches converge here"; strong for a developer
  audience, weaker for execs.
- `versions` — stacked-versions glyph; reinforces the
  "one identity, many versions" angle that OCM owns.
- `circles-relation` — multiple sources mapping into one; conceptual but
  abstract.

**Recommendation:** keep the custom glyph if it is visually consistent with
Tabler's stroke weight; otherwise swap to `database` for style parity.

---

## Tile 6 — Automated compliance reporting

**Current:** `report-analytics.svg` — keep

Document-with-chart reads cleanly as "generated report". The "automated"
half is carried by the tile copy, which is acceptable — no single glyph
captures both *report* and *automation* without becoming a logo.

**Alternatives:**
- `clipboard-check` — "checked-off compliance"; emphasises the
  pass/fail audit angle over the analytics angle.
- `file-check` — same idea, lighter weight; good if the tile sits next to
  another document-shaped icon and we need contrast.
- `report` — plainer document; loses the analytics signal.
- `chart-bar` — pure analytics; loses the document/report signal.

**Recommendation:** keep `report-analytics.svg`. If the deck ends up
showing tile 6 next to another chart icon, switch to `clipboard-check` to
lean into the *audit / compliance* reading instead of *analytics*.

---

## Summary table

| Tile | Concept | Current | Verdict | Recommended swap |
|------|---------|---------|---------|------------------|
| 1 | Code signing across stacks | `lock` | acceptable | consider `signature` (already in repo) |
| 2 | Air-gapped delivery | `cloud-upload` | replace | **`package-export` (fetched)** |
| 3 | Kubernetes-native deployment | `rocket` | acceptable | consider `topology-star-3` |
| 4 | Asynchronous security scans | `radar` | keep | — |
| 5 | One source of truth | `source-of-truth` (custom) | keep | fallback `database` if style drifts |
| 6 | Automated compliance reporting | `report-analytics` | keep | `clipboard-check` only if avoiding chart-icon collision |

## Files added by this audit

- `package-export.svg` — Tabler outline, MIT licensed. Replacement for
  `cloud-upload.svg` on tile 2 (air-gapped delivery).
