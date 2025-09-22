---
status: draft
deciders: OCM Technical Steering Committee
date: 2025-09-19
title: Discussion — Versioning, Branching and Release Orchestration for the OCM Monorepo
---

# Discussion Draft — Versioning, Branching & Release Orchestration (OCM monorepo)

Purpose
- Provide a concise, decision-ready basis for the team meeting that captures options, trade-offs and concrete bot/workflow behaviour required to handle:
  - sprint-driven sub-component releases (0–2 finals per sprint),
  - OCM root bundling and RC creation,
  - sub-component patch delivery and targeted OCM patching.

Assumptions (pre-agreed)
- Sprint cadence: one RC per sprint (two weeks) is the normal promotion window; team decides per sprint which sub-components (if any) release.
- Sub-components publish annotated Git tags (e.g., `cli/v0.30.0`).
- `/ocm/component-constructor.yaml` in `main` is the OCM template; concrete constructor snapshots are produced by the bot and attached only to OCM root releases (RC/final).
- Component-constructor updates are made exclusively via bot PRs (no manual edits).
- Persistent release branches exist for active minor lines (e.g., `releases/cli/v0.30`); hotfixes use current hotfix workflow (fix on `main` → cherry-pick to release branch → tag from release branch).

Key decision topics
1. Versioning SSoT (three options)
2. Orchestration / batching for OCM root updates (single deterministic option for sequential finals)
3. Bot responsibilities, idempotency, conflict handling
4. Targeted OCM patch flow and required index mapping
5. Policy: handling patches created during an in‑flight OCM RC (default + emergency)
6. Maintenance SLA (which OCM lines are patchable)

1) Versioning — options
A. `VERSION` file per component (persisted)
- Pros: human-visible file inside component; easy to inspect offline.
- Cons: additional file maintenance; risk of drift unless guarded by CI.

B. Git annotated tags for sub-components + persisted `/ocm/component-constructor.yaml` in `main` (preferred)
- Pros: git-native published SSoT for each component; constructor in `main` expresses intended bundle for OCM; tooling reads tags and the constructor template.
- Cons: CI must parse/validate tags (standard tooling can handle this).

C. Git annotated tags for sub-components + component-constructor generated on-the-fly in CI and attached only to OCM release artifacts
- Pros: minimal repo footprint; constructor snapshot produced reproducibly at release time.
- Cons: less visible in repo; requires storing snapshot artifact for reproducibility.

Recommendation for discussion: B (tags as primary SSoT + constructor in `main`), with tooling to make tag-reading trivial and snapshot artifacts attached to OCM releases.

2) Orchestration / bundling policy (deterministic single option for sequential finals)

Context
- Within a sprint there can be 0–2 sub-component final releases and they occur sequentially. Each final is a trigger for updating `/ocm/component-constructor.yaml`. We must avoid producing excessive OCM RCs while preserving traceability and deterministic version bumping.

Chosen behaviour (Sprint-batch collector)
- Trigger: Bot reacts to any sub-component final tag event.
- Behaviour:
  1. On first final in sprint: bot opens or updates a single *draft batch PR* against `/ocm/component-constructor.yaml` in `main` (PR contains updated versions for whatever finals exist so far).
  2. On second final in the same sprint: bot updates the same draft PR to add the second final.
  3. At the sprint boundary (or when the release manager chooses to promote), the batch PR is merged. The merge MUST create a new OCM RC tag (e.g., `ocm/vX.Y.Z-rc.N`) automatically.
  4. Merging always leads to a new RC; promotion to final follows normal RC→Final gating.

RC version bump mapping rule (deterministic)
- If any included sub-component change is MAJOR → bump OCM major.
- Else if any included sub-component change is MINOR → bump OCM minor.
- Else (all included changes are PATCH) → bump OCM patch.

Notes
- The PR should be draft while collecting; merge behavior (auto‑merge vs manual approval) is a separate policy choice.
- Force/urgent path: release manager can request immediate flush/merge to create an RC outside the normal boundary.

3) Branching & Hotfix/backport policy (agreed)
- Active maintained minors: persistent release branches `releases/<component>/vX.Y`.
- Hotfix workflow (current, keep):
  * Develop fix on `main`.
  * Cherry-pick fix into relevant `releases/<component>/vX.Y` branch(s).
  * Open PR targeting release branch(s).
  * Tag patch from release branch after merge.
- For older, rarely-maintained minors, create a temporary branch from tag, cherry-pick fix, tag, then delete temp branch.

4) Bot behaviour & RC creation semantics
- Bot triggers:
  * On final annotated tag of any sub-component it will parse the tag, validate, then open/update the sprint-batch draft PR for `/ocm/component-constructor.yaml`.
  * If PR already merged for the sprint, that final will be included in next sprint’s batch (no retroactive inclusion).
- Batch PR merge is the point where bot:
  * Writes concrete constructor snapshot into a release artifact,
  * Creates the new OCM RC tag (`ocm/vX.Y.Z-rc.N`),
  * Triggers conformance CI,
  * Publishes artifacts and signed attestations for the RC.
- Idempotency & conflict handling:
  * If multiple bot updates race, bot updates the single draft PR; if a manual conflict happens the bot opens a conflict PR or alerts humans (never overwrite without human approval).

5) Targeted OCM patch workflow (essential for delivering sub-component patches)

Problem
- A sub-component patch for an older minor (e.g., `cli/v0.25.1`) should be deliverable as a tested OCM bundle for users who rely on that older OCM line.

Required capability
- Bot-maintained index mapping `sub-component tag -> list of OCM releases that include it` (machine-readable JSON artifact per OCM release).

Targeted OCM patch flow (policy-driven)
1. Trigger: sub-component final tag for a patch (e.g., `cli/v0.25.1`).
2. Bot looks up index to find supported OCM releases that include `cli/v0.25.0`.
3. Per SLA, select target OCM release to patch (e.g., latest supported OCM that contained the prior version).
4. Bot fetches that OCM release snapshot, updates only the sub-component entry to the patch version, opens PR `ocm: patch <OCM> with <component>@<patch>`.
5. Run CI (conformance for that OCM snapshot), require approvals, merge → bot creates `ocm/<target>-rc.N` (patch RC) and on promotion a final ocm patch.
6. Bot updates index mapping to include the new sub-component tag -> OCM mapping.

If no supported OCM contains the prior sub-component version, bot notifies maintainers and no automatic OCM patch is created.

Bot pseudocode (concise)
```bash
# Trigger: annotated tag COMPONENT@vA.B.C
PRIOR=vA.B.(C-1)
INDEX = bot.find_ocm_releases_for(COMPONENT, PRIOR)
if INDEX.empty:
  notify("no matching OCM; manual action")
else:
  TARGET = select_latest_supported(INDEX)
  SNAPSHOT = bot.fetch_constructor_snapshot(TARGET)
  PATCH_SNAPSHOT = SNAPSHOT.update_component(COMPONENT, vA.B.C)
  create_branch_and_PR(PATCH_SNAPSHOT)
  run_conformance_ci()
  require_approvals()
  on_merge: create_ocm_rc_from_merge(), attach_snapshot(), update_index()
```

6) Policy: patches during an in-flight OCM RC
- Default behaviour: do NOT mutate in-flight RCs. Post-cut patches are excluded from the active RC to preserve reproducibility.
- Emergency/maintenance path (recommended hybrid): allow targeted OCM patch releases only when criteria met (security, critical regression, SLA). These follow the targeted OCM patch flow and require explicit human approval.

7) Maintenance SLA — decision required
- Decide which OCM lines are eligible for targeted patches (e.g., last 2 minors; N months). This drives the number of persistent release branches and operational cost.

Examples
- The document includes several timeline examples for single-sub, multi-sub, RC failure and recovery to illustrate behaviours (see existing ADR for reference).

Decision questions for the meeting (concise)
- Confirm Versioning option: B (tags + constructor in `main`)?
- Confirm sprint-batch behaviour (single draft PR per sprint, merge → new RC) and mapping rule (major>minor>patch)?
- Draft vs non-draft PRs while collecting — which preference?
- Merge policy: auto-merge vs require human approval for batch PRs?
- Emergency criteria and who can trigger force-flush and targeted OCM patches?
- SLA: which OCM lines are supported for targeted patches (N minors / M months)?
- Bot privileges and audit requirements (who can approve bot PRs, protected tags, attestation).

Next steps (practical)
1. Agree policy answers above in meeting.
2. Convert agreed options into ADR decisions.
3. Create bot implementation tickets:
   - maintain index at OCM RC/final creation,
   - sprint-batch PR logic with "force now" and idempotency,
   - targeted OCM patch flow (lookup, create PR, tests, tag).
4. Write minimal acceptance tests for bot behaviour and index correctness.
5. Document emergency flow and SLA publicly in repo.

Meeting agenda (30–45 min)
- 5 min: purpose & assumptions
- 10 min: versioning SSoT + preferred option
- 10 min: orchestration & batch PR behaviour + mapping rule
- 10 min: targeted OCM patch flow, index and SLA
- 5–10 min: bot privileges, approvals, next steps

---

End of discussion draft.
