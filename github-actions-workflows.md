# Overview of the GitHub Actions Workflows

This document describes how the release workflows fit together after the recent RC/final release refactoring.

Scope:
- release branch creation
- RC preparation + RC publishing
- final promotion from latest RC
- CLI build/publish pipeline

---

## Workflow Summary

| Workflow file | Name | Short description |
|---|---|---|
| `release-branch.yml` | Create OCM Release Branch | Creates a `releases/v0.X` branch from a source branch. |
| `release-candidate-version.yml` | Release Candidate Version (reusable) | Computes RC metadata and changelog; now also exposes normalized promotion version output. |
| `cli-release.yml` | CLI Release | Main orchestrator for both RC creation and final promotion. |
| `cli.yml` | CLI Build & Publish | Builds binaries + OCI layout and publishes OCI image/attestations. |

---

## High-Level Flow

```text
1) Branch creation (manual)
   release-branch.yml

2) RC release (manual)
   cli-release.yml (release_candidate=true)
   ├─ prepare (reusable: release-candidate-version.yml)
   ├─ tag_rc
   ├─ build (calls cli.yml)
   └─ release_rc (GitHub pre-release)

3) Final promotion (manual)
   cli-release.yml (release_candidate=false)
   ├─ prepare (reusable: release-candidate-version.yml)
   ├─ validate_final
   ├─ tag_final
   ├─ promote_image
   └─ release_final
```

---

# Detailed Workflow Analysis

## 1) `release-branch.yml` — Release Branch Creation

### Purpose
Creates a release branch that matches policy (`releases/v0.<minor>`).

### Trigger
`workflow_dispatch`

### Inputs
- `target_branch`
- `source_branch` (default `main`)

### Notable behavior
- Uses GitHub App token with fallback to `GITHUB_TOKEN`.
- Validates branch naming with regex: `^releases/v0\.[0-9]+$`.
- Creates branch through GitHub API (`git.createRef`).

---

## 2) `release-candidate-version.yml` — RC Metadata + Changelog (Reusable)

### Purpose
Reusable metadata workflow used by `cli-release.yml`.

### Inputs
- `branch`
- `component_path`

### Outputs
- `new_tag` (e.g. `cli/v0.3.2-rc.1`)
- `new_version` (e.g. `v0.3.2-rc.1`)
- `base_version`
- `promotion_tag` (e.g. `cli/v0.3.2`)
- `latest_rc_tag`
- `latest_rc_version` (e.g. `0.3.2-rc.4`)
- `latest_promotion_tag` (e.g. `cli/v0.3.2`)
- `latest_promotion_version` (e.g. `0.3.2`) **(new)**
- `changelog_b64`

### Internal mechanics
- `compute-rc-version.js`: computes next RC tag/version.
- `resolve-latest-rc.js`: resolves latest existing RC line metadata.
- `git-cliff-action`: generates changelog (RC tags ignored for release body generation).
- `summarize` step exports changelog as base64 for downstream jobs.

### Recent change
Added normalized output `latest_promotion_version` to reduce downstream string parsing in final image promotion.

---

## 3) `cli-release.yml` — CLI RC + Final Orchestrator

### Trigger
`workflow_dispatch`

### Inputs
- `branch`
- `release_candidate` (bool, default `true`)
- `dry_run` (bool, default `true`)

### Concurrency
```yaml
concurrency:
  cancel-in-progress: true
  group: cli-release-${{ github.event.inputs.branch }}
```

### Modes

#### A) RC mode (`release_candidate == true`)
Jobs:
1. `prepare`
2. `tag_rc` (only if `dry_run == false`)
3. `build` (only if `tag_rc.outputs.pushed == 'true'`)
4. `release_rc` (pre-release)

#### B) Final mode (`release_candidate == false`)
Jobs:
1. `prepare`
2. `validate_final`
3. `tag_final` (only if `dry_run == false`)
4. `promote_image`
5. `release_final`

---

### Key job details

#### `tag_rc`
- Checks if RC tag already exists.
- Creates annotated RC tag with changelog message.
- Pushes tag and sets `pushed=true/false`.

#### `validate_final`
- Verifies that latest RC metadata exists (`latest_rc_tag`, `latest_promotion_tag`).
- Verifies required metadata outputs exist.

#### `tag_final`
- Creates immutable final tag from latest RC commit.
- Uses robust commit resolution: `refs/tags/<rcTag>^{commit}`.
- Fails if final tag already exists (intentional immutability guard).

#### `promote_image`
- Promotes image from RC tag to:
  - normalized final version (`latest_promotion_version`)
  - `latest`
- Recent simplification: no inline regex conversion from `cli/vX.Y.Z` anymore.

#### `release_final`
- Downloads assets from latest RC release.
- Reuses RC release notes as source-of-truth.
- Creates final GitHub release + uploads RC assets.
- Recent simplification: uses only `secrets.GITHUB_TOKEN` (App token removed here).

---

## 4) `cli.yml` — Build & Publish

### Triggers
- Push (`main`, `releases/v**`, tags `cli/v**`)
- PR (`main`, CLI path filtered)
- `workflow_call`

### Jobs
- `build`: compile/generate/verify/attest/upload artifact
- `publish`: pushes OCI image + attestation if push-eligible

### Push eligibility gate
OCI push only when ref is allowed (`main`, `releases/v0.*`, `cli/v*` tag path).

---

# Current Contracts and Invariants (LLM-critical)

## Naming invariants
- Release branches: `releases/v0.<minor>`
- RC tags: `<component>/v<semver>-rc.<n>` (e.g. `cli/v0.3.2-rc.1`)
- Final promotion tags: `<component>/v<semver>` (e.g. `cli/v0.3.2`)

## Data-flow invariants
- `prepare` is the metadata authority for downstream jobs.
- `latest_promotion_version` is the canonical OCI final version (`X.Y.Z`) for promotion.
- `release_final` notes must come from RC release body (do not regenerate).

## Safety invariants
- Final tag is immutable: do not overwrite existing final tag.
- `dry_run=true` must not push tags or publish release/promotion artifacts.
- `validate_final` must fail fast if RC source metadata is missing.

## Token invariants
- `cli-release.yml/release_final` now uses `GITHUB_TOKEN` only.
- App token is still used in other workflows where elevated/explicit app identity may be desired (e.g. `release-branch.yml`).

---

# LLM Change Guide (How to edit safely)

## If you change promotion logic
1. Start from `release-candidate-version.yml` outputs first.
2. Avoid parsing tag strings repeatedly in downstream jobs.
3. Prefer passing normalized fields (`*_version`, `*_tag`) from prepare.

## If you change release notes behavior
- Keep final release notes sourced from RC release body unless a deliberate policy change is approved.
- If changing, update both implementation and this document’s invariants.

## If you change token strategy
- Check per-job `permissions` and whether the operation is same-repo.
- `GITHUB_TOKEN` is usually sufficient for same-repo contents operations.
- Use App token only when required by org/repo policy, cross-repo access, or app-identity/audit requirements.

## If you refactor tags/jobs
- Preserve branch concurrency group.
- Preserve immutability check in `tag_final`.
- Keep explicit mode split (`release_candidate` true vs false).

---

# Practical Verification Checklist

After workflow edits:

```bash
ruby -e "require 'yaml'; YAML.load_file('.github/workflows/release-candidate-version.yml'); YAML.load_file('.github/workflows/cli-release.yml'); puts 'YAML OK'"
node .github/scripts/resolve-latest-rc.test.js
```

Optional:
```bash
git diff -- .github/workflows .github/scripts github-actions-workflows.md
```

---

# Conclusion

The release architecture now supports two explicit manual paths in one orchestrator:
- RC creation path
- final promotion path

Recent improvements reduced complexity in `promote_image`, removed unnecessary token indirection in `release_final`, and made normalized version data an explicit reusable contract for safer future automation.
