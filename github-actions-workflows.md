# GitHub Actions Workflows Overview

This document provides **quick context for LLM sessions** around release/build workflows.
Goal: A new session should be able to immediately implement changes to workflow setup, RC/Final flows, and publish pipelines without further exploration.

---

## 0) Current Target State

The release process supports **two modes** via `cli-release.yml`:

1. **Release Candidate (RC)**
   - `release_candidate=true`
   - Computes new RC tag, creates/pushes RC tag, builds, publishes, creates GitHub **Pre-Release**
   - Exports attestation bundles for binaries and OCI image

2. **Final Promotion**
   - `release_candidate=false`
   - Uses **existing RC** on the release branch as source of truth
   - **Verifies all attestations** from the RC release
   - Creates final tag from RC commit
   - Promotes OCI tag to final + `latest`
   - Creates GitHub **Final Release** from RC assets/notes

Additional:
- `dry_run=true` prevents tag/publish write operations
- `release-candidate-version.yml` is the central reusable workflow for metadata (RC + Final inputs/outputs)

---

## 1) Workflow Overview

| File | Name | Role |
|---|---|---|
| `.github/workflows/release-branch.yml` | Create OCM Release Branch | Manually creates `releases/v0.X` branches |
| `.github/workflows/release-candidate-version.yml` | Release Candidate Version | Reusable for RC/Final metadata + RC changelog |
| `.github/workflows/cli-release.yml` | CLI Release | Orchestration for RC release **and** Final promotion |
| `.github/workflows/cli.yml` | CLI | Build + Publish + Attestations for CLI |

---

## 2) High-Level Relationships

```text
release-branch.yml (manual)
   └─ creates releases/v0.X

cli-release.yml (manual)
   ├─ prepare (calls release-candidate-version.yml)
   ├─ RC Path:
   │    tag_rc -> build (calls cli.yml) -> release_rc (with attestations export)
   └─ Final Path:
        validate_final -> verify_attestations -> tag_final -> promote_image -> release_final

cli.yml (push/PR/workflow_call)
   ├─ build (+ attest binaries)
   └─ publish (+ attest OCI image)
       └─ outputs: image_digest, image_tag
```

---

# 3) Detailed Analysis

## 3.1 `release-branch.yml`

### Trigger
- `workflow_dispatch`

### Inputs
- `target_branch` (required): must match `^releases/v0\.[0-9]+$`
- `source_branch` (optional, default `main`)

### Behavior
- Attempts GitHub App Token (`actions/create-github-app-token`) with `permission-contents: write`
- Falls back to `GITHUB_TOKEN`
- Creates branch only if target doesn't already exist
- Writes Step Summary with source, target, SHA

---

## 3.2 `release-candidate-version.yml` (Reusable)

### Purpose
Central metadata workflow for both flows:
- Prepare RC
- Derive Final promotion metadata from latest RC

### Inputs
- `branch` (required)
- `component_path` (required, e.g., `cli`)
- `release_candidate` (optional, boolean, default `true`)

### Outputs
**RC Outputs**
- `new_tag`
- `new_version`
- `base_version`
- `promotion_tag`
- `changelog_b64` (only meaningful for RC)

**Final-relevant Outputs**
- `latest_rc_tag`
- `latest_rc_version`
- `latest_promotion_tag`
- `latest_promotion_version`

### Steps
1. Checkout (sparse: `component_path`, `.github/scripts`, `fetch-depth: 0`)
2. `compute-rc-version.js` (always, but RC summary only for RC)
3. `resolve-latest-rc.js` (only for Final)
4. `git-cliff` only when `release_candidate == true`
5. `Summarize changelog` only for RC (sets `changelog_b64`, writes raw log)

---

## 3.3 `cli-release.yml` (Orchestrator)

### Trigger
- `workflow_dispatch`

### Inputs
- `branch` (required)
- `release_candidate` (optional, default `true`)
- `dry_run` (optional, default `true`)

### Concurrency
```yaml
group: cli-release-${{ github.event.inputs.branch }}
cancel-in-progress: true
```

### Job Matrix by Mode

#### A) RC Mode (`release_candidate == 'true'`)
1. `prepare` (calls reusable workflow)
2. `tag_rc` (only when `dry_run == 'false'`)
   - Creates App Token with `permission-contents: write` + `permission-workflows: write`
   - Creates annotated RC tag from `prepare.outputs.new_tag`
3. `build` (only when `tag_rc.outputs.pushed == 'true'`)
   - Calls `cli.yml` via `workflow_call` with `ref=new_tag`
   - **outputs:** `artifact_name`, `artifact_id`, `image_digest`, `image_tag`
4. `release_rc` (only when tag pushed)
   - Decodes `changelog_b64`
   - Downloads build artifacts
   - **Exports attestation bundles** via `export-attestations.js`
   - Creates GitHub **pre-release** (`prerelease: true`)

#### B) Final Mode (`release_candidate == 'false'`)
1. `prepare`
2. `validate_final`
   - Aborts if no `latest_rc_tag` exists
3. `verify_attestations`
   - Downloads RC release assets
   - **Verifies all attestations** via `verify-attestations.js`
4. `tag_final` (only when `dry_run == 'false'`)
   - Creates final tag from `latest_rc_tag` commit (immutability check)
5. `promote_image`
   - ORAS tag promotion: `:<rcVersion>` -> `:<finalVersion>` + `:latest`
6. `release_final`
   - Downloads RC assets from existing RC release
   - Reuses RC release notes (with promotion header)
   - Creates Final Release (`prerelease: false`)

---

## 3.4 `cli.yml` (Build/Publish)

### Trigger
- Push to `main`, `releases/v**`, tags `cli/v**`
- PR to `main` (with `cli/**` or workflow file changes)
- `workflow_call`

### Outputs (for workflow_call)
- `artifact_name` - Build artifact name
- `artifact_id` - Build artifact ID
- `image_digest` - SHA256 digest of pushed OCI image
- `image_tag` - Tag of pushed OCI image

### Job `build`
- Checkout (sparse: `.github/scripts`, `cli/`)
- Setup Go, Task, buildx
- `compute-version.js`
- `task cli:generate/ctf` + `task cli:verify/ctf`
- **Attest binaries** (not on PR)
- Branch eligibility (`should_push_oci_image`) via script
- Upload artifacts (only if push-eligible)

### Job `publish`
- Only when `should_push_oci_image == 'true'`
- Downloads artifacts
- ORAS push from OCI layout
- Optional additional branch tag (`:main`)
- Resolve digest
- **Attest OCI image** with `push-to-registry: true`
- **outputs:** `digest`, `tag`

---

# 4) Attestation Scripts

## 4.1 `export-attestations.js`

**Purpose:** Exports attestation bundles for RC releases.

### Inputs (ENV)
| Variable | Required | Description |
|---|---|---|
| `ASSETS_DIR` | ✓ | Directory with build artifacts |
| `ASSET_PATTERNS` | ✓ | JSON array with glob patterns, e.g., `["bin/ocm-*"]` |
| `IMAGE_DIGEST` | ✓ | SHA256 digest of OCI image (directly from build output) |
| `IMAGE_TAG` | ✓ | OCI image tag |
| `TARGET_REPO` | ✓ | OCI repository, e.g., `ghcr.io/owner/cli` |
| `OUTPUT_DIR` | ✓ | Output directory for bundles |
| `REPOSITORY` | ✓ | GitHub repository for attestation lookup |

### Outputs
- `bundle_count` - Number of exported bundles
- `index_path` - Path to `attestations-index.json`

### Generated Files
- `attestation-<asset-name>.jsonl` - One bundle per binary (e.g., `attestation-ocm-linux-amd64.jsonl`)
- `attestation-ocm-oci-image.jsonl` - Bundle for OCI image
- `attestations-index.json` - Index with metadata

### Note
- **Uses `IMAGE_DIGEST` directly** from build output, no registry lookup needed
- Human-readable bundle names instead of cryptic hash names

---

## 4.2 `verify-attestations.js`

**Purpose:** Verifies attestations before final promotion.

### Inputs (ENV)
| Variable | Required | Description |
|---|---|---|
| `ASSETS_DIR` | ✓ | Directory with RC release assets |
| `ASSET_PATTERNS` | ✓ | JSON array with glob patterns, e.g., `["ocm-*"]` |
| `IMAGE_REF` | optional | OCI reference for image verification |
| `REPOSITORY` | ✓ | GitHub repository for attestation verification |

### Outputs
- `verified_count` - Number of verified attestations
- `verified_image_digest` - Digest of verified image

### Behavior
1. Loads `attestations-index.json` from assets
2. Verifies each binary against its bundle
3. **Verifies OCI image by digest** (not by tag!) against its bundle
   - OCI tags are mutable and can be overwritten
   - Uses `index.image.digest` for exact identification
4. Fails if any verification is unsuccessful

### Important Design Decision
OCI image verification uses the **digest from the index**, not the current tag.
This is essential because OCI tags are mutable and can be overwritten by other builds
between RC creation and final promotion.

---

## 4.3 `attestation-utils.js`

**Purpose:** Shared utility functions for attestation scripts.

### Exported Functions
| Function | Description |
|----------|-------------|
| `sha256File(path)` | Computes `sha256:<hex>` for a local file |
| `parsePatterns(json)` | Parses and validates JSON array for asset patterns |
| `findAssets(dir, patterns)` | Finds assets by glob, throws error if pattern has no matches |
| `runCmd(cmd, args, opts)` | Wrapper for execFileSync, mockable in tests |

### Usage
Imported by `export-attestations.js` and `verify-attestations.js`:
```javascript
import { sha256File, parsePatterns, findAssets, runCmd } from "./attestation-utils.js";
```

---

## 4.4 `attestations-index.json` Format

```json
{
  "version": "1",
  "generated_at": "2026-02-13T09:27:00.000Z",
  "rc_version": "0.8.0-rc.1",
  "image": {
    "ref": "ghcr.io/owner/cli:0.8.0-rc.1",
    "digest": "sha256:abc123..."
  },
  "attestations": [
    {
      "subject": "ocm-linux-amd64",
      "type": "binary",
      "digest": "sha256:def456...",
      "bundle": "attestation-ocm-linux-amd64.jsonl"
    },
    {
      "subject": "ghcr.io/owner/cli:0.8.0-rc.1",
      "type": "oci-image",
      "digest": "sha256:abc123...",
      "bundle": "attestation-ocm-oci-image.jsonl"
    }
  ]
}
```

---

# 5) Script Contracts (for Quick Adjustments)

## `.github/scripts/compute-rc-version.js`

### Expected ENV
- `BRANCH`
- `COMPONENT_PATH`
- `RELEASE_CANDIDATE` (optional, default true)

### Outputs via `core.setOutput`
- `new_tag`
- `new_version`
- `base_version`
- `promotion_tag`

### Note
- Writes RC compute summary **only when** `RELEASE_CANDIDATE == true`

## `.github/scripts/resolve-latest-rc.js`

### Expected ENV
- `BRANCH`
- `COMPONENT_PATH`
- `RELEASE_CANDIDATE` (optional)

### Outputs
- `latest_rc_tag`
- `latest_rc_version`
- `latest_promotion_version`
- `latest_promotion_tag`

### Note
- Writes final-oriented summary **only when** `RELEASE_CANDIDATE == false`

---

# 6) LLM Quickstart (Playbook)

## When user says: "Change RC/Final release logic"
1. First check `cli-release.yml` (job gates and `needs`)
2. Then `release-candidate-version.yml` (inputs/outputs)
3. Then scripts (`compute-rc-version.js`, `resolve-latest-rc.js`)

## When user says: "Change version computation"
- Modify `compute-rc-version.js` + associated tests
- Note: Keep file as close to upstream as possible, only necessary deltas

## When user says: "Final promotion behaves incorrectly"
- Check `validate_final`, `verify_attestations`, `tag_final`, `promote_image`, `release_final` in `cli-release.yml`
- Verify `latest_rc_*` and `latest_promotion_*` are propagated correctly

## When user says: "Adjust attestations"
- `export-attestations.js` for RC export
- `verify-attestations.js` for final verification
- Check `attestations-index.json` format

## When user says: "Adjust build/publish"
- `cli.yml` in jobs `build`/`publish`
- Eligibility rule in `branch-check`
- Outputs `image_digest` and `image_tag` for downstream

---

# 7) Common Pitfalls

1. **Boolean vs String in Workflow Inputs**
   - `workflow_dispatch` inputs are often stringly typed (`'true'/'false'`)
   - For reusable calls, `fromJSON(...)` may be needed

2. **Job Conditions Collide with `needs`**
   - When adding new jobs, always verify `if` + `needs` are consistent

3. **Missing Outputs in Reusable Workflow**
   - New data must be passed through step-output, job-output, workflow-output

4. **Tag Immutability for Final**
   - `tag_final` intentionally aborts if final tag already exists

5. **Summary/Release-Notes Duplicates**
   - RC and Final summaries are intentionally separate to avoid noise

6. **Attestation Export: IMAGE_DIGEST Missing**
   - `cli.yml` must provide `image_digest` and `image_tag` as outputs
   - These come from the `publish` job

---

# 8) Planned Extensions

## Kubernetes Controller Release

The same release model (RC + Final Promotion) will also be used for the Kubernetes Controller. The attestation scripts are therefore **generic** and can be reused for any component path:

- `COMPONENT_PATH=cli` → CLI Release
- `COMPONENT_PATH=kubernetes/controller` → Controller Release (planned)

## Additional Attestation Subjects

If additional artifacts need to be attested:
1. Extend `ASSET_PATTERNS` (e.g., `["bin/ocm-*", "helm/*.tgz"]`)
2. New entry is automatically included in `attestations-index.json`
3. Verification verifies all entries from the index

---

# 9) Change Log (Relevant for Future Sessions)

The following extensions/changes have been introduced:

### Workflows
- `cli-release.yml` now supports RC **and** Final Promotion in separate paths
- `release-candidate-version.yml` has input `release_candidate` and additional latest/promotion outputs
- `cli.yml`: New outputs `image_digest` and `image_tag` from `publish` job

### Workflow Simplifications
- **Committer steps:** Reduced from 2 steps to 1 step (inline git config)
- **`validate_final`:** Converted from JavaScript to Shell (simpler validation)
- **`Capture RC notes`:** Converted from JavaScript to Shell (`gh release view`)

### Scripts
- `resolve-latest-rc.js` introduced for Final metadata
- `compute-rc-version.js` kept close to upstream; necessary addition: RC/Final-dependent summary output
- **NEW:** `attestation-utils.js` - Shared utilities for attestation scripts
- **NEW:** `export-attestations.js` exports attestation bundles with human-readable names
- **NEW:** `verify-attestations.js` verifies attestations before final promotion
- **NEW:** `attestations-index.json` format for structured bundle references
- **REMOVED:** `attestations-release-assets.js` and `verify-attestations-from-release.js` (replaced by new scripts)

---

# 10) Minimal Validation After Changes

Recommended quick checks:

```bash
# Script tests
node .github/scripts/compute-rc-version.test.js
node .github/scripts/resolve-latest-rc.test.js

# Targeted workflow diff
git --no-pager diff -- .github/workflows/cli-release.yml .github/workflows/release-candidate-version.yml .github/workflows/cli.yml
```

If release flow was changed, additionally verify via dry-run:
- `cli-release.yml` with `dry_run=true`
- One RC run and one Final run against test branch

---

# 11) Release Flow Overview (Visual)

```
┌─────────────────────────────────────────────────────────────┐
│                     RC RELEASE FLOW                          │
├─────────────────────────────────────────────────────────────┤
│  1. prepare          → compute-rc-version.js                │
│                       → git-cliff changelog                  │
│  2. tag_rc           → create cli/v0.X.Y-rc.N tag           │
│  3. build            → cli.yml                               │
│     └─ build job     → compile, attest binaries              │
│     └─ publish job   → push OCI, attest image                │
│         └─ outputs   → image_digest, image_tag               │
│  4. release_rc       → download artifacts                    │
│     └─ export        → export-attestations.js                │
│         └─ creates   → attestation-*.jsonl files             │
│         └─ creates   → attestations-index.json               │
│     └─ publish       → GitHub Pre-Release                    │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   FINAL PROMOTION FLOW                       │
├─────────────────────────────────────────────────────────────┤
│  1. prepare          → resolve-latest-rc.js                  │
│  2. validate_final   → check RC exists                       │
│  3. verify_attest.   → download RC assets                    │
│     └─ verify        → verify-attestations.js                │
│         └─ uses      → attestations-index.json               │
│         └─ verifies  → all binaries + OCI image              │
│  4. tag_final        → create cli/v0.X.Y tag                 │
│  5. promote_image    → oras tag :rc → :final + :latest       │
│  6. release_final    → GitHub Final Release                  │
│     └─ copies        → RC assets + attestations              │
│     └─ updates       → release notes with promotion header   │
└─────────────────────────────────────────────────────────────┘
```

---

## Conclusion

The repo now has a two-path release approach (**create RC** vs **promote RC to Final**) with:

- **Clear separation** in jobs and outputs
- **Complete attestation support** for supply-chain security
- **Generic scripts** for reuse with other components (Controller)
- **Human-readable attestation names** for better traceability

For LLM changes, entry points are clear:
- Orchestration: `cli-release.yml`
- Metadata: `release-candidate-version.yml`
- Computation: `.github/scripts/compute-*.js`, `.github/scripts/resolve-*.js`
- Attestations: `.github/scripts/export-attestations.js`, `.github/scripts/verify-attestations.js`
- Build/Publish/Attest: `cli.yml`