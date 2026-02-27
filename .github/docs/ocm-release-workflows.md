# OCM Release Process: Architecture and Design

This document explains the OCM CLI release workflow architecture, design decisions, and the unified release model with environment-gated promotion.

---

## Overview

The release process uses a **unified single-run model**:

1. **Phase 1 - Release Candidate (RC)**: Creates RC tag, builds artifacts, generates attestations, publishes pre-release
2. **Environment Gate**: 14-day wait timer + required reviewer approval
3. **Phase 2 - Final Promotion**: Verifies RC attestations, creates final tag from RC commit, promotes OCI tags, publishes final release

Both phases run in **a single workflow execution** (`cli-release.yml`), with the environment gate providing the separation between RC and Final.

---

## Core Concepts

### Release Candidate (RC)
- Versioned as `cli/v0.X.Y-rc.N` (e.g., `cli/v0.8.0-rc.1`)
- Built from release branch (`releases/v0.X`)
- Full build + attestation generation
- Published as GitHub **pre-release**
- RC commit is immutable source of truth for final promotion

### Environment Gate
- GitHub Environment: `cli/release`
- **Wait Timer**: 14 days (20160 minutes)
- **Required Reviewers**: At least 1 reviewer must approve
- Blocks workflow execution between RC and Final phases

### Final Promotion
- Uses outputs from the **same workflow run** as RC
- Verifies all RC attestations before proceeding
- Creates final tag (`cli/v0.X.Y`) from **same commit** as RC
- Promotes OCI tags (`:rc.N` → `:0.X.Y` + `:latest`)
- Publishes GitHub **final release** with same artifacts

### Attestations
Supply-chain security artifacts proving build provenance:
- Generated during build via `actions/attest-build-provenance`
- Stored in GitHub's attestation store
- Verified using `gh attestation verify` (no local bundles needed)
- Uses SLSA Provenance v1 format (https://slsa.dev/provenance/v1)

---

## Architecture

### Workflow Files

```
release-branch.yml          Creates releases/v0.X branches
    │
    └─> cli-release.yml     Single workflow for RC + Final
            │
            ├─> release-candidate-version.yml    Version computation + changelog
            └─> cli.yml                          Build + Publish + Attest
```

### Job Flow (Single Workflow Run)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 1: RC                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  prepare ──▶ tag_rc ──▶ build ──▶ release_rc                               │
│     │          │          │           │                                     │
│     │          │          │           └─▶ Create GitHub pre-release         │
│     │          │          └─▶ Build binaries, OCI image, attest all        │
│     │          └─▶ Create annotated RC tag                                  │
│     └─▶ Compute version, generate changelog                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                         ENVIRONMENT GATE                                    │
│                     cli/release (14 days + approval)                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                            PHASE 2: FINAL                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  verify_attestations ──▶ promote_final ──▶ release_final                   │
│          │                     │                │                           │
│          │                     │                └─▶ GitHub final release    │
│          │                     └─▶ Final tag + OCI tag promotion           │
│          └─▶ Verify binary + OCI attestations via gh CLI                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Design Decisions

### 1. Single Workflow Run
**Why**: Simplifies the release process and ensures consistency between RC and Final.

**Benefits**:
- All outputs from RC phase are directly available in Final phase
- No need to download RC assets or resolve latest RC tag
- Eliminates drift between RC and Final
- Single audit trail in workflow run history

### 2. Environment Gate for Promotion
**Why**: Provides controlled waiting period and approval process.

```yaml
verify_attestations:
  environment:
    name: cli/release  # 14-day wait + reviewer approval
```

The environment must be configured in GitHub with:
- Required reviewers (at least 1)
- Wait timer: 20160 minutes (14 days)

### 3. Simplified Attestation Verification
**Why**: GitHub's attestation API handles everything; no local bundle management needed.

```bash
# Binary verification
gh attestation verify <file> --repo <repo>

# OCI image verification  
gh attestation verify oci://<repo>@<digest> --repo <repo>
```

**Benefits**:
- No attestation bundles stored as release assets
- No custom scripts for export/verify
- Uses SLSA Provenance v1 standard
- Verification against GitHub's attestation store

### 4. Immutable RC Commits
**Why**: Final tag references the **exact commit** of the RC tag, ensuring binary reproducibility.

```javascript
const rcSha = execSync(`git rev-parse "refs/tags/${rcTag}^{commit}"`);
execSync(`git tag -a "${finalTag}" "${rcSha}" -m "Promote ${rcTag}"`);
```

If the final tag already exists, the workflow aborts—tags are immutable.

### 5. Git-cliff for Both RC and Final
**Why**: Consistent changelog generation using the same tool and configuration.

Both RC and Final releases use git-cliff with identical parameters:
- `--ignore-tags` excludes RC tags from final changelog
- `--tag` sets the target tag for changelog scope
- Same `cliff.toml` configuration

### 6. Dry-Run for RC Phase Only
**Why**: The dry-run mode validates the RC phase without creating artifacts.

```yaml
dry_run:
  description: "Dry-run RC phase without pushing tags or creating releases."
```

- `dry_run=true`: Runs prepare step only, validates version computation
- `dry_run=false`: Executes full RC + Final flow (with gate in between)

---

## Workflow Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `branch` | Yes | - | Release branch (e.g., `releases/v0.8`) |
| `dry_run` | No | `true` | Dry-run RC phase only |

---

## Workflow Outputs (from prepare job)

| Output | Example | Description |
|--------|---------|-------------|
| `new_tag` | `cli/v0.8.0-rc.1` | RC tag name |
| `new_version` | `0.8.0-rc.1` | RC version |
| `base_version` | `0.8.0` | Base version without RC suffix |
| `promotion_tag` | `cli/v0.8.0` | Final tag name |
| `promotion_version` | `0.8.0` | Final version |
| `changelog_b64` | (base64) | Changelog for release notes |

---

## Environment Setup

The `cli/release` environment must be configured in GitHub:

1. Go to **Settings → Environments → New environment**
2. Name: `cli/release`
3. Configure protection rules:
   - ✅ **Required reviewers**: Add at least 1 reviewer
   - ✅ **Wait timer**: 20160 minutes (14 days)

---

## Scripts

### compute-rc-version.js
Computes the next RC version based on existing tags:

**Inputs** (env vars):
- `BRANCH`: Release branch (e.g., `releases/v0.8`)
- `COMPONENT_PATH`: Component path (e.g., `cli`)

**Outputs**:
- `new_tag`, `new_version`, `base_version`, `promotion_tag`, `promotion_version`

**Versioning Rules**:
- No existing tags → `0.X.0-rc.1`
- Only stable exists → bump patch, start RC sequence
- Only RC exists → increment RC number
- Both exist → compare and continue appropriately

---

## Validation

```bash
# Run version computation tests
node .github/scripts/compute-rc-version.test.js

# Dry-run validation
# Trigger cli-release.yml with dry_run=true
```

---

## Migration from Two-Workflow Model

The previous model required two separate workflow runs:
1. RC workflow run (with `release_candidate=true`)
2. Final workflow run (with `release_candidate=false`)

The new unified model:
1. Single workflow run handles both phases
2. Environment gate provides the separation
3. No `release_candidate` input parameter
4. Simplified scripts (removed `resolve-latest-rc.js`, `export-attestations.js`, `verify-attestations.js`)

---

## Summary

The OCM release process ensures:
- **Simplicity**: Single workflow run for entire release cycle
- **Immutability**: Final releases reference exact RC commits
- **Security**: Attestation verification via GitHub's native API
- **Reproducibility**: Same artifacts used for RC and Final
- **Control**: Environment gate with wait timer and approval
- **Consistency**: Git-cliff for both RC and Final release notes