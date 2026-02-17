# Current Controller Workflow Setup

**Date:** February 17, 2026  
**Branch:** enhance-controller-release  
**Status:** ✅ Implemented - OCI Layout Pattern

---

## Overview

The Controller workflow uses an **OCI Layout pattern** for multi-arch image builds:

1. **Single build** - Multi-arch image built once to OCI directory
2. **Test before publish** - E2E tests run before registry push
3. **No PR pollution** - Pull requests don't push to registry
4. **Platform filtering** - ORAS extracts linux/amd64 for Kind cluster

---

## File Structure

```
.github/workflows/
├── kubernetes-controller-new.yml    # Build workflow (~300 lines)
└── controller-release.yml           # Release workflow (~280 lines)
```

---

## Build Workflow: `kubernetes-controller-new.yml`

### Triggers

| Event | E2E | Publish |
|-------|-----|---------|
| `push` to `main` | ✅ | ✅ |
| `push` to `releases/v**` | ✅ | ✅ |
| `push` tag `kubernetes/controller/v**` | ✅ | ✅ |
| `pull_request` to `main` | ✅ | ❌ |
| `workflow_call` | ✅ | ✅ |

### Jobs

```
verify-chart → build → E2E → publish (conditional)
```

| Job | Purpose |
|-----|---------|
| `verify-chart` | Validate Helm chart |
| `build` | Build multi-arch to OCI Layout |
| `E2E` | Run E2E tests |
| `publish` | Push image & chart (if should_publish) |

### Key Features

**Build to OCI Layout:**
```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --output type=oci,dest=tmp/oci/controller,oci-mediatypes=true
```

**E2E - Load with ORAS platform filter:**
```bash
oras cp --from-oci-layout tmp/oci/controller:${VERSION} \
  --platform linux/amd64 docker://${IMAGE_NAME}:${VERSION}
kind load docker-image "${CONTROLLER_IMG}"
```

**Publish - Push from OCI Layout:**
```bash
oras cp --from-oci-layout tmp/oci/controller:${VERSION} ${IMAGE_NAME}:${VERSION}
```

### Outputs

| Output | Description |
|--------|-------------|
| `artifact_name` | Artifact name |
| `artifact_id` | GitHub artifact ID |
| `image_digest` | Published image digest |

---

## Release Workflow: `controller-release.yml`

### Two-Phase Process

```
PHASE 1: Release Candidate
├─ prepare      → Compute RC version
├─ tag_rc       → Create RC tag
├─ build        → Call kubernetes-controller-new.yml
└─ release_rc   → Create GitHub pre-release

⏳ GATE: Environment "controller/release" (14 days + approval)

PHASE 2: Final Release
├─ verify_attestations  → Verify RC artifacts
├─ promote_final        → Re-tag image, re-package chart
└─ release_final        → Create GitHub release
```

### Phase 2 Details

- **Image promotion**: RC tag → final tag + latest (if highest version)
- **Chart re-packaging**: New version with same IMAGE_DIGEST
- **Chart attestation**: After push

---

## Version Convention

| REF | Version |
|-----|---------|
| `kubernetes/controller/v0.21.0-rc.1` | `0.21.0-rc.1` |
| `kubernetes/controller/v0.21.0` | `0.21.0` |
| `main` | `0.0.0-main` |

**Tag Format:** `kubernetes/controller/v{MAJOR}.{MINOR}.{PATCH}[-{PRERELEASE}]`

---

## Published Artifacts

**Image:** `ghcr.io/{owner}/kubernetes/controller:{version}`
**Chart:** `oci://ghcr.io/{owner}/kubernetes/controller/chart:{version}`

---

## Comparison with CLI Workflow

| Aspect | CLI | Controller |
|--------|-----|------------|
| Jobs (build) | 2 | 4 |
| E2E Tests | ❌ | ✅ |
| Helm Chart | ❌ | ✅ |
| OCI Layout | ✅ | ✅ |
| Attestations | ✅ | ✅ |

Controller has additional complexity for E2E and Helm handling.