# OCM Monorepo Release Strategy - Team Discussion

**Date:** September 26, 2025  
**Purpose:** Develop shared understanding for new release strategy  
**Status:** Discussion basis for ADR

---

## 🎯 Summary

### Current Status

We have **migrated to a monorepo** containing multiple OCM v2 components:

- `cli` - CLI v2
- `kubernetes/controller` - controller v2
- `website` (future)
- `ocm` - Root / Product component (future)

### Goal

Establish coordinated release process for multiple components and an aggregating `ocm` component with a clear strategy for versioning, branching, and releasing.

### Solution

Our approach combines multiple coordinated elements:

**Lockstep SemVer:** All components share MAJOR.MINOR versions, independent PATCH releases possible.  
**Root Component:** Aggregating `ocm` component bundles compatible sub-component versions.  
**Unified Branching:** Single release branch per MINOR version for coordinated releases.  
**Evolutionary Implementation:** Start simple with proven patterns, evolve to full automation.

---

## Core Concepts

### 1. Implementation Philosophy: Start Simple, Evolve

**Core Principle:** Begin with proven patterns, evolve based on experience

**Why this approach:**

- Reduces initial complexity and implementation risk
- Leverages lessons learned from OCM v1 release experience
- Provides clear migration path without big-bang changes
- Allows team to focus on process before tooling complexity

### 2. Lockstep SemVer Versioning

**Rule:** All components share same MAJOR.MINOR, independent PATCH releases

**Why lockstep?**

- Simplifies the overall release process.
- Versioning of ocm root component is straightforward.

```text
cli/v0.9.0, controller/v0.9.0, ocm/v0.9.0     ← coordinated release
cli/v0.9.1, controller/v0.9.0, ocm/v0.9.1     ← independent patch
```

### 3. Root Component "ocm"

Use `component-constructor.yaml` as version matrix, referencing all sub-components with their final release versions.

```yaml
components:
- name: ocm.software/ocm
  version: 0.9.1  # new root component version
  provider:
    name: ocm.software
  references:
    - name: cli
      component: ocm.software/cli
      version: 0.9.1  # patched
    - name: kubernetes-controller
      component: ocm.software/kubernetes/controller
      version: 0.9.0  # unchanged
```

**Purpose:** Umbrella component for all sub-components. Bundles compatible versions, tested together using conformance tests.

**Conformance Testing Strategy:**

**Component-Level Tests:** Each component has individual tests running
**Root Component Conformance Tests:** End-to-end tests validating sub-components work together

- **Phase 1:** Manual end-to-end testing during 2-week RC phase, stakeholder validation
- **Phase 2:** Conformance test suite (end-to-end scenarios using sub-components)  

**Risk Management:** Initially rely on component-level testing + manual RC validation until automated conformance tests are established

### 4. Release Roles & Responsibilities

**Release Manager:** Orchestrates sprint releases, coordinates RC promotions, decides on emergency patches.  
**Maintainers:** Ensure component readiness, approve backports, validate release quality.  
**TSC (Technical Steering Committee):** Sign-off for high-risk changes and major decisions.

**Decision Gates:**

- **RC → Release Promotion:** Release Manager decision, with maintainer sign-off
- **Emergency Release Approval:** Release Manager decision (critical CVSS (≥ 9) or business critical)
- **Backport Authorization:** Maintainer approval required
- **Major Policy Changes:** TSC approval (e.g., support policy, branching strategy changes)

### 5. Release Notes

**Approach:** Automated per-component release notes + aggregated root component notes

- Path-based change detection, e.g., `cli/**` → CLI release notes (avoid additional component-scoped labels)  
- Aggregated root component notes with component sections
  
### 6. Release Cadence

**4-Week Cycle:** 2 weeks development + 2 weeks RC testing → orchestrated release  
**Maintenance:** y-2 policy (current + 2 previous MINOR versions) ???  
**Emergency:** Critical fixes (CVSS ≥ 9 or business critical) can be released anytime

---

## 🚀 Key Decisions We Need to Make

### Decision 1: Version Storage

| Option | Description | Pros | Cons | **Recommendation** |
|--------|-------------|------|------|-------------------|
| **V1: VERSION Files** | `cli/VERSION`, `controller/VERSION` | ✅ Explicit and readable<br>✅ Faster implementation | ❌ Extra commits needed<br>❌ Potential VERSION/tag drift | 🟡 **Recommended** *(Start simple)* |
| **V2: Git Tags only** | Only tags: `cli/v2.1.0` | ✅ Single source of truth<br>✅ No version bump commits | ❌ More complex automation<br>❌ Requires robust `git describe` | 🟢 **Target Solution** *(Long-term goal)* |

**Proposal:** Start with V1 for faster initial implementation, re-using principles learned in OCM v1, migrate to V2 once automation is mature.

### Decision 2: Branching Strategy

| Option | Description | Pros | Cons | **Recommendation** |
|--------|-------------|------|------|-------------------|
| **B0: One Branch per Minor** | `releases/2.1` for all components | ✅ Simple coordination | ❌ Discipline required | 🟢 **Recommended** *(Best fit)* |
| **B1: Branch per Component** | `releases/cli/2.1` `releases/controller/2.1` | ✅ Clear separation | ❌ More branches to manage | 🟡 **Alternative** *(If needed)* |
| **B2: Tags Only** | Temporary branches for patches | ✅ Minimal overhead | ❌ Complex automation<br>❌ No patch baseline history | 🔴 **Not Recommended** *(Too complex)* |

**Proposal:** Start with B0 (unified branch) for simplicity, reducing overhead and coordination benefits.

### Decision 3: Root Component Implementation

| Option | Description | Pros | Cons | **Recommendation** |
|--------|-------------|------|------|-------------------|
| **R1: Root Component from Start** | Implement `ocm` root component immediately with sub-component references | ✅ Complete product artifact<br>✅ Clear version matrix | ❌ High initial complexity<br>❌ Big-bang approach | 🔴 **Not Recommended** *(Against philosophy)* |
| **R2: Phased Approach** | Start with R1, add root component after component release is stable | ✅ **Aligns with "Start Simple, Evolve"**<br>✅ Learn from initial releases<br>✅ Manageable complexity | ❌ Minor migration effort<br>❌ Delayed complete product | 🟢 **Recommended** *(Aligns with philosophy)* |

**Proposal:** Start with R2 (phased approach) - align with our "Start Simple, Evolve" philosophy by proving the multi-component release process first, then adding root component complexity.

---

## 🗓️ Example Workflow: Sprint Cycle

**Context:** All release operations happen in release branches (`releases/X.Y` or `releases/<component>/X.Y`, depending on decision B0/B1) and will be supported by GitHub workflows.

### Sprint N: Development Phase (2 weeks)

```bash
# Create release branch from main for new minor version
git checkout main
git checkout -b releases/v0.9
git push origin releases/v0.9

# Create RCs for all components
# Triggered by GitHub Actions workflow
cli/v0.9.0-rc.1
kubernetes/controller/v0.9.0-rc.1
ocm/v0.9.0-rc.1
```

### Sprint N+1: RC Testing Phase (2 weeks)

```bash
# Bug found in CLI during RC testing
git checkout releases/v0.9
git cherry-pick <bugfix>

# Increment RC versions for affected components
cli/v0.9.0-rc.2           ← RC incremented due to patch
kubernetes/controller/v0.9.0-rc.1  ← unchanged
ocm/v0.9.0-rc.2           ← RC incremented (references patched CLI)
```

### Sprint N+1 End: Orchestrated Release Day

**Release Manager orchestrates:** All current RCs get promoted to finals

```bash
# All RCs become finals simultaneously
cli/v0.9.0 
kubernetes/controller/v0.9.0
ocm/v0.9.0

# Start next cycle - create new release branch + RCs
releases/v0.10 → cli/v0.10.0-rc.1, controller/v0.10.0-rc.1, ocm/v0.10.0-rc.1
```

**Emergency patches:** Can be released immediately with shorter RC phase as decided by Release Manager.

### Maintenance Patches (Separate Workflow)

```bash
# Security fix for previous cli release (already finalized)
git checkout releases/0.8  # previous release branch
git cherry-pick <security-fix>

# Create patch RCs for maintenance release
cli/v0.8.1-rc.1
kubernetes/controller/v0.8.0  ← keep same version if unaffected
ocm/v0.8.1-rc.1           ← root component references patched versions

# These maintenance RCs also get promoted during next orchestrated release day.
```

---

## ❓ Discussion Points & Risks

### Key Decisions Needed

1. **Version Storage:** V1 (VERSION files) or direct V2 (Git tags)?
2. **Branching Strategy:** B0 (unified branch) or B1 (per-component branches) or B2 (tags only)?
3. **Implementation Timeline:** R1 (establish root component immediately) or R2 (phased approach)?
4. **Support Policy Details:** Confirm y-2 policy specifics, branch retirement, and EOL procedures

### Risks & Open Questions

1. **Without conformance tests:** How do we ensure component compatibility in Phase 1?
2. **Cherry-pick overhead:** Who owns backports to release branches and for how long
3. **Emergency criteria:** What exactly constitutes an emergency release beyond CVSS ≥ 9?
4. **Maintenance burden:** Do we stick to y-2? This would mean support for only three months.
