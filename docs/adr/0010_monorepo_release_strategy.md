# ADR 0010 — OCM Monorepo Release Strategy

* Status: Proposed
* Deciders: OCM Technical Steering Committee
* Date: 2025-09-26

Technical Story: Enable coordinated release process for multiple components in the OCM monorepo with a clear strategy for versioning, branching, and releasing, starting with proven patterns and evolving to advanced automation.

## Context and Problem Statement

The OCM project has migrated to a monorepo containing multiple independently developed components:

* `cli` - OCM CLI v2
* `kubernetes/controller` - OCM Controller v2  
* `website` - OCM Website (future)
* `ocm` - Root/Product component (future)

**Current Challenge**: Today, components are available in the monorepo but no releases have been created yet. We need to establish a coordinated release process that allows both independent component releases and aggregated product releases.

**Key Requirements**:

* Enable releases from the monorepo immediately with proven patterns
* Provide clear coordination between multiple components
* Support future evolution to
  * add `ocm`product component
  * git tag based v
  * advanced automation
* Maintain team familiarity with release processes

## Decision Drivers

* **Start Simple, Evolve**: Begin with proven patterns, avoid big-bang complexity
* **Immediate Release Capability**: Enable monorepo releases quickly without waiting for complex automation
* **Component Independence**: Allow independent component releases while maintaining coordination
* **Clear Evolution Path**: Provide defined migration to advanced solutions without technical debt
* **Team Familiarity**: Leverage existing release process knowledge and patterns
* **Manageable Complexity**: Keep initial implementation simple enough for reliable operation

## Solution Approach

**Chosen Strategy**: Phased Implementation with Lockstep SemVer Versioning

**Core Principle**: All components share same MAJOR.MINOR versions, independent PATCH releases possible

**Evolution Path**:

* **Phase 1 (Immediate)**: Multi-component releases with VERSION files and unified branching
* **Phase 2 (Evolution)**: Add OCM root component for tested bundles  
* **Phase 3 (Advanced)**: Migrate to Git-native tags when automation is mature

**Why This Approach**:

* **VERSION files over Git tags**: Faster to implement and debug during initial rollout
* **Lockstep MAJOR.MINOR**: Simplifies dependency management and user communication
* **Three-phase evolution**: Each phase provides value while building toward advanced automation
* **Unified branching**: Reduces coordination overhead compared to per-component branches

### Key Design Decisions

#### Decision 1: Version Storage (Phase 1)

| Option | Description | Status |
|--------|-------------|---------|
| **V1: VERSION Files** | `cli/VERSION`, `controller/VERSION` files | **Chosen** *(Start simple)* |
| **V2: Git Tags only** | Only tags: `cli/v0.9.0` | **Future** *(Phase 3 target)* |

**Rationale**: Start with VERSION files for faster implementation, migrate to Git tags when automation is mature.

#### Decision 2: Branching Strategy  

| Option | Description | Status |
|--------|-------------|---------|
| **B0: Unified Branch** | `releases/v0.9` for all components | **Chosen** *(Best fit)* |
| **B1: Per-Component** | `releases/cli/v0.9` `releases/controller/v0.9` | **Alternative** *(If needed)* |
| **B2: Tags Only** | Temporary branches for patches | **Rejected** *(Too complex)* |

**Rationale**: Unified branching simplifies coordination and reduces overhead.

#### Decision 3: Root Component Timeline

| Option | Description | Status |
|--------|-------------|---------|
| **R1: Immediate Implementation** | Implement OCM root component immediately | **Future** *(Phase 2 target)* |
| **R2: Phased Approach** | Add root component after component releases stable | **Chosen** *(Start simple)* |

**Rationale**: Phased approach aligns with "Start Simple, Evolve" philosophy.

## High-level Architecture

### Repository Structure (Phase 1)

```text
Repository Structure:
├── cli/
│   ├── VERSION                       # Component version (e.g., "0.9.0")
│   └── ...                           # CLI source code
├── kubernetes/controller/
│   ├── VERSION                       # Component version (e.g., "0.9.0") 
│   └── ...                           # Controller source code
├── website/                          # Future component
└── .github/
    ├── config/
    │   └── release.yml               # Release notes configuration
    └── workflows/
        ├── release-component.yaml    # New: Generic component release workflow
        ├── release-branch.yaml       # New: Unified branch management
        ├── release-drafter.yaml      # New: Automated release notes workflow
        └── release-orchestrator.yaml # New: Multi-component release wrapper

```

## Contract

### Phase 1: VERSION File Based Releases

#### VERSION File Management

**Implementation Required**:

* Each component maintains a `VERSION` file containing semantic version
* Lockstep MAJOR.MINOR versions maintained manually across all components
* PATCH versions can differ between components
* During development: VERSION contains next release version with `-dev` suffix

```text
# Development phase:
cli/VERSION:        "0.9.0-dev"
kubernetes/controller/VERSION: "0.9.0-dev"

# After MINOR release:
cli/VERSION:        "0.9.0"
kubernetes/controller/VERSION: "0.9.0"

# After CLI PATCH release:
cli/VERSION:        "0.9.1"  
kubernetes/controller/VERSION: "0.9.0"
```

#### Release Branch Strategy

**Implementation Required**:

* Unified release branches: `releases/v<major>.<minor>`
* All components share the same release branch
* Branch contains VERSION files with `-dev` suffix indicating version in development
* `-dev` suffix persists in release branches, showing what's being developed

```text
# Release branch created from main:
releases/v0.9/
├── cli/VERSION: "0.9.0-dev"        # Developing 0.9.0
└── controller/VERSION: "0.9.0-dev"

# After patch development:
releases/v0.9/
├── cli/VERSION: "0.9.1-dev"        # Developing 0.9.1 patch
└── controller/VERSION: "0.9.0-dev" # Still on 0.9.0
```

#### CI/CD Workflows

**Implementation Required**:

1. **Unified Branch Creation**:

   ```yaml
   # Workflow: release-branch.yaml

   # Creates releases/v0.9 from main
   # Validates all VERSION files are in lockstep (same MAJOR.MINOR)
   # Fails if lockstep validation fails
   # Does NOT modify VERSION files - they must be prepared upfront
   ```

2. **Generic Component Release Workflow**:

   ```yaml  
   # Workflow: release-component.yaml

   inputs:
     component (string): "cli" | "controller" | "website"
     release_candidate (boolean): true | false
     release_candidate_name (string): "rc.1"   # Optional, if release_candidate is true, default "rc.1"

   # Reads <component>/VERSION as single source of truth
   # Creates tags, publishes artifacts
   # Reusable for all current and future components
   ```

3. **Multi-Component Release Orchestrator**:

   ```yaml
   # Workflow: release-orchestrator.yaml
   
   inputs:
     release_candidate (boolean): true | false
     release_candidate_name (string): "rc.1"      # Optional, if release_candidate is true, default "rc.1"
     components: ["cli", "controller"]            # Components to release  
   
   # Orchestrates parallel component releases
   # - Triggers release-component.yaml for each component in parallel
   # - Waits for all to complete or handles partial failures
   # - Provides summary of successful/failed component releases
   # - Enables individual component re-runs on failures
    ```

4. **Release Notes Workflow**:

   ```yaml
   # Workflow: release-drafter.yaml
   
   # Triggers on push to release branches (releases/v*)
   # Automatic generation via GitHub API based on commits/PRs between tags
   # Draft release notes continuously updated during development
   # Configuration via .github/config/release.yml
   # Uses GitHub API for commit/PR-based note generation
   # Automatically creates/updates draft releases
   ```

5. **Release Coordination & Orchestration**:

   ```yaml
   # Multi-Component Release Orchestration (new sprint cycle)
   
   # Step 1: Final Release (RC -> Final)
   # - Trigger release workflow for current RC version (rc.N -> final)
   # - Executes for all components that have RC tags
   # - Creates final tags and releases
   
   # Step 2: New Release Branch Creation  
   # - Create new unified release branch (releases/vX.Y+1)
   # - Validate lockstep compliance across all VERSION files
   # - Fail if versions not aligned
   
   # Step 3: Initial RC Release
   # - Trigger component release workflows (RC=true, rc.1)
   # - Wrapper job orchestrates individual component workflows
   # - Independent execution: failure in one component doesn't block others
   # - Individual component re-run capability for failed releases
   ```

#### Tagging Strategy

**Implementation Required**:

* Component-scoped Git tags: `<component>/v<version>`
* Examples: `cli/v0.9.0`, `kubernetes/controller/v0.9.0`
* Tags created from unified release branches
* Final tags only after RC validation

### Phase 2: Root Component Addition (Future)

**Implementation Required**:

#### Repository Structure Extension

```text
├── ocm/
│   ├── VERSION                      # OCM product version (lockstep with components)
│   ├── component-constructor.yaml   # Version matrix for tested combinations
│   └── conformance/                 # End-to-end integration test suite
└── .github/workflows/
    └── ocm-update.yaml             # New: OCM root component update workflow
```

#### OCM Root Component Release Strategy

**MINOR Release Handling** (via release-orchestrator.yaml):
```yaml
# After all component releases complete successfully:
ocm-release-job:
  needs: [component-releases]
  if: success()
  uses: ./.github/workflows/release-component.yaml
  with:
    component: "ocm"
    release_candidate: ${{ inputs.release_candidate }}
```

**PATCH Release Handling** (triggered by individual component releases):
```yaml
# New workflow: ocm-update.yaml
# Triggered after individual component PATCH releases

on:
  workflow_run:
    workflows: ["Generic Component Release"]
    types: [completed]
    
jobs:
  update-ocm-if-patch:
    if: github.event.workflow_run.conclusion == 'success'
    steps:
      - name: "Detect PATCH Release"
        run: |
          # Parse component and version from completed workflow
          COMPONENT="${{ github.event.workflow_run.inputs.component }}"
          IS_RC="${{ github.event.workflow_run.inputs.release_candidate }}"
          
          # Only process non-RC releases
          if [ "$IS_RC" = "false" ]; then
            # Get released version and check if it's a PATCH
            RELEASED_VERSION=$(git describe --tags --match="${COMPONENT}/v*" | head -1)
            # Extract MAJOR.MINOR.PATCH
            if [[ $RELEASED_VERSION =~ ${COMPONENT}/v([0-9]+)\.([0-9]+)\.([1-9][0-9]*) ]]; then
              echo "PATCH release detected: $RELEASED_VERSION"
              echo "component=$COMPONENT" >> $GITHUB_OUTPUT
              echo "version=$RELEASED_VERSION" >> $GITHUB_OUTPUT
              echo "is_patch=true" >> $GITHUB_OUTPUT
            fi
          fi
          
      - name: "Update component-constructor.yaml"
        if: steps.detect.outputs.is_patch == 'true'
        run: |
          COMPONENT="${{ steps.detect.outputs.component }}"
          VERSION="${{ steps.detect.outputs.version }}"
          
          # Update component-constructor.yaml with new PATCH version
          yq eval ".components[] |= select(.name == \"$COMPONENT\").version = \"$VERSION\"" -i ocm/component-constructor.yaml
          
      - name: "Run Conformance Tests"
        if: steps.detect.outputs.is_patch == 'true'
        run: |
          # Run conformance tests with updated component matrix
          cd ocm/conformance
          ./run-tests.sh
          
      - name: "Release OCM PATCH Version"
        if: steps.detect.outputs.is_patch == 'true'
        uses: ./.github/workflows/release-component.yaml
        with:
          component: "ocm"
          release_candidate: false
```

#### Component Constructor Management

**Lockstep Behavior (MINOR/MAJOR)**:
```yaml
# All components share same MAJOR.MINOR due to lockstep
components:
  - name: cli
    version: v0.9.0      # Same MAJOR.MINOR
  - name: controller  
    version: v0.9.0      # Same MAJOR.MINOR
```

**PATCH Update Behavior**:
```yaml
# Individual PATCH releases update only affected component
# Before CLI PATCH release:
components:
  - name: cli
    version: v0.9.0
  - name: controller  
    version: v0.9.0

# After CLI PATCH release (via ocm-update.yaml):
components:
  - name: cli
    version: v0.9.1      # Updated by ocm-update workflow
  - name: controller  
    version: v0.9.0      # Unchanged
```

#### Workflow Integration

**Two-Tiered Release Process**:
1. **Orchestrated Releases** (MINOR/MAJOR): `release-orchestrator.yaml` → triggers OCM release
2. **Individual Releases** (PATCH): `release-component.yaml` → triggers `ocm-update.yaml`

**Benefits**:
- OCM root component stays in sync with all component PATCH releases
- Conformance testing validates each PATCH before OCM update
- Automatic OCM versioning for both orchestrated and individual releases
- Single OCM release per component PATCH (no bundling issues)

### Phase 3: Git-native Versioning (Future)

**Migration Path**:

* Replace VERSION files with Git tags as single source of truth
* Maintain same branching and workflow structure
* Enhanced automation for version management

## Pros and Cons of the Solution Approach

### Pros

* **Immediate Implementation**: Can start releases quickly using simple VERSION files
* **Familiar Patterns**: Builds on known release process concepts
* **Low Risk**: Simple initial implementation reduces chance of failure
* **Clear Evolution**: Defined path to advanced features without technical debt
* **Team Alignment**: Leverages existing knowledge and experience
* **Lockstep Simplicity**: Coordinated MAJOR.MINOR versions simplify management

### Cons  

* **Manual Workflow Triggers**: Phase 1 requires manual triggering of release workflows
* **Implementation Overhead**: New workflows and tooling need to be built (although existing workflows and patterns from OCM v1 release flow can be reused)
* **Incomplete Initially**: Phase 1 doesn't include root component features

## Discovery and Distribution

### Implementation Plan

**Phase 1 (ASAP)**:

1. Create VERSION files for existing components
2. Implement all release workflows
3. Test with first monorepo releases

**Phase 2 (After 2-3 successful releases)**:

1. Implement OCM root component structure in repository
2. Add component-constructor.yaml
3. Develop conformance test framework
4. Automate lockstep validation

**Phase 3 (6+ months)**:

1. Design Git-native tag strategy
2. Migrate from VERSION files to Git tags
3. Enhanced automation and validation

### Team Responsibilities

* **Release Manager**: Coordinates releases, validates lockstep compliance
* **Maintainers**: Manage component VERSION files, approve releases, implement new workflows and automation
* **TSC**: Approve major changes and migration phases

## Conclusion

This phased implementation approach enables the OCM team to start releasing from the monorepo immediately using proven patterns, while providing a clear evolution path to advanced features. By starting simple with VERSION files and unified branching, we reduce implementation risk and allow the team to learn from experience before adding complexity.

The lockstep versioning strategy simplifies coordination between components while maintaining the flexibility for independent patch releases. This approach balances immediate needs with long-term goals, ensuring sustainable release management as the project grows.
