# Überblick über die GitHub Actions Workflows

Dieses Dokument ist der **Schnellkontext für LLM-Sitzungen** rund um Release-/Build-Workflows.
Ziel: Eine neue Sitzung soll ohne weitere Exploration sofort produktiv Änderungen an Workflow-Setup, RC/Final-Flow und Publish-Pipeline umsetzen können.

---

## 0) Was ist der aktuelle Sollzustand?

Der Release-Prozess unterstützt **zwei Modi** über `cli-release.yml`:

1. **Release Candidate (RC)**
   - `release_candidate=true`
   - berechnet neuen RC-Tag, erstellt/pusht RC-Tag, baut, published, erstellt GitHub **Pre-Release**.
   - Exportiert Attestation-Bundles für Binaries und OCI-Image ins Release.

2. **Final Promotion**
   - `release_candidate=false`
   - nimmt **existierenden RC** auf dem Release-Branch als Source of Truth,
   - **verifiziert alle Attestationen** aus dem RC-Release,
   - erstellt Final-Tag vom RC-Commit,
   - promoted OCI-Tag auf final + `latest`,
   - erstellt GitHub **Final Release** aus RC-Assets/RC-Notes.

Zusätzlich:
- `dry_run=true` verhindert tag-/publish-seitige Schreiboperationen.
- `release-candidate-version.yml` ist der zentrale Reusable-Workflow für Metadaten (RC + Final Inputs/Outputs).

### Design-Prinzip: Generische Komponenten-Unterstützung

Alle Skripte und Workflows sind bewusst **generisch** gestaltet, um verschiedene Komponenten zu unterstützen:
- **Aktuell**: `cli` (OCM CLI)
- **Geplant**: `kubernetes/controller` (OCM Controller)

Die Parametrisierung erfolgt über:
- `COMPONENT_PATH` / `component_path` für den Komponenten-Pfad
- `ASSET_PATTERNS_JSON` für flexible Asset-Glob-Patterns
- `OCI_SUBJECTS_JSON` / `TARGET_REPO` für OCI-Referenzen
- `TAG_PREFIX` für komponenten-spezifische Tag-Präfixe

---

## 1) Workflow-Übersicht

| Datei | Name | Rolle |
|---|---|---|
| `.github/workflows/release-branch.yml` | Create OCM Release Branch | Erstellt `releases/v0.X` Branches manuell. |
| `.github/workflows/release-candidate-version.yml` | Release Candidate Version | Reusable für RC/Final-Metadaten + RC-Changelog. |
| `.github/workflows/cli-release.yml` | CLI Release | Orchestrierung für RC-Release **und** Final-Promotion. |
| `.github/workflows/cli.yml` | CLI | Build + optional Publish + Attestations für CLI. |

---

## 2) High-Level Beziehungen

```text
release-branch.yml (manuell)
   └─ erstellt releases/v0.X

cli-release.yml (manuell)
   ├─ prepare (calls release-candidate-version.yml)
   ├─ RC-Pfad:
   │    tag_rc → build (calls cli.yml) → release_rc (export attestations)
   └─ Final-Pfad:
        validate_final → [verify_attestations + tag_final] → promote_image → release_final

cli.yml (push/PR/workflow_call)
   ├─ build (compute-version.js, attest binaries)
   └─ publish (push OCI, attest OCI image)
```

---

## 3) Detaillierte Flow-Diagramme

### 3.1 RC-Flow (release_candidate=true)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ cli-release.yml (release_candidate=true)                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 1. prepare                                                       │   │
│  │    └─ release-candidate-version.yml                              │   │
│  │        ├─ compute-rc-version.js → new_tag, new_version, etc.    │   │
│  │        └─ git-cliff → changelog_b64                              │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 2. tag_rc (if dry_run=false)                                     │   │
│  │    └─ Creates annotated RC tag (e.g. cli/v0.1.0-rc.1)           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 3. build (calls cli.yml with ref=new_tag)                        │   │
│  │    ├─ compute-version.js → VERSION                               │   │
│  │    ├─ task cli:generate/ctf → binaries + OCI layout             │   │
│  │    ├─ actions/attest-build-provenance → attest binaries         │   │
│  │    └─ publish job:                                               │   │
│  │        ├─ oras push → OCI image to GHCR                          │   │
│  │        └─ actions/attest-build-provenance → attest OCI image    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 4. release_rc                                                    │   │
│  │    ├─ Download build artifacts                                   │   │
│  │    ├─ attestations-release-assets.js                            │   │
│  │    │   ├─ gh attestation download (binaries)                    │   │
│  │    │   ├─ gh attestation download (OCI image)                   │   │
│  │    │   ├─ Rename to readable names                               │   │
│  │    │   └─ Create attestations-index.json                        │   │
│  │    └─ softprops/action-gh-release                                │   │
│  │        └─ Upload: binaries, OCI layout, attestation bundles     │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Output: GitHub Pre-Release with all artifacts + attestations          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Final-Flow (release_candidate=false)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ cli-release.yml (release_candidate=false)                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 1. prepare                                                       │   │
│  │    └─ release-candidate-version.yml                              │   │
│  │        └─ resolve-latest-rc.js → latest_rc_tag, promotion_tag   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 2. validate_final                                                │   │
│  │    └─ Ensures latest_rc_tag exists on branch                    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│              ┌───────────────┴───────────────┐                          │
│              ▼                               ▼                          │
│  ┌──────────────────────────┐   ┌──────────────────────────┐           │
│  │ 3a. verify_attestations  │   │ 3b. tag_final            │           │
│  │  (parallel)              │   │  (if dry_run=false)      │           │
│  │  ├─ Download RC assets   │   │  └─ Create final tag     │           │
│  │  └─ verify-attestations- │   │     from RC commit       │           │
│  │     from-release.js      │   │     (e.g. cli/v0.1.0)    │           │
│  │     ├─ Load index.json   │   └──────────────────────────┘           │
│  │     ├─ gh attestation    │                                          │
│  │     │  verify (binaries) │                                          │
│  │     └─ gh attestation    │                                          │
│  │        verify (OCI)      │                                          │
│  └──────────────────────────┘                                          │
│              │                               │                          │
│              └───────────────┬───────────────┘                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 4. promote_image                                                 │   │
│  │    └─ oras tag :rc_version → :final_version + :latest           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 5. release_final                                                 │   │
│  │    ├─ Download RC release assets                                 │   │
│  │    ├─ Capture RC release notes                                   │   │
│  │    └─ Create GitHub Final Release (prerelease=false)            │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Output: GitHub Final Release + OCI :latest tag                        │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4) Detaillierte Workflow-Analyse

### 4.1 `release-branch.yml`

#### Trigger
- `workflow_dispatch`

#### Inputs
- `target_branch` (required): muss zu `^releases/v0\.[0-9]+$` passen
- `source_branch` (optional, default `main`)

#### Verhalten
- versucht GitHub App Token (`actions/create-github-app-token`) mit `permission-contents: write`
- fallback auf `GITHUB_TOKEN`
- erstellt Branch nur, wenn Ziel nicht bereits existiert
- schreibt Step Summary mit Source, Target, SHA

---

### 4.2 `release-candidate-version.yml` (Reusable)

#### Zweck
Zentraler Metadata-Workflow für beide Flows:
- RC vorbereiten (neue Version berechnen, Changelog generieren)
- Final-Promotion-Metadaten aus latest RC ableiten

#### Inputs
- `branch` (required): Release-Branch (z.B. `releases/v0.1`)
- `component_path` (required): Komponenten-Pfad (z.B. `cli`)
- `release_candidate` (optional, boolean, default `true`)

#### Outputs
**RC-Outputs (bei release_candidate=true)**
- `new_tag`: Neuer RC-Tag (z.B. `cli/v0.1.0-rc.3`)
- `new_version`: Neue RC-Version (z.B. `0.1.0-rc.3`)
- `base_version`: Base-Version (z.B. `0.1.0`)
- `promotion_tag`: Promotion-Tag (z.B. `cli/v0.1.0`)
- `changelog_b64`: Base64-encodierter Changelog

**Final-Outputs (bei release_candidate=false)**
- `latest_rc_tag`: Letzter RC-Tag auf dem Branch
- `latest_rc_version`: Letzte RC-Version
- `latest_promotion_tag`: Final-Tag für Promotion
- `latest_promotion_version`: Final-Version

#### Steps
1. Checkout (sparse: `component_path`, `.github/scripts`, `fetch-depth: 0`)
2. `compute-rc-version.js` (immer, aber Summary nur bei RC)
3. `resolve-latest-rc.js` (nur bei `release_candidate=false`)
4. `git-cliff` (nur bei `release_candidate=true`)
5. `Summarize changelog` (nur bei RC, setzt `changelog_b64`)

---

### 4.3 `cli-release.yml` (Orchestrator)

#### Trigger
- `workflow_dispatch`

#### Inputs
- `branch` (required): Release-Branch
- `release_candidate` (optional, default `true`)
- `dry_run` (optional, default `true`)

#### Concurrency
```yaml
group: cli-release-${{ github.event.inputs.branch }}
cancel-in-progress: true
```

#### Job-Matrix nach Modus

**A) RC-Modus (`release_candidate=true`)**
1. `prepare` → calls `release-candidate-version.yml`
2. `tag_rc` (nur wenn `dry_run=false`) → erstellt RC-Tag
3. `build` (nur wenn tag gepusht) → ruft `cli.yml` auf
4. `release_rc` → exportiert Attestationen, erstellt Pre-Release

**B) Final-Modus (`release_candidate=false`)**
1. `prepare` → calls `release-candidate-version.yml`
2. `validate_final` → prüft ob RC existiert
3. `verify_attestations` → verifiziert alle RC-Attestationen
4. `tag_final` (parallel zu verify) → erstellt Final-Tag
5. `promote_image` → ORAS tag promotion
6. `release_final` → erstellt Final Release

---

### 4.4 `cli.yml` (Build/Publish)

#### Trigger
- push auf `main`, `releases/v**`, tags `cli/v**`
- PR auf `main` (mit `cli/**` oder Workflow-Datei-Änderung)
- `workflow_call`

#### Job `build`
1. Checkout (sparse: `.github/scripts`, `cli/`)
2. Setup Go, Task, buildx
3. `compute-version.js` → berechnet VERSION
4. `task cli:generate/ctf` + `task cli:verify/ctf`
5. **Attest binaries** (nicht auf PR)
6. Branch eligibility (`should_push_oci_image`)
7. Upload artifacts (nur wenn push-eligible)

#### Job `publish`
- nur wenn `should_push_oci_image=true`
- ORAS push aus OCI-Layout
- optional branch tag (`:main`)
- **Attest OCI image** mit `push-to-registry: true`

---

## 5) Skript-Verträge (vollständig)

### 5.1 `compute-version.js`

**Zweck**: Vereinheitlichte Versionsberechnung für alle OCM-Komponenten (CLI, Bindings, etc.)

**Verwendet in**: `cli.yml` → Build Job

#### ENV-Variablen
| Variable | Required | Beschreibung |
|----------|----------|--------------|
| `REF` | ✅ | Git ref (Branch-Name, Tag-Name, z.B. `main`, `cli/v1.2.3`) |
| `TAG_PREFIX` | ✅ | Tag-Präfix-Pattern (z.B. `cli/v`, `bindings/go/helm/v`) |

#### Outputs
- `VERSION` (exportVariable + setOutput): Berechnete Version

#### Logik
```javascript
// Tag-Refs (matching pattern): Extrahiert Version aus Tag-Name
computeVersion("cli/v1.2.3", "cli/v")           // → "1.2.3"
computeVersion("cli/v1.2.3-rc.1", "cli/v")      // → "1.2.3-rc.1"

// Branch/andere Refs: Generiert Pseudo-Version
computeVersion("main", "cli/v")                 // → "0.0.0-main"
computeVersion("releases/v0.1", "cli/v")        // → "0.0.0-releases-v0.1"
computeVersion("feature/foo", "cli/v")          // → "0.0.0-feature-foo"
```

#### Exportierte Funktionen
- `computeVersion(ref, tagPrefix)`: Hauptfunktion

---

### 5.2 `compute-rc-version.js`

**Zweck**: Berechnet die nächste RC-Version basierend auf existierenden Tags

**Verwendet in**: `release-candidate-version.yml` → prepare Job

#### ENV-Variablen
| Variable | Required | Beschreibung |
|----------|----------|--------------|
| `BRANCH` | ✅ | Release-Branch (z.B. `releases/v0.1`) |
| `COMPONENT_PATH` | ✅ | Komponenten-Pfad (z.B. `cli`) |
| `RELEASE_CANDIDATE` | ❌ | `true`/`false`, default `true`. Steuert Summary-Ausgabe |

#### Outputs
- `new_tag`: Neuer RC-Tag (z.B. `cli/v0.1.0-rc.3`)
- `new_version`: Neue RC-Version (z.B. `0.1.0-rc.3`)
- `base_version`: Base-Version ohne RC-Suffix (z.B. `0.1.0`)
- `promotion_tag`: Tag für spätere Final-Promotion (z.B. `cli/v0.1.0`)

#### Versioning-Rules (computeNextVersions)
```javascript
// Keine Tags existieren → Start fresh
basePrefix="0.1", latestStable=null, latestRc=null
  → baseVersion="0.1.0", rcVersion="0.1.0-rc.1"

// Nur stable Tag → Bump patch, start RC
basePrefix="0.1", latestStable="cli/v0.1.0", latestRc=null
  → baseVersion="0.1.1", rcVersion="0.1.1-rc.1"

// Nur RC Tags → Continue RC numbering
basePrefix="0.1", latestStable=null, latestRc="cli/v0.1.1-rc.2"
  → baseVersion="0.1.1", rcVersion="0.1.1-rc.3"

// Stable neuer als RC → Bump patch, new RC sequence
basePrefix="0.1", latestStable="cli/v0.1.2", latestRc="cli/v0.1.1-rc.4"
  → baseVersion="0.1.3", rcVersion="0.1.3-rc.1"

// RC neuer als stable → Continue RC sequence
basePrefix="0.1", latestStable="cli/v0.1.1", latestRc="cli/v0.1.2-rc.6"
  → baseVersion="0.1.2", rcVersion="0.1.2-rc.7"
```

#### Exportierte Funktionen
- `computeNextVersions(basePrefix, latestStableTag, latestRcTag, bumpMinorVersion)`: Hauptlogik
- `parseBranch(branch)`: Extrahiert Base-Prefix aus Branch
- `parseVersion(tag)`: Parsed Version-Tag zu `[major, minor, patch]`
- `isStableNewer(stable, rc)`: Vergleicht Stable vs RC

#### Besonderheit
- Summary wird **nur bei `RELEASE_CANDIDATE=true`** geschrieben

---

### 5.3 `resolve-latest-rc.js`

**Zweck**: Findet den neuesten RC-Tag auf einem Release-Branch für Final-Promotion

**Verwendet in**: `release-candidate-version.yml` → prepare Job (nur bei `release_candidate=false`)

#### ENV-Variablen
| Variable | Required | Beschreibung |
|----------|----------|--------------|
| `BRANCH` | ✅ | Release-Branch (z.B. `releases/v0.1`) |
| `COMPONENT_PATH` | ✅ | Komponenten-Pfad (z.B. `cli`) |
| `RELEASE_CANDIDATE` | ❌ | `true`/`false`. Steuert Summary-Ausgabe |

#### Outputs
- `latest_rc_tag`: Neuester RC-Tag (z.B. `cli/v0.1.0-rc.3`)
- `latest_rc_version`: RC-Version ohne Tag-Prefix (z.B. `0.1.0-rc.3`)
- `latest_promotion_version`: Final-Version (z.B. `0.1.0`)
- `latest_promotion_tag`: Final-Tag (z.B. `cli/v0.1.0`)

#### Logik
```javascript
// Input: branch="releases/v0.1", componentPath="cli"
// Git command: git tag --list 'cli/v0.1.*-rc.*' | sort -V | tail -n1

resolveLatestRc("releases/v0.1", "cli")
// Falls letzter RC ist cli/v0.1.2-rc.5:
// → {
//     latestRcTag: "cli/v0.1.2-rc.5",
//     latestRcVersion: "0.1.2-rc.5",
//     latestPromotionVersion: "0.1.2",
//     latestPromotionTag: "cli/v0.1.2"
//   }
```

#### Exportierte Funktionen
- `resolveLatestRc(branch, componentPath)`: Hauptfunktion
- `parseReleaseBranch(branch)`: Validiert und parsed Release-Branch
- `deriveLatestRcMetadata(latestRcTag, componentPath)`: Leitet Promotion-Metadaten ab

#### Besonderheit
- Summary wird **nur bei `RELEASE_CANDIDATE=false`** geschrieben

---

### 5.4 `attestations-release-assets.js`

**Zweck**: Exportiert Attestation-Bundles für RC-Releases und erstellt einen Index für spätere Verifikation

**Verwendet in**: `cli-release.yml` → `release_rc` Job

#### ENV-Variablen
| Variable | Required | Beschreibung |
|----------|----------|--------------|
| `ASSETS_ROOT` | ✅ | Pfad zu Build-Assets (z.B. `${{ runner.temp }}/rc-build-assets`) |
| `ASSET_PATTERNS_JSON` | ✅ | JSON-Array mit Glob-Patterns (z.B. `'["bin/ocm-*"]'`) |
| `BUNDLE_DIR` | ✅ | Output-Verzeichnis für Bundles |
| `REPOSITORY` | ✅ | GitHub Repository (z.B. `owner/repo`) |
| `TARGET_REPO` | ❌* | OCI Registry Repo (z.B. `ghcr.io/owner/cli`) |
| `RC_VERSION` | ❌* | RC-Version für OCI-Tag |
| `OCI_SUBJECTS_JSON` | ❌* | Alternative: JSON-Array mit OCI-Refs |
| `ALLOW_MISSING_OCI_SUBJECTS` | ❌ | `true`/`false`, default `false`. Skip fehlende OCI-Attestationen |

*Entweder `OCI_SUBJECTS_JSON` ODER `TARGET_REPO`+`RC_VERSION` müssen gesetzt sein.

#### Outputs
- `bundle_count`: Anzahl exportierter Bundles
- `index_path`: Pfad zur `attestations-index.json`

#### Erzeugte Artefakte
```
$BUNDLE_DIR/
├── attestation-ocm-darwin-arm64-a1b2c3d4e5f6.jsonl
├── attestation-ocm-darwin-amd64-b2c3d4e5f6a7.jsonl
├── attestation-ocm-linux-arm64-c3d4e5f6a7b8.jsonl
├── attestation-ocm-linux-amd64-d4e5f6a7b8c9.jsonl
├── attestation-ghcr.io-owner-cli-0.1.0-rc.1-e5f6a7b8c9d0.jsonl
└── attestations-index.json
```

#### Index-Format (`attestations-index.json`)
```json
{
  "generated_at": "2026-02-13T08:24:32.000Z",
  "image": "oci://ghcr.io/owner/cli:0.1.0-rc.1",
  "bundles": [
    { "name": "attestation-ocm-darwin-arm64-a1b2c3d4e5f6.jsonl", "digest": "sha256:a1b2..." },
    { "name": "attestation-ghcr.io-owner-cli-0.1.0-rc.1-e5f6a7b8c9d0.jsonl", "digest": "sha256:e5f6..." }
  ],
  "entries": [
    { "subject": "file:ocm-darwin-arm64", "digest": "sha256:a1b2...", "bundle_file": "...", "kind": "file" },
    { "subject": "oci://ghcr.io/owner/cli:0.1.0-rc.1", "digest": "sha256:e5f6...", "bundle_file": "...", "kind": "oci" }
  ]
}
```

#### Ablauf
1. Parse `ASSET_PATTERNS_JSON` zu Glob-Patterns
2. Finde alle matching Files unter `ASSETS_ROOT`
3. Für jedes File: `gh attestation download <file> --repo <repo>`
4. Parse OCI-Subjects (aus JSON oder TARGET_REPO:RC_VERSION)
5. Für jedes OCI-Subject: `oras resolve` → `gh attestation download`
6. Rename Bundles zu lesbaren Namen
7. Erstelle `attestations-index.json`

#### Exportierte Funktionen
- `runExport({ core, run })`: Hauptfunktion
- `parsePatternList(json)`: Parsed ASSET_PATTERNS_JSON
- `resolveLocalSubjects(assetsRoot, patterns)`: Findet lokale Files
- `resolveOciSubjects({ ociSubjectsJson, targetRepo, rcVersion })`: Baut OCI-Subject-Liste
- `sha256File(filePath)`: Berechnet SHA256-Digest
- `prettyBundleName(subjectRef, digest)`: Generiert lesbaren Bundle-Namen
- `buildAttestationsIndex({ imageRef, entries })`: Erstellt Index-Struktur

#### CLI-Tools (müssen installiert sein)
- `gh` (GitHub CLI) mit `attestation download` Subcommand
- `oras` für OCI-Digest-Resolution

---

### 5.5 `verify-attestations-from-release.js`

**Zweck**: Verifiziert alle Attestationen aus einem RC-Release vor der Final-Promotion

**Verwendet in**: `cli-release.yml` → `verify_attestations` Job

#### ENV-Variablen
| Variable | Required | Beschreibung |
|----------|----------|--------------|
| `RC_ASSETS_DIR` | ✅ | Pfad zu heruntergeladenen RC-Assets |
| `ASSET_PATTERNS_JSON` | ✅ | JSON-Array mit Glob-Patterns (z.B. `'["ocm-*"]'`) |
| `REPOSITORY` | ✅ | GitHub Repository |
| `TARGET_REPO` | ❌* | OCI Registry Repo |
| `RC_VERSION` | ❌* | RC-Version für OCI-Tag |
| `OCI_SUBJECTS_JSON` | ❌* | Alternative: JSON-Array mit OCI-Refs |

*Entweder `OCI_SUBJECTS_JSON` ODER `TARGET_REPO`+`RC_VERSION` müssen gesetzt sein.

#### Outputs
- `verified_assets`: Anzahl verifizierter lokaler Assets
- `verified_image_digest`: Digest des verifizierten OCI-Images

#### Ablauf
1. Parse `ASSET_PATTERNS_JSON` zu Glob-Patterns
2. Finde alle matching Files unter `RC_ASSETS_DIR`
3. Lade optional `attestations-index.json` für Bundle-Auflösung
4. Für jedes lokale Asset:
   - Berechne SHA256-Digest
   - Finde Bundle via Index oder Digest-Name
   - `gh attestation verify <asset> --repo <repo> --bundle <bundle>`
5. Für jedes OCI-Subject:
   - `oras resolve` für Digest
   - Finde Bundle via Index
   - `gh attestation verify <oci-ref> --repo <repo> --bundle <bundle>`

#### Exportierte Funktionen
- `runVerify({ core, run })`: Hauptfunktion
- `expectedReleaseAssets(rcAssetsDir, patterns)`: Findet erwartete Assets
- `loadAttestationIndex(rcAssetsDir)`: Lädt Index falls vorhanden
- `resolveBundlePath({ rcAssetsDir, index, subjectRef, digest })`: Findet Bundle-Pfad
- `requireBundlePath(...)`: Wie resolveBundlePath, aber wirft Error wenn nicht gefunden

#### CLI-Tools (müssen installiert sein)
- `gh` (GitHub CLI) mit `attestation verify` Subcommand
- `oras` für OCI-Digest-Resolution

---

## 6) Attestation-Flow im Detail

### 6.1 Wo werden Attestationen erstellt?

**Im Build (cli.yml):**
```yaml
# Binary Attestation (build job)
- uses: actions/attest-build-provenance@v3
  with:
    subject-path: "${{ env.LOCATION }}/tmp/bin/ocm-*"

# OCI Image Attestation (publish job)
- uses: actions/attest-build-provenance@v3
  with:
    subject-digest: ${{ steps.digest.outputs.digest }}
    subject-name: ${{ env.TARGET_REPO }}
    push-to-registry: true
```

### 6.2 Wo werden Attestationen exportiert?

**Im RC Release (cli-release.yml → release_rc):**
```yaml
- name: Export attestation bundles and index
  uses: actions/github-script@v8
  env:
    ASSETS_ROOT: ${{ runner.temp }}/rc-build-assets
    ASSET_PATTERNS_JSON: '["bin/ocm-*"]'
    RC_VERSION: ${{ needs.prepare.outputs.new_version }}
    TARGET_REPO: ${{ env.REGISTRY }}/${{ github.repository_owner }}/cli
    BUNDLE_DIR: ${{ runner.temp }}/attestation-bundles
  with:
    script: |
      const script = await import('.github/scripts/attestations-release-assets.js');
      await script.default({ core });
```

### 6.3 Wo werden Attestationen verifiziert?

**Im Final Release (cli-release.yml → verify_attestations):**
```yaml
- name: Verify RC release attestations
  uses: actions/github-script@v8
  env:
    RC_ASSETS_DIR: ${{ runner.temp }}/rc-assets
    ASSET_PATTERNS_JSON: '["ocm-*"]'
    RC_VERSION: ${{ needs.prepare.outputs.latest_rc_version }}
    TARGET_REPO: ${{ env.REGISTRY }}/${{ github.repository_owner }}/cli
  with:
    script: |
      const script = await import('.github/scripts/verify-attestations-from-release.js');
      await script.default({ core });
```

### 6.4 Attestation-Artefakte im Release

Ein RC-Release enthält:
- `ocm-darwin-arm64`, `ocm-darwin-amd64`, `ocm-linux-arm64`, `ocm-linux-amd64` (Binaries)
- `cli.tar` (OCI Layout)
- `attestation-*.jsonl` (Attestation Bundles)
- `attestations-index.json` (Index für Verifikation)

---

## 7) LLM Quickstart (Playbook)

### Wenn der User sagt: „RC/Final-Release-Logik ändern"
1. zuerst `cli-release.yml` prüfen (Job-Gates und `needs`)
2. dann `release-candidate-version.yml` (Inputs/Outputs)
3. danach Scripts (`compute-rc-version.js`, `resolve-latest-rc.js`)

### Wenn der User sagt: „Versionberechnung ändern"
- `compute-version.js` für Build-Versions (cli.yml)
- `compute-rc-version.js` für RC-Versions (Release-Flow)
- beachten: Versioning-Rules in `computeNextVersions`

### Wenn der User sagt: „Final-Promotion verhält sich falsch"
- `validate_final`, `tag_final`, `promote_image`, `release_final` in `cli-release.yml`
- prüfen, ob `latest_rc_*` und `latest_promotion_*` korrekt propagiert werden
- `resolve-latest-rc.js` für Metadaten-Berechnung

### Wenn der User sagt: „Publish/Attestation anpassen"
- `cli.yml` in Jobs `build`/`publish`
- eligibility-Regel in `branch-check` und attestation-steps prüfen

### Wenn der User sagt: „Attestation-Export oder -Verifikation ändern"
1. **Export (RC)**: `attestations-release-assets.js`
   - Wird in `release_rc` Job aufgerufen
   - Outputs: Bundle-Files + `attestations-index.json`
2. **Verify (Final)**: `verify-attestations-from-release.js`
   - Wird in `verify_attestations` Job aufgerufen
   - Liest `attestations-index.json` für Bundle-Auflösung

### Wenn der User sagt: „Neue Komponente zum Release-System hinzufügen"
1. Neuen Workflow `<component>-release.yml` erstellen (kopiere `cli-release.yml`)
2. Anpassen:
   - `COMPONENT_PATH` auf neuen Pfad
   - `ASSET_PATTERNS_JSON` auf neue Patterns
   - `TARGET_REPO` auf neues OCI-Registry-Ziel
3. Neuen Build-Workflow `<component>.yml` erstellen (kopiere `cli.yml`)
4. `TAG_PREFIX` anpassen (z.B. `kubernetes/controller/v`)
5. Alle Skripte sind bereits generisch und funktionieren mit neuen Parametern

---

## 8) Häufige Fehlerquellen

1. **Boolean vs String in Workflow-Inputs**
   - `workflow_dispatch`-Inputs sind oft stringly typed (`'true'/'false'`).
   - bei reusable calls ggf. `fromJSON(...)` nötig.

2. **Job-Conditions kollidieren mit `needs`**
   - bei neuen Jobs immer prüfen, ob `if` + `needs` konsistent sind.

3. **Fehlende Outputs im Reusable-Workflow**
   - neue Daten müssen in Step-Output, Job-Output, Workflow-Output durchgereicht werden.

4. **Tag-Immutability bei Final**
   - `tag_final` bricht absichtlich ab, wenn Final-Tag schon existiert.

5. **Summary-/Release-Notes-Duplikate**
   - RC- und Final-Summaries sind bewusst getrennt, um Noise zu vermeiden.
   - `RELEASE_CANDIDATE` ENV steuert Summary-Ausgabe in Skripten.

6. **Attestation-Bundle nicht gefunden**
   - Prüfen ob `attestations-index.json` korrekt erstellt wurde
   - Fallback: Script sucht nach `<digest>.jsonl` wenn Index fehlt

7. **OCI-Attestation-Download fehlschlägt**
   - `ALLOW_MISSING_OCI_SUBJECTS=true` setzt, um fortzufahren
   - Prüfen ob OCI-Image bereits attestiert wurde (publish job)

8. **Glob-Patterns matchen nicht**
   - `ASSET_PATTERNS_JSON` muss relative Pfade unter ASSETS_ROOT matchen
   - Bei RC: `"bin/ocm-*"` (mit bin/ Prefix)
   - Bei Final: `"ocm-*"` (ohne bin/, da flache Download-Struktur)

---

## 9) Änderungsstand (für kommende Sessions)

Folgende Erweiterungen/Änderungen sind bereits eingeführt:

### Workflows
- `cli-release.yml` unterstützt jetzt RC **und** Final Promotion in getrennten Pfaden
- `release-candidate-version.yml` hat Input `release_candidate` und zusätzliche latest/promotion-Outputs
- `cli.yml`: Attestation von Binaries + OCI Image ist aktiv

### Skripte
- `compute-version.js`: Generische Versionsberechnung für alle Komponenten
- `compute-rc-version.js`: RC-Versionsberechnung mit Summary-Gating
- `resolve-latest-rc.js`: Final-Metadaten-Auflösung mit Summary-Gating
- `attestations-release-assets.js`: **NEU** - Exportiert Attestation-Bundles für RC
- `verify-attestations-from-release.js`: **NEU** - Verifiziert Attestationen vor Final

### Generisches Design
- Alle Skripte arbeiten mit `COMPONENT_PATH` und sind wiederverwendbar
- `ASSET_PATTERNS_JSON` ermöglicht flexible Asset-Matching
- Vorbereitet für: `cli`, `kubernetes/controller`, zukünftige Komponenten

### Test-Infrastruktur
- `release-utils.js` wurde entfernt; Tests nutzen direkte Exports
- `attestations-release-assets.test.js` testet Export-Flow
- Bestehende Tests für Version-Skripte

---

## 10) Minimal-Validierung nach Änderungen

Empfohlene schnelle Checks:

```bash
# Script-Tests
cd .github/scripts
npm test

# Oder einzeln:
node --experimental-vm-modules node_modules/jest/bin/jest.js compute-version.test.js
node --experimental-vm-modules node_modules/jest/bin/jest.js compute-rc-version.test.js
node --experimental-vm-modules node_modules/jest/bin/jest.js resolve-latest-rc.test.js
node --experimental-vm-modules node_modules/jest/bin/jest.js attestations-release-assets.test.js

# gezielter Workflow-Diff
git --no-pager diff -- .github/workflows/cli-release.yml .github/workflows/release-candidate-version.yml .github/workflows/cli.yml
```

Wenn Release-Flow geändert wurde, zusätzlich per Dry-Run prüfen:
- `cli-release.yml` mit `dry_run=true`
- jeweils ein RC-Lauf und ein Final-Lauf gegen Test-Branch.

---

## 11) Fazit

Das Repo hat jetzt einen zweipfadigen Release-Ansatz (**RC erstellen** vs **RC zu Final promoten**) mit klarer Trennung in Jobs und Outputs.

**Attestation-Integration:**
- Build: Binaries + OCI Image werden attestiert
- RC-Release: Attestation-Bundles werden exportiert und ins Release hochgeladen
- Final-Promotion: Attestationen werden verifiziert bevor Final-Release erstellt wird

**Generisches Design:**
- Alle Skripte sind parametrisiert für verschiedene Komponenten
- Aktuell: `cli`
- Geplant: `kubernetes/controller`

**LLM-Einstiegspunkte:**
- Orchestrierung: `cli-release.yml`
- Metadata: `release-candidate-version.yml`
- Versionsberechnung: `compute-version.js`, `compute-rc-version.js`, `resolve-latest-rc.js`
- Attestation-Export: `attestations-release-assets.js`
- Attestation-Verifikation: `verify-attestations-from-release.js`
- Build/Publish/Attest: `cli.yml`