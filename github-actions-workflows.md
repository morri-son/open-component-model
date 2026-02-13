# Überblick über die GitHub Actions Workflows

Dieses Dokument ist der **Schnellkontext für LLM-Sitzungen** rund um Release-/Build-Workflows.
Ziel: Eine neue Sitzung soll ohne weitere Exploration sofort produktiv Änderungen an Workflow-Setup, RC/Final-Flow und Publish-Pipeline umsetzen können.

---

## 0) Was ist der aktuelle Sollzustand?

Der Release-Prozess unterstützt **zwei Modi** über `cli-release.yml`:

1. **Release Candidate (RC)**
   - `release_candidate=true`
   - berechnet neuen RC-Tag, erstellt/pusht RC-Tag, baut, published, erstellt GitHub **Pre-Release**.
   - Exportiert Attestation-Bundles für Binaries und OCI-Image

2. **Final Promotion**
   - `release_candidate=false`
   - nimmt **existierenden RC** auf dem Release-Branch als Source of Truth,
   - **verifiziert alle Attestations** aus dem RC-Release,
   - erstellt Final-Tag vom RC-Commit,
   - promoted OCI-Tag auf final + `latest`,
   - erstellt GitHub **Final Release** aus RC-Assets/RC-Notes.

Zusätzlich:
- `dry_run=true` verhindert tag-/publish-seitige Schreiboperationen.
- `release-candidate-version.yml` ist der zentrale Reusable-Workflow für Metadaten (RC + Final Inputs/Outputs).

---

## 1) Workflow-Übersicht

| Datei | Name | Rolle |
|---|---|---|
| `.github/workflows/release-branch.yml` | Create OCM Release Branch | Erstellt `releases/v0.X` Branches manuell. |
| `.github/workflows/release-candidate-version.yml` | Release Candidate Version | Reusable für RC/Final-Metadaten + RC-Changelog. |
| `.github/workflows/cli-release.yml` | CLI Release | Orchestrierung für RC-Release **und** Final-Promotion. |
| `.github/workflows/cli.yml` | CLI | Build + Publish + Attestations für CLI. |

---

## 2) High-Level Beziehungen

```text
release-branch.yml (manuell)
   └─ erstellt releases/v0.X

cli-release.yml (manuell)
   ├─ prepare (calls release-candidate-version.yml)
   ├─ RC-Pfad:
   │    tag_rc -> build (calls cli.yml) -> release_rc (mit attestations export)
   └─ Final-Pfad:
        validate_final -> verify_attestations -> tag_final -> promote_image -> release_final

cli.yml (push/PR/workflow_call)
   ├─ build (+ attest binaries)
   └─ publish (+ attest OCI image)
       └─ outputs: image_digest, image_tag
```

---

# 3) Detaillierte Analyse

## 3.1 `release-branch.yml`

### Trigger
- `workflow_dispatch`

### Inputs
- `target_branch` (required): muss zu `^releases/v0\.[0-9]+$` passen
- `source_branch` (optional, default `main`)

### Verhalten
- versucht GitHub App Token (`actions/create-github-app-token`) mit `permission-contents: write`
- fallback auf `GITHUB_TOKEN`
- erstellt Branch nur, wenn Ziel nicht bereits existiert
- schreibt Step Summary mit Source, Target, SHA

---

## 3.2 `release-candidate-version.yml` (Reusable)

### Zweck
Zentraler Metadata-Workflow für beide Flows:
- RC vorbereiten
- Final-Promotion-Metadaten aus latest RC ableiten

### Inputs
- `branch` (required)
- `component_path` (required, z. B. `cli`)
- `release_candidate` (optional, boolean, default `true`)

### Outputs
**RC-Outputs**
- `new_tag`
- `new_version`
- `base_version`
- `promotion_tag`
- `changelog_b64` (nur RC sinnvoll gefüllt)

**Final-relevante Outputs**
- `latest_rc_tag`
- `latest_rc_version`
- `latest_promotion_tag`
- `latest_promotion_version`

### Steps
1. Checkout (sparse: `component_path`, `.github/scripts`, `fetch-depth: 0`)
2. `compute-rc-version.js` (immer, aber RC-Summary nur bei RC)
3. `resolve-latest-rc.js` (nur bei Final)
4. `git-cliff` nur bei `release_candidate == true`
5. `Summarize changelog` nur bei RC (setzt `changelog_b64`, schreibt Raw-Log)

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

### Job-Matrix nach Modus

#### A) RC-Modus (`release_candidate == 'true'`)
1. `prepare` (calls reusable workflow)
2. `tag_rc` (nur wenn `dry_run == 'false'`)
   - erstellt App Token mit `permission-contents: write` + `permission-workflows: write`
   - erstellt annotierten RC-Tag aus `prepare.outputs.new_tag`
3. `build` (nur wenn `tag_rc.outputs.pushed == 'true'`)
   - ruft `cli.yml` via `workflow_call` auf `ref=new_tag`
   - **outputs:** `artifact_name`, `artifact_id`, `image_digest`, `image_tag`
4. `release_rc` (nur wenn Tag gepusht)
   - decodiert `changelog_b64`
   - lädt Build-Artefakte
   - **exportiert Attestation-Bundles** via `export-attestations.js`
   - erstellt GitHub **pre-release** (`prerelease: true`)

#### B) Final-Modus (`release_candidate == 'false'`)
1. `prepare`
2. `validate_final`
   - bricht ab, wenn kein `latest_rc_tag` vorhanden
3. `verify_attestations` (NEU!)
   - lädt RC-Release-Assets herunter
   - **verifiziert alle Attestations** via `verify-attestations.js`
4. `tag_final` (nur wenn `dry_run == 'false'`)
   - erstellt Final-Tag aus Commit von `latest_rc_tag` (immutability-check)
5. `promote_image`
   - ORAS-Tag-Promotion: `:<rcVersion>` -> `:<finalVersion>` + `:latest`
6. `release_final`
   - lädt RC-Assets aus bestehendem RC-Release
   - übernimmt RC-Release-Notes (mit Promotion-Header)
   - erstellt Final Release (`prerelease: false`)

---

## 3.4 `cli.yml` (Build/Publish)

### Trigger
- push auf `main`, `releases/v**`, tags `cli/v**`
- PR auf `main` (mit `cli/**` oder Workflow-Datei-Änderung)
- `workflow_call`

### Outputs (für workflow_call)
- `artifact_name` - Name des Build-Artefakts
- `artifact_id` - ID des Build-Artefakts
- `image_digest` - SHA256-Digest des gepushten OCI-Images (NEU!)
- `image_tag` - Tag des gepushten OCI-Images (NEU!)

### Job `build`
- Checkout (sparse: `.github/scripts`, `cli/`)
- Setup Go, Task, buildx
- `compute-version.js`
- `task cli:generate/ctf` + `task cli:verify/ctf`
- **Attest binaries** (nicht auf PR)
- Branch eligibility (`should_push_oci_image`) über Script
- Upload artifacts (nur wenn push-eligible)

### Job `publish`
- nur wenn `should_push_oci_image == 'true'`
- lädt Artefakte
- ORAS push aus OCI-Layout
- optional zusätzlicher branch tag (`:main`)
- resolve digest
- **Attest OCI image** mit `push-to-registry: true`
- **outputs:** `digest`, `tag`

---

# 4) Attestation-Skripte

## 4.1 `export-attestations.js`

**Zweck:** Exportiert Attestation-Bundles für RC-Releases.

### Inputs (ENV)
| Variable | Required | Beschreibung |
|---|---|---|
| `ASSETS_DIR` | ✓ | Verzeichnis mit Build-Artefakten |
| `ASSET_PATTERNS` | ✓ | JSON-Array mit Glob-Patterns, z.B. `["bin/ocm-*"]` |
| `IMAGE_DIGEST` | ✓ | SHA256-Digest des OCI-Images (direkt vom Build-Output) |
| `IMAGE_TAG` | ✓ | Tag des OCI-Images |
| `TARGET_REPO` | ✓ | OCI Repository, z.B. `ghcr.io/owner/cli` |
| `OUTPUT_DIR` | ✓ | Ausgabeverzeichnis für Bundles |
| `REPOSITORY` | ✓ | GitHub Repository für Attestation-Lookup |

### Outputs
- `bundle_count` - Anzahl exportierter Bundles
- `index_path` - Pfad zur `attestations-index.json`

### Erzeugte Dateien
- `attestation-<asset-name>.jsonl` - Ein Bundle pro Binary (z.B. `attestation-ocm-linux-amd64.jsonl`)
- `attestation-ocm-image.jsonl` - Bundle für OCI-Image
- `attestations-index.json` - Index mit Metadaten

### Besonderheit
- **Verwendet `IMAGE_DIGEST` direkt** vom Build-Output, kein Registry-Lookup nötig
- Human-readable Bundle-Namen statt kryptischer Hash-Namen

---

## 4.2 `verify-attestations.js`

**Zweck:** Verifiziert Attestations vor Final-Promotion.

### Inputs (ENV)
| Variable | Required | Beschreibung |
|---|---|---|
| `ASSETS_DIR` | ✓ | Verzeichnis mit RC-Release-Assets |
| `ASSET_PATTERNS` | ✓ | JSON-Array mit Glob-Patterns, z.B. `["ocm-*"]` |
| `IMAGE_REF` | optional | OCI-Referenz für Image-Verifikation |
| `REPOSITORY` | ✓ | GitHub Repository für Attestation-Verifikation |

### Outputs
- `verified_count` - Anzahl verifizierter Attestations
- `verified_image_digest` - Digest des verifizierten Images

### Verhalten
1. Lädt `attestations-index.json` aus Assets
2. Verifiziert jedes Binary gegen sein Bundle
3. **Verifiziert OCI-Image per Digest** (nicht per Tag!) gegen sein Bundle
   - OCI-Tags sind mutable und können überschrieben werden
   - Verwendet `index.image.digest` für exakte Identifikation
4. Schlägt fehl, wenn eine Verifikation nicht erfolgreich ist

### Wichtige Design-Entscheidung
Die OCI-Image-Verifikation verwendet den **Digest aus dem Index**, nicht den aktuellen Tag.
Dies ist essentiell, da OCI-Tags mutable sind und zwischen RC-Erstellung und Final-Promotion
durch andere Builds überschrieben werden können.

---

## 4.3 `attestations-index.json` Format

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
      "bundle": "attestation-ocm-image.jsonl"
    }
  ]
}
```

---

# 5) Skript-Verträge (für schnelle Anpassungen)

## `.github/scripts/compute-rc-version.js`

### Erwartete ENV
- `BRANCH`
- `COMPONENT_PATH`
- `RELEASE_CANDIDATE` (optional, default true)

### Outputs via `core.setOutput`
- `new_tag`
- `new_version`
- `base_version`
- `promotion_tag`

### Besonderheit
- schreibt RC-Compute-Summary **nur wenn** `RELEASE_CANDIDATE == true`.

## `.github/scripts/resolve-latest-rc.js`

### Erwartete ENV
- `BRANCH`
- `COMPONENT_PATH`
- `RELEASE_CANDIDATE` (optional)

### Outputs
- `latest_rc_tag`
- `latest_rc_version`
- `latest_promotion_version`
- `latest_promotion_tag`

### Besonderheit
- schreibt Final-orientierte Summary **nur wenn** `RELEASE_CANDIDATE == false`.

---

# 6) LLM Quickstart (Playbook)

## Wenn der User sagt: „RC/Final-Release-Logik ändern"
1. zuerst `cli-release.yml` prüfen (Job-Gates und `needs`)
2. dann `release-candidate-version.yml` (Inputs/Outputs)
3. danach Scripts (`compute-rc-version.js`, `resolve-latest-rc.js`)

## Wenn der User sagt: „Versionberechnung ändern"
- `compute-rc-version.js` + zugehörige Tests anpassen
- beachten: file möglichst upstream-nah halten, nur notwendige Deltas

## Wenn der User sagt: „Final-Promotion verhält sich falsch"
- `validate_final`, `verify_attestations`, `tag_final`, `promote_image`, `release_final` in `cli-release.yml`
- prüfen, ob `latest_rc_*` und `latest_promotion_*` korrekt propagiert werden

## Wenn der User sagt: „Attestations anpassen"
- `export-attestations.js` für RC-Export
- `verify-attestations.js` für Final-Verifikation
- `attestations-index.json` Format prüfen

## Wenn der User sagt: „Build/Publish anpassen"
- `cli.yml` in Jobs `build`/`publish`
- eligibility-Regel in `branch-check`
- Outputs `image_digest` und `image_tag` für downstream

---

# 7) Häufige Fehlerquellen

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

6. **Attestation-Export: IMAGE_DIGEST fehlt**
   - `cli.yml` muss `image_digest` und `image_tag` als Outputs bereitstellen
   - Diese kommen vom `publish` Job

---

# 8) Geplante Erweiterungen

## Kubernetes Controller Release

Das gleiche Release-Modell (RC + Final Promotion) soll auch für den Kubernetes Controller verwendet werden. Die Attestation-Skripte sind daher **generisch** gehalten und können für jeden Component-Path wiederverwendet werden:

- `COMPONENT_PATH=cli` → CLI Release
- `COMPONENT_PATH=kubernetes/controller` → Controller Release (geplant)

## Weitere Attestation-Subjects

Falls weitere Artefakte attestiert werden sollen:
1. `ASSET_PATTERNS` erweitern (z.B. `["bin/ocm-*", "helm/*.tgz"]`)
2. Neuer Eintrag wird automatisch in `attestations-index.json` aufgenommen
3. Verifikation verifiziert alle Einträge aus dem Index

---

# 9) Änderungsstand (relevant für kommende Sessions)

Folgende Erweiterungen/Änderungen wurden eingeführt:

- `cli-release.yml` unterstützt jetzt RC **und** Final Promotion in getrennten Pfaden.
- `release-candidate-version.yml` hat Input `release_candidate` und zusätzliche latest/promotion-Outputs.
- `resolve-latest-rc.js` wurde eingeführt für Final-Metadaten.
- `compute-rc-version.js` blieb upstream-nah; notwendige Ergänzung: RC/Final-abhängige Summary-Ausgabe.
- `cli.yml`: Neue Outputs `image_digest` und `image_tag` vom `publish` Job.
- **NEU:** `export-attestations.js` exportiert Attestation-Bundles mit human-readable Namen
- **NEU:** `verify-attestations.js` verifiziert Attestations vor Final-Promotion
- **NEU:** `attestations-index.json` Format für strukturierte Bundle-Referenzen
- **ENTFERNT:** `attestations-release-assets.js` und `verify-attestations-from-release.js` (durch neue Skripte ersetzt)

---

# 10) Minimal-Validierung nach Änderungen

Empfohlene schnelle Checks:

```bash
# Script-Tests
node .github/scripts/compute-rc-version.test.js
node .github/scripts/resolve-latest-rc.test.js

# gezielter Workflow-Diff
git --no-pager diff -- .github/workflows/cli-release.yml .github/workflows/release-candidate-version.yml .github/workflows/cli.yml
```

Wenn Release-Flow geändert wurde, zusätzlich per Dry-Run prüfen:
- `cli-release.yml` mit `dry_run=true`
- jeweils ein RC-Lauf und ein Final-Lauf gegen Test-Branch.

---

# 11) Release-Flow Übersicht (Visual)

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

## Fazit

Das Repo hat jetzt einen zweipfadigen Release-Ansatz (**RC erstellen** vs **RC zu Final promoten**) mit:

- **Klarer Trennung** in Jobs und Outputs
- **Vollständiger Attestation-Support** für Supply-Chain-Security
- **Generische Skripte** für Wiederverwendung bei anderen Komponenten (Controller)
- **Human-readable Attestation-Namen** für bessere Nachvollziehbarkeit

Für LLM-Änderungen sind die Einstiegspunkte eindeutig:
- Orchestrierung: `cli-release.yml`
- Metadata: `release-candidate-version.yml`
- Berechnung: `.github/scripts/compute-*.js`, `.github/scripts/resolve-*.js`
- Attestations: `.github/scripts/export-attestations.js`, `.github/scripts/verify-attestations.js`
- Build/Publish/Attest: `cli.yml`