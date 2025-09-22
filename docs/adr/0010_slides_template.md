# Slides — ADR Discussion: Versioning, Branching & Release Orchestration

Slide 1 — Title
- Title: "ADR Discussion: Versioning, Branching & Release Orchestration"
- Subtitle: "OCM monorepo"
- Date & attendees

Slide 2 — Purpose & Assumptions
- Purpose: Align on decisions to finalize ADR
- Assumptions: sprint cadence, tags as published artifacts, bot-only constructor updates

Slide 3 — Versioning Options
- A: VERSION file per component
- B: Tags + `/ocm/component-constructor.yaml` in `main` (recommended)
- C: Tags + generated constructor at release-time

Slide 4 — Orchestration (Batching)
- Sprint-batch collector behaviour (single draft PR per sprint)
- Mapping rule: major>minor>patch
- Force/urgent path

Slide 5 — Targeted OCM Patch Flow
- Bot maintains index: sub-component tag -> OCM releases
- Steps to create targeted OCM patch PR

Slide 6 — Patches during in-flight RCs
- Default: exclude post-cut patches
- Emergency path: allow targeted OCM patch releases with approvals

Slide 7 — Decisions Needed
- Confirm Versioning option
- Confirm batching behaviour & PR policy
- Confirm SLA (which OCM lines support patches)
- Confirm emergency approvers

Slide 8 — Next Actions
- Create bot tickets (index, batch PR, targeted patch flow)
- Define SLA & merge policies
- Write ADR from agreed options
