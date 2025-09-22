# ADR Discussion Meeting Agenda — Versioning, Branching & Release Orchestration

Purpose: Align the Technical Steering Committee on decisions needed to finalize ADR for versioning, branching and release orchestration.

Duration: 45 minutes

Attendees: OCM Technical Steering Committee, Release Manager, CI Owner, Representatives from `cli` and `controller` teams

Agenda

1. Opening and goals (5 min)
   - Quick context and desired outcome: select options for Versioning SSoT, Orchestration Model, Maintenance SLA, Bot responsibilities.

2. Versioning options (10 min)
   - Present three options (VERSION file, Tags + constructor in `main`, Tags + generated constructor)
   - Confirm preferred option (expected: Tags + constructor in `main`)

3. Orchestration & batching behaviour (10 min)
   - Explain sprint-batch collector and mapping rule (major>minor>patch)
   - Discuss draft PR vs non-draft and merge policy (auto vs gated)

4. Targeted OCM patch flow & index (10 min)
   - Explain bot index mapping and targeted patch algorithm
   - Decide which OCM lines are supported for patching (SLA)

5. Emergency / force-flush policy (5 min)
   - Define criteria and approver(s)

6. Next steps & owners (5 min)
   - Create tickets for bot implementation, CI gating, documentation
   - Assign owners and timeline

Pre-meeting prep for attendees
- Read `docs/adr/0010_discussion_versioning_branching_releasing.md`
- Be ready to confirm SLA proposals (e.g., last 2 minors)
