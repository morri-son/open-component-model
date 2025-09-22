# One-slide Invite — ADR Discussion: Versioning, Branching & Release Orchestration

When: 60 minutes (please block)
Who: OCM TSC, Release Manager, CI Owner, `cli` & `controller` reps

Purpose
- Align on Versioning SSoT, OCM orchestration (batching), targeted OCM patch policy, and Bot responsibilities so we can convert the result into an ADR.

Pre-read (required)
- `docs/adr/0010_discussion_versioning_branching_releasing.md`

Key decisions to make (3)
1. Versioning SSoT: Use Git tags for sub-components + `/ocm/component-constructor.yaml` in `main`? (recommended)
2. Orchestration: Sprint-batch collector (single draft PR per sprint) with bump rules (major>minor>patch)?
3. Patching policy: Default exclude post-cut patches from in-flight RCs; allow targeted OCM patch releases per SLA (emergency path)?

Ask from attendees
- Read the pre-read and be ready to state SLA preference (e.g., support last 2 minors). Bring questions about the bot index and approval gates.

Meeting output
- Final selection for the three decisions above; owners assigned to bot tickets (index, batch PR, targeted patch flow); ADR drafting owner.
