# Website & Docs Pointers

**When a session needs authoritative OCM technical detail, go here, not to memory.**

## Why pointers, not extracts

The OCM website (`./website/content/docs/`) is:
- Actively maintained
- Git-tag-versioned
- The canonical reference for user-facing docs
- Already in the same repo as this workspace

Extracting it here would create a stale copy. Instead: this file tells you which website path answers which kind of question.

## Website map: where to go for what

### Getting started / adoption
- `website/content/docs/tutorial/`, end-to-end learning path
- `website/content/docs/how-to/`, task-oriented recipes

### The technical model
- `website/content/docs/concepts/`, component model, descriptor, resources, references
- `website/content/docs/reference/`, spec-level detail, YAML schemas

### Signing & verification
- `website/content/docs/how-to/Sign and Verify/sign-component-version.md`, CLI signing walkthrough
- `website/content/docs/how-to/verify-component-version-controller.md`, K8s controller verification (opt-in behavior; RSA-only today)
- `website/content/docs/reference/signing-and-verification-concept.md`, the concept doc for the trust model

### Transport
- `website/content/docs/how-to/Transport/`, transfer patterns, CTF, air-gap
- Look for `--copy-resources`, this is the air-gap default footgun on the architect deck Slide 14

### Kubernetes controllers
- `website/content/docs/reference/kubernetes-api/`, CRD reference (Repository, Component, Resource, Deployer)
- `website/content/docs/reference/kubernetes-api/replication.md`, Replication CR (external Slide 16 appendix)

### Composition
- `website/content/docs/concepts/component-references/`, service vs product; transitive trust

## Spec (definitive)

For spec-level questions:
- `~/github/github.com/morri-son/ocm-spec/doc/`, the OCM Working-Group spec (checked out separately)
- Especially: `~/github/github.com/morri-son/ocm-spec/doc/component-descriptor.md`

## Code (implementation truth)

- `bindings/go/`, v2 Go implementation
- `kubernetes/controller/`, K8s controllers
- Specifically for verify semantics: `kubernetes/controller/api/v1alpha1/component_types.go` (the CR type) and `kubernetes/controller/internal/resolution/workerpool/workerpool.go` (the verify loop)

## Historical documents (in ~/dies-und-das/OCM/)

These are outside the repo (on user's local disk). They inform history but aren't the current source of truth:

- `OCM-Adoption Plan.pdf` (June 2024), historical strategy. **Stale on TG withdrawal, SLC-29 status, renames (ODG, OCP), Landscaper sunset.** Use `sap-adoption-2026.md` here instead.
- `whitepaper.pdf`, Uwe's technical whitepaper. Reference for whitepaper-quotable framing.
- `20250327 IPCEI-CIS GA OCM-ODG – Kopie.pdf`, NeoNephos / sovereign-cloud / IPCEI framing.
- `2024-05-28_OCM_Delivery_and_Compliance_Automation.pdf`, older Delivery & Compliance Automation framing.

If a session extracts summaries of these into `references/`, put them there with a **freshness date** and **staleness notes** (e.g., "the 2024 adoption plan claims X; the 2026 reality is Y, see `ocm-knowledge/sap-adoption-2026.md`").

## Verification workflow

When a session needs to verify a technical claim in a deck:

1. Try the website first (`./website/content/docs/`).
2. If more detail needed, spec (`ocm-spec/doc/`).
3. If implementation truth needed, code (`bindings/go/`, `kubernetes/controller/`).
4. Never rely on memory alone for a claim on a slide.

This discipline is what caught the "Q&A on verifier policy floor" hallucination in the June 2026 correction pass (see `SKILL-CHARTER.md` anchor A7–A9).
