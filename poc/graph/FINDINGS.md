# Findings: kro Graph (KREP-024, PR #1355) as OCM bootstrap payload — POC, 2026-08-18

Empirical validation of kro's experimental **Graph** engine as the bootstrap payload of
an OCM component, replacing the `ResourceGraphDefinition` blob of the tutorial
`website/content/docs/tutorials/deploy-helm-chart-bootstrap.md` (kro inline-manifests
variant: podinfo via plain Deployment + Service, no Helm/Flux). The nested `graph:`
child node replaces the "RGD of RGDs" construction tested in
`poc/rgd-of-rgds` (branch `poc/rgd-of-rgds`, not pushed), which is structurally broken
on kro 0.9.3.

**All checks passed.** Graph nesting with child-scope capture works end to end through
the real OCM bootstrap flow (transfer to ghcr, Deployer applies blob). Compile-time
validation of child scopes and lifecycle cascade behave as designed.

Setup and reproduction steps: [README.md](README.md).

## Environment

- kro source: PR #1355 head `9b0a56d` ("test: de-serialize GraphRevision specs..."),
  no kro code modified
- kind cluster `kro-graph`, Kubernetes v1.36.1, colima on Apple Silicon
- kro controller: PR image `ko.local/kro:pr-1355` built with `ko`, installed via the
  PR's own `helm/` chart with `config.featureGates.GraphKind=true` (gate off by
  default)
- OCM controllers: `oci://ghcr.io/open-component-model/kubernetes/controller/chart`
  release `ocm-k8s-toolkit` (website getting-started setup), plus `custom-rbac.yaml`
  granting `graphs.kro.run` to the controller service account
- Registry: `ghcr.io/morri-son/ocm-graph-poc`, packages private at test time; cluster
  used the tutorial's `ghcr-secret` pattern (Repository `ocmConfig`, Graph template
  `ocmConfig`, Deployment `imagePullSecrets`)
- Timestamps: `date +%H:%M:%S.%3N` (CEST, UTC+2); `lastTransitionTime` values are Z.
  Single-run wall clock, unscientific but real.

## KREP-024 vs. the PR code (source of truth: `api/v1alpha1/graph_types.go`)

The design proposal `docs/design/proposals/graph.md` is stale in parts:

- Node keywords implemented: `template`, `ref`, `def`, `graph` (+ `readyWhen`,
  `includeWhen`, `forEach`). `watch:` and `patch:` from the KREP text did **not** make
  it into the PR code.
- Conditions: `Accepted` (False reason `InvalidGraph` on compile errors) and `Ready`;
  the controller additionally sets `ResourcesConverged`. The KREP's `Compiled`
  condition is `Accepted` in code.
- `graph:` child nodes form a lexical frame (KREP "nested composition"): children may
  reference parent nodes (capture, creating a dependency edge from the subgraph node)
  and child outputs are addressable as `${nodeID.childNode.field}`. One CEL expression
  must not mix frames.

## Test flow

Mirrors the tutorial: component `ocm.software/ocm-k8s-toolkit/graph:1.0.0` with
`image-resource` (public podinfo
`ghcr.io/stefanprodan/podinfo:6.11.1@sha256:8fa56908408de98f24aed2a162b1bb42c0b98df7abfcc5a76a14a8be510457c5`)
and a `blob` resource `graph` containing `graph.yaml`. The Graph spec:

- parent node `resourceImage`: OCM `Resource` CR, identical to the tutorial's
  `resourceImage` RGD node (`additionalStatusFields.oci: resource.access.toOCI()`,
  `readyWhen` on `Ready == True`)
- parent node `image`: `def:` computing the localized coordinates
  (`registry`, `repository`, `digest`, digest-pinned `ref`)
- parent node `app`: nested `graph:` child with podinfo Deployment (`image:
  ${image.ref}` — capture of the parent `def`, port 9898) and Service

Files: `component-constructor.yaml`, `graph.yaml`, `bootstrap.yaml`
(Repository → Component → Resource → Deployer, envsubst for `$OCM_REPO`),
`bad-graph.yaml` (T3), `custom-rbac.yaml`.

## Results — verbatim

### Deployer applies the Graph; Accepted/Ready (T1)

```text
$ kubectl get graph -n default
NAME                READY   AGE
podinfo-bootstrap   True    45s
```

```yaml
status:
  conditions:
  - lastTransitionTime: "2026-08-18T21:09:38Z"
    message: compiled 3 nodes
    reason: Compiled
    status: "True"
    type: Accepted
  - lastTransitionTime: "2026-08-18T21:09:46Z"
    message: all nodes applied and ready
    reason: Applied
    status: "True"
    type: ResourcesConverged
  - lastTransitionTime: "2026-08-18T21:09:46Z"
    reason: Ready
    status: "True"
    type: Ready
  managedResources:
  - apiVersion: delivery.ocm.software/v1alpha1
    kind: Resource
    name: graph-image-resource
    namespace: default
    nodeID: resourceImage
  - apiVersion: apps/v1
    kind: Deployment
    name: podinfo-graph
    namespace: default
    nodeID: app/deployment          # child-scope resources carry path nodeIDs
  - apiVersion: v1
    kind: Service
    name: podinfo-graph
    namespace: default
    nodeID: app/service
```

### Child-scope capture + localization proof (T2)

The child Deployment's image literal is the value captured from the parent `def` node:

```text
$ kubectl get deployment podinfo-graph -o jsonpath='{.spec.template.spec.containers[0].image}'
ghcr.io/morri-son/ocm-graph-poc/stefanprodan/podinfo@sha256:8fa56908408de98f24aed2a162b1bb42c0b98df7abfcc5a76a14a8be510457c5
availableReplicas: 1

$ kubectl get pods -l app=podinfo-graph -o jsonpath='...'
podinfo-graph-5cd4f47d4d-cnstt Running image=ghcr.io/morri-son/ocm-graph-poc/stefanprodan/podinfo@sha256:8fa56908408de98f24aed2a162b1bb42c0b98df7abfcc5a76a14a8be510457c5 true

$ kubectl get endpoints podinfo-graph -o jsonpath='{.subsets[0].addresses[0].ip}:{.subsets[0].ports[0].port}'
10.244.0.8:9898
```

The image points at the transferred registry (`ghcr.io/morri-son/ocm-graph-poc/...`),
not `ghcr.io/stefanprodan/...`: the OCM Resource resolved the localized access, the
parent `def` mapped it, the child Deployment consumed it across the scope boundary.
Upstream OCM `Resource` status for reference:

```json
{"digest":"sha256:8fa56908408de98f24aed2a162b1bb42c0b98df7abfcc5a76a14a8be510457c5",
 "host":"ghcr.io","reference":"6.11.1@sha256:8fa56908...","registry":"ghcr.io",
 "repository":"morri-son/ocm-graph-poc/stefanprodan/podinfo","tag":"6.11.1"}
```

### Compile-time validation incl. child scope (T3)

`bad-graph.yaml` carries a CEL syntax error inside the child node
(`image: ${image.ref + }`). Applied 23:10:29.821, `Accepted=False` at 23:10:30.005
(~0.2 s):

```yaml
- type: Accepted
  status: "False"
  reason: InvalidGraph
  message: "build node \"app\": build dependency graph: node \"deployment\": variable
    at \"spec.template.spec.containers[0].image\": inspect: parse error: ERROR:
    <input>:1:13: Syntax error: mismatched input '<EOF>' ...
     | image.ref +
     | ............^"
- type: Ready
  status: "False"
  reason: InvalidGraph   (same message)
```

The child-scope error is reported **on the parent Graph** at compile time. Zero cluster
resources were created: `graph-bad-image-resource` (OCM Resource) NotFound,
`deployment/podinfo-bad` NotFound, `status.managedResources` empty. Object deleted
after capture.

### Lifecycle cascade (T4)

Deleting the Graph directly does **not** stick while the Deployer lives: it re-applied
the Graph ~0.1–1 s after `kubectl delete graph` (new UID, creationTimestamp one second
later). This is correct GitOps drift behavior, but worth one sentence in a tutorial.

Correct path — delete the `Deployer` (23:13:22.019):

```text
Graph object gone:             23:13:23.126   (+1.1 s)
Deployment/Service/OCM Resource all gone: 23:13:23.243   (+1.2 s total)
$ kubectl get graph,deployment,svc,resources.delivery.ocm.software -n default
service/kubernetes only
```

The kro Graph finalizer (`kro.run/graph-finalizer`) pruned child resources using the
recorded `status.managedResources` entries (UID-preconditioned deletes per the API
comments).

## Timings (single run, first = cold image pull, rerun = warm)

| stage | cold run | rerun |
|---|---|---|
| bootstrap chain applied (T0) | 23:09:30.738 | 23:12:59.533 |
| Component `Ready` | 23:09:36.689 (+6.0 s) | n/a |
| bootstrap-graph Resource `Ready` | 23:09:42.128 (+11.4 s) | n/a |
| Graph exists in cluster | 23:09:38 (+7.3 s)¹ | 23:12:59.570 |
| Graph `Accepted=True` (Compiled) | 21:09:38Z (+0 s) | — |
| Graph `Ready=True` | 21:09:46Z (+8 s after creation, +15.3 s after T0) | 23:13:01.038 (+1.5 s) |
| bad Graph `Accepted=False` | 23:10:30.005 (+0.2 s after apply) | — |
| Deployer delete → full cascade | +1.2 s | — |

¹ Graph creationTimestamp 21:09:38Z precedes Deployer `Ready` (23:09:42.264): the
Deployer applies before reporting its own Ready condition.

Cold `Ready` includes the ghcr pull of the freshly pushed podinfo image by the kind
node (imagePullSecret path exercised: package was private at test time).

## Comparison: RGD-of-RGDs @ kro 0.9.3 (poc/rgd-of-rgds) vs Graph @ PR #1355

| aspect | RGD nesting, kro 0.9.3 | Graph, PR #1355 |
|---|---|---|
| Nesting possible? | Structurally broken for realistic inner RGDs (blocker B: outer graph walks inner template tree and binds inner CEL to outer scope); only CEL-free inner templates work, parameterization frozen at materialization | Yes, first-class: `graph:` child node compiles into a SubProgram evaluated in-place (no separate child Graph object; child resources tracked as `app/...` nodeIDs in parent `managedResources`); no documented depth limit |
| CEL scope binding | One flat scope per instance; no way to embed a parameterized sub-composition | Lexical frames: child captures parent nodes (`${image.ref}`), shadowing resolves nearest frame, single-frame rule per expression; child outputs addressable as `${app.deployment...}` from parent |
| Compile-time validation | Outer RGD goes `Inactive` with `InvalidResourceGraph`: `references unknown identifiers: [deployment]`; recovery retry-driven (backoff up to minutes), not CRD-event-driven; errors surface only on the RGD, after instance CRD machinery | Parent `Accepted=False, reason=InvalidGraph` ~0.2 s after apply; child-scope errors with exact field path reported on the parent; **zero cluster resources created**; deterministic, no backoff storm |
| Readiness propagation | Nested inner RGD cannot carry `readyWhen`/status CEL (blocker B) → shallow ("manifests applied"); deep readiness only via the decoupled standalone-RGD shape | `readyWhen` per node at any depth (child Deployment gated on `availableReplicas == 1`); Graph `Ready` aggregates; extra `ResourcesConverged` condition separates apply from health |
| Lifecycle | Instance delete removes owned inner RGD + instances (~18 s observed); CRDs persist (allowCRDDeletion); ordering traps with stranded finalizers | `status.managedResources` write-ahead list, UID-preconditioned prune; full cascade ~1.2 s via finalizer; no CRDs spawned at all (Graph does not manage CRDs) |
| OCM bootstrap fit | RGD blob works (tutorial), but nesting needed the decoupled two-document shape | Single Graph blob delivers the whole nested flow; Deployer needs `graphs` RBAC grant instead of `resourcegraphdefinitions` |

## Blockers encountered

None against kro/OCM. One environment-only issue during setup: ko's multi-arch
`--local` image load picking amd64 on an arm64 colima VM (fix in README.md). Not
counted as an infrastructure blocker against the PR.

## ghcr leftovers (cleanup)

Private packages pushed under user `morri-son` (delete via GitHub package settings or
`gh api -X DELETE "/user/packages/container/<url-encoded-name>"`):

- `ocm-graph-poc/component-descriptors/ocm.software/ocm-k8s-toolkit/graph`
- `ocm-graph-poc/stefanprodan/podinfo`

## Cluster state at end

`kro-graph` kept running: kro (PR image, GraphKind on) + OCM controllers installed,
`ghcr-secret` in default, all POC objects (Graph, Deployment, Service, OCM
Resource/Component/Repository/Deployer) deleted. `kind/kubectl` context:
`kind-kro-graph`.
