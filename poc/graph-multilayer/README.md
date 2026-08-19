# POC: OCM multi-layer stack — Graph composition + RGD product APIs (KREP-024, PR #1355)

Empirical validation of the layering hypothesis

> OCM component = the shippable unit, OCM Deployer = the entry point,
> Graph = the composition layer, RGD = the product API layer

on a minimal 2-product stack. Combines the Graph engine of the sibling POC
`poc/graph` (branch `poc/graph-krep024`, kro PR kubernetes-sigs/kro#1355 @
`9b0a56d`) with the productive multi-RGD layering pattern ("one leaf-installer
RGD per product, one stack-installer RGD on top" — see
`task-center-core/tc-product-stack/public/task-center-installer.yaml` and
`shared/cf-services-installer.yaml` in NDBS-Automation-Development), minimized
here to two products.

**Status: all tests ran; claims 1–5 PROVEN, claim 6 PROVEN WITH CAVEAT
(recovery is automatic but backoff-driven, not CRD-event-driven).** Verbatim
evidence and timings: [FINDINGS.md](FINDINGS.md).

## Contents

| file | purpose |
|---|---|
| `component-constructor.yaml` | OCM component `ocm.software/graph-multilayer/stack:1.0.1`: four `blob` resources (`installer-graph`, `composition-graph`, `product-a-rgd`, `product-b-rgd`) |
| `product-a-rgd.yaml` | RGD `backend-service` minting kind `BackendService` (Deployment+Service, computed `status.endpoint`, `status.ready`) |
| `product-b-rgd.yaml` | RGD `frontend-service` minting kind `FrontendService` (+ `spec.backendRef` wired to container env `BACKEND_REF`) |
| `installer-graph.yaml` | Graph `stack-installer`: one `def` node listing product blob names + TWO `forEach` nodes creating the OCM Resource+Deployer pair per product. Replaces the ~420-line leaf-installer RGD |
| `composition-graph.yaml` | Graph `stack-composition`: `frontend.spec.backendRef: ${backend.status.endpoint}` — real CEL data-flow edge, zero annotations |
| `stack-rgd-minimal.yaml` | T5 only: RGD `oldstyle-stack`, 1:1 miniature of the productive `task-center-installer` incl. the annotation-ordering hack |
| `oldstyle-instance.yaml` | T5 instance of `OldStyleStack` (ns t5) |
| `bad-composition-graph.yaml` | T4 negative test: CEL typo in `readyWhen` (ns t4) |
| `bootstrap.yaml` | OCM stage 1: Repository + Component (`stack-component`); apply via envsubst (`$OCM_REPO`) |
| `installer-deploy.yaml` | OCM stage 2: Resource + Deployer for the `installer-graph` blob. Applying this STARTS the installer |
| `composition-deploy.yaml` | OCM stage 3: Resource + Deployer for the `composition-graph` blob (apply only after T2) |
| `custom-rbac.yaml` | Grants `graphs` AND `resourcegraphdefinitions` (kro.run) verbs to the OCM controller SA |
| `transport-archive/` | `ocm add cv` build artifact, gitignored |

## Prerequisites

Same as `poc/graph` ([../graph/README.md](../graph/README.md)): kind, helm,
kubectl, ko, `ocm` CLI, GitHub PAT with `write:packages`, kro source checkout
of PR #1355 pinned at head `9b0a56d`. This POC **reuses the cluster built by
`poc/graph`** (kind `kro-graph`, Kubernetes v1.36.1, Apple Silicon + colima,
kro with `config.featureGates.GraphKind=true`, OCM controllers, `ghcr-secret`
in default). If that cluster is gone, recreate it following `../graph/README.md`
§Setup-1/2/3 EXACTLY, including the `ko --platform=linux/arm64` trap and the
inotify budget fix. The colima VM resets `fs.inotify.max_user_instances` to 128
on every docker restart; symptom afterwards: `kube-proxy` CrashLoopBackOff with
`too many open files`, then every controller pod loses API connectivity (this
POC's run started with exactly that incident — see FINDINGS.md §Environment).
Fix on the running VM:

```bash
docker run --rm --privileged --pid=host busybox \
  nsenter -t 1 -m -n -i sysctl -w fs.inotify.max_user_instances=1024
```

```bash
export OCM_REPO=ghcr.io/<your-user>/ocm-graph-multilayer   # transfer target + source in bootstrap.yaml
# every kubectl below wants: --context kind-kro-graph
```

## Setup

Order matters: T2/T5 occupy the window in which the product CRDs do not exist
yet, so they must be applied BEFORE the installer (stage 2) runs.

### 1. Grant Graph + RGD RBAC, create the test namespaces

`custom-rbac.yaml` extends the `poc/graph` grant: the OCM controller SA gets
verbs for `graphs` AND `resourcegraphdefinitions` (kro.run). Namespaces
t2/t4/t5 isolate the late-CRD and negative tests from the main chain
(namespace `default`).

```bash
kubectl apply -f custom-rbac.yaml
kubectl create ns t2; kubectl create ns t4; kubectl create ns t5
```

### 2. Build, publish, and verify the component

```bash
ocm add cv
ocm transfer cv --copy-resources --upload-as ociArtifact \
  transport-archive//ocm.software/graph-multilayer/stack:1.0.1 $OCM_REPO
ocm get cv $OCM_REPO//ocm.software/graph-multilayer/stack:1.0.1 -o yaml | grep name
# → installer-graph / composition-graph / product-a-rgd / product-b-rgd
```

Immutability note: if you change a blob, BUMP the version (`component-constructor.yaml`
and the `semver:` field in `bootstrap.yaml`). Re-transferring an overwritten tag
did not propagate to the in-cluster Component CR within 6+ min (FINDINGS.md T0).

### 3. Apply the bootstrap chain — stage 1 (Repository + Component)

```bash
envsubst < bootstrap.yaml | kubectl apply -f -
kubectl wait --for=condition=Ready component/stack-component --timeout=120s
```

### 4. Occupy the late-CRD window (T2 + T5)

```bash
# T2 (Graph path): composition into ns t2 BEFORE the product CRDs exist
sed 's/namespace: default/namespace: t2/' composition-graph.yaml | kubectl apply -f -
kubectl -n t2 get graph stack-composition          # Accepted=False InvalidGraph, same second
kubectl -n t2 get all                              # empty — zero child resources

# T5 (RGD path): the oldstyle stack BEFORE the product CRDs exist
kubectl apply -f stack-rgd-minimal.yaml            # state Inactive, "schema not found"
```

### 5. Start the installer — stage 2 (and watch T2/T5 recover)

Recovery is backoff-driven; lag grows with the failure streak (observed
+150..185 s after an 8.5–11 min streak, seconds for short ones). Poll tight.

```bash
kubectl apply -f installer-deploy.yaml             # Resource + Deployer for installer-graph
kubectl -n t2 get graph stack-composition -w       # Accepted flips True automatically
kubectl get rgd oldstyle-stack -w                  # Inactive → Active automatically
kubectl wait graph/stack-installer --for=jsonpath='{.status.conditions[?(@.type=="Ready")].status}'=True --timeout=600s
kubectl get crd | grep kro.run                     # backendservices/frontendservices registered
kubectl apply -f oldstyle-instance.yaml            # T5 instance (ns t5)
```

### 6. Composition via OCM + negative test (T3 + T4)

```bash
kubectl apply -f composition-deploy.yaml           # stage 3, CRDs present now
kubectl get graph stack-composition -w             # Accepted/ResourcesConverged/Ready
kubectl get pods -l app=frontend -o jsonpath='{.spec}...' # env BACKEND_REF = backend endpoint

kubectl apply -f bad-composition-graph.yaml        # T4: CEL typo, ns t4
kubectl -n t4 get graph bad-composition            # Accepted=False same second
kubectl get all -n t4                              # empty
```

## Teardown

Delete **Deployers**, not Graphs: the Deployer re-applies a directly deleted
Graph in ~1 s (GitOps drift protection, same as `poc/graph`; observed again
here). Deleting the Deployer cascades in ~1 s via `status.managedResources`.
RGD path: instances BEFORE RGDs (finalizer trap otherwise).

```bash
kubectl delete deployer stack-composition stack-installer
kubectl delete oldstylestack t5-stack -n t5        # instances BEFORE RGDs
kubectl -n t2 delete graph stack-composition       # kubectl-applied, no Deployer above it
kubectl -n t4 delete graph bad-composition
kubectl delete rgd oldstyle-stack
# product CRDs persist (allowCRDDeletion off) — delete manually if wanted:
kubectl delete crd backendservices.kro.run frontendservices.kro.run oldstylestacks.kro.run
```

## Authoring notes (delta vs `poc/graph`)

- **forEach `readyWhen` uses the `each` keyword** (`${each.status...}`),
  evaluated per element. The `graph_types.go` doc comment suggesting CEL list
  functions like `.all()` on the collection value does NOT compile for a
  collection self-reference (`unexpected failed resolution of
  '__type_<id>.@idx'`). Working idiom found via the PR's integration tests
  (`compiler/typecheck.go`). Worth PR feedback. See FINDINGS.md T1.
- `watch:`/`patch:` nodes in the PR's `examples/graph/singleton.yaml` and
  `namespace-decorator.yaml` are NOT in the `Node` XValidation
  (template/ref/def/graph only) — those examples are stale.
- A Graph has **no schema and no custom status fields**: computed cross-node
  status (the productive `status.ready` conjunction) exists only as the
  intrinsic `Ready` condition. Keep computed status on the RGD layer.
- Same-tag OCI overwrite (re-transfer of version 1.0.0 with a changed blob)
  did NOT propagate in-cluster within 6+ min. Treat component versions as
  immutable; bump on every payload change (this component is 1.0.1 for that
  reason).
