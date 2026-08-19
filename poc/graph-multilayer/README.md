# POC: OCM component + Deployer + kro Graph (KREP-024) as the multi-layer stack installer

Combines the Graph engine from the sibling POC `poc/graph` (branch `poc/graph`,
kro PR kubernetes-sigs/kro#1355 @ `9b0a56d`) with the productive multi-RGD
layering pattern ("one leaf-installer RGD per product, one stack-installer RGD
on top"). The hypothesis under test:

> OCM component = the shippable unit, OCM Deployer = the entry point,
> Graph = the composition layer, RGD = the product API layer.

**Status: all tests ran; claims 1–5 PROVEN, claim 6 PROVEN WITH CAVEAT
(backoff-driven, not event-driven recovery).** Verbatim evidence and timings:
[FINDINGS.md](FINDINGS.md).

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

Same as `poc/graph`: kind, helm, kubectl, ko, `ocm` CLI, GitHub PAT with
`write:packages`, kro PR #1355 checkout pinned at `9b0a56d`. This POC **reuses
the cluster built by `poc/graph`** (kind `kro-graph`, Kubernetes v1.36.1, kro
with `GraphKind=true`, OCM controllers, `ghcr-secret` in default). If that
cluster is gone, recreate it following `../../graph/poc/graph/README.md`
§Setup-1/2/3 EXACTLY — including the `ko --platform=linux/arm64` trap on
Apple Silicon + colima and the inotify budget fix (the colima VM resets
`fs.inotify.max_user_instances` to 128 on docker restart; symptom after VM
restart: `kube-proxy` CrashLoopBackOff with `too many open files`, then every
controller pod loses API connectivity):

```bash
docker run --rm --privileged --pid=host busybox \
  nsenter -t 1 -m -n -i sysctl -w fs.inotify.max_user_instances=1024
```

```bash
export OCM_REPO=ghcr.io/<your-user>/ocm-graph-multilayer
kubectl config use-context kind-kro-graph   # pass --context kind-kro-graph if unset
```

## Test flow (order matters — T2/T5 need the late-CRD window open)

```bash
# 0. RBAC (Deployer applies Graphs AND RGDs), namespaces, bootstrap stage 1
kubectl apply -f custom-rbac.yaml
kubectl create ns t2; kubectl create ns t4; kubectl create ns t5
ocm add cv
ocm transfer cv --copy-resources --upload-as ociArtifact \
  transport-archive//ocm.software/graph-multilayer/stack:1.0.1 $OCM_REPO
envsubst < bootstrap.yaml | kubectl apply -f -     # Repository + Component only
kubectl wait --for=condition=Ready component/stack-component --timeout=120s

# 1. T2 (late-CRD, Graph path): composition into t2 BEFORE product CRDs exist
sed 's/namespace: default/namespace: t2/' composition-graph.yaml | kubectl apply -f -
kubectl -n t2 get graph stack-composition -o yaml   # Accepted=False InvalidGraph, ~0s

# 2. T5 (late-CRD, RGD path): oldstyle RGD BEFORE product CRDs exist
kubectl apply -f stack-rgd-minimal.yaml             # state Inactive, "schema not found"

# 3. Start the installer (stage 2) => product CRDs register;
#    watch t2 Graph and oldstyle RGD recover (poll 2s, expect minutes: backoff)
kubectl apply -f installer-deploy.yaml
kubectl wait graph/stack-installer --for=jsonpath='{.status.conditions[?(@.type=="Ready")].status}'=True --timeout=120s

# 4. T5 instance
kubectl apply -f oldstyle-instance.yaml

# 5. T3 (composition via OCM path, CRDs present)
kubectl apply -f composition-deploy.yaml
kubectl -n default get graph stack-composition -w

# 6. T4 (fail-fast): CEL typo variant in ns t4
kubectl apply -f bad-composition-graph.yaml         # Accepted=False same second, 0 children

# 7. T6 (lifecycle) — see FINDINGS.md; order: instances before Deployers before RGDs
```

## Teardown

Delete **Deployers**, not Graphs (the Deployer re-applies a directly deleted
Graph in ~1 s; observed again here). Cascade took ~1 s per delete.

```bash
kubectl delete deployer stack-composition stack-installer
kubectl delete oldstylestack t5-stack -n t5   # instances BEFORE RGDs
kubectl -n t2 delete graph stack-composition  # kubectl-applied, no Deployer above it
kubectl delete rgd oldstyle-stack
# product CRDs persist (allowCRDDeletion off) — delete manually if wanted:
kubectl delete crd backendservices.kro.run frontendservices.kro.run oldstylestacks.kro.run
```

## Authoring notes (delta vs `poc/graph`)

- **forEach readyWhen uses the `each` keyword** (`${each.status...}`), evaluated
  per item. The `graph_types.go` doc comment that suggests `.all()` on the
  collection value does NOT compile for a self-referencing collection node
  (`unexpected failed resolution of '__type_<id>.@idx'`). See FINDINGS.md.
- `watch:`/`patch:` nodes in `examples/graph/singleton.yaml` and
  `namespace-decorator.yaml` are NOT in the PR's `Node` XValidation
  (template/ref/def/graph only) — those two examples are stale.
- Same-tag OCI overwrite (re-transfer of version 1.0.0 with a changed blob)
  did NOT propagate to the in-cluster Component CR within 6+ min. Bump the
  component version (this repo ships as 1.0.1 for that reason).
