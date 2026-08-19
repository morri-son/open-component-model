# Findings: OCM + kro Graph multi-layer stack — POC, 2026-08-19

Empirical validation of the layering hypothesis

> **OCM component = the shippable unit, OCM Deployer = the entry point,
> Graph = the composition layer, RGD = the product API layer**

against a minimal 2-product stack on kind cluster `kro-graph` (the cluster built
by the sibling POC `poc/graph`, kro PR kubernetes-sigs/kro#1355 @ `9b0a56d`,
`GraphKind=true`, Kubernetes v1.36.1). The productive pattern being minimized:
`task-center-installer.yaml` + `cf-services-installer.yaml` (13 hand-written
Resource+Deployer pairs, a 13-term status `&&` conjunction, and the
annotation-ordering hack `${string(cfServices.status.ready)}`).

Setup/reproduction: [README.md](README.md). Timestamps are Z unless noted;
`date +%s` epochs appear where the event has no API timestamp.

## Environment incident before testing (worth documenting)

The reused cluster was broken at POC start: `kube-proxy` CrashLoopBackOff with
`run.go:72] "command failed" err="failed complete: too many open files"` —
`fs.inotify.max_user_instances=128` on the colima VM (docker had restarted,
resetting the budget documented in `poc/graph/README.md`). kube-proxy failing
programmed no iptables rules, so the OCM controller logged
`dial tcp 10.96.0.1:443: i/o timeout` and CrashLoopBackOff'ed too. Fix (same as
the earlier POC, applied to the running VM):

```bash
docker run --rm --privileged --pid=host busybox \
  nsenter -t 1 -m -n -i sysctl -w fs.inotify.max_user_instances=1024
# then delete the stuck pods; kube-proxy/coredns/local-path/ocm all recovered within ~20 s
```

## Verdict table

| # | claim | verdict | headline evidence |
|---|---|---|---|
| 1 | Installer boilerplate collapses to ONE Graph with forEach | **PROVEN** | 64-line installer Graph replaces the 421-line `cf-services-installer.yaml` (13 pairs); growth per added product: +1 string vs +~32 lines; the 13-term status conjunction is engine-free (Graph `Ready` aggregates) |
| 2 | No annotation hacks between layers — real CEL edges | **PROVEN** | `frontend.spec.backendRef: ${backend.status.endpoint}`; running frontend pod carries `BACKEND_REF=backend.default.svc:8080`, i.e. backend's computed endpoint. Value flow ⇒ causal ordering, no annotation. (T5 shows the old annotation hack still works under an RGD, for comparison) |
| 3 | Validation fails fast | **PROVEN** | Same-second `Accepted=False/InvalidGraph` with exact CEL field path; ZERO child resources (compile gate is atomic — even the *valid* node never applied). Waited 0 additional machinery: the same mechanism caught a POC-authoring error in the installer Graph before any stray object was created |
| 4 | Readiness propagates deep, aggregated | **PROVEN** (one limitation) | readyWhen on RGD nodes, Graph template nodes, and forEach collections (`each`); Graph `Ready` flips only when every layer is ready. Limitation: a Graph has **no custom status fields** (no schema) — a computed cross-node status (like the productive `status.ready` conjunction) exists only as the intrinsic `Ready` condition, not as a spec-able field |
| 5 | One OCM component ships the whole stack | **PROVEN** | `ocm.software/graph-multilayer/stack:1.0.1` carries installer Graph + composition Graph + 2 product RGDs as 4 blob resources; the whole chain (Repository→Component→Resource→Deployer→Graph→forEach pairs→RGDs→CRDs→instances) ran end to end from ghcr |
| 6 | Late-CRD compile failure: does the Graph controller recover? | **PROVEN WITH CAVEAT** | Recovery exists and is fully automatic (no nudge needed) on BOTH paths — but it is **controller-runtime exponential-backoff-driven, not CRD-event-driven**. After 8.5–11 min failure streaks: Graph Accepted=True +150 s after CRD registration; RGD Active +185 s. Worst case ≈ backoff cap (~17 min). Apply-order discipline remains advisable for fast-install SLAs |

Claim 6 is the make-or-break question from the mandate; details in T2/T5 below.

## Component assembly & transfer (T0)

```text
$ ocm transfer cv --copy-resources --upload-as ociArtifact \
    transport-archive//ocm.software/graph-multilayer/stack:1.0.1 ghcr.io/morri-son/ocm-graph-multilayer
... "Transferring component versions: operation finished"

$ ocm get cv ghcr.io/morri-son/ocm-graph-multilayer//ocm.software/graph-multilayer/stack:1.0.1 -o yaml
resources: installer-graph / composition-graph / product-a-rgd / product-b-rgd   (4 x type: blob, access LocalBlob/v1)
```

Bootstrap stage 1 (Repository + Component `stack-component`):
applied 12:36:58Z (epoch 1787143018) → Component `Ready=True` at epoch 1787143023 (**+5 s**).

**Gotcha hit during the run:** re-transferring an OVERWRITTEN tag (1.0.0 with a
changed blob) did not propagate to the in-cluster Component CR within 6+
minutes of 1-minute reconciles. Bumping the constructor to a new version
(1.0.1) and the Component's `semver:` field propagated within ~4 s. Treat
component versions as immutable; bump on every payload change.

## T2 — late CRDs, Graph path (the key finding)

`sed`'ed copy of `composition-graph.yaml` (ns t2) applied at 12:37:11Z while
`backendservices.kro.run` / `frontendservices.kro.run` did NOT exist.

**Fail-fast:** same second, `Accepted=False`:

```yaml
- type: Accepted
  status: "False"
  reason: InvalidGraph
  message: 'build node "backend": resolve schema for kro.run/v1alpha1, Kind=BackendService:
    cannot resolve group version kind "kro.run/v1alpha1, Kind=BackendService": schema
    not found'
```

`kubectl -n t2 get all` → `No resources found in t2 namespace.` (zero children).

**Recovery: YES, automatic, no nudge — but backoff-driven.** Product CRDs
registered 12:45:35/37Z; the t2 Graph flipped `Accepted=True (Compiled)` at
**12:48:07Z (+150..152 s)**, `Ready=True` at 12:48:13Z. The 5-minute nudge
fallback was never needed; `kubectl annotate poke=1` was never run.

Mechanism, kro controller log (`compile failed` retry timestamps for t2/stack-composition):

```text
12:37:11 x5, 12:37:12 x3, 12:37:13, 12:37:14, 12:37:17, 12:37:22, 12:37:32,
12:37:52, 12:38:33, 12:39:55, 12:42:39   (17 failures; gaps double 10s→20s→41s→82s→164s)
```

`Accepted=True` at 12:48:07Z is exactly 12:42:39Z + 328 s: one more backoff
doubling. Controller-runtime exponential backoff (5 ms base), no other wakeup.

Why not event-driven, although the PR ships a SchemaWatcher whose `onAdd`
broadcasts CRD events "to give stuck Graphs a chance to recover"? Code read
(`pkg/graphengine/controller/graph/controller.go`, `schemawatcher/watcher.go`):

- `onAdd` enqueues "every Graph in our **subscriptions map**".
- A Graph only enters the subscriptions map via `schemaSub.Track(...)` — called
  in `reconcileGraph` AFTER `Registry.Compile` **succeeds**.
- A never-compiled Graph tracks nothing ⇒ the broadcast never reaches it.
- Verified empirically: zero `schema-watcher` log lines for the whole run.

Consequence: recovery lag grows with the failure streak (backoff capped at the
controller-runtime default 1000 s ≈ 17 min worst case). For our 8.5-min streak:
+150 s. For sub-minute streaks (the realistic fast-install case), the lag is
seconds — see T1's own compile error recovering within one generation bump.

## T5 — late CRDs, RGD on the new engine (rgdadapter / GraphRevisions)

`stack-rgd-minimal.yaml` (kind OldStyleStack, leaves BackendService +
FrontendService, annotation hack on frontend) applied 12:37:46Z, CRDs absent:

```text
state: Inactive
GraphAccepted False InvalidResourceGraph 12:37:46Z
  failed to build resource "backend": failed to get schema for resource backend:
  cannot resolve group version kind "kro.run/v1alpha1, Kind=BackendService": schema not found
GraphRevisionsResolved/KindReady/ControllerReady: Unknown AwaitingReconciliation
```

Same failure as blocker A on kro 0.9.3, but the PR's RGD carries the new
`GraphAccepted` condition and the GraphRevision machinery.

**Recovery: automatic, backoff-driven, slightly slower than the Graph path.**
CRDs at 12:45:35/37Z → `GraphAccepted=True (Valid)` at **12:48:42Z (+185..187 s)**,
`Ready=True` 12:48:43Z. Controller log for `oldstyle-stack` shows the same
doubling backoff: 12:37:49, :52, :57, 12:38:07, :28, 12:39:09, 12:40:30,
12:43:14 — then the next double (328 s later) succeeded at 12:48:42Z.

OldStyleStack instance (ns t5): apply epoch 1787143816 (12:50:16Z) →
`ACTIVE / status.ready=true` at the +9 s probe. Ordering evidence — the
productive annotation hack still works under the new engine:

```text
backend  apply-order=1                                    (internal.kro.run/apply-order)
frontend apply-order=2, poc.ocm.software/after-backend="true"
```

## T1 — forEach installer

One caught authoring error first (evidence value): readyWhen written as
`rgdResource.all(r, ...)` on the forEach node failed compile with
`unexpected failed resolution of '__type_rgdResource.@idx'` — the doc comment
in the PR's `graph_types.go` ("use CEL list functions like `all()`") does not
hold for a collection self-reference. The working idiom is the `each` keyword
(per-element), found via the PR's own integration tests
(`compiler/typecheck.go: "readyWhen for a collection is evaluated per-element
with each bound"`). The failure produced zero stray objects — claim 3's
compile gate protected the cluster from my own mistake.

Fixed flow (component bump applied 12:45:28.5Z, epoch 1787143528):

```text
installer Graph Accepted=True (Compiled)   12:45:32Z (+4 s)
installer Graph Ready=True                 12:45:37Z (+9 s)
managedResources: Resource/product-a-rgd, Resource/product-b-rgd,
                  Deployer/product-a-rgd, Deployer/product-b-rgd
both Deployers Ready=True                  12:45:37Z
CRDs backendservices/frontendservices      12:45:35Z / 12:45:37Z
RGDs backend-service/frontend-service      Active
```

**Claim-1 comparison:**

```text
$ wc -l installer-graph.yaml cf-services-installer.yaml
  64 installer-graph.yaml        (2 products, incl. comments)
 421 cf-services-installer.yaml  (13 products, productive file)
```

Growth per added product: +1 string in the Graph's `def` node (plus its blob
entry in the component constructor) vs ~32 lines of hand-written pair + one
term in the status conjunction in the productive RGD. At 13 products the Graph
stays ≈75 lines.

## T3 — real CEL edge + deep readiness (composition via OCM, ns default)

`composition-deploy.yaml` applied 12:51:07.2Z (epoch 1787143867). First probe
(+8 s): everything already true.

```text
graph stack-composition: created 12:51:09Z; Accepted/ResourcesConverged/Ready=True all 12:51:09Z
BackendService backend:  created 12:51:09Z, instance Ready 12:51:09Z, status.endpoint=backend.default.svc:8080
FrontendService frontend:created 12:51:09Z, instance Ready 12:51:09Z, spec.backendRef=backend.default.svc:8080
frontend Deployment env: BACKEND_REF=backend.default.svc:8080
```

Notes: (a) warm path — the nginx image was already node-cached from t2's pods;
the same flow in t2 (cold pull) took compile→Ready ≈ 6 s. (b) "frontend only
after backend Ready": same-second timestamps cannot show it, but the ordering
is proven structurally — the frontend spec CONTAINS backend's computed
endpoint (`${backend.status.endpoint}`, DataPending until present), so its
apply strictly postdates backend's status publication. That is stronger than a
timestamp delta.

## T4 — fail-fast / zero side effects

`bad-composition-graph.yaml` (`readyWhen: ${frontend.status.readyness}`) in ns
t4, applied 12:51:55.958Z → `Accepted=False/InvalidGraph` at 12:51:55Z (same
second):

```text
compile node "frontend": node "frontend": readyWhen[0] ("frontend.status.readyness"):
ERROR: <input>:1:16: undefined field 'readyness'
 | frontend.status.readyness
 | ...............^
```

```text
$ kubectl get all,backendservices,frontendservices -n t4
No resources found in t4 namespace.
```

Not even the valid `backend` node applied: the compile gate is atomic per Graph.

## T6 — lifecycle

- `kubectl -n default delete graph stack-composition` (Deployer alive): the
  Graph was re-applied within ~1 s (GitOps drift protection, same as poc/graph).
- `kubectl delete deployer stack-composition` 12:53:12Z (epoch 1787143992): at
  the +1 s probe Graph, both instances and both Deployments were **gone**.
- `kubectl -n t2 delete graph stack-composition`: instances pruned within 1 s.
- `kubectl -n t5 delete oldstylestack t5-stack`: leaves gone in ~4 s (RGD
  instance path, slightly slower, no finalizer hang).
- `kubectl delete deployer stack-installer` 12:53:45Z (epoch 1787144025): at
  +1 s, Graph stack-installer + both forEach Resource CRs + both product
  Deployers + **both product RGDs** all gone — the whole generated chain.
- No stranded finalizers anywhere (`instances: No resources found`).

CRD persistence (matches poc/rgd-of-rgds):

```text
12:53:45Z INFO rgd-controller skipping CRD deletion because allowCRDDeletion is disabled  crd=frontendservices.kro.run
12:53:45Z INFO rgd-controller skipping CRD deletion because allowCRDDeletion is disabled  crd=backendservices.kro.run
12:53:57Z INFO rgd-controller skipping CRD deletion because allowCRDDeletion is disabled  crd=oldstylestacks.kro.run
```

`kubectl get crd` still lists backendservices, frontendservices, oldstylestacks.

## Timing summary (single run)

| transition | value |
|---|---|
| bootstrap stage1 apply → Component Ready | +5 s |
| t2 composition apply → Accepted=False (CRDs absent) | same second (≤1 s) |
| oldstyle RGD apply → Inactive | same second |
| installer chain (post-bump) apply → Graph Ready incl. 2 RGDs + CRDs | +9 s |
| **T2 recovery: CRDs registered → t2 Graph Accepted=True (auto, backoff)** | **+150..152 s** |
| **T5 recovery: CRDs registered → RGD GraphAccepted=True (auto, backoff)** | **+185..187 s** |
| t2 compile→Ready (cold nginx pull, both layers) | +6 s |
| t5 instance apply → OldStyleStack ACTIVE+ready | ≤9 s |
| t4 bad Graph apply → Accepted=False, 0 children | same second (≤1 s) |
| T3 composition-chain apply → Graph Ready (warm) | ≤8 s (transitions +2 s) |
| T6 deployer-delete cascades | ≤1 s each (t5 instance prune 4 s) |

## Aside: kro log noise worth knowing

While an instance's custom status field is not yet computed, the Graph
controller logs a `ResourcesConverged=False`-style ERROR per second:
`readyWhen "backend.status.ready": eval: no such key: ready (executor: node
not ready)`. Benign (5 observed in t2 during warmup) but log-noisy for
operators; surfaced as `DataPending`/`WaitingForReadiness` conditions.

## ghcr leftovers (manual cleanup — token lacks delete:packages)

One new package (blobs ride as layers of the component OCI artifact):

- `ghcr.io/morri-son/ocm-graph-multilayer/component-descriptors/ocm.software/graph-multilayer/stack`

## Cluster state at end

`kro-graph` running and healthy. Deliberately left: namespaces t2/t4/t5 (empty),
bootstrap stage-1/2/3 OCM objects (`stack-repository`, `stack-component`,
Resources `stack-installer-graph`, `stack-composition-graph` in default;
Deployers deleted per T6), product CRDs `backendservices/frontendservices/
oldstylestacks.kro.run` (allowCRDDeletion off). All Graphs, all product
instances, all product RGDs, all workload pods deleted. Leftovers from
poc/graph (`bootstrap-repository`, `bootstrap-component`, Resource
`bootstrap-graph`) untouched.
