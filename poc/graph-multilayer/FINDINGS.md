# Findings: OCM multi-layer stack — Graph composition + RGD product APIs — POC, 2026-08-19

Empirical validation of the layering hypothesis

> **OCM component = the shippable unit, OCM Deployer = the entry point,
> Graph = the composition layer, RGD = the product API layer**

against a minimal 2-product stack, reusing the cluster built by the sibling POC
`poc/graph` (branch `poc/graph-krep024`). The productive pattern being
minimized: `task-center-installer.yaml` + `cf-services-installer.yaml` from
NDBS-Automation-Development (13 hand-written Resource+Deployer pairs, a 13-term
status `&&` conjunction, and the annotation-ordering hack
`${string(cfServices.status.ready)}`), reduced here to two products.

Setup and reproduction steps: [README.md](README.md). Timestamps are Z unless
noted; `date +%s` epochs appear where the event has no API timestamp. Single
run, unscientific but real.

## Environment

- kro source: PR #1355 head `9b0a56d`, no kro code modified (same build as
  `poc/graph`)
- kind cluster `kro-graph`, Kubernetes v1.36.1, colima on Apple Silicon —
  **reused** from `poc/graph`, including kro with
  `config.featureGates.GraphKind=true` and the OCM controllers
  (`oci://ghcr.io/open-component-model/kubernetes/controller/chart`, release
  `ocm-k8s-toolkit`), plus `custom-rbac.yaml` granting `graphs` AND
  `resourcegraphdefinitions` (kro.run) to the controller service account
- Registry: `ghcr.io/morri-son/ocm-graph-multilayer`, package private at test
  time; `ghcr-secret` pattern for the Repository `ocmConfig`. Product workload
  images: public `nginx`, no pull secret needed
- Timestamps: `kubectl` conditions are Z; wall clock CEST via `date +%s` epochs

### Incident before testing (environment-only)

The reused cluster was broken at POC start: `kube-proxy` CrashLoopBackOff with
`run.go:72] "command failed" err="failed complete: too many open files"` —
`fs.inotify.max_user_instances=128` on the colima VM (docker had restarted,
resetting the budget documented in `poc/graph/README.md`). kube-proxy failing
programmed no iptables rules, so the OCM controller logged
`dial tcp 10.96.0.1:443: i/o timeout` and CrashLoopBackOff'ed too. Fix (applied
to the running VM, same as the earlier POC):

```bash
docker run --rm --privileged --pid=host busybox \
  nsenter -t 1 -m -n -i sysctl -w fs.inotify.max_user_instances=1024
# then delete the stuck pods; kube-proxy/coredns/local-path/ocm all recovered within ~20 s
```

## What this POC adds over `poc/graph` (source of truth: PR #1355 code)

- **forEach `readyWhen` is evaluated per element with the `each` keyword**
  (`${each.status...}`). The doc comment in `api/v1alpha1/graph_types.go`
  suggesting `.all()` on the collection value does NOT compile for a collection
  self-reference: `unexpected failed resolution of '__type_<id>.@idx'`. Working
  idiom confirmed via the PR's integration tests (`compiler/typecheck.go`).
  Worth upstream PR feedback.
- **A Graph has no schema ⇒ no custom status fields.** A computed cross-node
  status (the productive `status.ready` conjunction) exists only as the
  intrinsic `Ready` condition (plus `ResourcesConverged`), not as a spec-able
  field. Computed status stays an RGD feature.
- **Late-CRD recovery is backoff-driven, not CRD-event-driven** (the T2
  finding, mechanism below): the PR's SchemaWatcher `onAdd` broadcast only
  reaches Graphs in its subscriptions map, and a Graph enters that map via
  `schemaSub.Track(...)` — called in `reconcileGraph` AFTER a successful
  compile. A never-compiled Graph tracks nothing, so the broadcast never
  reaches it. Verified empirically: zero `schema-watcher` log lines all run.
- **Same-tag OCI overwrite does not propagate in-cluster** (T0 gotcha): only a
  version bump updated the Component CR in reasonable time (~4 s vs 6+ min of
  silent non-propagation). Treat component versions as immutable.

## Test flow

Order matters — T2/T5 need the late-CRD window open:

0. **T0**: build + transfer component `ocm.software/graph-multilayer/stack:1.0.1`
   (4 blobs: installer Graph, composition Graph, 2 product RGDs); apply RBAC,
   namespaces t2/t4/t5, bootstrap stage 1 (Repository + Component
   `stack-component`). Product CRDs do NOT exist yet.
1. **T2**: `composition-graph.yaml` into ns t2 — Graph path with CRDs absent.
2. **T5**: `stack-rgd-minimal.yaml` — RGD-on-new-engine path with CRDs absent.
3. **T1**: `installer-deploy.yaml` starts the installer; product CRDs register;
   watch T2/T5 recover (the recovery measurement is part of T2/T5).
4. **T5 (instance)**: `oldstyle-instance.yaml` into ns t5.
5. **T3**: `composition-deploy.yaml` — composition via the OCM path (ns
   default), CRDs present.
6. **T4**: `bad-composition-graph.yaml` into ns t4 — compile gate.
7. **T6**: lifecycle / teardown order.

## Results — verbatim

### Component assembly & transfer (T0)

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
(1.0.1) and the Component's `semver:` field propagated within ~4 s.

### Late CRDs, Graph path — the key finding (T2)

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
doubling. Controller-runtime exponential backoff, no other wakeup. Why not
event-driven, although the PR ships a SchemaWatcher whose `onAdd` broadcasts
CRD events: `Track()` runs only after a successful compile, so never-compiled
Graphs are never subscribed (see the analysis section above).

Consequence: recovery lag grows with the failure streak (backoff capped at the
controller-runtime default 1000 s ≈ 17 min worst case). For our 8.5-min
streak: +150 s. For sub-minute streaks (the realistic fast-install case), the
lag is seconds — see T1's own compile error recovering within one generation
bump.

**Post-hoc verification on the healthy cluster (controlled CRD).** To rule out
that the inotify incident skewed the measurement, a clean-room probe repeated
the experiment after the fix: Graph `latebind-probe` in a fresh ns t7
templating `poc.test/v1alpha1, Kind=LateBind` (CRD absent), failures allowed to
build a 100 s streak, then the CRD registered deliberately BETWEEN two backoff
boundaries:

| event | timestamp |
|---|---|
| Graph applied → `Accepted=False/InvalidGraph` | 13:53:10Z (same second) |
| compile retry series (kro log) | 13:53:20 → :30 → :51 → 13:54:32 (gaps 10→21→41 s) |
| CRD `latebinds.poc.test` registered | 13:55:12Z (41 s before the next boundary) |
| predicted next backoff retry | 13:55:53Z |
| `Accepted=True` observed | **13:55:55Z** (1 s poll granularity) |

Event-driven recovery would have flipped `Accepted` 1–2 s after CRD
registration; instead the Graph sat on a resolvable schema for 43 s and
recovered exactly on the predicted backoff boundary. Zero schema-watcher log
lines. Same signature as the main T2 run. Probe objects cleaned up afterwards;
cluster state unchanged.

### Late CRDs, RGD on the new engine (T5)

`stack-rgd-minimal.yaml` (kind `OldStyleStack`, leaves BackendService +
FrontendService, annotation hack on frontend) applied 12:37:46Z, CRDs absent:

```text
state: Inactive
GraphAccepted False InvalidResourceGraph 12:37:46Z
  failed to build resource "backend": failed to get schema for resource backend:
  cannot resolve group version kind "kro.run/v1alpha1, Kind=BackendService": schema not found
GraphRevisionsResolved/KindReady/ControllerReady: Unknown AwaitingReconciliation
```

Same failure as blocker A on kro 0.9.3 (see `poc/rgd-of-rgds/FINDINGS.md`), but
the PR's RGD carries the new `GraphAccepted` condition and the GraphRevision
machinery.

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

### forEach installer (T1)

One caught authoring error first (evidence value): `readyWhen` written as
`rgdResource.all(r, ...)` on the forEach node failed compile with
`unexpected failed resolution of '__type_rgdResource.@idx'` — the doc-comment
idiom does not hold for a collection self-reference (correct: `each`, see
analysis section). The failure produced zero stray objects — the compile gate
(T4) protected the cluster from the authoring mistake.

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

**Line-count comparison (claim 1):**

```text
$ wc -l installer-graph.yaml cf-services-installer.yaml
  64 installer-graph.yaml        (2 products, incl. comments)
 421 cf-services-installer.yaml  (13 products, productive file)
```

Growth per added product: +1 string in the Graph's `def` node (plus its blob
entry in the component constructor) vs ~32 lines of hand-written pair + one
term in the status conjunction in the productive RGD. At 13 products the Graph
stays ≈75 lines.

### Real CEL edge + deep readiness (T3)

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

### Fail-fast / zero side effects (T4)

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

### Lifecycle (T6)

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

## Timings (single run)

| stage | value |
|---|---|
| bootstrap stage1 apply → Component `Ready` (T0) | +5 s |
| t2 composition apply → `Accepted=False`, CRDs absent (T2) | same second (≤1 s) |
| oldstyle RGD apply → `Inactive` (T5) | same second |
| installer chain apply → Graph `Ready` incl. 2 RGDs + CRDs (T1) | +9 s |
| **T2 recovery: CRDs registered → t2 Graph `Accepted=True`** (auto, backoff) | **+150..152 s** |
| **T5 recovery: CRDs registered → RGD `GraphAccepted=True`** (auto, backoff) | **+185..187 s** |
| t2 compile→`Ready` (cold nginx pull, both layers) | +6 s |
| t5 instance apply → OldStyleStack `ACTIVE`+ready | ≤9 s |
| t4 bad Graph apply → `Accepted=False`, 0 children (T4) | same second (≤1 s) |
| T3 composition-chain apply → Graph `Ready` (warm) | ≤8 s (transitions +2 s) |
| T6 deployer-delete cascades | ≤1 s each (t5 instance prune 4 s) |

## Claims: hypothesis vs. measured

| # | claim | verdict | headline evidence |
|---|---|---|---|
| 1 | Installer boilerplate collapses to ONE Graph with forEach | **PROVEN** | 64-line installer Graph replaces the 421-line `cf-services-installer.yaml` (13 pairs); growth per added product: +1 string vs +~32 lines; the 13-term status conjunction is engine-free (Graph `Ready` aggregates) |
| 2 | No annotation hacks between layers — real CEL edges | **PROVEN** | `frontend.spec.backendRef: ${backend.status.endpoint}`; running frontend pod carries `BACKEND_REF=backend.default.svc:8080`. Value flow ⇒ causal ordering, no annotation. (T5 shows the old annotation hack still works under an RGD, for comparison) |
| 3 | Validation fails fast | **PROVEN** | Same-second `Accepted=False/InvalidGraph` with exact CEL field path; ZERO child resources (compile gate is atomic — even the *valid* node never applied). The same mechanism caught a POC-authoring error before any stray object was created |
| 4 | Readiness propagates deep, aggregated | **PROVEN** (one limitation) | `readyWhen` on RGD nodes, Graph template nodes, and forEach collections (`each`); Graph `Ready` flips only when every layer is ready. Limitation: no custom status fields on a Graph — computed cross-node status exists only as the intrinsic `Ready` condition |
| 5 | One OCM component ships the whole stack | **PROVEN** | `ocm.software/graph-multilayer/stack:1.0.1` carries all 4 blobs; the whole chain (Repository→Component→Resource→Deployer→Graph→forEach pairs→RGDs→CRDs→instances) ran end to end from ghcr |
| 6 | Late-CRD compile failure: does the controller recover? | **PROVEN WITH CAVEAT** | Recovery exists and is fully automatic (no nudge) on BOTH paths — but backoff-driven, not CRD-event-driven. After 8.5–11 min failure streaks: Graph +150 s, RGD +185 s. Worst case ≈ 1000 s backoff cap. Apply-order discipline remains advisable for fast-install SLAs |

## Blockers encountered

None against kro/OCM. One environment-only incident before testing (colima
inotify budget reset by a docker restart; fix in §Environment). Two operational
gotchas, not blockers: same-tag OCI overwrite non-propagation (T0) and
per-second `no such key: ready` ERROR noise from the Graph controller while an
instance's custom status field is uncomputed (benign; surfaced as
`DataPending`/`WaitingForReadiness` conditions, but log-noisy for operators).

## ghcr leftovers (cleanup)

Token lacks `delete:packages`; delete via GitHub package settings or
`gh api -X DELETE "/user/packages/container/<url-encoded-name>"`:

- `ocm-graph-multilayer/component-descriptors/ocm.software/graph-multilayer/stack`

## Cluster state at end

`kro-graph` running and healthy (kro PR image, GraphKind on, OCM controllers,
`ghcr-secret` in default). Deliberately left: namespaces t2/t4/t5 (empty),
bootstrap stage-1/2/3 OCM objects (`stack-repository`, `stack-component`,
Resources `stack-installer-graph`, `stack-composition-graph` in default;
Deployers deleted per T6), product CRDs `backendservices/frontendservices/
oldstylestacks.kro.run` (`allowCRDDeletion` off). All Graphs, all product
instances, all product RGDs, all workload pods deleted. Leftovers from
poc/graph (`bootstrap-repository`, `bootstrap-component`) untouched.
`kind export kubeconfig --name kro-graph` restores the kubectl context if the
session kubeconfig lost it.
