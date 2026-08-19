# POC: kro Graph (KREP-024, PR #1355) as OCM bootstrap payload

Setup and reproduction for the empirical validation of kro's experimental **Graph**
engine as the bootstrap payload of an OCM component, replacing the
`ResourceGraphDefinition` blob of the tutorial
`website/content/docs/tutorials/deploy-helm-chart-bootstrap.md` (kro
inline-manifests variant: podinfo via plain Deployment + Service, no Helm/Flux). The
nested `graph:` child node replaces the "RGD of RGDs" construction from the sibling
POC `poc/rgd-of-rgds` (branch `poc/rgd-of-rgds`, not pushed; its results are included
in the comparison table in [FINDINGS.md](FINDINGS.md)).

**Status: all checks passed** (2026-08-18). Results, verbatim outputs, timings, and
the RGD comparison: [FINDINGS.md](FINDINGS.md).

## Contents

| file | purpose |
|---|---|
| `component-constructor.yaml` | OCM component `ocm.software/ocm-k8s-toolkit/graph:1.0.0`: `image-resource` (public podinfo, digest-pinned) + `blob` resource `graph` containing `graph.yaml` |
| `graph.yaml` | The Graph payload. Parent: `resourceImage` (OCM Resource CR, `additionalStatusFields.oci`, readyWhen on `Ready == True`), `image` (`def:` computing localized coordinates), `app` (nested `graph:` child: podinfo Deployment + Service, captures parent image ref) |
| `bootstrap.yaml` | Repository → Component → Resource → Deployer chain; apply via envsubst (`$OCM_REPO`) |
| `custom-rbac.yaml` | Grants `graphs.kro.run` verbs to the `ocm-k8s-toolkit-controller-manager` SA (mirrors the website custom-RBAC how-to, for Graph instead of RGD) |
| `bad-graph.yaml` | T3 negative test: CEL syntax error inside the child node |
| `transport-archive/` | `ocm add cv` build artifact, gitignored |

## Prerequisites

- kind, helm, kubectl, ko, `ocm` CLI
- GitHub PAT with `write:packages` (used both for `ocm transfer` and as the
  in-cluster pull/`ocmConfig` credentials)
- kro source checkout of PR kubernetes-sigs/kro#1355, tested at head `9b0a56d`
- Tested on: Apple Silicon, colima, kind cluster with Kubernetes v1.36.1. If kind
  bootstrap fails with "Too many open files" while other clusters run, raise the
  inotify budget first:

  ```bash
  docker run --rm --privileged --pid=host busybox \
    nsenter -t 1 -m -n -i sysctl -w fs.inotify.max_user_instances=1024
  ```

```bash
export OCM_REPO=ghcr.io/<your-user>/ocm-graph-poc   # target for transfer + source in bootstrap.yaml
kind create cluster --name kro-graph                 # this POC ran with Kubernetes v1.36.1
```

## Setup

### 1. Build and load the kro controller image from PR #1355

In the kro worktree (no kro code modified):

```bash
make build-image
```

Gotcha (Apple Silicon + colima): the Makefile's `ko build --local` with
`defaultPlatforms: [linux/arm64, linux/amd64]` loads an index into the colima docker
daemon that resolves to **linux/amd64 only** on the arm64 VM. The controller
crashloops with `exec /ko-app/controller: exec format error`. Fix: rebuild
single-platform with ko directly (same inputs as `make build-image`, but
`--bare --local --platform=linux/arm64 --tags pr-1355`), then:

```bash
kind load docker-image ko.local/kro:pr-1355 --name kro-graph
```

### 2. Install kro with the GraphKind feature gate

```bash
helm install kro ./helm -n kro-system --create-namespace \
  --set image.repository=ko.local/kro \
  --set image.tag=pr-1355 \
  --set config.featureGates.GraphKind=true
```

The gate is off by default. Verify: the controller log shows
`GraphKind feature enabled; starting Graph controller`, and
`kubectl get crd` lists `graphs.kro.run` (plus
`graphrevisions.internal.kro.run`).

### 3. Install the OCM controllers and grant Graph RBAC

1. Install per the website getting-started guide
   (`oci://ghcr.io/open-component-model/kubernetes/controller/chart`, release
   `ocm-k8s-toolkit`).
2. The stock chart lacks permissions for `graphs.kro.run`; apply the grant and
   verify:

   ```bash
   kubectl apply -f custom-rbac.yaml
   kubectl auth can-i create graphs.kro.run \
     --as=system:serviceaccount:ocm-k8s-toolkit-system:ocm-k8s-toolkit-controller-manager
   # → yes
   ```

### 4. Registry secret

One `ghcr-secret` in `default`, referenced three times: Repository `ocmConfig`
(`bootstrap.yaml`), the OCM Resource template `ocmConfig` and the Deployment
`imagePullSecrets` (both `graph.yaml`):

```bash
kubectl create secret docker-registry ghcr-secret -n default \
  --docker-server=ghcr.io --docker-username=<user> --docker-password=<PAT>
```

### 5. Build, publish, and verify the component

```bash
ocm add cv
ocm transfer cv --copy-resources --upload-as ociArtifact \
  transport-archive//ocm.software/ocm-k8s-toolkit/graph:1.0.0 $OCM_REPO
ocm get cv $OCM_REPO//ocm.software/ocm-k8s-toolkit/graph:1.0.0 -o yaml | grep imageReference
# → imageReference: ghcr.io/<your-user>/ocm-graph-poc/stefanprodan/podinfo:...  (localized)
```

`--copy-resources` rehosts the public podinfo image into your registry; the
descriptor's access info is rewritten (localized) in the transfer.

### 6. Apply the bootstrap chain

```bash
envsubst < bootstrap.yaml | kubectl apply -f -
kubectl get graph -n default            # expect: podinfo-bootstrap   True
kubectl get pods -l app=podinfo-graph   # image = localized ghcr ref, digest-pinned
```

Cold `apply → Graph Ready` took 15.3 s including the private-registry image pull;
warm rerun 1.5 s (single run, see FINDINGS.md).

## Teardown

Delete the **Deployer**, not the Graph: the Deployer re-applies a directly deleted
Graph within ~1 s (GitOps drift protection). Deleting the Deployer cascades:
Graph, Deployment, Service, and the OCM Resource are pruned via
`status.managedResources` in ~1.2 s.

```bash
kubectl delete deployer bootstrap-deployer
```

## Authoring notes (KREP-024 vs. PR #1355 code)

- Valid node keywords: `template`, `ref`, `def`, `graph` (plus `readyWhen`,
  `includeWhen`, `forEach`). The KREP text's `watch:` and `patch:` do not exist as
  user-facing keywords in the PR.
- Conditions on a Graph: `Accepted` (compile result, False reason `InvalidGraph`)
  and `Ready`; the controller additionally sets `ResourcesConverged`.
- See FINDINGS.md for the full divergence list; `api/v1alpha1/graph_types.go` in
  the PR is the source of truth.
