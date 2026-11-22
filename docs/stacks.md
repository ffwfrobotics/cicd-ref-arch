# Stacks: clusters as apps

A **stack** is an enrolled app whose deploy is a whole cluster: its definition, the platform it runs, and the apps on it. It goes through the same pipeline as an app:
- **dev:** stand a cluster up from the definition, check it, stand it down;
- **promotion:** a PR that someone approves and schedules;
- **prod:** the definition applied to a real target in a window.

The tenant record says `kind: Stack` (docs/enrollment.md). The IaC root's `cicd.yaml` describes the cluster:

```yaml
apiVersion: cicd.ffwf.net/v1alpha1
kind: Stack
metadata: {name: stack-ref}
spec:
  provider: k0s-pod                 # how a cluster is made (below)
  definition: cluster/              # k0s.yaml for the node, flux.yaml for what the cluster pulls
  check:
    timeout: 900s
    smoke: tests/smoke.sh           # optional: run against the cluster's kubeconfig after it is Ready
  environments:
    dev:  {target: nested}          # a throwaway cluster per run
    prod: {target: <cluster>, window: {weekday: sat, start: "02:00", hours: 2}}
```

## Lifecycle

`tools/stack.py` runs each step and writes what it saw: timings, versions, each Flux Kustomization's state, check results. It goes to the run's artifact `stack` and to the state repo, under `stacks/<cluster>/<stack>/`.

| Step | What it does |
|---|---|
| `up` | the provider makes the cluster in a platform-allocated slot and returns a handle (a kubeconfig); then Flux is bootstrapped at the stack's commit, with one GitRepository per pinned submodule |
| `check` | waits for every Flux Kustomization to be Ready, deploys `hello` and runs the runtime check on it, then the stack's smoke test. One word, as for apps: `ready`, `not-ready <kustomization>`, `smoke-failed`, `timeout` |
| `down` | removes the cluster and everything it made in the host |

A dev run is `up`, `check`, `down`, and `down` runs even when `check` failed. A failed check is recorded and shown; the evidence stays after the cluster is gone.

## The provider contract

`tools/stack.py` (akb #493) defines `Slot`, `ClusterRequest`, `ClusterHandle` and `Provider`:
- **The platform allocates the slots:** names, pod and service ranges, API port (`clusters/<cluster>/stack-slots.yaml`). A provider never chooses them, so nested clusters can't collide with the host or with each other.
- **A provider** turns a request into a cluster and returns a handle: a kubeconfig, the API endpoint, the registry, its capabilities (`api`, `nodes`, `cni`, `csi`, ...) and its isolation (`none`, `userns`, `vm`). Everything after `up` uses only the handle.
- **A check names the capabilities it needs.** On a provider without one, the check is recorded as **not exercised**, never as passed.
- **The lifecycle is the provider's,** implemented here, never in the stack repo. The stack's own check script (`spec.check.smoke`) runs **inside** the nested cluster as a Job, with that cluster's kubectl and a read-only role without Secrets. It never runs on the platform's runner, next to the platform's credentials.

**No platform credentials go into a stack's cluster.** Whoever writes a stack repo decides what Flux applies there, as cluster-admin, so they could read anything put there. A repo anyone can clone needs no credentials. Any other repo gets a **deploy key of its own for the run**: read-only, on that repo only, made when the cluster is bootstrapped and deleted when it goes down. A stack writer can then read only a key that reads their own repo, for as long as their cluster exists.

## Providers

### `k0s-pod`: a cluster as one pod in the host cluster

The dev provider: a single k0s controller-and-worker, as a privileged pod in a namespace of its own (`stack-<name>-<run>`) on the cluster the platform runs on. Measured on c-local: Ready in about 25 s, all system pods Ready in about 65 s, idle at about 0.27 CPU and 770 MiB.

The image is `images/stack-node` (k0s, pinned by digest; `build.sh` builds it). Three things make a nested node safe and self-contained. Each was found the hard way:
1. **A private cgroup namespace.** A privileged pod sees the host node's whole cgroup tree. A nested kubelet then finds the host's `kubepods` and tries to "clean up" the host's pods as orphans: it tried, on c-local. `entry.sh` moves the node into a child of its own cgroup, unshares the cgroup namespace and remounts cgroup2, so the nested kubelet's root is its own pod.
2. **Its own address ranges.** The host's pods use `10.244.0.0/16`, which is also k0s's default. A nested cluster on the same range routes its own traffic back into the host. Nested clusters use pods `10.250.0.0/16` and services `10.251.0.0/16`. They never talk to each other, so every nested cluster can use the same pair.
3. **System images inside the image.** The node's own images (`k0s airgap list-images`) are a bundle in the image, imported at start. A nested cluster becomes Ready without any registry. The stack's own images come from the host's registry (`registry.pull` in `cicd-cluster.yaml`), configured as a mirror in the nested containerd.

The namespace is `pod-security.kubernetes.io/enforce: privileged`. Only the platform's stack workflow creates these namespaces, and its runner pod has a ServiceAccount allowed to do so in `stack-*` namespaces only. App pipelines never get one.

### `k0s-docker`: a cluster as a container on a host

The provider for real targets on a machine with docker: `infra/k0s-local/create.sh` (c-local was built this way). It needs a runner on that host with the docker socket. That runner is privileged on the host, registered on the platform repo only, and not part of the base setup: adding one is an admin decision.

## Promotion

A stack is promoted like an app: a PR, approved by a second person (recorded, docs/security.md), merged and applied when due. For a stack, **due** means inside the window: the earliest `notBefore` is the window's start. **Applied** means `up` against the prod target, either standing a new cluster up in place of the old, or rolling in place where the provider allows it. A failed `check` after the apply is recorded and shown on the stack's prod page; rolling back is promoting the previous stack commit.

## Sources: the chain

A stack's IaC root can hold app IaC roots as submodules (`sources`, docs/enrollment.md). When an app is promoted, the bot bumps the stack's pointer to that app's IaC commit: a commit in follow mode, a PR in pin mode. The stack's dev run then checks the cluster with the new app. Each hop carries `Source-Commit` trailers, so the lineage from cluster to app IaC to app source can be read from git.

## Capacity

Nested clusters share the host. On midlife (12 cores, 125 GB) c-local idles at about 1.2 cores and 12 GB. One nested cluster with the platform on it needs about 1.5 cores and 4 GB while it runs. The stack workflow runs one lifecycle at a time (a concurrency group), with a timeout, and `down` on every exit.
