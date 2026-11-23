#!/usr/bin/env bash
# A one-node lab cluster for trying the platform from scratch: k0s in docker, with a plain-HTTP
# registry in the node's network namespace (pods pull localhost:5000). Not for production: an
# enterprise brings its own cluster and registry; everything after this script is the same.
#   NAME c-lab  PORT 6446 (API on 127.0.0.1)  REG_PORT 5004 (registry on 127.0.0.1)  DIR /var/lib/lab/<NAME>
#   lab-cluster.sh [--recreate] [--list]
# CoreDNS is left out (k0s would revert edits to its Corefile): bootstrap.sh installs it with the
# instance's own zone, so pods resolve the forge and app names to the cluster's gateway.
# Writes kubeconfig.<NAME> next to this script (mode 600, git-ignored).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
NAME=${NAME:-c-lab} PORT=${PORT:-6446} REG_PORT=${REG_PORT:-5004} DIR=${DIR:-/var/lib/lab/$NAME}
VER=${K0S_VERSION:-v1.37.2-k0s.1}
KC=${LAB_KUBECONFIG:-$here/kubeconfig.$NAME}
case "${1:-}" in
  --list) echo "container $NAME (k0s $VER) + $NAME-registry; state $DIR; API 127.0.0.1:$PORT; registry 127.0.0.1:$REG_PORT; kubeconfig $KC"; exit 0 ;;
  --recreate) docker rm -f "$NAME-registry" "$NAME" >/dev/null 2>&1 || true
              docker run --rm -v "$DIR:/d" alpine:3 sh -c 'rm -rf /d/k0s /d/kubelet' >/dev/null 2>&1 || true ;;
esac
mkdir -p "$DIR"/{k0s,kubelet,registry}
sed "s/\${NAME}/$NAME/g" "$here/k0s.yaml" > "$DIR/k0s.yaml"
if ! docker inspect "$NAME" >/dev/null 2>&1; then
  docker run -d --name "$NAME" --hostname "$NAME" --privileged --cgroupns=private --restart unless-stopped \
    -v "$DIR/k0s.yaml:/etc/k0s/k0s.yaml:ro" -v "$DIR/k0s:/var/lib/k0s" -v "$DIR/kubelet:/var/lib/kubelet:rshared" \
    -p 127.0.0.1:$PORT:6443 -p 127.0.0.1:$REG_PORT:5000 \
    docker.io/k0sproject/k0s:$VER \
    k0s controller --enable-worker --no-taints --disable-components=coredns --kubelet-root-dir=/var/lib/kubelet \
    --kubelet-extra-args='--eviction-hard=imagefs.available<10Gi,nodefs.available<10Gi,memory.available<200Mi' >/dev/null
fi
docker inspect "$NAME-registry" >/dev/null 2>&1 || \
  docker run -d --name "$NAME-registry" --restart unless-stopped --network "container:$NAME" \
    -v "$DIR/registry:/var/lib/registry" registry:2 >/dev/null
until docker exec "$NAME" k0s kubeconfig admin > "$KC" 2>/dev/null && [ -s "$KC" ]; do
  [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" = true ] || { docker logs "$NAME" 2>&1 | tail -5 >&2; exit 1; }
  sleep 3
done
sed -i -E "s#server: https://[^:]+:6443#server: https://localhost:$PORT#; \
  s/^(  name:|    cluster:|    user:) (local|user|Default)\$/\1 $NAME/; s/^- name: user\$/- name: $NAME/; \
  s/^current-context: Default\$/current-context: $NAME/" "$KC"
chmod 600 "$KC"
until KUBECONFIG=$KC kubectl get nodes 2>/dev/null | grep -q ' Ready'; do sleep 3; done
echo "$NAME ready: KUBECONFIG=$KC; node IP $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME")"
