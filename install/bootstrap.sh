#!/usr/bin/env bash
# Stage 0 for a lab instance, on a fresh cluster from lab-cluster.sh (an enterprise cluster that
# already has DNS, storage, cert-manager and a forge starts at the platform instead: docs/install.md).
#   bootstrap.sh instances/<name>.env
# Makes (idempotent): CoreDNS with the zone rewrite, local-path storage, Flux, the instance CA,
# cert-manager + ClusterIssuer lab-ca, Forgejo with its admin. Secrets it makes (the CA key, the
# admin password) stay in $SECRETS (default /var/lib/lab/<CLUSTER>/secrets, mode 700), never in git.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1090
. "$1"
export INSTANCE BRAND CLUSTER ZONE FORGE_HOST ADMIN_USER
export ZONE_RE=${ZONE//./\\.}
KC=${LAB_KUBECONFIG:-$here/kubeconfig.$CLUSTER}; export KUBECONFIG=$KC   # never an ambient KUBECONFIG
SECRETS=${SECRETS:-/var/lib/lab/$CLUSTER/secrets}
LOCAL_PATH=v0.0.32
t0=$(date +%s); mark() { echo "[$(( $(date +%s) - t0 ))s] $*"; }
render() { envsubst '${INSTANCE} ${BRAND} ${CLUSTER} ${ZONE} ${ZONE_RE} ${FORGE_HOST} ${ADMIN_USER}' < "$1"; }
mkdir -p "$SECRETS"; chmod 700 "$SECRETS"

# DNS first: Flux and the charts need it
helm repo add coredns https://coredns.github.io/helm >/dev/null 2>&1 || true
helm upgrade --install coredns coredns/coredns --version 1.50.8 -n kube-system \
  -f <(render "$here/lab/coredns-values.yaml") --wait --timeout 5m >/dev/null
mark "CoreDNS (zone $ZONE -> the gateway)"
kubectl apply -f "https://raw.githubusercontent.com/rancher/local-path-provisioner/$LOCAL_PATH/deploy/local-path-storage.yaml" >/dev/null
kubectl annotate sc local-path storageclass.kubernetes.io/is-default-class=true --overwrite >/dev/null
mark "local-path storage (default)"
flux check --pre >/dev/null 2>&1 && kubectl get ns flux-system >/dev/null 2>&1 || flux install >/dev/null 2>&1
mark "Flux"

# The instance CA: name-constrained, so it can't vouch for anything outside the instance
if [ ! -s "$SECRETS/ca.key" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -keyout "$SECRETS/ca.key" -out "$SECRETS/ca.crt" -subj "/O=$BRAND/CN=$BRAND lab CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "nameConstraints=critical,permitted;DNS:$ZONE,permitted;DNS:.$ZONE,permitted;DNS:.svc.cluster.local" 2>/dev/null
  chmod 600 "$SECRETS/ca.key"
fi
cp "$SECRETS/ca.crt" "$here/ca.$INSTANCE.crt"
render "$here/lab/cert-manager.yaml" | kubectl apply -f - >/dev/null
kubectl -n cert-manager create secret tls lab-ca --cert="$SECRETS/ca.crt" --key="$SECRETS/ca.key" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n cert-manager wait helmrelease/cert-manager --for=condition=Ready --timeout=10m >/dev/null
kubectl apply -f "$here/lab/issuer.yaml" >/dev/null
mark "cert-manager + ClusterIssuer lab-ca ($here/ca.$INSTANCE.crt is the CA to trust)"

# Forgejo and its admin
render "$here/lab/forgejo.yaml" | kubectl apply -f - >/dev/null
[ -s "$SECRETS/forgejo-admin" ] || { openssl rand -base64 24 | tr -d '/+=\n' > "$SECRETS/forgejo-admin"; chmod 600 "$SECRETS/forgejo-admin"; }
kubectl -n forgejo create secret generic forgejo-admin --from-literal=username="$ADMIN_USER" \
  --from-file=password="$SECRETS/forgejo-admin" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n forgejo wait helmrelease/forgejo --for=condition=Ready --timeout=15m >/dev/null
mark "Forgejo (admin $ADMIN_USER, password in $SECRETS/forgejo-admin)"
