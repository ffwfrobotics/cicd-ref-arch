#!/bin/sh
# needs: api
# The stack's own check, after every Flux Kustomization is Ready: run with KUBECONFIG set to the nested
# cluster. The platform layer's CRDs and controllers are there and answer.
set -eu
kubectl get crd gateways.gateway.networking.k8s.io httproutes.gateway.networking.k8s.io >/dev/null
kubectl -n keda get deploy keda-operator -o jsonpath='{.status.readyReplicas}' | grep -q '^[1-9]'
kubectl get ingressclass traefik >/dev/null 2>&1 || kubectl get gatewayclass traefik >/dev/null
echo "platform layer answers"
