#!/usr/bin/env bash
# End-to-end local deployment on kind: cluster, ingress, Kyverno, app, policies.
set -euo pipefail

CLUSTER="${CLUSTER:-helpdesk}"
IMAGE="${IMAGE:-helpdesk:1.0.0}"

command -v kind >/dev/null || { echo "kind is required: https://kind.sigs.k8s.io/"; exit 1; }
command -v kubectl >/dev/null || { echo "kubectl is required"; exit 1; }

echo "==> Creating kind cluster"
kind create cluster --name "$CLUSTER" --config deploy/kind/cluster.yaml || true

echo "==> Installing ingress-nginx"
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=240s

echo "==> Installing Kyverno"
kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.12.6/install.yaml || true
kubectl wait --namespace kyverno \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=admission-controller \
  --timeout=300s

echo "==> Building and loading image $IMAGE"
docker build -t "$IMAGE" .
kind load docker-image "$IMAGE" --name "$CLUSTER"

echo "==> Creating namespace and database secret"
kubectl apply -f deploy/manifests/namespace.yaml
./scripts/create_k8s_secret.sh

echo "==> Applying admission policies (before the workloads)"
kubectl apply -f deploy/policies/kyverno-hardening.yaml

echo "==> Applying workloads"
kubectl apply -k deploy/manifests
kubectl rollout status deployment/helpdesk-db -n helpdesk --timeout=240s
kubectl rollout status deployment/helpdesk-app -n helpdesk --timeout=240s

echo "==> Applying default-deny network policy"
kubectl apply -f deploy/network/default-deny.yaml
echo "    (app is now unreachable until the targeted allows are applied)"
sleep 3

echo "==> Applying targeted network allows"
kubectl apply -f deploy/network/allow-app.yaml
kubectl apply -f deploy/network/allow-db.yaml

echo
echo "Deployed. Open: http://helpdesk.localhost:8080"
echo "If the host does not resolve, add to /etc/hosts:"
echo "  127.0.0.1 helpdesk.localhost"
echo
echo "Negative admission test:"
echo "  kubectl apply -f tests/k8s/bad-pod.yaml   # must be rejected"
