#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-autoremedy}"
CPUS="${CPUS:-4}"
MEMORY="${MEMORY:-8192}"

minikube start \
  --profile "${CLUSTER_NAME}" \
  --cpus "${CPUS}" \
  --memory "${MEMORY}" \
  --driver=docker

kubectl apply -f "$(dirname "$0")/namespace.yaml"
