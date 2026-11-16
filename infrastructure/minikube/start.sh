#!/bin/bash

set -e

echo "======================================"
echo "Starting AutoRemedy Minikube Cluster"
echo "======================================"

minikube start \
  --driver=docker \
  --cpus=4 \
  --memory=7168 \
  --disk-size=40g

echo ""
echo "======================================"
echo "Cluster Status"
echo "======================================"

kubectl get nodes

echo ""
echo "======================================"
echo "Cluster Information"
echo "======================================"

kubectl cluster-info

echo ""
echo "AutoRemedy Minikube cluster started."