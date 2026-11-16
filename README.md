# AutoRemedy

## Multi-Agent LLM Framework for GitOps-Compliant Root Cause Analysis and Automated Remediation in Kubernetes

AutoRemedy is a research prototype for diagnosing Kubernetes failures using multiple specialised AI agents and generating GitOps-compliant remediation.

## Architecture

Metrics
Logs
Traces
Kubernetes Context
        |
        v
Specialised Agents
        |
        v
Coordinator
        |
        v
Root Cause
        |
        v
Remediation
        |
        v
GitHub Pull Request
        |
        v
Human Approval
        |
        v
ArgoCD
        |
        v
Kubernetes
        |
        v
Validation

## Current Phase

Local Minikube research environment.

## Technologies

- Kubernetes
- Minikube
- Docker
- Helm
- Prometheus
- Loki
- OpenTelemetry
- Jaeger
- Python
- LangGraph
- Ollama
- GitHub
- ArgoCD