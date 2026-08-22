                 ┌──────────────────────────┐
                 │     GitHub GitOps Repo    │
                 │ Helm + Kubernetes YAML    │
                 └────────────┬─────────────┘
                              │
                         ArgoCD sync
                              │
                              ▼
                 ┌──────────────────────────┐
                 │   Kubernetes Cluster     │
                 │ Minikube / EKS           │
                 │                          │
                 │ Online Boutique/SockShop │
                 └────────────┬─────────────┘
                              │
                       Fault Injection
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
         Metrics            Logs             Traces
        Prometheus       OpenSearch          X-Ray/
                                             Jaeger
             │                │                │
             └────────────────┼────────────────┘
                              │
                              ▼
                   Telemetry Collector
                              │
                              ▼
                   ┌─────────────────────┐
                   │    LangGraph        │
                   │   Multi-Agent AI    │
                   └──────────┬──────────┘
                              │
       ┌──────────────┬───────┼────────┬──────────────┐
       ▼              ▼       ▼        ▼              │
   Metrics Agent  Log Agent Trace Agent K8s Agent      │
       │              │       │        │              │
       └──────────────┴───────┼────────┴──────────────┘
                              ▼
                    Coordinator Agent
                     Evidence Fusion
                              │
                              ▼
                       Root Cause
                              │
                              ▼
                     Remediation Agent
                              │
                              ▼
                    Helm/YAML Patch
                              │
                              ▼
                       GitHub PR
                              │
                       Human Approval
                              │
                              ▼
                          ArgoCD
                              │
                              ▼
                       Kubernetes Fix
                              │
                              ▼
                     Validation Agent
                              │
                 ┌────────────┴────────────┐
                 │                         │
              Resolved                 Not Resolved
                 │                         │
                 ▼                         ▼
             Record Result          Re-run analysis