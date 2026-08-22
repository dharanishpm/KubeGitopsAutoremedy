# agents

LangGraph-based multi-agent system for root cause analysis:

- **Metrics Agent** — analyzes Prometheus metrics for anomalies
- **Log Agent** — analyzes logs from Loki for error patterns
- **Trace Agent** — analyzes distributed traces from Jaeger for latency/failure paths
- **K8s Agent** — inspects cluster/resource state (pods, deployments, events)
- **Coordinator Agent** — fuses evidence from the above agents into a root cause hypothesis
