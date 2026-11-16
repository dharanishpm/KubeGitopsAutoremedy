# CLAUDE.md – AutoRemedyRIC (read this first)

## What this project is
MSc Cloud Computing research project: **"A Multi-Agent AIOps Framework for LLM-Driven Root Cause Analysis and GitOps-Based Automated Remediation in Kubernetes."**

AutoRemedyRIC monitors Google Online Boutique (test workload, NOT our app) on Minikube, uses specialist agents to collect evidence, a Coordinator to identify the root cause, a Remediation Agent to propose a fix, GitOps (GitHub PR + Argo CD) to deploy it after human approval, and a Validation Agent to confirm recovery. Final goal: run reproducible fault experiments locally, then on AWS EKS, and report results in the thesis.

This is an EXISTING implementation. Do not treat it as a new project.

## Environment
- macOS, Minikube, Python **3.9.6** in `.venv` (keep 3.9 compatible: no `X | Y` types, no `match`)
- langgraph 0.6.11, langchain-ollama 0.3.10, kubernetes 35.0.0, PyYAML, requests
- Ollama + `llama3.2:latest`, temperature 0
- Observability: Prometheus, Loki, Jaeger, OpenTelemetry, Grafana
- Port-forwards (must be running before any test):
  ```
  kubectl port-forward -n monitoring svc/kube-prometheus-stack-prometheus 9090:9090
  kubectl port-forward -n monitoring svc/kube-prometheus-stack-grafana 3000:80
  kubectl port-forward -n loki svc/loki 3100:3100
  kubectl port-forward -n observability svc/jaeger 16686:16686
  kubectl port-forward -n default svc/frontend-external 8080:80
  ```
- There is NO loadgenerator pod; traffic must be generated manually (curl loop on :8080).

## Repository layout
```
workflow.py          LangGraph orchestrator (Stage 1, working)
faults.yaml          fault definitions + ground truth
runs/<exp_id>/       per-run outputs (gitignore this)
agents/
  metrics-agent/metrics_agent.py   (+ baseline_calculator.py, baseline.json)
  log-agent/log_agent.py
  trace-agent/trace_agent.py
  k8s-agent/k8s_agent.py
  coordinator/coordinator.py       (V2)
  remediation-agent/remediation_agent.py   (V1, PROPOSAL_ONLY)
  validation-agent/validation_agent.py     (V1)
infrastructure/, application/online-boutique, evaluation/, fault-injection/, remediation/, telemetry/
```
Do NOT rename the hyphenated agent folders. Agents are invoked as subprocesses.

## Agent CLIs (verified from source)
| Agent | Command | Output |
|---|---|---|
| metrics | `python agents/metrics-agent/metrics_agent.py <service>` | stdout: progress lines + banner + JSON + trailing `====` |
| logs | `python agents/log-agent/log_agent.py <service> [lookback_min]` | stdout: progress + banner + JSON |
| traces | `python agents/trace-agent/trace_agent.py <service> [lookback_min]` | stdout: progress + banner + JSON |
| k8s | `python agents/k8s-agent/k8s_agent.py <service> [event_lookback_min]` | clean JSON on stdout |
| coordinator | `python agents/coordinator/coordinator.py --metrics F --logs F --trace F --k8s F` | JSON on stdout |
| remediation | `--coordinator F --k8s F --output F --patch-output F` | writes files + prints JSON |
| validation | `<service> [--namespace default] [--wait 10] [--output F]` | clean JSON on stdout |

Metrics/log/trace/remediation/validation hardcode localhost URLs; only k8s-agent reads env vars (`K8S_NAMESPACE`, `OLLAMA_URL`, `OLLAMA_MODEL`, `OLLAMA_TIMEOUT`).

JSON shapes: metrics/logs/traces wrap as `{"service","agent","evidence":{...,"analysis":{"status":...}},"ollama_analysis"}`. k8s is flat: `deployment`, `pods`, `endpoints`, `events`, `analysis`, `ollama_analysis`. Coordinator result: `ollama_analysis.analysis.{incident_status, root_cause_candidate, confidence, affected_services}` and `deterministic_findings.{deterministic_incident_status, deterministic_root_cause_candidates, deterministic_confidence}`.

## workflow.py (current)
- Graph: `init` → metrics/logs/traces/k8s in parallel → `coordinator` → (if CONFIRMED_INCIDENT) `remediation` → `approval` (LangGraph `interrupt`, MemorySaver) → `validation`.
- `extract_json()` skips banners and decodes the first line starting with `{`.
- Failed/unparseable agent → `MISSING_EVIDENCE` placeholder file (never treated as healthy).
- `--service` = fault target, `--trace-service` = symptom service (Jaeger is queried on the caller, e.g. frontend).
- Flags: `--fault F01`, `--lookback N`, `--stop-after-diagnosis`.
- Approval currently = human applies `kubectl scale ...` manually, then answers y (stand-in until GitOps exists).
- Writes `runs/<id>/{metrics,logs,traces,k8s,coordinator,remediation,validation,summary}.json` + `*.stdout.txt/*.stderr.txt`.

Run: `python workflow.py --fault F01 --stop-after-diagnosis --lookback 3`

## Results so far
- Run `20261116-170346_F01_8d89bd` (no traffic after fault): Coordinator LLM = POSSIBLE_INCIDENT / currencyservice / MEDIUM; deterministic = NO_CONFIRMED_INCIDENT. Correct refusal under insufficient evidence — keep as an example.
- Run `20261116-174158_F01_b86ca2` (with traffic): POSSIBLE_INCIDENT, candidate **checkoutservice**, deterministic candidates [checkoutservice, paymentservice]. **Wrong.** currencyservice was scaled to 0.

### Diagnosed causes of the misattribution
1. **k8s_agent.py `analyse_kubernetes_state` ignores desired_replicas == 0** (all checks gated by `desired > 0`) → returns NORMAL for the injected fault. This also leaks experiment knowledge ("scale-to-zero is intentional").
2. Metrics/logs have no data for a service with no pods (no pod → no series / NO_LOG_DATA).
3. Trace Agent attributes failed spans to the **caller** (checkoutservice/frontend); the real callee only appears in the operation name (e.g. `hipstershop.CurrencyService/Convert`).
4. **paymentservice has ~1814 restarts** (pre-existing instability) → background noise polluting traces.
5. 15-min lookback includes pre-fault traces.

## IMMEDIATE NEXT TASKS (in order)
1. **Inspect** `runs/20261116-174158_F01_b86ca2/{traces,k8s}.json` and confirm causes 1 and 3 (span_error_counts_by_service, affected_operations, k8s analysis status).
2. **Fix A – k8s_agent.py → v1.1** (commit before editing):
   - Add finding `SCALED_TO_ZERO` (severity ERROR) when `desired == 0`.
   - Fire `NO_READY_ENDPOINTS` when `endpoints.found and ready_count == 0`, regardless of desired.
   - Bump version strings to "1.1". Keep the Ollama prompt rule that zero replicas alone isn't the root cause.
3. **Fix B – coordinator.py**: read its candidate-selection logic first, then map failed client spans to the **callee** service parsed from the gRPC operation name (`hipstershop.<X>Service/<Method>` → `<x>service`) or `peer.service`. Preserve deterministic-first design.
4. **Fix C – paymentservice noise**: inspect `kubectl describe pod -l app=paymentservice` and `kubectl logs --previous`; fix it, or formally label it as background noise and exclude from scoring.
5. **Re-test F01**: scale currencyservice to 0, wait 2 min, 40-request curl loop on :8080, wait 30 s, `python workflow.py --fault F01 --stop-after-diagnosis --lookback 3`. Expected: CONFIRMED_INCIDENT, currencyservice, HIGH.
6. Also run healthy-system check (no fault) → must NOT confirm an incident.
7. Full flow `python workflow.py --fault F01` with approval gate → VALIDATION_PASSED.

## Known issues to address later
- Validation Agent returns VALIDATION_PASSED on `NO_TRACE_DATA` → conflicts with "missing telemetry ≠ healthy". Decide and document.
- k8s & validation agents use deprecated v1 Endpoints API → migrate to EndpointSlice.
- Hardcoded localhost URLs in 5 agents → move to env vars before Docker/EKS.
- Grafana RIC Dashboard on EmptyDir → export + provision via ConfigMap.
- Parallel agents share one Ollama → limited speedup; report per-agent timings honestly.
- Human approval time must be reported separately from MTTR.

## Later stages
- **Stage 2 GitOps**: GitOps repo with Online Boutique manifests; Argo CD Application (selfHeal); Remediation Agent edits real YAML, creates branch `autoremedy/<exp_id>`, opens PR (PyGithub), allowlist guardrail (replicas/resources/env only); merge = approval; wait Argo Synced/Healthy; then Validation. Inject faults via Git or pause auto-sync (selfHeal would otherwise undo kubectl faults).
- **Stage 3 harness** (`harness/run_experiment.py`): reset → inject (t_inject) → traffic warmup → workflow (t_detect, t_diagnosis) → PR/merge → t_recovered. Faults F01–F05 (unavailable, CPU stress, memory/OOM, app errors, network latency via Chaos Mesh/stress-ng). Randomised order, ≥5 reps. Baselines A (rule-based) and B (single LLM, same evidence). Ablation: disable one evidence agent at a time.
- **Stage 4 container**: one Docker image (all agents + workflow), env-var config, `--platform linux/amd64`, test as K8s Job on Minikube.
- **Stage 5 AWS**: EKS (eksctl, m5.xlarge ×3, EBS CSI), ECR, observability via Helm (pinned), Argo CD, Ollama on CPU or g4dn node (document choice), S3 results via Pod Identity/IRSA, read-only RBAC for agents, budget alerts, tear down cluster between sessions.
- **Metrics for thesis**: exact & top-k RCA accuracy, precision/recall/F1, false-positive rate, unsupported-claim rate, per-agent & total diagnosis latency, time-to-detect, time-to-PR, Argo sync time, MTTR (with/without human wait), remediation & validation success, ablation deltas, local vs EKS comparison, cost per run; mean±std, CIs, McNemar/bootstrap.

## Rules (must follow)
1. Inspect source before changing any agent; make minimal, targeted edits; commit before edits.
2. Never invent metrics, logs, traces or experiment results. No numbers in the thesis until real runs exist.
3. Deterministic evidence is the source of truth; LLM output is explanation only.
4. Missing telemetry is never proof of health.
5. Remediation stays PROPOSAL_ONLY until GitOps is built; human approval always required; never apply arbitrary changes directly to the cluster.
6. Keep runs reproducible: timestamps, experiment ID, model, prompt/code version (git commit), baseline.json frozen.
7. Explain each step and give exact terminal commands. Test locally before AWS. Minimise AWS cost.
