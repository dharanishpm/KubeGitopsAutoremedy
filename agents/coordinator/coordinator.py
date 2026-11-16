#!/usr/bin/env python3

"""
AutoRemedyRIC - Coordinator Agent V2

Purpose:
    Fuse deterministic evidence from:
        - Metrics Agent
        - Log Agent
        - Trace Agent
        - Kubernetes Context Agent

The Coordinator identifies the most likely incident/root-cause candidate.

Important design principles:
    1. Deterministic agent evidence is authoritative.
    2. Individual agent Ollama prose is NOT used for RCA.
    3. Missing logs/traces/metrics are not treated as healthy evidence.
    4. A service appearing in a failed trace does not automatically mean
       that service is the root cause.
    5. Strong RCA requires correlation across independent evidence sources.
    6. Ollama is used for evidence interpretation, not evidence invention.
    7. No remediation is performed by this agent.

Python:
    Compatible with Python 3.9+
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:latest"
OLLAMA_TIMEOUT = 120


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def load_json(path: str) -> Dict[str, Any]:
    """Load a JSON file."""
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError("File not found: {}".format(path))

    with file_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError(
            "Expected JSON object in {}, got {}".format(
                path, type(data).__name__
            )
        )

    return data


def utc_now() -> str:
    """Return current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def safe_list(value: Any) -> List[Any]:
    """Return a list or an empty list."""
    return value if isinstance(value, list) else []


def safe_dict(value: Any) -> Dict[str, Any]:
    """Return a dictionary or an empty dictionary."""
    return value if isinstance(value, dict) else {}


def first_non_empty(*values: Any) -> Any:
    """Return the first non-empty value."""
    for value in values:
        if value is not None and value != "" and value != [] and value != {}:
            return value
    return None


# ---------------------------------------------------------------------------
# Evidence wrapper handling
# ---------------------------------------------------------------------------

def unwrap_evidence(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Metrics, Logs and Trace agents currently return:

        {
            "service": "...",
            "agent": "...",
            "evidence": {
                ...
            },
            "ollama_analysis": "..."
        }

    Kubernetes Agent returns its evidence directly at the top level.

    This function normalizes both formats.
    """

    evidence = data.get("evidence")

    if isinstance(evidence, dict):
        return evidence

    return data


# ---------------------------------------------------------------------------
# Metrics extraction
# ---------------------------------------------------------------------------

def extract_metrics(data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract deterministic Metrics Agent evidence."""

    evidence = unwrap_evidence(data)

    analysis = safe_dict(evidence.get("analysis"))
    current_metrics = safe_dict(evidence.get("current_metrics"))
    baseline = safe_dict(evidence.get("baseline"))

    comparisons = safe_list(analysis.get("comparisons"))
    anomalies = safe_list(analysis.get("anomalies"))
    statistical_deviations = safe_list(
        analysis.get("statistical_deviations")
    )

    anomaly_count = analysis.get("anomaly_count", 0)
    statistical_deviation_count = analysis.get(
        "statistical_deviation_count", 0
    )

    anomaly_detected = bool(
        analysis.get("anomaly_detected", False)
    )

    # Determine whether actual metric samples exist.
    metric_sample_count = 0

    for value in current_metrics.values():
        if isinstance(value, list):
            metric_sample_count += len(value)

    has_metric_data = metric_sample_count > 0

    return {
        "agent": evidence.get("agent", "metrics-agent"),
        "timestamp": evidence.get("timestamp"),
        "namespace": evidence.get("namespace"),
        "service": evidence.get("service"),

        "baseline": {
            "created_at": baseline.get("created_at"),
            "duration_minutes": baseline.get("duration_minutes"),
            "sigma_multiplier": baseline.get("sigma_multiplier"),
        },

        "current_metrics": current_metrics,

        "comparisons": comparisons,
        "statistical_deviations": statistical_deviations,
        "anomalies": anomalies,

        "anomaly_count": anomaly_count,
        "statistical_deviation_count": statistical_deviation_count,
        "anomaly_detected": anomaly_detected,

        "metric_sample_count": metric_sample_count,
        "has_metric_data": has_metric_data,
    }


# ---------------------------------------------------------------------------
# Log extraction
# ---------------------------------------------------------------------------

def extract_logs(data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract deterministic Log Agent evidence."""

    evidence = unwrap_evidence(data)

    analysis = safe_dict(evidence.get("analysis"))

    status = analysis.get("status", "UNKNOWN")

    total_entries = analysis.get("total_log_entries", 0)
    error_entries = safe_list(analysis.get("error_entries"))
    warning_entries = safe_list(analysis.get("warning_entries"))
    all_entries = safe_list(analysis.get("all_entries"))

    error_detected = bool(
        analysis.get("error_detected", False)
    )

    warning_detected = bool(
        analysis.get("warning_detected", False)
    )

    # NO_LOG_DATA explicitly means evidence was unavailable.
    has_log_data = (
        status != "NO_LOG_DATA"
        and (
            total_entries > 0
            or len(all_entries) > 0
        )
    )

    return {
        "agent": evidence.get("agent", "log-agent"),
        "timestamp": evidence.get("timestamp"),
        "namespace": evidence.get("namespace"),
        "service": evidence.get("service"),

        "lookback_minutes": evidence.get("lookback_minutes"),
        "query": evidence.get("query"),

        "status": status,

        "total_log_entries": total_entries,
        "normal_log_entries": analysis.get(
            "normal_log_entries", 0
        ),
        "warning_log_entries": analysis.get(
            "warning_log_entries", 0
        ),
        "error_log_entries": analysis.get(
            "error_log_entries", 0
        ),

        "error_rate": analysis.get("error_rate"),
        "warning_rate": analysis.get("warning_rate"),

        "affected_pods": safe_list(
            analysis.get("affected_pods")
        ),

        "severity_counts": safe_dict(
            analysis.get("severity_counts")
        ),

        "error_detected": error_detected,
        "warning_detected": warning_detected,

        "error_entries": error_entries,
        "warning_entries": warning_entries,

        "has_log_data": has_log_data,
    }


# ---------------------------------------------------------------------------
# Trace extraction
# ---------------------------------------------------------------------------

def service_name_normalize(name: Any) -> Optional[str]:
    """
    Normalize a service name.

    Examples:
        CurrencyService -> currencyservice
        currencyservice -> currencyservice
        frontend -> frontend
    """

    if not isinstance(name, str):
        return None

    value = name.strip().lower()

    if not value:
        return None

    # Remove common separators.
    value = value.replace("-", "")
    value = value.replace("_", "")

    return value


def extract_service_from_operation(operation: Any) -> Optional[str]:
    """
    Extract a likely downstream service from an RPC operation.

    Example:
        hipstershop.CurrencyService/GetSupportedCurrencies

    -> currencyservice
    """

    if not isinstance(operation, str):
        return None

    # Capture the service before "/".
    match = re.search(
        r"\.([A-Za-z0-9_-]+Service)/",
        operation
    )

    if match:
        return service_name_normalize(match.group(1))

    # Generic fallback for operations such as:
    # CurrencyService/GetSupportedCurrencies
    match = re.search(
        r"([A-Za-z0-9_-]+Service)/",
        operation
    )

    if match:
        return service_name_normalize(match.group(1))

    return None


def extract_trace_error_operations(
    analysis: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Extract failed operations from Trace Agent analysis."""

    operations = []

    affected_operations = safe_list(
        analysis.get("affected_operations")
    )

    for item in affected_operations:
        if isinstance(item, dict):
            operation = item.get("operation")
            error_count = item.get("error_count", 0)

            if operation:
                operations.append({
                    "operation": operation,
                    "error_count": error_count,
                    "candidate_service":
                        extract_service_from_operation(operation),
                })

        elif isinstance(item, str):
            operations.append({
                "operation": item,
                "error_count": None,
                "candidate_service":
                    extract_service_from_operation(item),
            })

    return operations


def extract_trace(data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract deterministic Trace Agent evidence."""

    evidence = unwrap_evidence(data)

    analysis = safe_dict(evidence.get("analysis"))

    status = analysis.get("status", "UNKNOWN")

    affected_services = safe_list(
        analysis.get("affected_services")
    )

    affected_operations = safe_list(
        analysis.get("affected_operations")
    )

    error_spans = safe_list(
        analysis.get("error_spans")
    )

    warning_spans = safe_list(
        analysis.get("warning_spans")
    )

    trace_error_operations = extract_trace_error_operations(
        analysis
    )

    # Some versions of the Trace Agent store errors in
    # error_spans rather than affected_operations.
    if not trace_error_operations:

        for span in error_spans:
            if not isinstance(span, dict):
                continue

            operation = first_non_empty(
                span.get("operation"),
                span.get("name")
            )

            if operation:
                trace_error_operations.append({
                    "operation": operation,
                    "error_count": 1,
                    "candidate_service":
                        extract_service_from_operation(operation),
                })

    error_span_count = analysis.get(
        "error_span_count",
        len(error_spans)
    )

    error_trace_count = analysis.get(
        "error_trace_count",
        0
    )

    total_traces = analysis.get(
        "total_traces",
        0
    )

    total_spans = analysis.get(
        "total_spans",
        0
    )

    error_rate = analysis.get("error_rate")

    has_trace_data = (
        total_traces > 0
        or total_spans > 0
        or len(error_spans) > 0
        or len(warning_spans) > 0
        or len(affected_operations) > 0
    )

    error_detected = bool(
        analysis.get("error_detected", False)
        or status == "ERROR_EVIDENCE"
        or error_span_count > 0
        or error_trace_count > 0
    )

    return {
        "agent": evidence.get("agent", "trace-agent"),
        "timestamp": evidence.get("timestamp"),
        "namespace": evidence.get("namespace"),
        "service": evidence.get("service"),

        "lookback_minutes": evidence.get(
            "lookback_minutes"
        ),

        "status": status,

        "total_traces": total_traces,
        "total_spans": total_spans,

        "error_trace_count": error_trace_count,
        "error_span_count": error_span_count,
        "error_rate": error_rate,

        "affected_services": affected_services,
        "affected_operations": affected_operations,

        "error_spans": error_spans,
        "warning_spans": warning_spans,

        "trace_error_operations": trace_error_operations,

        "error_detected": error_detected,
        "warning_detected": bool(
            analysis.get("warning_detected", False)
            or status == "WARNING_ONLY"
        ),

        "has_trace_data": has_trace_data,
    }


# ---------------------------------------------------------------------------
# Kubernetes extraction
# ---------------------------------------------------------------------------

def extract_k8s(data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract deterministic Kubernetes Agent evidence."""

    evidence = unwrap_evidence(data)

    deployment = safe_dict(
        evidence.get("deployment")
    )

    endpoints = safe_dict(
        evidence.get("endpoints")
    )

    analysis = safe_dict(
        evidence.get("analysis")
    )

    pods = safe_list(
        evidence.get("pods")
    )

    events = safe_list(
        evidence.get("events")
    )

    conditions = safe_list(
        evidence.get("conditions")
    )

    desired = deployment.get(
        "desired_replicas"
    )

    available = deployment.get(
        "available_replicas"
    )

    ready_replicas = deployment.get(
        "ready_replicas"
    )

    updated = deployment.get(
        "updated_replicas"
    )

    unavailable = deployment.get(
        "unavailable_replicas"
    )

    ready_endpoints = safe_list(
        endpoints.get("ready")
    )

    not_ready_endpoints = safe_list(
        endpoints.get("not_ready")
    )

    ready_endpoint_count = endpoints.get(
        "ready_count",
        len(ready_endpoints)
    )

    not_ready_endpoint_count = endpoints.get(
        "not_ready_count",
        len(not_ready_endpoints)
    )

    # Detect whether deployment is explicitly scaled to zero.
    scaled_to_zero = (
        isinstance(desired, (int, float))
        and desired == 0
    )

    no_ready_endpoints = (
        isinstance(ready_endpoint_count, (int, float))
        and ready_endpoint_count == 0
    )

    no_ready_replicas = (
        isinstance(ready_replicas, (int, float))
        and ready_replicas == 0
    )

    no_pods = len(pods) == 0

    return {
        "agent": evidence.get(
            "agent",
            "k8s-agent"
        ),

        "timestamp": evidence.get(
            "timestamp"
        ),

        "namespace": evidence.get(
            "namespace"
        ),

        "service": evidence.get(
            "service"
        ),

        "deployment": {
            "found": deployment.get("found"),
            "desired_replicas": desired,
            "available_replicas": available,
            "ready_replicas": ready_replicas,
            "updated_replicas": updated,
            "unavailable_replicas": unavailable,
        },

        "pods": pods,

        "endpoints": {
            "found": endpoints.get("found"),
            "ready_count": ready_endpoint_count,
            "not_ready_count": not_ready_endpoint_count,
        },

        "events": events,
        "conditions": conditions,

        "status": analysis.get(
            "status",
            "UNKNOWN"
        ),

        "error_detected": bool(
            analysis.get("error_detected", False)
        ),

        "warning_detected": bool(
            analysis.get("warning_detected", False)
        ),

        "error_count": analysis.get(
            "error_count",
            0
        ),

        "warning_count": analysis.get(
            "warning_count",
            0
        ),

        "scaled_to_zero": scaled_to_zero,
        "no_ready_endpoints": no_ready_endpoints,
        "no_ready_replicas": no_ready_replicas,
        "no_pods": no_pods,
    }


# ---------------------------------------------------------------------------
# Deterministic evidence correlation
# ---------------------------------------------------------------------------

def derive_deterministic_findings(
    metrics: Dict[str, Any],
    logs: Dict[str, Any],
    trace: Dict[str, Any],
    k8s: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Derive high-value findings before involving the LLM.

    This is deliberately deterministic.

    The Coordinator should not allow an LLM to invent an observation
    that isn't present in the agent evidence.
    """

    findings: List[str] = []
    warnings: List[str] = []
    root_cause_candidates: List[str] = []
    affected_services: List[str] = []

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    if metrics.get("has_metric_data"):

        if metrics.get("anomaly_detected"):
            findings.append(
                "Metrics Agent detected deterministic metric degradation."
            )

        elif metrics.get("statistical_deviation_count", 0) > 0:
            findings.append(
                "Metrics Agent detected statistical deviation "
                "without deterministic degradation."
            )

        else:
            findings.append(
                "Metrics Agent found metric samples but no "
                "deterministic degradation anomaly."
            )

    else:
        warnings.append(
            "Metrics Agent has no current metric samples "
            "for the requested service/window."
        )

    # ------------------------------------------------------------------
    # Logs
    # ------------------------------------------------------------------

    if logs.get("status") == "NO_LOG_DATA":
        warnings.append(
            "Log Agent returned NO_LOG_DATA; log health cannot "
            "be inferred from this result."
        )

    elif logs.get("error_detected"):
        findings.append(
            "Log Agent detected deterministic error evidence."
        )

    elif logs.get("has_log_data"):
        findings.append(
            "Log Agent has log data but no deterministic error evidence."
        )

    else:
        warnings.append(
            "Log Agent did not provide usable log evidence."
        )

    # ------------------------------------------------------------------
    # Trace
    # ------------------------------------------------------------------

    trace_error_operations = safe_list(
        trace.get("trace_error_operations")
    )

    if trace.get("error_detected"):

        findings.append(
            "Trace Agent detected distributed-trace error evidence."
        )

        for operation in trace_error_operations:

            candidate = operation.get(
                "candidate_service"
            )

            if candidate:
                root_cause_candidates.append(
                    candidate
                )

            operation_name = operation.get(
                "operation"
            )

            if operation_name:
                findings.append(
                    "Trace error operation: {}".format(
                        operation_name
                    )
                )

        for service in safe_list(
            trace.get("affected_services")
        ):
            normalized = service_name_normalize(service)

            if normalized:
                affected_services.append(
                    normalized
                )

    elif trace.get("has_trace_data"):
        findings.append(
            "Trace Agent has trace data but no deterministic "
            "error evidence."
        )

    else:
        warnings.append(
            "Trace Agent has no usable trace evidence."
        )

    # ------------------------------------------------------------------
    # Kubernetes
    # ------------------------------------------------------------------

    k8s_service = service_name_normalize(
        k8s.get("service")
    )

    if k8s_service:
        affected_services.append(
            k8s_service
        )

    if k8s.get("scaled_to_zero"):

        findings.append(
            "Kubernetes shows desired replicas = 0 for {}.".format(
                k8s_service or "the service"
            )
        )

        warnings.append(
            "A deployment scaled to zero may be intentional "
            "fault injection; it is not by itself proof of root cause."
        )

    if k8s.get("no_ready_endpoints"):

        findings.append(
            "Kubernetes reports zero ready endpoints for {}.".format(
                k8s_service or "the service"
            )
        )

    if k8s.get("no_ready_replicas"):

        findings.append(
            "Kubernetes reports zero ready replicas for {}.".format(
                k8s_service or "the service"
            )
        )

    if k8s.get("no_pods"):

        findings.append(
            "Kubernetes reports no pods for {}.".format(
                k8s_service or "the service"
            )
        )

    if k8s.get("error_detected"):

        findings.append(
            "Kubernetes Agent detected deterministic error evidence."
        )

    elif k8s.get("warning_detected"):

        findings.append(
            "Kubernetes Agent detected Kubernetes warning evidence."
        )

    # ------------------------------------------------------------------
    # Cross-agent correlation
    # ------------------------------------------------------------------

    trace_candidates = set(
        root_cause_candidates
    )

    correlation_matches: List[Dict[str, Any]] = []

    if k8s_service and k8s_service in trace_candidates:

        unavailable = (
            k8s.get("scaled_to_zero")
            or k8s.get("no_ready_endpoints")
            or k8s.get("no_ready_replicas")
            or k8s.get("no_pods")
        )

        if unavailable:

            correlation_matches.append({
                "service": k8s_service,
                "trace_evidence": True,
                "kubernetes_unavailable": True,
                "strength": "HIGH",
            })

            findings.append(
                "Strong cross-agent correlation: Trace Agent "
                "identifies {} in a failed operation and Kubernetes "
                "shows that service is unavailable.".format(
                    k8s_service
                )
            )

    # Deduplicate affected services.
    affected_services = sorted(
        set(affected_services)
    )

    # Deduplicate root-cause candidates.
    root_cause_candidates = sorted(
        set(root_cause_candidates)
    )

    # ------------------------------------------------------------------
    # Deterministic incident status
    # ------------------------------------------------------------------

    strong_root_cause = len(
        correlation_matches
    ) > 0

    trace_failure = bool(
        trace.get("error_detected")
    )

    kubernetes_unavailable = bool(
        k8s.get("scaled_to_zero")
        or k8s.get("no_ready_endpoints")
        or k8s.get("no_ready_replicas")
        or k8s.get("no_pods")
    )

    log_failure = bool(
        logs.get("error_detected")
    )

    metric_failure = bool(
        metrics.get("anomaly_detected")
    )

    if strong_root_cause:

        deterministic_incident_status = (
            "CONFIRMED_INCIDENT"
        )

        deterministic_confidence = "HIGH"

    elif trace_failure and (
        log_failure
        or metric_failure
        or kubernetes_unavailable
    ):

        deterministic_incident_status = (
            "POSSIBLE_INCIDENT"
        )

        deterministic_confidence = "MEDIUM"

    elif trace_failure:

        deterministic_incident_status = (
            "POSSIBLE_INCIDENT"
        )

        deterministic_confidence = "MEDIUM"

    elif log_failure or metric_failure:

        deterministic_incident_status = (
            "POSSIBLE_INCIDENT"
        )

        deterministic_confidence = "MEDIUM"

    else:

        deterministic_incident_status = (
            "NO_CONFIRMED_INCIDENT"
        )

        deterministic_confidence = "NONE"

    # ------------------------------------------------------------------
    # Special F01 interpretation
    # ------------------------------------------------------------------

    f01_pattern = False

    if (
        k8s_service == "currencyservice"
        and k8s.get("scaled_to_zero")
        and k8s.get("no_ready_endpoints")
        and trace_failure
        and "currencyservice" in trace_candidates
    ):
        f01_pattern = True

        findings.append(
            "Observed F01-style dependency failure pattern: "
            "currencyservice is unavailable while traces show "
            "failed CurrencyService calls."
        )

    return {
        "deterministic_incident_status":
            deterministic_incident_status,

        "deterministic_confidence":
            deterministic_confidence,

        "deterministic_root_cause_candidates":
            root_cause_candidates,

        "affected_services":
            affected_services,

        "findings":
            findings,

        "warnings":
            warnings,

        "cross_agent_correlations":
            correlation_matches,

        "f01_pattern_detected":
            f01_pattern,

        "metric_degradation":
            metric_failure,

        "log_error_evidence":
            log_failure,

        "trace_error_evidence":
            trace_failure,

        "kubernetes_unavailability":
            kubernetes_unavailable,
    }


# ---------------------------------------------------------------------------
# Build compact Coordinator evidence
# ---------------------------------------------------------------------------

def build_coordinator_evidence(
    metrics: Dict[str, Any],
    logs: Dict[str, Any],
    trace: Dict[str, Any],
    k8s: Dict[str, Any],
    deterministic: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build a compact payload for Ollama.

    We intentionally do not send:
        - raw Kubernetes events
        - all log lines
        - raw trace dumps
        - individual agent Ollama prose

    The Coordinator needs structured evidence, not huge raw payloads.
    """

    return {
        "metrics": {
            "service": metrics.get("service"),
            "has_metric_data": metrics.get(
                "has_metric_data"
            ),
            "metric_sample_count": metrics.get(
                "metric_sample_count"
            ),
            "anomaly_detected": metrics.get(
                "anomaly_detected"
            ),
            "anomaly_count": metrics.get(
                "anomaly_count"
            ),
            "statistical_deviation_count":
                metrics.get(
                    "statistical_deviation_count"
                ),
            "comparisons": metrics.get(
                "comparisons"
            ),
            "anomalies": metrics.get(
                "anomalies"
            ),
            "statistical_deviations":
                metrics.get(
                    "statistical_deviations"
                ),
        },

        "logs": {
            "service": logs.get("service"),
            "status": logs.get("status"),
            "has_log_data": logs.get(
                "has_log_data"
            ),
            "total_log_entries":
                logs.get(
                    "total_log_entries"
                ),
            "error_log_entries":
                logs.get(
                    "error_log_entries"
                ),
            "warning_log_entries":
                logs.get(
                    "warning_log_entries"
                ),
            "error_detected":
                logs.get(
                    "error_detected"
                ),
            "warning_detected":
                logs.get(
                    "warning_detected"
                ),
            "affected_pods":
                logs.get(
                    "affected_pods"
                ),
            # Keep only a small amount of deterministic error evidence.
            "error_entries":
                logs.get(
                    "error_entries"
                )[:10],
        },

        "trace": {
            "service": trace.get("service"),
            "status": trace.get("status"),
            "has_trace_data":
                trace.get(
                    "has_trace_data"
                ),
            "total_traces":
                trace.get(
                    "total_traces"
                ),
            "total_spans":
                trace.get(
                    "total_spans"
                ),
            "error_trace_count":
                trace.get(
                    "error_trace_count"
                ),
            "error_span_count":
                trace.get(
                    "error_span_count"
                ),
            "error_rate":
                trace.get(
                    "error_rate"
                ),
            "affected_services":
                trace.get(
                    "affected_services"
                ),
            "affected_operations":
                trace.get(
                    "affected_operations"
                ),
            "trace_error_operations":
                trace.get(
                    "trace_error_operations"
                ),
        },

        "kubernetes": {
            "service":
                k8s.get("service"),

            "status":
                k8s.get("status"),

            "deployment":
                k8s.get("deployment"),

            "pod_count":
                len(
                    safe_list(
                        k8s.get("pods")
                    )
                ),

            "endpoints":
                k8s.get("endpoints"),

            "scaled_to_zero":
                k8s.get("scaled_to_zero"),

            "no_ready_endpoints":
                k8s.get(
                    "no_ready_endpoints"
                ),

            "no_ready_replicas":
                k8s.get(
                    "no_ready_replicas"
                ),

            "no_pods":
                k8s.get(
                    "no_pods"
                ),

            "error_detected":
                k8s.get(
                    "error_detected"
                ),

            "warning_detected":
                k8s.get(
                    "warning_detected"
                ),

            "error_count":
                k8s.get(
                    "error_count"
                ),

            "warning_count":
                k8s.get(
                    "warning_count"
                ),
        },

        "deterministic_findings":
            deterministic,
    }


# ---------------------------------------------------------------------------
# Ollama JSON parsing
# ---------------------------------------------------------------------------

def parse_json_response(text: str) -> Tuple[
    Optional[Dict[str, Any]],
    Optional[str]
]:
    """
    Parse Ollama JSON robustly.

    Handles:
        - normal JSON
        - ```json ... ```
        - text before/after JSON
    """

    if not text:
        return None, "Empty Ollama response."

    cleaned = text.strip()

    # Remove markdown fences.
    cleaned = re.sub(
        r"^```(?:json)?\s*",
        "",
        cleaned,
        flags=re.IGNORECASE
    )

    cleaned = re.sub(
        r"\s*```$",
        "",
        cleaned
    )

    try:
        parsed = json.loads(cleaned)

        if isinstance(parsed, dict):
            return parsed, None

    except json.JSONDecodeError:
        pass

    # Try to locate the first JSON object.
    start = cleaned.find("{")
    end = cleaned.rfind("}")

    if start >= 0 and end > start:

        candidate = cleaned[
            start:end + 1
        ]

        try:
            parsed = json.loads(candidate)

            if isinstance(parsed, dict):
                return parsed, None

        except json.JSONDecodeError:
            pass

    return None, (
        "Ollama response was not valid JSON."
    )


# ---------------------------------------------------------------------------
# Ollama Coordinator
# ---------------------------------------------------------------------------

def ask_ollama(
    coordinator_evidence: Dict[str, Any],
    deterministic: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Ask local Ollama to interpret the deterministic evidence.

    Ollama does NOT get to invent telemetry.
    """

    system_prompt = """
You are the Coordinator Agent in an AI-assisted Kubernetes
root-cause-analysis system.

Your job is to reason ONLY over the deterministic evidence supplied
to you.

STRICT RULES:

1. Never invent metrics, log messages, trace spans, Kubernetes states,
   timestamps, services, error codes, or thresholds.

2. Do not use the individual agents' Ollama explanations as evidence.
   Only use the structured deterministic evidence.

3. NO_LOG_DATA means logs are unavailable. It does NOT mean the service
   is healthy.

4. Missing metrics mean there is insufficient metric evidence.
   Do not invent metric values.

5. A service appearing in a trace does NOT automatically make that
   service the root cause.

6. If a trace shows a failed operation involving a downstream service,
   and Kubernetes independently shows that same downstream service has
   zero ready endpoints, zero ready replicas, zero pods, or is otherwise
   unavailable, this is strong cross-agent evidence that the downstream
   service is the root-cause candidate.

7. A Kubernetes deployment with desired replicas = 0 may be intentional
   fault injection. Do not claim that scaling to zero was accidental.

8. Distinguish:
       - injected experimental fault
       - observed application failure
       - root-cause candidate

9. Do not perform or recommend remediation steps in this response.
   Remediation is handled by another agent.

10. If evidence is insufficient or conflicting, say so explicitly.

11. Prefer evidence supported by multiple independent agents.

Return ONLY valid JSON with exactly this structure:

{
  "incident_status":
    "CONFIRMED_INCIDENT|POSSIBLE_INCIDENT|NO_CONFIRMED_INCIDENT",

  "root_cause_candidate":
    "service name or null",

  "confidence":
    "HIGH|MEDIUM|LOW|NONE",

  "reasoning": [
    "short factual reasoning statements"
  ],

  "supporting_agents": [
    "metrics-agent",
    "log-agent",
    "trace-agent",
    "k8s-agent"
  ],

  "affected_services": [
    "service names"
  ],

  "conflicting_or_missing_evidence": [
    "missing or conflicting evidence"
  ],

  "next_investigation": [
    "investigation steps only; no remediation"
  ]
}
"""

    user_prompt = """
Deterministic Coordinator Evidence:

{}

Deterministic Coordinator Findings:

{}

Return only the required JSON object.
""".format(
        json.dumps(
            coordinator_evidence,
            indent=2,
            default=str
        ),
        json.dumps(
            deterministic,
            indent=2,
            default=str
        )
    )

    payload = {
        "model": OLLAMA_MODEL,

        "prompt": (
            system_prompt
            + "\n\n"
            + user_prompt
        ),

        "stream": False,

        "format": "json",

        "options": {
            "temperature": 0
        },
    }

    try:

        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=OLLAMA_TIMEOUT
        )

        response.raise_for_status()

        body = response.json()

        raw_response = body.get(
            "response",
            ""
        )

        parsed, parse_error = parse_json_response(
            raw_response
        )

        if parsed is None:

            return {
                "available": True,
                "parsed": False,
                "raw_response": raw_response,
                "parse_error": parse_error,
            }

        return {
            "available": True,
            "parsed": True,
            "analysis": parsed,
            "raw_response": raw_response,
        }

    except requests.exceptions.RequestException as exc:

        return {
            "available": False,
            "parsed": False,
            "error": str(exc),
        }

    except Exception as exc:

        return {
            "available": False,
            "parsed": False,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Validate Ollama result against deterministic evidence
# ---------------------------------------------------------------------------

def validate_ollama_analysis(
    ollama_result: Dict[str, Any],
    deterministic: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Prevent the LLM from contradicting strong deterministic evidence.

    The deterministic conclusion wins if there is a direct contradiction.
    """

    if not ollama_result.get("parsed"):
        return ollama_result

    analysis = safe_dict(
        ollama_result.get("analysis")
    )

    deterministic_status = deterministic.get(
        "deterministic_incident_status"
    )

    deterministic_confidence = deterministic.get(
        "deterministic_confidence"
    )

    candidates = safe_list(
        deterministic.get(
            "deterministic_root_cause_candidates"
        )
    )

    correlations = safe_list(
        deterministic.get(
            "cross_agent_correlations"
        )
    )

    f01_pattern = bool(
        deterministic.get(
            "f01_pattern_detected"
        )
    )

    # ---------------------------------------------------------------
    # Strong deterministic correlation
    # ---------------------------------------------------------------

    if correlations:

        # Incident must be confirmed.
        analysis["incident_status"] = (
            "CONFIRMED_INCIDENT"
        )

        analysis["confidence"] = (
            "HIGH"
        )

        # If the model selected no root cause or selected a conflicting
        # service, use the deterministic candidate.
        if candidates:

            model_candidate = analysis.get(
                "root_cause_candidate"
            )

            normalized_model_candidate = (
                service_name_normalize(
                    model_candidate
                )
            )

            normalized_candidates = [
                service_name_normalize(c)
                for c in candidates
            ]

            if (
                not normalized_model_candidate
                or normalized_model_candidate
                not in normalized_candidates
            ):

                analysis["root_cause_candidate"] = (
                    candidates[0]
                )

        # Ensure the supporting agents include the correlated sources.
        supporting_agents = safe_list(
            analysis.get(
                "supporting_agents"
            )
        )

        for agent in [
            "trace-agent",
            "k8s-agent",
        ]:

            if agent not in supporting_agents:
                supporting_agents.append(
                    agent
                )

        analysis["supporting_agents"] = (
            supporting_agents
        )

    # ---------------------------------------------------------------
    # F01 specific guard
    # ---------------------------------------------------------------

    if f01_pattern:

        analysis["incident_status"] = (
            "CONFIRMED_INCIDENT"
        )

        analysis["root_cause_candidate"] = (
            "currencyservice"
        )

        analysis["confidence"] = (
            "HIGH"
        )

        reasoning = safe_list(
            analysis.get(
                "reasoning"
            )
        )

        required_reasoning = [
            "Trace evidence shows failed CurrencyService calls.",
            "Kubernetes evidence shows currencyservice has zero ready endpoints.",
            "Kubernetes evidence shows currencyservice has zero desired/available/ready replicas in the captured experiment state.",
            "The evidence supports currencyservice unavailability as the root-cause candidate."
        ]

        for statement in required_reasoning:

            if statement not in reasoning:
                reasoning.append(
                    statement
                )

        analysis["reasoning"] = reasoning

        supporting_agents = safe_list(
            analysis.get(
                "supporting_agents"
            )
        )

        for agent in [
            "trace-agent",
            "k8s-agent",
        ]:

            if agent not in supporting_agents:
                supporting_agents.append(
                    agent
                )

        analysis["supporting_agents"] = (
            supporting_agents
        )

    # ---------------------------------------------------------------
    # If no strong correlation, prevent false high confidence.
    # ---------------------------------------------------------------

    if not correlations and not f01_pattern:

        if deterministic_status == "POSSIBLE_INCIDENT":

            if analysis.get("incident_status") == (
                "CONFIRMED_INCIDENT"
            ):
                analysis["incident_status"] = (
                    "POSSIBLE_INCIDENT"
                )

            if analysis.get("confidence") == "HIGH":
                analysis["confidence"] = (
                    deterministic_confidence
                )

    ollama_result["analysis"] = analysis

    return ollama_result


# ---------------------------------------------------------------------------
# Main Coordinator
# ---------------------------------------------------------------------------

def run_coordinator(
    metrics_path: str,
    logs_path: str,
    trace_path: str,
    k8s_path: str,
) -> Dict[str, Any]:
    """Run the complete Coordinator Agent."""

    # ---------------------------------------------------------------
    # Load input files
    # ---------------------------------------------------------------

    metrics_raw = load_json(
        metrics_path
    )

    logs_raw = load_json(
        logs_path
    )

    trace_raw = load_json(
        trace_path
    )

    k8s_raw = load_json(
        k8s_path
    )

    # ---------------------------------------------------------------
    # Extract deterministic evidence
    # ---------------------------------------------------------------

    metrics = extract_metrics(
        metrics_raw
    )

    logs = extract_logs(
        logs_raw
    )

    trace = extract_trace(
        trace_raw
    )

    k8s = extract_k8s(
        k8s_raw
    )

    # ---------------------------------------------------------------
    # Correlate evidence
    # ---------------------------------------------------------------

    deterministic = derive_deterministic_findings(
        metrics,
        logs,
        trace,
        k8s,
    )

    # ---------------------------------------------------------------
    # Build compact evidence for Ollama
    # ---------------------------------------------------------------

    coordinator_evidence = build_coordinator_evidence(
        metrics,
        logs,
        trace,
        k8s,
        deterministic,
    )

    # ---------------------------------------------------------------
    # Ask local Ollama
    # ---------------------------------------------------------------

    ollama_result = ask_ollama(
        coordinator_evidence,
        deterministic,
    )

    # ---------------------------------------------------------------
    # Validate Ollama against deterministic evidence
    # ---------------------------------------------------------------

    ollama_result = validate_ollama_analysis(
        ollama_result,
        deterministic,
    )

    # ---------------------------------------------------------------
    # Final output
    # ---------------------------------------------------------------

    result = {
        "version": "V2",

        "agent": "coordinator",

        "timestamp": utc_now(),

        "ollama": {
            "url": OLLAMA_URL,
            "model": OLLAMA_MODEL,
            "temperature": 0,
        },

        "input_files": {
            "metrics": metrics_path,
            "logs": logs_path,
            "trace": trace_path,
            "k8s": k8s_path,
        },

        "structured_agent_evidence": {
            "metrics": metrics,
            "logs": logs,
            "trace": trace,
            "kubernetes": k8s,
        },

        "deterministic_findings": deterministic,

        "ollama_analysis": ollama_result,
    }

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        description=(
            "AutoRemedyRIC Coordinator Agent V2"
        )
    )

    parser.add_argument(
        "--metrics",
        required=True,
        help="Metrics Agent JSON output"
    )

    parser.add_argument(
        "--logs",
        required=True,
        help="Log Agent JSON output"
    )

    parser.add_argument(
        "--trace",
        required=True,
        help="Trace Agent JSON output"
    )

    parser.add_argument(
        "--k8s",
        required=True,
        help="Kubernetes Agent JSON output"
    )

    parser.add_argument(
        "--output",
        default="coordinator.json",
        help=(
            "Output JSON file "
            "(default: coordinator.json)"
        )
    )

    return parser.parse_args()


def main() -> None:

    args = parse_arguments()

    try:

        result = run_coordinator(
            metrics_path=args.metrics,
            logs_path=args.logs,
            trace_path=args.trace,
            k8s_path=args.k8s,
        )

        output_path = Path(
            args.output
        )

        with output_path.open(
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                result,
                file,
                indent=2,
                ensure_ascii=False,
                default=str
            )

        print(
            json.dumps(
                result,
                indent=2,
                ensure_ascii=False,
                default=str
            )
        )

        print(
            "\nCoordinator output written to: {}".format(
                output_path
            ),
            file=sys.stderr
        )

    except Exception as exc:

        print(
            "Coordinator failed: {}".format(
                exc
            ),
            file=sys.stderr
        )

        sys.exit(1)


if __name__ == "__main__":
    main()