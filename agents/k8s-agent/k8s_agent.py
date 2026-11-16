#!/usr/bin/env python3

"""
AutoRemedyRIC - Kubernetes Context Agent V1.1

Responsibilities:
    - Collect Kubernetes deployment state
    - Collect pod state and readiness
    - Collect container states and restarts
    - Collect Service endpoint state
    - Collect relevant Kubernetes events
    - Perform deterministic Kubernetes evidence analysis
    - Use local Ollama to explain summarized evidence
    - Return structured JSON suitable for the Coordinator

The K8s Agent does NOT:
    - Perform final root-cause analysis
    - Perform remediation
    - Modify Kubernetes resources
    - Override deterministic classifications

Python:
    Compatible with Python 3.9+
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests
from kubernetes import client, config
from kubernetes.client.rest import ApiException


# ============================================================================
# CONFIGURATION
# ============================================================================

NAMESPACE = os.getenv(
    "K8S_NAMESPACE",
    "default"
)

OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://localhost:11434/api/generate"
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "llama3.2:latest"
)

OLLAMA_TIMEOUT = int(
    os.getenv(
        "OLLAMA_TIMEOUT",
        "120"
    )
)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def utc_now() -> datetime:
    """Return current UTC time."""
    return datetime.now(timezone.utc)


def safe_int(
    value: Any,
    default: int = 0
) -> int:
    """Safely convert a value to an integer."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def iso_time(
    value: Any
) -> Optional[str]:
    """Convert a Kubernetes datetime to ISO format."""
    if value is None:
        return None

    try:
        return value.isoformat()
    except AttributeError:
        return str(value)


def container_state_to_dict(
    state: Any
) -> Optional[Dict[str, Any]]:
    """Convert Kubernetes container state into JSON-safe data."""

    if state is None:
        return None

    result: Dict[str, Any] = {}

    if state.running is not None:

        result["state"] = "running"

        result["started_at"] = iso_time(
            state.running.started_at
        )

    elif state.waiting is not None:

        result["state"] = "waiting"

        result["reason"] = state.waiting.reason

        result["message"] = state.waiting.message

    elif state.terminated is not None:

        result["state"] = "terminated"

        result["reason"] = state.terminated.reason

        result["message"] = state.terminated.message

        result["exit_code"] = state.terminated.exit_code

        result["signal"] = state.terminated.signal

        result["started_at"] = iso_time(
            state.terminated.started_at
        )

        result["finished_at"] = iso_time(
            state.terminated.finished_at
        )

    else:

        result["state"] = "unknown"

    return result


# ============================================================================
# KUBERNETES CLIENT
# ============================================================================

def load_kubernetes_clients():
    """
    Load Kubernetes configuration.

    First tries local kubeconfig.
    Falls back to in-cluster configuration.
    """

    try:

        config.load_kube_config()

        config_source = "kubeconfig"

    except Exception:

        try:

            config.load_incluster_config()

            config_source = "in_cluster"

        except Exception as exc:

            raise RuntimeError(
                "Unable to load Kubernetes configuration: {}".format(
                    exc
                )
            )

    core_api = client.CoreV1Api()

    apps_api = client.AppsV1Api()

    return (
        core_api,
        apps_api,
        config_source
    )


# ============================================================================
# DEPLOYMENT
# ============================================================================

def collect_deployment(
    apps_api: client.AppsV1Api,
    service: str
) -> Dict[str, Any]:

    result: Dict[str, Any] = {
        "found": False,
        "name": service,
        "desired_replicas": None,
        "available_replicas": None,
        "ready_replicas": None,
        "updated_replicas": None,
        "unavailable_replicas": None,
        "conditions": []
    }

    try:

        deployment = apps_api.read_namespaced_deployment(
            name=service,
            namespace=NAMESPACE
        )

    except ApiException as exc:

        if exc.status == 404:

            result["status"] = "NOT_FOUND"

            return result

        result["status"] = "ERROR"

        result["error"] = str(exc)

        return result

    result["found"] = True

    result["status"] = "FOUND"

    spec = deployment.spec

    status = deployment.status

    result["desired_replicas"] = safe_int(
        getattr(
            spec,
            "replicas",
            0
        )
    )

    result["available_replicas"] = safe_int(
        getattr(
            status,
            "available_replicas",
            0
        )
    )

    result["ready_replicas"] = safe_int(
        getattr(
            status,
            "ready_replicas",
            0
        )
    )

    result["updated_replicas"] = safe_int(
        getattr(
            status,
            "updated_replicas",
            0
        )
    )

    result["unavailable_replicas"] = safe_int(
        getattr(
            status,
            "unavailable_replicas",
            0
        )
    )

    conditions = (
        getattr(
            status,
            "conditions",
            None
        )
        or []
    )

    for condition in conditions:

        result["conditions"].append({
            "type": condition.type,
            "status": condition.status,
            "reason": condition.reason,
            "message": condition.message,
            "last_update_time": iso_time(
                condition.last_update_time
            ),
            "last_transition_time": iso_time(
                condition.last_transition_time
            )
        })

    return result


# ============================================================================
# PODS
# ============================================================================

def collect_pods(
    core_api: client.CoreV1Api,
    service: str
) -> List[Dict[str, Any]]:

    pods_data: List[Dict[str, Any]] = []

    try:

        pods = core_api.list_namespaced_pod(
            namespace=NAMESPACE,
            label_selector="app={}".format(service)
        )

    except ApiException as exc:

        return [
            {
                "collection_error": str(exc)
            }
        ]

    for pod in pods.items:

        restart_count = 0

        containers: List[Dict[str, Any]] = []

        container_statuses = (
            getattr(
                pod.status,
                "container_statuses",
                None
            )
            or []
        )

        for container in container_statuses:

            restarts = safe_int(
                getattr(
                    container,
                    "restart_count",
                    0
                )
            )

            restart_count += restarts

            containers.append({
                "name": container.name,
                "ready": bool(
                    container.ready
                ),
                "restart_count": restarts,
                "state": container_state_to_dict(
                    container.state
                ),
                "last_state": container_state_to_dict(
                    container.last_state
                ),
                "image": container.image
            })

        pod_conditions = []

        for condition in (
            getattr(
                pod.status,
                "conditions",
                None
            )
            or []
        ):

            pod_conditions.append({
                "type": condition.type,
                "status": condition.status,
                "reason": condition.reason,
                "message": condition.message,
                "last_transition_time": iso_time(
                    condition.last_transition_time
                )
            })

        if containers:

            ready = all(
                container["ready"]
                for container in containers
            )

        else:

            ready = False

        pods_data.append({
            "name": pod.metadata.name,
            "namespace": pod.metadata.namespace,
            "phase": pod.status.phase,
            "pod_ip": pod.status.pod_ip,
            "host_ip": pod.status.host_ip,
            "ready": ready,
            "restart_count": restart_count,
            "containers": containers,
            "conditions": pod_conditions,
            "created_at": iso_time(
                pod.metadata.creation_timestamp
            )
        })

    return pods_data


# ============================================================================
# ENDPOINTS
# ============================================================================

def collect_endpoints(
    core_api: client.CoreV1Api,
    service: str
) -> Dict[str, Any]:

    result: Dict[str, Any] = {
        "found": False,
        "ready_count": 0,
        "not_ready_count": 0,
        "ready": [],
        "not_ready": []
    }

    try:

        endpoints = core_api.read_namespaced_endpoints(
            name=service,
            namespace=NAMESPACE
        )

    except ApiException as exc:

        if exc.status == 404:

            result["status"] = "NOT_FOUND"

            return result

        result["status"] = "ERROR"

        result["error"] = str(exc)

        return result

    result["found"] = True

    result["status"] = "FOUND"

    subsets = (
        getattr(
            endpoints,
            "subsets",
            None
        )
        or []
    )

    for subset in subsets:

        ports = []

        for port in (
            getattr(
                subset,
                "ports",
                None
            )
            or []
        ):

            ports.append({
                "name": port.name,
                "port": port.port,
                "protocol": port.protocol
            })

        for address in (
            getattr(
                subset,
                "addresses",
                None
            )
            or []
        ):

            target_ref = getattr(
                address,
                "target_ref",
                None
            )

            result["ready"].append({
                "ip": address.ip,
                "node_name": address.node_name,
                "hostname": address.hostname,
                "target": (
                    target_ref.name
                    if target_ref is not None
                    else None
                ),
                "ports": ports
            })

        for address in (
            getattr(
                subset,
                "not_ready_addresses",
                None
            )
            or []
        ):

            target_ref = getattr(
                address,
                "target_ref",
                None
            )

            result["not_ready"].append({
                "ip": address.ip,
                "node_name": address.node_name,
                "hostname": address.hostname,
                "target": (
                    target_ref.name
                    if target_ref is not None
                    else None
                ),
                "ports": ports
            })

    result["ready_count"] = len(
        result["ready"]
    )

    result["not_ready_count"] = len(
        result["not_ready"]
    )

    return result


# ============================================================================
# EVENTS
# ============================================================================

def collect_events(
    core_api: client.CoreV1Api,
    service: str,
    pods: List[Dict[str, Any]],
    lookback_minutes: int = 60
) -> List[Dict[str, Any]]:

    events_data: List[Dict[str, Any]] = []

    pod_names = {
        pod.get("name")
        for pod in pods
        if pod.get("name")
    }

    cutoff = (
        utc_now()
        - timedelta(
            minutes=lookback_minutes
        )
    )

    try:

        events = core_api.list_namespaced_event(
            namespace=NAMESPACE
        )

    except ApiException as exc:

        return [
            {
                "collection_error": str(exc)
            }
        ]

    for event in events.items:

        involved = getattr(
            event,
            "involved_object",
            None
        )

        if involved is None:
            continue

        object_name = getattr(
            involved,
            "name",
            ""
        )

        object_kind = getattr(
            involved,
            "kind",
            ""
        )

        relevant = (
            object_name == service
            or object_name in pod_names
            or service.lower()
            in object_name.lower()
        )

        if not relevant:
            continue

        event_time = (
            getattr(
                event,
                "last_timestamp",
                None
            )
            or getattr(
                event,
                "event_time",
                None
            )
            or getattr(
                event,
                "first_timestamp",
                None
            )
        )

        if event_time is not None:

            try:

                if event_time < cutoff:
                    continue

            except TypeError:

                pass

        source = getattr(
            event,
            "source",
            None
        )

        events_data.append({
            "type": event.type,
            "reason": event.reason,
            "message": event.message,
            "object_kind": object_kind,
            "object_name": object_name,
            "source": (
                source.component
                if source is not None
                else None
            ),
            "first_timestamp": iso_time(
                event.first_timestamp
            ),
            "last_timestamp": iso_time(
                event.last_timestamp
            ),
            "count": event.count
        })

    events_data.sort(
        key=lambda item: (
            item.get("last_timestamp")
            or item.get("first_timestamp")
            or ""
        )
    )

    return events_data


# ============================================================================
# DETERMINISTIC ANALYSIS
# ============================================================================

def analyse_kubernetes_state(
    service: str,
    deployment: Dict[str, Any],
    pods: List[Dict[str, Any]],
    endpoints: Dict[str, Any],
    events: List[Dict[str, Any]]
) -> Dict[str, Any]:

    findings: List[Dict[str, Any]] = []

    warnings: List[Dict[str, Any]] = []

    desired = deployment.get(
        "desired_replicas"
    )

    available = deployment.get(
        "available_replicas"
    )

    ready_replicas = deployment.get(
        "ready_replicas"
    )

    # ========================================================================
    # DEPLOYMENT
    # ========================================================================

    # v1.1: zero desired replicas is reported as factual availability
    # evidence (the Service cannot serve requests). Whether it is the root
    # cause is decided by the Coordinator, not here.

    if (
        deployment.get("found", False)
        and desired == 0
    ):

        findings.append({
            "type": "SCALED_TO_ZERO",
            "severity": "ERROR",
            "message": (
                "Deployment has zero desired replicas; "
                "no pods can serve requests."
            ),
            "desired": desired,
            "available": available
        })

    elif (
        desired is not None
        and desired > 0
    ):

        if available == 0:

            findings.append({
                "type": "SERVICE_UNAVAILABLE",
                "severity": "ERROR",
                "message": (
                    "Deployment requires replicas but "
                    "no replicas are available."
                )
            })

        elif ready_replicas == 0:

            findings.append({
                "type": "NO_READY_REPLICAS",
                "severity": "ERROR",
                "message": (
                    "Deployment has desired replicas but "
                    "no ready replicas."
                )
            })

        elif available < desired:

            warnings.append({
                "type": "DEGRADED_REPLICA_AVAILABILITY",
                "severity": "WARNING",
                "message": (
                    "Available replicas are below desired replicas."
                ),
                "desired": desired,
                "available": available
            })

    # ========================================================================
    # ENDPOINTS
    # ========================================================================

    ready_endpoint_count = safe_int(
        endpoints.get(
            "ready_count",
            0
        )
    )

    not_ready_endpoint_count = safe_int(
        endpoints.get(
            "not_ready_count",
            0
        )
    )

    if (
        endpoints.get("found", False)
        and ready_endpoint_count == 0
    ):

        findings.append({
            "type": "NO_READY_ENDPOINTS",
            "severity": "ERROR",
            "message": (
                "Service exists but has no ready endpoints."
            ),
            "not_ready_count": not_ready_endpoint_count
        })

    elif not_ready_endpoint_count > 0:

        warnings.append({
            "type": "NOT_READY_ENDPOINTS",
            "severity": "WARNING",
            "message": (
                "Service has endpoints that are not ready."
            ),
            "count": not_ready_endpoint_count
        })

    # ========================================================================
    # PODS
    # ========================================================================

    running_pods = 0

    ready_pods = 0

    pod_restart_total = 0

    for pod in pods:

        if pod.get("phase") == "Running":

            running_pods += 1

        if pod.get("ready"):

            ready_pods += 1

        pod_restart_total += safe_int(
            pod.get(
                "restart_count",
                0
            )
        )

        for container in pod.get(
            "containers",
            []
        ):

            state = (
                container.get("state")
                or {}
            )

            state_name = state.get(
                "state"
            )

            if state_name == "waiting":

                warnings.append({
                    "type": "CONTAINER_WAITING",
                    "severity": "WARNING",
                    "pod": pod.get("name"),
                    "container": container.get("name"),
                    "reason": state.get("reason"),
                    "message": state.get("message")
                })

            elif state_name == "terminated":

                findings.append({
                    "type": "CONTAINER_TERMINATED",
                    "severity": "ERROR",
                    "pod": pod.get("name"),
                    "container": container.get("name"),
                    "reason": state.get("reason"),
                    "exit_code": state.get("exit_code"),
                    "message": state.get("message")
                })

            last_state = (
                container.get("last_state")
                or {}
            )

            if (
                last_state.get("state")
                == "terminated"
            ):

                warnings.append({
                    "type": "PREVIOUS_CONTAINER_TERMINATION",
                    "severity": "WARNING",
                    "pod": pod.get("name"),
                    "container": container.get("name"),
                    "reason": last_state.get("reason"),
                    "exit_code": last_state.get("exit_code"),
                    "message": last_state.get("message")
                })

    if pod_restart_total > 0:

        warnings.append({
            "type": "POD_RESTARTS",
            "severity": "WARNING",
            "message": (
                "One or more containers have restarted."
            ),
            "total_restart_count": pod_restart_total
        })

    # ========================================================================
    # EVENTS
    # ========================================================================

    error_event_count = 0

    warning_event_count = 0

    for event in events:

        event_type = (
            event.get("type")
            or ""
        ).upper()

        reason = (
            event.get("reason")
            or ""
        ).lower()

        message = (
            event.get("message")
            or ""
        ).lower()

        if event_type == "WARNING":

            warning_event_count += 1

            if any(
                keyword in reason
                or keyword in message
                for keyword in [
                    "unhealthy",
                    "probe",
                    "failed",
                    "back-off",
                    "backoff",
                    "killing",
                    "failedmount",
                    "failedsync"
                ]
            ):

                warnings.append({
                    "type": "KUBERNETES_EVENT",
                    "severity": "WARNING",
                    "reason": event.get("reason"),
                    "message": event.get("message"),
                    "object_name": event.get("object_name"),
                    "object_kind": event.get("object_kind")
                })

        elif event_type == "ERROR":

            error_event_count += 1

            findings.append({
                "type": "KUBERNETES_ERROR_EVENT",
                "severity": "ERROR",
                "reason": event.get("reason"),
                "message": event.get("message"),
                "object_name": event.get("object_name"),
                "object_kind": event.get("object_kind")
            })

    # ========================================================================
    # FINAL STATUS
    # ========================================================================

    if findings:

        status = "ERROR_EVIDENCE"

        error_detected = True

        warning_detected = bool(
            warnings
        )

    elif warnings:

        status = "WARNING_EVIDENCE"

        error_detected = False

        warning_detected = True

    elif not deployment.get(
        "found",
        False
    ):

        status = "NO_DEPLOYMENT"

        error_detected = False

        warning_detected = False

    elif (
        not pods
        and desired
        and desired > 0
    ):

        status = "NO_POD_DATA"

        error_detected = False

        warning_detected = False

    else:

        status = "NORMAL"

        error_detected = False

        warning_detected = False

    return {
        "status": status,
        "error_detected": error_detected,
        "warning_detected": warning_detected,
        "findings": findings,
        "warnings": warnings,
        "finding_count": len(findings),
        "warning_count": len(warnings),
        "running_pod_count": running_pods,
        "ready_pod_count": ready_pods,
        "total_restart_count": pod_restart_total,
        "kubernetes_error_event_count": error_event_count,
        "kubernetes_warning_event_count": warning_event_count
    }


# ============================================================================
# OLLAMA LIST NORMALIZATION
# ============================================================================

def normalize_list(
    value: Any
) -> List[str]:
    """Convert a value into a list of strings."""

    if value is None:

        return []

    if isinstance(
        value,
        list
    ):

        result = []

        for item in value:

            if isinstance(
                item,
                str
            ):

                result.append(item)

            else:

                result.append(
                    json.dumps(
                        item,
                        default=str
                    )
                )

        return result

    if isinstance(
        value,
        str
    ):

        return [value]

    return [
        json.dumps(
            value,
            default=str
        )
    ]


# ============================================================================
# OLLAMA ANALYSIS
# ============================================================================

def ask_ollama(
    service: str,
    deterministic_analysis: Dict[str, Any],
    deployment: Dict[str, Any],
    pods: List[Dict[str, Any]],
    endpoints: Dict[str, Any],
    events: List[Dict[str, Any]]
) -> Dict[str, Any]:

    # ========================================================================
    # IMPORTANT
    #
    # Do NOT send raw Kubernetes events to the LLM.
    #
    # The events remain available in the final K8s Agent output for the
    # Coordinator, but the LLM receives only compact deterministic evidence.
    #
    # This prevents the local model from copying Kubernetes Event objects
    # instead of producing an explanation.
    # ========================================================================

    evidence = {
        "service": service,

        "deployment": {
            "desired_replicas": deployment.get(
                "desired_replicas"
            ),
            "available_replicas": deployment.get(
                "available_replicas"
            ),
            "ready_replicas": deployment.get(
                "ready_replicas"
            ),
            "updated_replicas": deployment.get(
                "updated_replicas"
            ),
            "unavailable_replicas": deployment.get(
                "unavailable_replicas"
            )
        },

        "endpoints": {
            "ready_count": endpoints.get(
                "ready_count"
            ),
            "not_ready_count": endpoints.get(
                "not_ready_count"
            )
        },

        "pod_summary": {
            "running_pods": deterministic_analysis.get(
                "running_pod_count"
            ),
            "ready_pods": deterministic_analysis.get(
                "ready_pod_count"
            ),
            "restart_count": deterministic_analysis.get(
                "total_restart_count"
            )
        },

        "deterministic_status": deterministic_analysis.get(
            "status"
        ),

        "error_detected": deterministic_analysis.get(
            "error_detected"
        ),

        "warning_detected": deterministic_analysis.get(
            "warning_detected"
        ),

        "findings": deterministic_analysis.get(
            "findings",
            []
        ),

        "warnings": deterministic_analysis.get(
            "warnings",
            []
        ),

        "recent_event_summary": {
            "total_events": len(events),
            "warning_events": deterministic_analysis.get(
                "kubernetes_warning_event_count",
                0
            ),
            "error_events": deterministic_analysis.get(
                "kubernetes_error_event_count",
                0
            )
        }
    }

    # ========================================================================
    # PROMPT
    # ========================================================================

    prompt = """
You are the Kubernetes Context Agent in a multi-agent
Root Cause Analysis system.

You receive deterministic Kubernetes evidence that has
already been collected and analysed.

Your job is ONLY to explain the Kubernetes evidence.

You are NOT the Coordinator.

Do NOT:
- determine the final root cause
- perform remediation
- invent information
- invent Kubernetes states
- invent metrics
- invent logs
- invent traces
- change deterministic classifications
- rewrite Kubernetes Event objects

IMPORTANT:

1. The deterministic analysis is authoritative.

2. A SCALED_TO_ZERO finding means the deployment has zero
   desired replicas, so the service cannot serve requests.
   This is a factual availability observation.

3. Do not speculate about why the deployment has zero
   replicas.

4. Zero replicas alone is NOT proof of the root cause.
   The Coordinator decides the root cause.

5. No ready endpoints is a factual Kubernetes observation.

6. Probe failures are evidence but are not automatically
   the final root cause.

7. Pod restarts are evidence but are not automatically
   the final root cause.

8. The Coordinator will combine this Kubernetes evidence
   with Metrics, Logs and Traces.

9. Only use information contained in the supplied evidence.

10. Keep the response concise.

Return ONLY valid JSON.

Do not use Markdown.
Do not use ```json.
Do not add any text before or after the JSON.

Return exactly this structure:

{
  "summary": "brief factual explanation",
  "evidence": [
    "factual Kubernetes observation"
  ],
  "implications": [
    "possible implication based only on Kubernetes evidence"
  ],
  "limitations": [
    "what cannot be concluded from Kubernetes evidence alone"
  ]
}

Kubernetes evidence:

""" + json.dumps(
        evidence,
        indent=2,
        default=str
    )

    # ========================================================================
    # OLLAMA REQUEST
    # ========================================================================

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,

        # Ask Ollama for JSON.
        "format": "json",

        "options": {
            "temperature": 0
        }
    }

    try:

        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=OLLAMA_TIMEOUT
        )

        response.raise_for_status()

        data = response.json()

        raw_response = data.get(
            "response",
            ""
        )

        if not raw_response:

            return {
                "available": False,
                "parsed": False,
                "error": (
                    "Ollama returned an empty response."
                )
            }

        # ====================================================================
        # PARSE JSON
        # ====================================================================

        try:

            parsed = json.loads(
                raw_response
            )

        except json.JSONDecodeError as exc:

            return {
                "available": True,
                "parsed": False,
                "raw_response": raw_response,
                "parse_error": (
                    "Ollama returned invalid JSON: {}".format(
                        exc
                    )
                )
            }

        # ====================================================================
        # VALIDATE TOP LEVEL
        # ====================================================================

        if not isinstance(
            parsed,
            dict
        ):

            return {
                "available": True,
                "parsed": False,
                "raw_response": raw_response,
                "parse_error": (
                    "Ollama returned JSON, but the top-level "
                    "value was not an object."
                )
            }

        # ====================================================================
        # NORMALIZE MODEL RESPONSE
        # ====================================================================

        summary = parsed.get(
            "summary",
            parsed.get(
                "analysis",
                parsed.get(
                    "explanation",
                    parsed.get(
                        "description",
                        ""
                    )
                )
            )
        )

        current_state = parsed.get(
            "current_state",
            parsed.get(
                "observations",
                parsed.get(
                    "state",
                    []
                )
            )
        )

        important_evidence = parsed.get(
            "important_kubernetes_evidence",
            parsed.get(
                "evidence",
                parsed.get(
                    "important_evidence",
                    []
                )
            )
        )

        possible_implications = parsed.get(
            "possible_implications",
            parsed.get(
                "implications",
                parsed.get(
                    "possible_causes",
                    []
                )
            )
        )

        limitations = parsed.get(
            "limitations",
            parsed.get(
                "limitations_or_missing_evidence",
                []
            )
        )

        # ====================================================================
        # NORMALIZE VALUES
        # ====================================================================

        if summary is None:

            summary = ""

        if not isinstance(
            summary,
            str
        ):

            summary = json.dumps(
                summary,
                default=str
            )

        current_state = normalize_list(
            current_state
        )

        important_evidence = normalize_list(
            important_evidence
        )

        possible_implications = normalize_list(
            possible_implications
        )

        limitations = normalize_list(
            limitations
        )

        # ====================================================================
        # PREVENT EMPTY LLM OUTPUT
        # ====================================================================

        meaningful_content = (
            bool(summary.strip())
            or bool(current_state)
            or bool(important_evidence)
            or bool(possible_implications)
            or bool(limitations)
        )

        if not meaningful_content:

            return {
                "available": True,
                "parsed": False,
                "raw_response": raw_response,
                "parse_error": (
                    "Ollama returned valid JSON but no "
                    "meaningful explanation fields."
                )
            }

        # ====================================================================
        # STANDARD K8S AGENT LLM OUTPUT
        # ====================================================================

        normalized = {
            "summary": summary,
            "current_state": current_state,
            "important_kubernetes_evidence": important_evidence,
            "possible_implications": possible_implications,
            "limitations": limitations
        }

        return {
            "available": True,
            "parsed": True,
            "analysis": normalized,
            "raw_response": raw_response
        }

    # ========================================================================
    # OLLAMA ERRORS
    # ========================================================================

    except requests.exceptions.Timeout:

        return {
            "available": False,
            "parsed": False,
            "error": "Ollama request timed out."
        }

    except requests.exceptions.RequestException as exc:

        return {
            "available": False,
            "parsed": False,
            "error": (
                "Ollama request failed: {}".format(
                    exc
                )
            )
        }

    except Exception as exc:

        return {
            "available": False,
            "parsed": False,
            "error": str(exc)
        }


# ============================================================================
# AGENT EXECUTION
# ============================================================================

def run_agent(
    service: str,
    lookback_minutes: int = 60
) -> Dict[str, Any]:

    (
        core_api,
        apps_api,
        config_source
    ) = load_kubernetes_clients()

    # ------------------------------------------------------------------------
    # Collect Kubernetes evidence
    # ------------------------------------------------------------------------

    deployment = collect_deployment(
        apps_api,
        service
    )

    pods = collect_pods(
        core_api,
        service
    )

    endpoints = collect_endpoints(
        core_api,
        service
    )

    events = collect_events(
        core_api,
        service,
        pods,
        lookback_minutes
    )

    # ------------------------------------------------------------------------
    # Deterministic analysis
    # ------------------------------------------------------------------------

    deterministic_analysis = (
        analyse_kubernetes_state(
            service=service,
            deployment=deployment,
            pods=pods,
            endpoints=endpoints,
            events=events
        )
    )

    # ------------------------------------------------------------------------
    # Ollama explanation
    # ------------------------------------------------------------------------

    ollama_analysis = ask_ollama(
        service=service,
        deterministic_analysis=deterministic_analysis,
        deployment=deployment,
        pods=pods,
        endpoints=endpoints,
        events=events
    )

    # ------------------------------------------------------------------------
    # Final output
    # ------------------------------------------------------------------------

    return {
        "agent": "k8s-agent",
        "version": "1.1",
        "timestamp": utc_now().isoformat(),
        "namespace": NAMESPACE,
        "service": service,

        "configuration": {
            "kubernetes_config_source": config_source,
            "event_lookback_minutes": lookback_minutes,
            "ollama_model": OLLAMA_MODEL,
            "ollama_url": OLLAMA_URL
        },

        "deployment": deployment,

        "pods": pods,

        "endpoints": endpoints,

        # Raw/structured Kubernetes events remain available
        # for the Coordinator.
        "events": events,

        # Deterministic evidence is authoritative.
        "analysis": deterministic_analysis,

        # LLM explanation is supplemental.
        "ollama_analysis": ollama_analysis
    }


# ============================================================================
# CLI
# ============================================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "AutoRemedyRIC Kubernetes Context Agent"
        )
    )

    parser.add_argument(
        "service",
        help=(
            "Kubernetes deployment/service name "
            "(for example: currencyservice)"
        )
    )

    parser.add_argument(
        "lookback_minutes",
        nargs="?",
        type=int,
        default=60,
        help=(
            "Kubernetes event lookback window "
            "in minutes (default: 60)"
        )
    )

    args = parser.parse_args()

    try:

        result = run_agent(
            service=args.service,
            lookback_minutes=args.lookback_minutes
        )

        print(
            json.dumps(
                result,
                indent=2,
                default=str
            )
        )

    except KeyboardInterrupt:

        print(
            "\nK8s Agent interrupted.",
            file=sys.stderr
        )

        sys.exit(130)

    except Exception as exc:

        print(
            json.dumps(
                {
                    "agent": "k8s-agent",
                    "version": "1.1",
                    "status": "ERROR",
                    "error": str(exc)
                },
                indent=2
            )
        )

        sys.exit(1)


if __name__ == "__main__":
    main()