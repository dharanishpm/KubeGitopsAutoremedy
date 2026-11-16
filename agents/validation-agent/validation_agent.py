#!/usr/bin/env python3

"""
AutoRemedyRIC - Validation Agent V1

Purpose:
    Validate whether a previously detected Kubernetes service failure
    has been resolved.

Validation sources:
    1. Kubernetes deployment/pod readiness
    2. Kubernetes service endpoints
    3. Prometheus metric availability
    4. Optional trace evidence

The Validation Agent does NOT perform remediation.

It answers:
    - Has the service recovered?
    - Is it ready to receive traffic?
    - Are endpoints available?
    - Is there evidence of continuing trace errors?

Python:
    Compatible with Python 3.9+
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from kubernetes import client, config


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:latest"

PROMETHEUS_URL = "http://localhost:9090"

DEFAULT_NAMESPACE = "default"

DEFAULT_WAIT_SECONDS = 10

OLLAMA_TIMEOUT = 120


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def safe_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    return []


def load_kubernetes() -> None:
    """
    Load local kubeconfig.

    Falls back to in-cluster configuration if required.
    """

    try:
        config.load_kube_config()
    except Exception:
        config.load_incluster_config()


def normalize_service_name(service: str) -> str:
    return service.strip().lower()


# ---------------------------------------------------------------------------
# Kubernetes validation
# ---------------------------------------------------------------------------

def collect_kubernetes_state(
    service: str,
    namespace: str
) -> Dict[str, Any]:

    apps_api = client.AppsV1Api()
    core_api = client.CoreV1Api()

    deployment = None

    try:
        deployment = apps_api.read_namespaced_deployment(
            name=service,
            namespace=namespace
        )
    except Exception as exc:
        return {
            "available": False,
            "error": str(exc)
        }

    spec = deployment.spec
    status = deployment.status

    desired_replicas = (
        spec.replicas
        if spec and spec.replicas is not None
        else 0
    )

    available_replicas = (
        status.available_replicas
        if status and status.available_replicas is not None
        else 0
    )

    ready_replicas = (
        status.ready_replicas
        if status and status.ready_replicas is not None
        else 0
    )

    updated_replicas = (
        status.updated_replicas
        if status and status.updated_replicas is not None
        else 0
    )

    unavailable_replicas = (
        status.unavailable_replicas
        if status and status.unavailable_replicas is not None
        else 0
    )

    # ---------------------------------------------------------------
    # Pods
    # ---------------------------------------------------------------

    pods: List[Dict[str, Any]] = []

    try:

        pod_list = core_api.list_namespaced_pod(
            namespace=namespace,
            label_selector="app={}".format(service)
        )

        for pod in pod_list.items:

            restart_count = 0

            container_statuses = (
                pod.status.container_statuses or []
            )

            for container_status in container_statuses:

                if container_status.restart_count:
                    restart_count += (
                        container_status.restart_count
                    )

            ready = True

            if container_statuses:

                ready = all(
                    bool(
                        container_status.ready
                    )
                    for container_status
                    in container_statuses
                )

            else:
                ready = False

            pods.append({
                "name": pod.metadata.name,
                "phase": pod.status.phase,
                "ready": ready,
                "restart_count": restart_count,
                "pod_ip": pod.status.pod_ip,
            })

    except Exception as exc:

        pods = [{
            "error": str(exc)
        }]

    # ---------------------------------------------------------------
    # Service endpoints
    # ---------------------------------------------------------------

    endpoint_state: Dict[str, Any] = {
        "available": False,
        "ready_count": 0,
        "not_ready_count": 0,
        "ready_addresses": [],
        "not_ready_addresses": [],
    }

    try:

        endpoints = core_api.read_namespaced_endpoints(
            name=service,
            namespace=namespace
        )

        ready_addresses = []
        not_ready_addresses = []

        for subset in endpoints.subsets or []:

            for address in subset.addresses or []:

                ready_addresses.append(
                    address.ip
                )

            for address in (
                subset.not_ready_addresses or []
            ):

                not_ready_addresses.append(
                    address.ip
                )

        endpoint_state = {
            "available": True,
            "ready_count": len(
                ready_addresses
            ),
            "not_ready_count": len(
                not_ready_addresses
            ),
            "ready_addresses": ready_addresses,
            "not_ready_addresses": (
                not_ready_addresses
            ),
        }

    except Exception as exc:

        endpoint_state = {
            "available": False,
            "error": str(exc),
            "ready_count": 0,
            "not_ready_count": 0,
            "ready_addresses": [],
            "not_ready_addresses": [],
        }

    # ---------------------------------------------------------------
    # Deterministic recovery decision
    # ---------------------------------------------------------------

    service_available = (
        desired_replicas > 0
        and available_replicas > 0
        and ready_replicas > 0
        and endpoint_state["ready_count"] > 0
    )

    if service_available:

        status_text = "RECOVERED"

    elif desired_replicas == 0:

        status_text = "NOT_RUNNING"

    elif (
        available_replicas == 0
        or ready_replicas == 0
    ):

        status_text = "NOT_READY"

    elif endpoint_state["ready_count"] == 0:

        status_text = "NO_READY_ENDPOINTS"

    else:

        status_text = "PARTIALLY_RECOVERED"

    return {
        "available": True,

        "deployment": {
            "name": service,
            "desired_replicas": desired_replicas,
            "available_replicas": available_replicas,
            "ready_replicas": ready_replicas,
            "updated_replicas": updated_replicas,
            "unavailable_replicas": (
                unavailable_replicas
            ),
        },

        "pods": pods,

        "endpoints": endpoint_state,

        "service_available": service_available,

        "status": status_text,
    }


# ---------------------------------------------------------------------------
# Prometheus validation
# ---------------------------------------------------------------------------

def query_prometheus(
    query: str
) -> Dict[str, Any]:

    try:

        response = requests.get(
            "{}/api/v1/query".format(
                PROMETHEUS_URL
            ),
            params={
                "query": query
            },
            timeout=15
        )

        response.raise_for_status()

        data = response.json()

        return {
            "available": True,
            "result": data.get(
                "data",
                {}
            ).get(
                "result",
                []
            )
        }

    except Exception as exc:

        return {
            "available": False,
            "error": str(exc),
            "result": []
        }


def collect_prometheus_state(
    service: str,
    namespace: str
) -> Dict[str, Any]:

    cpu_query = """
sum(
  rate(
    container_cpu_usage_seconds_total{
      namespace="%s",
      pod=~"%s.*"
    }[5m]
  )
)
""" % (
        namespace,
        service
    )

    memory_query = """
sum(
  container_memory_working_set_bytes{
    namespace="%s",
    pod=~"%s.*"
  }
)
""" % (
        namespace,
        service
    )

    cpu_result = query_prometheus(
        cpu_query
    )

    memory_result = query_prometheus(
        memory_query
    )

    return {
        "cpu": cpu_result,
        "memory": memory_result,
    }


# ---------------------------------------------------------------------------
# Trace validation
# ---------------------------------------------------------------------------

def collect_trace_state(
    service: str
) -> Dict[str, Any]:

    """
    Query Jaeger for recent traces.

    This is deliberately lightweight.

    The Validation Agent only checks whether recent error evidence
    remains. Detailed trace analysis belongs to Trace Agent.
    """

    jaeger_url = "http://localhost:16686"

    end_us = int(
        time.time() * 1000000
    )

    # Five-minute lookback.
    start_us = end_us - (
        5 * 60 * 1000000
    )

    try:

        response = requests.get(
            "{}/api/traces".format(
                jaeger_url
            ),
            params={
                "service": service,
                "start": start_us,
                "end": end_us,
                "limit": 50,
            },
            timeout=15
        )

        response.raise_for_status()

        data = response.json()

        traces = safe_list(
            data.get("data")
        )

        error_span_count = 0
        total_spans = 0

        for trace in traces:

            spans = safe_list(
                trace.get("spans")
            )

            total_spans += len(spans)

            for span in spans:

                tags = safe_list(
                    span.get("tags")
                )

                error_found = False

                for tag in tags:

                    if not isinstance(tag, dict):
                        continue

                    key = tag.get("key")
                    value = tag.get("value")

                    if (
                        key == "error"
                        and value is True
                    ):
                        error_found = True

                    if (
                        key
                        in [
                            "otel.status_code",
                            "status.code",
                        ]
                        and str(value).upper()
                        == "ERROR"
                    ):
                        error_found = True

                if error_found:
                    error_span_count += 1

        if error_span_count > 0:

            status = "ERROR_EVIDENCE"

        elif traces:

            status = "NO_ERROR_EVIDENCE"

        else:

            status = "NO_TRACE_DATA"

        return {
            "available": True,
            "status": status,
            "trace_count": len(traces),
            "total_spans": total_spans,
            "error_span_count": error_span_count,
        }

    except Exception as exc:

        return {
            "available": False,
            "status": "TRACE_UNAVAILABLE",
            "trace_count": 0,
            "total_spans": 0,
            "error_span_count": 0,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Deterministic validation
# ---------------------------------------------------------------------------

def determine_validation_status(
    kubernetes: Dict[str, Any],
    prometheus: Dict[str, Any],
    trace: Dict[str, Any],
) -> Dict[str, Any]:

    findings: List[str] = []
    limitations: List[str] = []

    k8s_status = kubernetes.get(
        "status"
    )

    service_available = bool(
        kubernetes.get(
            "service_available"
        )
    )

    trace_status = trace.get(
        "status"
    )

    # ---------------------------------------------------------------
    # Kubernetes
    # ---------------------------------------------------------------

    if k8s_status == "RECOVERED":

        findings.append(
            "Kubernetes shows the service has "
            "ready replicas and ready endpoints."
        )

    elif k8s_status == "NOT_RUNNING":

        findings.append(
            "Kubernetes shows the deployment "
            "is still configured with zero replicas."
        )

    elif k8s_status == "NOT_READY":

        findings.append(
            "Kubernetes shows the service does "
            "not currently have ready replicas."
        )

    elif k8s_status == "NO_READY_ENDPOINTS":

        findings.append(
            "Kubernetes shows no ready service endpoints."
        )

    else:

        findings.append(
            "Kubernetes reports partial or indeterminate recovery."
        )

    # ---------------------------------------------------------------
    # Trace
    # ---------------------------------------------------------------

    if trace_status == "ERROR_EVIDENCE":

        findings.append(
            "Recent Jaeger traces still contain error evidence."
        )

    elif trace_status == "NO_ERROR_EVIDENCE":

        findings.append(
            "Recent Jaeger traces contain no detected error spans."
        )

    elif trace_status == "NO_TRACE_DATA":

        limitations.append(
            "No recent trace data was available."
        )

    else:

        limitations.append(
            "Trace validation was unavailable."
        )

    # ---------------------------------------------------------------
    # Prometheus
    # ---------------------------------------------------------------

    if prometheus.get("cpu", {}).get(
        "available"
    ):

        findings.append(
            "Prometheus is available for post-recovery metric validation."
        )

    else:

        limitations.append(
            "Prometheus metric validation was unavailable."
        )

    # ---------------------------------------------------------------
    # Final validation status
    # ---------------------------------------------------------------

    if (
        service_available
        and trace_status
        in [
            "NO_ERROR_EVIDENCE",
            "NO_TRACE_DATA",
        ]
    ):

        validation_status = "VALIDATION_PASSED"

    elif (
        not service_available
        or trace_status == "ERROR_EVIDENCE"
    ):

        validation_status = "VALIDATION_FAILED"

    else:

        validation_status = "VALIDATION_INCONCLUSIVE"

    return {
        "status": validation_status,
        "service_available": service_available,
        "findings": findings,
        "limitations": limitations,
    }


# ---------------------------------------------------------------------------
# Ollama explanation
# ---------------------------------------------------------------------------

def ask_ollama(
    service: str,
    validation: Dict[str, Any],
    kubernetes: Dict[str, Any],
    prometheus: Dict[str, Any],
    trace: Dict[str, Any],
) -> Dict[str, Any]:

    evidence = {
        "service": service,

        "validation": validation,

        "kubernetes": {
            "status": kubernetes.get("status"),
            "service_available":
                kubernetes.get(
                    "service_available"
                ),
            "deployment":
                kubernetes.get(
                    "deployment"
                ),
            "endpoint_ready_count":
                kubernetes.get(
                    "endpoints",
                    {}
                ).get(
                    "ready_count"
                ),
        },

        "prometheus": {
            "available":
                prometheus.get(
                    "cpu",
                    {}
                ).get(
                    "available"
                ),
            "cpu_samples":
                len(
                    prometheus.get(
                        "cpu",
                        {}
                    ).get(
                        "result",
                        []
                    )
                ),
            "memory_samples":
                len(
                    prometheus.get(
                        "memory",
                        {}
                    ).get(
                        "result",
                        []
                    )
                ),
        },

        "trace": trace,
    }

    prompt = """
You are the Validation Agent in a Kubernetes
root-cause-analysis and remediation system.

Your job is to explain whether the service has recovered.

Use ONLY the supplied deterministic evidence.

Rules:

1. Never invent telemetry.
2. Do not claim recovery if Kubernetes says the service
   is unavailable.
3. Do not claim that missing traces prove the service is healthy.
4. Do not change the deterministic validation status.
5. Do not recommend remediation.
6. Keep the explanation concise.

Return JSON:

{
  "summary": "brief factual explanation",
  "evidence": [
    "factual observations"
  ],
  "limitations": [
    "limitations"
  ]
}
"""

    payload = {
        "model": OLLAMA_MODEL,

        "prompt": (
            prompt
            + "\n\nEvidence:\n"
            + json.dumps(
                evidence,
                indent=2,
                default=str
            )
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

        raw = body.get(
            "response",
            ""
        )

        try:

            parsed = json.loads(
                raw
            )

            return {
                "available": True,
                "parsed": True,
                "analysis": parsed,
                "raw_response": raw,
            }

        except json.JSONDecodeError:

            return {
                "available": True,
                "parsed": False,
                "raw_response": raw,
                "parse_error":
                    "Ollama response was not valid JSON."
            }

    except Exception as exc:

        return {
            "available": False,
            "parsed": False,
            "error": str(exc)
        }


# ---------------------------------------------------------------------------
# Complete validation run
# ---------------------------------------------------------------------------

def run_validation(
    service: str,
    namespace: str,
    wait_seconds: int,
) -> Dict[str, Any]:

    service = normalize_service_name(
        service
    )

    load_kubernetes()

    # ---------------------------------------------------------------
    # Optional wait
    # ---------------------------------------------------------------

    if wait_seconds > 0:

        time.sleep(
            wait_seconds
        )

    # ---------------------------------------------------------------
    # Collect evidence
    # ---------------------------------------------------------------

    kubernetes = collect_kubernetes_state(
        service,
        namespace
    )

    prometheus = collect_prometheus_state(
        service,
        namespace
    )

    trace = collect_trace_state(
        service
    )

    # ---------------------------------------------------------------
    # Determine status
    # ---------------------------------------------------------------

    validation = determine_validation_status(
        kubernetes,
        prometheus,
        trace
    )

    # ---------------------------------------------------------------
    # Ollama explanation
    # ---------------------------------------------------------------

    ollama = ask_ollama(
        service,
        validation,
        kubernetes,
        prometheus,
        trace
    )

    return {
        "version": "V1",

        "agent": "validation-agent",

        "timestamp": utc_now(),

        "namespace": namespace,

        "service": service,

        "validation": validation,

        "kubernetes": kubernetes,

        "prometheus": prometheus,

        "trace": trace,

        "ollama_analysis": ollama,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "AutoRemedyRIC Validation Agent V1"
        )
    )

    parser.add_argument(
        "service",
        help=(
            "Kubernetes service/deployment name "
            "to validate"
        )
    )

    parser.add_argument(
        "--namespace",
        default=DEFAULT_NAMESPACE,
        help=(
            "Kubernetes namespace "
            "(default: default)"
        )
    )

    parser.add_argument(
        "--wait",
        type=int,
        default=DEFAULT_WAIT_SECONDS,
        help=(
            "Seconds to wait before validation "
            "(default: 10)"
        )
    )

    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Optional output JSON file"
        )
    )

    args = parser.parse_args()

    try:

        result = run_validation(
            service=args.service,
            namespace=args.namespace,
            wait_seconds=args.wait,
        )

        output = json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
            default=str
        )

        print(output)

        if args.output:

            output_path = Path(
                args.output
            )

            with output_path.open(
                "w",
                encoding="utf-8"
            ) as file:

                file.write(
                    output
                )

            print(
                "\nValidation output written to: {}".format(
                    output_path
                ),
                file=sys.stderr
            )

    except Exception as exc:

        print(
            "Validation Agent failed: {}".format(
                exc
            ),
            file=sys.stderr
        )

        sys.exit(1)


if __name__ == "__main__":
    main()