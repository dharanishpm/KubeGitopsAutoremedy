#!/usr/bin/env python3

"""
Trace Agent
-----------

Collects and analyses distributed traces from Jaeger for a Kubernetes service.

Responsibilities:
1. Query Jaeger for traces belonging to a service.
2. Extract spans and trace relationships.
3. Detect failed/error spans deterministically.
4. Detect high-latency spans.
5. Identify downstream services involved in traces.
6. Identify affected operations.
7. Distinguish:
      - NO_TRACE_DATA
      - NORMAL
      - WARNING_ONLY
      - ERROR_EVIDENCE
8. Send structured trace evidence to local Ollama.
9. Return structured evidence for the Coordinator Agent.

Environment:
    Jaeger UI/API: http://localhost:16686
    Ollama:        http://localhost:11434

Python:
    Compatible with Python 3.9+
"""

import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests


# ============================================================================
# Configuration
# ============================================================================

JAEGER_URL = "http://localhost:16686"
OLLAMA_URL = "http://localhost:11434"
OLLAMA_MODEL = "llama3.2:latest"

DEFAULT_LOOKBACK_MINUTES = 60

# Number of traces requested from Jaeger.
DEFAULT_TRACE_LIMIT = 50

# Maximum number of traces sent to Ollama.
OLLAMA_MAX_TRACES = 20

# Maximum number of spans retained per trace.
MAX_SPANS_PER_TRACE = 100

REQUEST_TIMEOUT = 20


# ============================================================================
# Trace status values
# ============================================================================

ERROR_STATUSES = {
    "error",
    "failed",
    "failure",
}

WARNING_STATUSES = {
    "timeout",
    "cancelled",
    "canceled",
}


# ============================================================================
# Utility functions
# ============================================================================

def utc_now() -> datetime:
    """Return current UTC time."""

    return datetime.now(timezone.utc)


def safe_int(
    value: Any,
    default: int = 0,
) -> int:
    """Safely convert a value to integer."""

    try:
        return int(value)

    except (TypeError, ValueError):
        return default


def safe_float(
    value: Any,
    default: float = 0.0,
) -> float:
    """Safely convert a value to float."""

    try:
        return float(value)

    except (TypeError, ValueError):
        return default


def normalize_string(
    value: Any,
) -> str:
    """Convert a value to a normalized string."""

    if value is None:
        return ""

    return str(value).strip()


def normalize_status(
    value: Any,
) -> str:
    """Normalize trace/span status."""

    return normalize_string(value).lower()


# ============================================================================
# Jaeger client
# ============================================================================

class JaegerClient:
    """HTTP client for Jaeger's query API."""

    def __init__(
        self,
        base_url: str = JAEGER_URL,
    ):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    # ------------------------------------------------------------------------
    # Get services
    # ------------------------------------------------------------------------

    def get_services(self) -> List[str]:
        """
        Retrieve services known to Jaeger.

        Endpoint:
            GET /api/services
        """

        url = "{}/api/services".format(
            self.base_url
        )

        response = self.session.get(
            url,
            timeout=REQUEST_TIMEOUT,
        )

        response.raise_for_status()

        data = response.json()

        services = data.get(
            "data",
            [],
        )

        if not isinstance(services, list):
            return []

        return services

    # ------------------------------------------------------------------------
    # Query traces
    # ------------------------------------------------------------------------

    def query_traces(
        self,
        service: str,
        lookback_minutes: int,
        limit: int = DEFAULT_TRACE_LIMIT,
    ) -> Dict[str, Any]:
        """
        Query traces for a service.

        Jaeger expects start/end in microseconds.
        """

        end_time = utc_now()

        start_time = (
            end_time
            - timedelta(
                minutes=lookback_minutes
            )
        )

        start_us = int(
            start_time.timestamp()
            * 1_000_000
        )

        end_us = int(
            end_time.timestamp()
            * 1_000_000
        )

        params = {
            "service": service,
            "start": str(start_us),
            "end": str(end_us),
            "limit": str(limit),
        }

        url = "{}/api/traces".format(
            self.base_url
        )

        response = self.session.get(
            url,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )

        response.raise_for_status()

        return response.json()


# ============================================================================
# Trace Agent
# ============================================================================

class TraceAgent:
    """
    Analyses distributed traces for a Kubernetes service.
    """

    def __init__(
        self,
        jaeger_url: str = JAEGER_URL,
        ollama_url: str = OLLAMA_URL,
        ollama_model: str = OLLAMA_MODEL,
    ):
        self.jaeger = JaegerClient(
            jaeger_url
        )

        self.ollama_url = ollama_url.rstrip("/")

        self.ollama_model = ollama_model

    # ------------------------------------------------------------------------
    # Retrieve traces
    # ------------------------------------------------------------------------

    def get_traces(
        self,
        service: str,
        lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
        limit: int = DEFAULT_TRACE_LIMIT,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve traces from Jaeger.
        """

        response = self.jaeger.query_traces(
            service=service,
            lookback_minutes=lookback_minutes,
            limit=limit,
        )

        traces = response.get(
            "data",
            [],
        )

        if not isinstance(traces, list):
            return []

        return traces

    # ------------------------------------------------------------------------
    # Span helpers
    # ------------------------------------------------------------------------

    @staticmethod
    def get_span_process(
        span: Dict[str, Any],
        process_map: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Resolve the process information associated with a span.
        """

        process_id = span.get(
            "processID"
        )

        if not process_id:
            return {}

        process = process_map.get(
            process_id,
            {},
        )

        return process

    @staticmethod
    def extract_span_service(
        span: Dict[str, Any],
        process_map: Dict[str, Dict[str, Any]],
    ) -> str:
        """
        Extract service name from a span.
        """

        process = TraceAgent.get_span_process(
            span,
            process_map,
        )

        service_name = process.get(
            "serviceName"
        )

        if service_name:
            return str(service_name)

        # Fallback to span tags.
        tags = span.get(
            "tags",
            [],
        )

        for tag in tags:
            if tag.get("key") in (
                "service.name",
                "peer.service",
            ):
                value = tag.get("value")

                if value:
                    return str(value)

        return "unknown"

    @staticmethod
    def get_tag_value(
        span: Dict[str, Any],
        keys: List[str],
    ) -> Optional[Any]:
        """
        Find a tag value from a list of possible keys.
        """

        tags = span.get(
            "tags",
            [],
        )

        for tag in tags:
            key = tag.get("key")

            if key in keys:
                return tag.get("value")

        return None

    @staticmethod
    def get_reference_count(
        span: Dict[str, Any],
    ) -> int:
        """
        Return number of references attached to a span.
        """

        references = span.get(
            "references",
            [],
        )

        if not isinstance(
            references,
            list,
        ):
            return 0

        return len(references)

    # ------------------------------------------------------------------------
    # Span classification
    # ------------------------------------------------------------------------

    def classify_span(
        self,
        span: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Deterministically classify a span.

        Error detection is based primarily on:
        - Jaeger error tags
        - span status tags
        - HTTP 5xx
        - RPC/grpc error indicators

        Latency is treated separately from failure.
        """

        tags = span.get(
            "tags",
            [],
        )

        tag_map = {}

        for tag in tags:
            key = tag.get("key")

            if key:
                tag_map[key] = tag.get(
                    "value"
                )

        status = normalize_status(
            tag_map.get(
                "status"
            )
            or tag_map.get(
                "otel.status_code"
            )
            or tag_map.get(
                "error.type"
            )
        )

        error_tag = tag_map.get(
            "error"
        )

        error_tag_true = (
            str(error_tag).lower()
            in (
                "true",
                "1",
            )
        )

        http_status = safe_int(
            tag_map.get(
                "http.status_code"
            )
            or tag_map.get(
                "http.status"
            ),
            default=0,
        )

        grpc_status = safe_int(
            tag_map.get(
                "rpc.grpc.status_code"
            ),
            default=0,
        )

        duration_us = safe_int(
            span.get(
                "duration"
            ),
            default=0,
        )

        # We do not impose an arbitrary latency threshold here.
        #
        # Latency is returned to the Coordinator, which can compare it
        # against other traces or an experimentally established baseline.
        #
        # This prevents the Trace Agent from declaring e.g. 500 ms as a
        # failure simply because of an arbitrary threshold.

        http_5xx = (
            http_status >= 500
            and http_status <= 599
        )

        grpc_error = (
            grpc_status != 0
            and grpc_status != 1
        )

        explicit_error = (
            error_tag_true
            or status in ERROR_STATUSES
            or http_5xx
            or grpc_error
        )

        warning = (
            not explicit_error
            and status in WARNING_STATUSES
        )

        if explicit_error:
            classification = "ERROR"

        elif warning:
            classification = "WARNING"

        else:
            classification = "NORMAL"

        return {
            "is_error": explicit_error,
            "is_warning": warning,
            "classification": classification,
            "error_tag": error_tag,
            "status": status,
            "http_status": (
                http_status
                if http_status > 0
                else None
            ),
            "http_5xx": http_5xx,
            "grpc_status": (
                grpc_status
                if grpc_status > 0
                else None
            ),
            "grpc_error": grpc_error,
            "duration_us": duration_us,
            "duration_ms": round(
                duration_us / 1000.0,
                3,
            ),
        }

    # ------------------------------------------------------------------------
    # Normalize trace
    # ------------------------------------------------------------------------

    def normalize_trace(
        self,
        trace: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Convert raw Jaeger trace into a compact structured representation.
        """

        trace_id = normalize_string(
            trace.get(
                "traceID"
            )
        )

        spans = trace.get(
            "spans",
            [],
        )

        if not isinstance(
            spans,
            list,
        ):
            spans = []

        process_map = trace.get(
            "processes",
            {},
        )

        if not isinstance(
            process_map,
            dict,
        ):
            process_map = {}

        normalized_spans = []

        services = set()

        operations = Counter()

        for span in spans[:MAX_SPANS_PER_TRACE]:
            service_name = self.extract_span_service(
                span,
                process_map,
            )

            services.add(
                service_name
            )

            operation_name = normalize_string(
                span.get(
                    "operationName"
                )
            )

            if operation_name:
                operations[
                    operation_name
                ] += 1

            classification = self.classify_span(
                span
            )

            normalized_span = {
                "span_id": normalize_string(
                    span.get(
                        "spanID"
                    )
                ),
                "operation": operation_name,
                "service": service_name,
                "start_time_us": safe_int(
                    span.get(
                        "startTime"
                    )
                ),
                "duration_us": classification.get(
                    "duration_us",
                    0,
                ),
                "duration_ms": classification.get(
                    "duration_ms",
                    0,
                ),
                "references": self.get_reference_count(
                    span
                ),
                "classification": classification,
            }

            normalized_spans.append(
                normalized_span
            )

        error_spans = [
            span
            for span in normalized_spans
            if span["classification"]["is_error"]
        ]

        warning_spans = [
            span
            for span in normalized_spans
            if span["classification"]["is_warning"]
        ]

        total_duration_us = sum(
            span.get(
                "duration_us",
                0,
            )
            for span in normalized_spans
        )

        max_duration_us = max(
            [
                span.get(
                    "duration_us",
                    0,
                )
                for span in normalized_spans
            ]
            or [0]
        )

        if error_spans:
            status = "ERROR_EVIDENCE"

        elif warning_spans:
            status = "WARNING_ONLY"

        else:
            status = "NORMAL"

        return {
            "trace_id": trace_id,
            "span_count": len(
                normalized_spans
            ),
            "service_count": len(
                services
            ),
            "services": sorted(
                services
            ),
            "operations": dict(
                operations
            ),
            "error_span_count": len(
                error_spans
            ),
            "warning_span_count": len(
                warning_spans
            ),
            "total_span_duration_ms": round(
                total_duration_us / 1000.0,
                3,
            ),
            "max_span_duration_ms": round(
                max_duration_us / 1000.0,
                3,
            ),
            "status": status,
            "error_spans": error_spans,
            "warning_spans": warning_spans,
            "spans": normalized_spans,
        }

    # ------------------------------------------------------------------------
    # Deterministic trace analysis
    # ------------------------------------------------------------------------

    def analyse_traces(
        self,
        service: str,
        traces: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Produce deterministic evidence from Jaeger traces.
        """

        if not traces:
            return {
                "status": "NO_TRACE_DATA",
                "total_traces": 0,
                "total_spans": 0,
                "error_trace_count": 0,
                "warning_trace_count": 0,
                "error_span_count": 0,
                "warning_span_count": 0,
                "error_rate": None,
                "warning_rate": None,
                "affected_services": [],
                "affected_operations": [],
                "span_error_counts_by_service": {},
                "trace_summaries": [],
                "error_spans": [],
                "warning_spans": [],
            }

        normalized_traces = []

        error_trace_count = 0
        warning_trace_count = 0

        error_span_count = 0
        warning_span_count = 0

        span_error_counts_by_service = defaultdict(int)

        affected_operations = Counter()

        affected_services = set()

        all_error_spans = []
        all_warning_spans = []

        for trace in traces:
            normalized = self.normalize_trace(
                trace
            )

            normalized_traces.append(
                normalized
            )

            if normalized["status"] == "ERROR_EVIDENCE":
                error_trace_count += 1

            elif normalized["status"] == "WARNING_ONLY":
                warning_trace_count += 1

            error_span_count += normalized[
                "error_span_count"
            ]

            warning_span_count += normalized[
                "warning_span_count"
            ]

            for span in normalized[
                "error_spans"
            ]:
                service_name = span.get(
                    "service",
                    "unknown",
                )

                span_error_counts_by_service[
                    service_name
                ] += 1

                affected_services.add(
                    service_name
                )

                operation = span.get(
                    "operation"
                )

                if operation:
                    affected_operations[
                        operation
                    ] += 1

                all_error_spans.append(
                    {
                        "trace_id": normalized[
                            "trace_id"
                        ],
                        "span": span,
                    }
                )

            for span in normalized[
                "warning_spans"
            ]:
                all_warning_spans.append(
                    {
                        "trace_id": normalized[
                            "trace_id"
                        ],
                        "span": span,
                    }
                )

        total_traces = len(
            normalized_traces
        )

        total_spans = sum(
            trace.get(
                "span_count",
                0,
            )
            for trace in normalized_traces
        )

        if error_trace_count > 0:
            status = "ERROR_EVIDENCE"

        elif warning_trace_count > 0:
            status = "WARNING_ONLY"

        else:
            status = "NORMAL"

        return {
            "status": status,
            "total_traces": total_traces,
            "total_spans": total_spans,
            "error_trace_count": error_trace_count,
            "warning_trace_count": warning_trace_count,
            "error_span_count": error_span_count,
            "warning_span_count": warning_span_count,
            "error_rate": round(
                error_trace_count
                / total_traces,
                4,
            ),
            "warning_rate": round(
                warning_trace_count
                / total_traces,
                4,
            ),
            "affected_services": sorted(
                affected_services
            ),
            "affected_operations": [
                {
                    "operation": operation,
                    "error_count": count,
                }
                for operation, count
                in affected_operations.most_common()
            ],
            "span_error_counts_by_service": dict(
                span_error_counts_by_service
            ),
            "trace_summaries": normalized_traces,
            "error_spans": all_error_spans[
                :OLLAMA_MAX_TRACES * 5
            ],
            "warning_spans": all_warning_spans[
                :OLLAMA_MAX_TRACES * 5
            ],
        }

    # ------------------------------------------------------------------------
    # Ollama
    # ------------------------------------------------------------------------

    def analyse_with_ollama(
        self,
        service: str,
        analysis: Dict[str, Any],
    ) -> str:
        """
        Ask local Ollama to interpret deterministic trace evidence.
        """

        trace_summaries = analysis.get(
            "trace_summaries",
            [],
        )

        compact_traces = []

        for trace in trace_summaries[
            :OLLAMA_MAX_TRACES
        ]:
            compact_traces.append(
                {
                    "trace_id": trace.get(
                        "trace_id"
                    ),
                    "status": trace.get(
                        "status"
                    ),
                    "span_count": trace.get(
                        "span_count"
                    ),
                    "services": trace.get(
                        "services"
                    ),
                    "error_span_count": trace.get(
                        "error_span_count"
                    ),
                    "warning_span_count": trace.get(
                        "warning_span_count"
                    ),
                    "max_span_duration_ms": trace.get(
                        "max_span_duration_ms"
                    ),
                    "error_spans": trace.get(
                        "error_spans",
                        [],
                    )[:10],
                    "warning_spans": trace.get(
                        "warning_spans",
                        [],
                    )[:10],
                }
            )

        prompt = """
You are the Trace Analysis component of a Kubernetes Root Cause Analysis
system.

Interpret only the deterministic distributed-trace evidence provided below.

IMPORTANT RULES:

1. Do not invent trace failures.
2. Do not change deterministic classifications.
3. ERROR_EVIDENCE means actual error evidence was detected.
4. WARNING_ONLY means warnings exist but no error evidence was detected.
5. NORMAL means traces were available and no error/warning evidence was
   detected.
6. NO_TRACE_DATA means no traces were available in the requested window.
7. Do not treat high latency as an error by itself.
8. Do not invent a latency threshold.
9. Do not claim a root cause from traces alone unless the evidence directly
   supports the claim.
10. Identify downstream services only from the supplied trace data.
11. Distinguish the service being analysed from downstream/related services.

Service being analysed:
{service}

Trace status:
{status}

Total traces:
{total_traces}

Total spans:
{total_spans}

Error traces:
{error_trace_count}

Warning traces:
{warning_trace_count}

Error spans:
{error_span_count}

Warning spans:
{warning_span_count}

Affected services:
{affected_services}

Affected operations:
{affected_operations}

Trace evidence:
{trace_evidence}

Return a concise report with exactly these sections:

Overall Trace Status
Observed Errors
Observed Warnings
Affected Services
Affected Operations
RCA Implications

If there is no error evidence, explicitly say so.
If traces are unavailable, explicitly state that no trace evidence was
available.
Do not infer a root cause merely from latency.
""".format(
            service=service,
            status=analysis.get(
                "status",
                "UNKNOWN",
            ),
            total_traces=analysis.get(
                "total_traces",
                0,
            ),
            total_spans=analysis.get(
                "total_spans",
                0,
            ),
            error_trace_count=analysis.get(
                "error_trace_count",
                0,
            ),
            warning_trace_count=analysis.get(
                "warning_trace_count",
                0,
            ),
            error_span_count=analysis.get(
                "error_span_count",
                0,
            ),
            warning_span_count=analysis.get(
                "warning_span_count",
                0,
            ),
            affected_services=analysis.get(
                "affected_services",
                [],
            ),
            affected_operations=analysis.get(
                "affected_operations",
                [],
            ),
            trace_evidence=json.dumps(
                compact_traces,
                indent=2,
            ),
        )

        url = "{}/api/generate".format(
            self.ollama_url
        )

        payload = {
            "model": self.ollama_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0,
            },
        }

        try:
            response = requests.post(
                url,
                json=payload,
                timeout=120,
            )

            response.raise_for_status()

            data = response.json()

            result = data.get(
                "response",
                "",
            ).strip()

            if result:
                return result

            return (
                "Ollama returned an empty trace analysis."
            )

        except requests.RequestException as exc:
            return (
                "Ollama trace analysis unavailable: {}".format(
                    exc
                )
            )

        except (
            ValueError,
            TypeError,
        ) as exc:
            return (
                "Ollama returned an invalid response: {}".format(
                    exc
                )
            )

    # ------------------------------------------------------------------------
    # Main
    # ------------------------------------------------------------------------

    def run(
        self,
        service: str,
        lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
    ) -> Dict[str, Any]:
        """
        Run complete Trace Agent workflow.
        """

        print(
            "Analyzing traces for service: {}".format(
                service
            )
        )

        print(
            "Lookback window: {} minutes".format(
                lookback_minutes
            )
        )

        print("Querying Jaeger...")

        traces = self.get_traces(
            service=service,
            lookback_minutes=lookback_minutes,
            limit=DEFAULT_TRACE_LIMIT,
        )

        print(
            "Retrieved {} traces.".format(
                len(traces)
            )
        )

        print(
            "Performing deterministic trace analysis..."
        )

        analysis = self.analyse_traces(
            service=service,
            traces=traces,
        )

        print(
            "Sending trace evidence to local Ollama..."
        )

        ollama_analysis = self.analyse_with_ollama(
            service=service,
            analysis=analysis,
        )

        evidence = {
            "agent": "trace-agent",
            "timestamp": utc_now().isoformat(),
            "service": service,
            "lookback_minutes": lookback_minutes,
            "analysis": analysis,
        }

        return {
            "service": service,
            "agent": "trace-agent",
            "evidence": evidence,
            "ollama_analysis": ollama_analysis,
        }


# ============================================================================
# CLI
# ============================================================================

def print_usage() -> None:
    """Print command-line usage."""

    print(
        "Usage:\n"
        "  python agents/trace-agent/trace_agent.py "
        "<service> [lookback_minutes]\n\n"
        "Examples:\n"
        "  python agents/trace-agent/trace_agent.py adservice\n"
        "  python agents/trace-agent/trace_agent.py adservice 60\n"
        "  python agents/trace-agent/trace_agent.py checkoutservice 30"
    )


def print_result(
    result: Dict[str, Any],
) -> None:
    """Print structured result."""

    print()
    print("=" * 70)
    print("TRACE AGENT RESULT")
    print("=" * 70)

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )


def main() -> None:
    """CLI entry point."""

    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    service = sys.argv[1].strip()

    if not service:
        print(
            "Error: service name cannot be empty."
        )
        sys.exit(1)

    lookback_minutes = DEFAULT_LOOKBACK_MINUTES

    if len(sys.argv) >= 3:
        try:
            lookback_minutes = int(
                sys.argv[2]
            )

            if lookback_minutes <= 0:
                raise ValueError

        except ValueError:
            print(
                "Error: lookback_minutes must be "
                "a positive integer."
            )
            sys.exit(1)

    agent = TraceAgent()

    try:
        result = agent.run(
            service=service,
            lookback_minutes=lookback_minutes,
        )

        print_result(result)

    except requests.RequestException as exc:
        print()
        print(
            "ERROR: Unable to communicate with Jaeger: {}".format(
                exc
            )
        )
        sys.exit(2)

    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)

    except Exception as exc:
        print()
        print(
            "ERROR: Trace Agent failed: {}".format(
                exc
            )
        )
        sys.exit(3)


if __name__ == "__main__":
    main()