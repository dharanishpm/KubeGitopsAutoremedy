#!/usr/bin/env python3

"""
Log Agent
---------

Collects and analyses application logs from Loki for a specific service.

Responsibilities:
1. Query Loki for service logs.
2. Parse structured JSON logs where available.
3. Classify logs deterministically as:
      - NORMAL
      - WARNING
      - ERROR
4. Detect HTTP 5xx errors and explicit error-level logs.
5. Keep warnings separate from actual errors.
6. Distinguish NO_LOG_DATA from NORMAL.
7. Send only structured log evidence to local Ollama.
8. Return structured evidence for the Coordinator Agent.

Python compatibility:
- Python 3.9+
- No Python 3.10+ union syntax.
"""

import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests


# ============================================================================
# Configuration
# ============================================================================

LOKI_URL = "http://localhost:3100"
OLLAMA_URL = "http://localhost:11434"
OLLAMA_MODEL = "llama3.2:latest"

DEFAULT_NAMESPACE = "default"

# Development/research lookback.
DEFAULT_LOOKBACK_MINUTES = 60

# Maximum number of Loki entries retrieved.
DEFAULT_LOG_LIMIT = 200

# Maximum number of log entries sent to Ollama.
OLLAMA_MAX_ENTRIES = 50

# HTTP timeout in seconds.
REQUEST_TIMEOUT = 15


# ============================================================================
# Log classification
# ============================================================================

ERROR_LEVELS = {
    "error",
    "err",
    "fatal",
    "critical",
    "crit",
    "emergency",
    "emerg",
}

WARNING_LEVELS = {
    "warn",
    "warning",
}

# These patterns are deliberately more conservative than simply searching
# every log for words such as "failed" or "unavailable".
#
# The objective is to avoid treating harmless informational messages such as:
#
#   "Tracing enabled but temporarily unavailable"
#
# as an application failure.
ERROR_PATTERNS = [
    r"\bexception\b",
    r"\btraceback\b",
    r"\bfatal\b",
    r"\bpanic\b",
    r"\bcritical\b",
    r"\bconnection\s+(?:refused|reset|failed)\b",
    r"\brequest\s+(?:failed|failure)\b",
    r"\bservice\s+(?:failed|failure)\b",
    r"\binternal\s+server\s+error\b",
    r"\bserver\s+error\b",
    r"\bstatus\s*[:=]?\s*5\d{2}\b",
    r"\bhttp\s*5\d{2}\b",
    r"\bgrpc\s+(?:error|failed|failure)\b",
]

# Explicit warning patterns.
WARNING_PATTERNS = [
    r"\bwarning\b",
    r"\bdeprecated\b",
    r"\bdeprecated\s+method\b",
]


# ============================================================================
# Utility functions
# ============================================================================

def utc_now() -> datetime:
    """Return the current UTC time."""
    return datetime.now(timezone.utc)


def normalize_level(level: Optional[str]) -> str:
    """Normalize a log severity level."""
    if not level:
        return "unknown"

    return str(level).strip().lower()


def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert a value to int."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def matches_any_pattern(message: str, patterns: List[str]) -> List[str]:
    """
    Return all patterns that match the supplied message.
    """
    matches = []

    for pattern in patterns:
        try:
            if re.search(pattern, message, flags=re.IGNORECASE):
                matches.append(pattern)
        except re.error:
            continue

    return matches


def extract_http_status(message: str) -> Optional[int]:
    """
    Try to extract an HTTP status code from a log message.

    Examples:
        HTTP 500
        status=503
        status: 404
        "statusCode":500
    """

    patterns = [
        r"\bHTTP\s+([45]\d{2})\b",
        r"\bstatus(?:Code)?\s*[:=]\s*['\"]?([45]\d{2})\b",
        r"\bstatus_code\s*[:=]\s*['\"]?([45]\d{2})\b",
        r"\bcode\s*[:=]\s*['\"]?([45]\d{2})\b",
    ]

    for pattern in patterns:
        match = re.search(pattern, message, flags=re.IGNORECASE)

        if match:
            return safe_int(match.group(1))

    return None


def parse_json_message(message: str) -> Dict[str, Any]:
    """
    Parse a structured JSON log message.

    Loki may return the log body as JSON followed by CR/LF characters.
    """
    if not message:
        return {}

    cleaned = message.strip()

    if not cleaned.startswith("{"):
        return {}

    try:
        parsed = json.loads(cleaned)

        if isinstance(parsed, dict):
            return parsed

    except json.JSONDecodeError:
        pass

    return {}


def extract_message_fields(
    raw_message: str,
    detected_level: str,
) -> Dict[str, Any]:
    """
    Extract useful fields from a raw Loki log entry.
    """

    parsed = parse_json_message(raw_message)

    if parsed:
        message = str(parsed.get("message", raw_message)).strip()

        json_level = normalize_level(
            parsed.get("level")
            or parsed.get("severity")
            or parsed.get("logLevel")
        )

        if json_level != "unknown":
            level = json_level
        else:
            level = detected_level

        timestamp = (
            parsed.get("time")
            or parsed.get("timestamp")
            or parsed.get("@timestamp")
        )

        logger_name = parsed.get("loggerName")

        trace_id = (
            parsed.get("logging.googleapis.com/trace")
            or parsed.get("traceId")
            or parsed.get("trace_id")
        )

        span_id = (
            parsed.get("logging.googleapis.com/spanId")
            or parsed.get("spanId")
            or parsed.get("span_id")
        )

        return {
            "message": message,
            "level": level,
            "timestamp": timestamp,
            "logger_name": logger_name,
            "trace_id": trace_id,
            "span_id": span_id,
            "structured": True,
            "raw_message": raw_message.strip(),
        }

    return {
        "message": raw_message.strip(),
        "level": detected_level,
        "timestamp": None,
        "logger_name": None,
        "trace_id": None,
        "span_id": None,
        "structured": False,
        "raw_message": raw_message.strip(),
    }


# ============================================================================
# Loki client
# ============================================================================

class LokiClient:
    """Simple Loki HTTP client."""

    def __init__(self, base_url: str = LOKI_URL):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def query_range(
        self,
        query: str,
        lookback_minutes: int,
        limit: int = DEFAULT_LOG_LIMIT,
    ) -> Dict[str, Any]:
        """
        Query Loki query_range API.
        """

        end_time = utc_now()
        start_time = end_time - timedelta(minutes=lookback_minutes)

        params = {
            "query": query,
            "start": str(int(start_time.timestamp() * 1_000_000_000)),
            "end": str(int(end_time.timestamp() * 1_000_000_000)),
            "limit": str(limit),
            "direction": "backward",
        }

        url = "{}/loki/api/v1/query_range".format(self.base_url)

        response = self.session.get(
            url,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )

        response.raise_for_status()

        return response.json()


# ============================================================================
# Log Agent
# ============================================================================

class LogAgent:
    """
    Analyses logs for a single Kubernetes service.
    """

    def __init__(
        self,
        namespace: str = DEFAULT_NAMESPACE,
        loki_url: str = LOKI_URL,
        ollama_url: str = OLLAMA_URL,
        ollama_model: str = OLLAMA_MODEL,
    ):
        self.namespace = namespace

        self.loki = LokiClient(loki_url)

        self.ollama_url = ollama_url.rstrip("/")
        self.ollama_model = ollama_model

    # ------------------------------------------------------------------------
    # Loki query
    # ------------------------------------------------------------------------

    def build_query(self, service: str) -> str:
        """
        Build the Loki query.

        The Online Boutique Loki streams expose the application service using
        the "app" label, so this is preferred over a pod-name regex.
        """

        safe_service = service.replace('"', '\\"')

        return (
            '{{namespace="{}",app="{}"}}'
            .format(self.namespace, safe_service)
        )

    def get_logs(
        self,
        service: str,
        lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
        limit: int = DEFAULT_LOG_LIMIT,
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Retrieve logs from Loki.

        Returns:
            query, normalized log entries
        """

        query = self.build_query(service)

        print("Loki query: {}".format(query))

        response = self.loki.query_range(
            query=query,
            lookback_minutes=lookback_minutes,
            limit=limit,
        )

        data = response.get("data", {})
        results = data.get("result", [])

        entries = []

        for stream in results:
            labels = stream.get("stream", {})

            pod = labels.get("pod", "unknown")
            container = labels.get("container", "unknown")
            service_name = labels.get(
                "service_name",
                labels.get("app", service),
            )

            detected_level = normalize_level(
                labels.get("detected_level")
            )

            values = stream.get("values", [])

            for timestamp_ns, raw_message in values:
                fields = extract_message_fields(
                    raw_message=raw_message,
                    detected_level=detected_level,
                )

                entry = {
                    "timestamp_ns": str(timestamp_ns),
                    "timestamp": self.nanoseconds_to_iso(
                        timestamp_ns
                    ),
                    "pod": pod,
                    "service": service_name,
                    "container": container,
                    "detected_level": detected_level,
                    "message": raw_message,
                    "parsed_message": fields.get("message"),
                    "parsed_level": fields.get("level"),
                    "structured": fields.get("structured", False),
                    "logger_name": fields.get("logger_name"),
                    "trace_id": fields.get("trace_id"),
                    "span_id": fields.get("span_id"),
                }

                classification = self.classify_log(
                    entry=entry
                )

                entry["classification"] = classification

                entries.append(entry)

        # Newest first.
        entries.sort(
            key=lambda item: safe_int(
                item.get("timestamp_ns"),
                0,
            ),
            reverse=True,
        )

        return query, entries

    @staticmethod
    def nanoseconds_to_iso(timestamp_ns: Any) -> str:
        """Convert Loki nanosecond timestamp to ISO UTC."""

        try:
            timestamp = int(timestamp_ns) / 1_000_000_000

            return datetime.fromtimestamp(
                timestamp,
                tz=timezone.utc,
            ).isoformat()

        except (TypeError, ValueError, OverflowError, OSError):
            return ""

    # ------------------------------------------------------------------------
    # Deterministic classification
    # ------------------------------------------------------------------------

    def classify_log(
        self,
        entry: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Deterministically classify a single log.

        Priority:
            ERROR > WARNING > NORMAL

        This prevents an error containing a warning word from being
        incorrectly classified as only a warning.
        """

        raw_message = str(
            entry.get("message", "")
        ).strip()

        parsed_message = str(
            entry.get("parsed_message", "")
        ).strip()

        message = parsed_message or raw_message

        detected_level = normalize_level(
            entry.get("detected_level")
        )

        parsed_level = normalize_level(
            entry.get("parsed_level")
        )

        severity_level = (
            parsed_level
            if parsed_level != "unknown"
            else detected_level
        )

        error_patterns = matches_any_pattern(
            message,
            ERROR_PATTERNS,
        )

        warning_patterns = matches_any_pattern(
            message,
            WARNING_PATTERNS,
        )

        http_status = extract_http_status(message)

        http_5xx = (
            http_status is not None
            and 500 <= http_status <= 599
        )

        severity_error = severity_level in ERROR_LEVELS

        severity_warning = severity_level in WARNING_LEVELS

        # An explicit error severity or HTTP 5xx is strong evidence.
        error_detected = (
            severity_error
            or http_5xx
            or len(error_patterns) > 0
        )

        warning_detected = (
            severity_warning
            or len(warning_patterns) > 0
        )

        if error_detected:
            classification = "ERROR"

        elif warning_detected:
            classification = "WARNING"

        else:
            classification = "NORMAL"

        return {
            "is_error": error_detected,
            "is_warning": warning_detected,
            "classification": classification,
            "error_patterns": error_patterns,
            "warning_patterns": warning_patterns,
            "severity_error": severity_error,
            "severity_warning": severity_warning,
            "detected_error_level": severity_error,
            "detected_warning_level": severity_warning,
            "http_status": http_status,
            "http_5xx": http_5xx,
        }

    # ------------------------------------------------------------------------
    # Deterministic analysis
    # ------------------------------------------------------------------------

    def analyse_logs(
        self,
        service: str,
        entries: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Produce deterministic evidence from retrieved logs.
        """

        if not entries:
            return {
                "status": "NO_LOG_DATA",
                "total_log_entries": 0,
                "normal_log_entries": 0,
                "warning_log_entries": 0,
                "error_log_entries": 0,
                "error_rate": None,
                "warning_rate": None,
                "affected_pods": [],
                "error_counts_by_pod": {},
                "warning_counts_by_pod": {},
                "severity_counts": {
                    "NORMAL": 0,
                    "WARNING": 0,
                    "ERROR": 0,
                },
                "error_detected": False,
                "warning_detected": False,
                "error_entries": [],
                "warning_entries": [],
                "all_entries": [],
            }

        normal_entries = []
        warning_entries = []
        error_entries = []

        error_counts_by_pod = defaultdict(int)
        warning_counts_by_pod = defaultdict(int)

        severity_counts = Counter()

        for entry in entries:
            classification = entry.get(
                "classification",
                {},
            )

            classification_name = classification.get(
                "classification",
                "NORMAL",
            )

            severity_counts[classification_name] += 1

            if classification_name == "ERROR":
                error_entries.append(entry)

                pod = entry.get("pod", "unknown")
                error_counts_by_pod[pod] += 1

            elif classification_name == "WARNING":
                warning_entries.append(entry)

                pod = entry.get("pod", "unknown")
                warning_counts_by_pod[pod] += 1

            else:
                normal_entries.append(entry)

        total = len(entries)

        error_count = len(error_entries)
        warning_count = len(warning_entries)
        normal_count = len(normal_entries)

        affected_pods = sorted(
            set(error_counts_by_pod.keys())
        )

        # Keep only useful evidence in the final report.
        evidence_errors = error_entries[:OLLAMA_MAX_ENTRIES]
        evidence_warnings = warning_entries[:OLLAMA_MAX_ENTRIES]

        if error_count > 0:
            status = "ERROR_EVIDENCE"

        elif warning_count > 0:
            status = "WARNING_ONLY"

        else:
            status = "NORMAL"

        return {
            "status": status,
            "total_log_entries": total,
            "normal_log_entries": normal_count,
            "warning_log_entries": warning_count,
            "error_log_entries": error_count,
            "error_rate": round(
                error_count / total,
                4,
            ),
            "warning_rate": round(
                warning_count / total,
                4,
            ),
            "affected_pods": affected_pods,
            "error_counts_by_pod": dict(
                error_counts_by_pod
            ),
            "warning_counts_by_pod": dict(
                warning_counts_by_pod
            ),
            "severity_counts": {
                "NORMAL": severity_counts.get(
                    "NORMAL",
                    0,
                ),
                "WARNING": severity_counts.get(
                    "WARNING",
                    0,
                ),
                "ERROR": severity_counts.get(
                    "ERROR",
                    0,
                ),
            },
            "error_detected": error_count > 0,
            "warning_detected": warning_count > 0,
            "error_entries": evidence_errors,
            "warning_entries": evidence_warnings,
            "all_entries": entries,
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
        Ask the local Ollama model to interpret deterministic log evidence.

        The model is explicitly prohibited from changing deterministic
        classification or inventing root causes.
        """

        error_entries = analysis.get(
            "error_entries",
            [],
        )

        warning_entries = analysis.get(
            "warning_entries",
            [],
        )

        error_evidence = self.prepare_ollama_entries(
            error_entries
        )

        warning_evidence = self.prepare_ollama_entries(
            warning_entries
        )

        prompt = """
You are the Log Analysis component of a Kubernetes Root Cause Analysis
system.

Your job is to interpret the log evidence supplied by a deterministic
log-analysis system.

IMPORTANT RULES:

1. Do not invent errors that are not present.
2. Do not change the deterministic classification.
3. WARNING is not the same as ERROR.
4. NORMAL logs are not evidence of failure.
5. NO_LOG_DATA means there was insufficient log evidence.
6. Do not claim a root cause based on logs alone unless the evidence
   explicitly supports it.
7. Do not treat words such as "unavailable", "failed", or "deprecated"
   as proof of an application failure when the deterministic classifier
   has not classified the entry as ERROR.
8. Treat HTTP 5xx and explicit ERROR/FATAL/CRITICAL logs as stronger
   evidence.
9. Keep the response concise and evidence-based.

Service:
{service}

Deterministic status:
{status}

Total logs:
{total}

Normal logs:
{normal}

Warning logs:
{warning}

Error logs:
{error}

Error rate:
{error_rate}

Warning rate:
{warning_rate}

Affected pods:
{affected_pods}

Error evidence:
{error_evidence}

Warning evidence:
{warning_evidence}

Return a short report with exactly these sections:

Overall Log Status
Observed Errors
Observed Warnings
Affected Pods
RCA Implications

If there are no errors, explicitly say that no error evidence was detected.
If there are warnings but no errors, explicitly say that warnings were
observed but they are not by themselves proof of an application failure.
If there is no log data, explicitly say that no log evidence was available.
""".format(
            service=service,
            status=analysis.get(
                "status",
                "UNKNOWN",
            ),
            total=analysis.get(
                "total_log_entries",
                0,
            ),
            normal=analysis.get(
                "normal_log_entries",
                0,
            ),
            warning=analysis.get(
                "warning_log_entries",
                0,
            ),
            error=analysis.get(
                "error_log_entries",
                0,
            ),
            error_rate=analysis.get(
                "error_rate",
                None,
            ),
            warning_rate=analysis.get(
                "warning_rate",
                None,
            ),
            affected_pods=analysis.get(
                "affected_pods",
                [],
            ),
            error_evidence=json.dumps(
                error_evidence,
                indent=2,
            ),
            warning_evidence=json.dumps(
                warning_evidence,
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

            return "Ollama returned an empty analysis."

        except requests.RequestException as exc:
            return (
                "Ollama analysis unavailable: {}".format(
                    exc
                )
            )

        except (ValueError, TypeError) as exc:
            return (
                "Ollama returned an invalid response: {}".format(
                    exc
                )
            )

    @staticmethod
    def prepare_ollama_entries(
        entries: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Reduce log entries before sending them to Ollama.
        """

        prepared = []

        for entry in entries:
            classification = entry.get(
                "classification",
                {},
            )

            prepared.append(
                {
                    "timestamp": entry.get(
                        "timestamp"
                    ),
                    "pod": entry.get(
                        "pod"
                    ),
                    "container": entry.get(
                        "container"
                    ),
                    "level": entry.get(
                        "parsed_level"
                    )
                    or entry.get(
                        "detected_level"
                    ),
                    "classification": classification.get(
                        "classification"
                    ),
                    "message": entry.get(
                        "parsed_message"
                    )
                    or entry.get(
                        "message"
                    ),
                    "logger_name": entry.get(
                        "logger_name"
                    ),
                    "trace_id": entry.get(
                        "trace_id"
                    ),
                    "span_id": entry.get(
                        "span_id"
                    ),
                    "http_status": classification.get(
                        "http_status"
                    ),
                    "error_patterns": classification.get(
                        "error_patterns",
                        [],
                    ),
                    "warning_patterns": classification.get(
                        "warning_patterns",
                        [],
                    ),
                }
            )

        return prepared

    # ------------------------------------------------------------------------
    # Main analysis
    # ------------------------------------------------------------------------

    def run(
        self,
        service: str,
        lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
    ) -> Dict[str, Any]:
        """
        Run the complete Log Agent workflow.
        """

        print(
            "Analyzing logs for service: {}".format(
                service
            )
        )

        print(
            "Lookback window: {} minutes".format(
                lookback_minutes
            )
        )

        print("Querying Loki...")

        query, entries = self.get_logs(
            service=service,
            lookback_minutes=lookback_minutes,
            limit=DEFAULT_LOG_LIMIT,
        )

        print("Extracting log entries...")

        print(
            "Retrieved {} log entries.".format(
                len(entries)
            )
        )

        print("Performing deterministic log analysis...")

        analysis = self.analyse_logs(
            service=service,
            entries=entries,
        )

        print("Sending log evidence to local Ollama...")

        ollama_analysis = self.analyse_with_ollama(
            service=service,
            analysis=analysis,
        )

        evidence = {
            "agent": "log-agent",
            "timestamp": utc_now().isoformat(),
            "namespace": self.namespace,
            "service": service,
            "lookback_minutes": lookback_minutes,
            "query": query,
            "analysis": analysis,
        }

        return {
            "service": service,
            "agent": "log-agent",
            "evidence": evidence,
            "ollama_analysis": ollama_analysis,
        }


# ============================================================================
# CLI
# ============================================================================

def print_result(result: Dict[str, Any]) -> None:
    """Print structured Log Agent result."""

    print()
    print("=" * 70)
    print("LOG AGENT RESULT")
    print("=" * 70)

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )


def print_usage() -> None:
    """Print command-line usage."""

    print(
        "Usage:\n"
        "  python agents/log-agent/log_agent.py <service> [lookback_minutes]\n\n"
        "Examples:\n"
        "  python agents/log-agent/log_agent.py adservice\n"
        "  python agents/log-agent/log_agent.py adservice 60\n"
        "  python agents/log-agent/log_agent.py checkoutservice 30"
    )


def main() -> None:
    """CLI entry point."""

    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    service = sys.argv[1].strip()

    if not service:
        print("Error: service name cannot be empty.")
        sys.exit(1)

    lookback_minutes = DEFAULT_LOOKBACK_MINUTES

    if len(sys.argv) >= 3:
        try:
            lookback_minutes = int(sys.argv[2])

            if lookback_minutes <= 0:
                raise ValueError

        except ValueError:
            print(
                "Error: lookback_minutes must be a positive integer."
            )
            sys.exit(1)

    agent = LogAgent()

    try:
        result = agent.run(
            service=service,
            lookback_minutes=lookback_minutes,
        )

        print_result(result)

    except requests.RequestException as exc:
        print()
        print(
            "ERROR: Unable to communicate with Loki: {}".format(
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
            "ERROR: Log Agent failed: {}".format(
                exc
            )
        )
        sys.exit(3)


if __name__ == "__main__":
    main()