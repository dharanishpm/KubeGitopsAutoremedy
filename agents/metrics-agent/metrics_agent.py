import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

import requests
from langchain_ollama import ChatOllama


# ============================================================
# CONFIGURATION
# ============================================================

PROMETHEUS_URL = "http://localhost:9090"

OLLAMA_URL = "http://localhost:11434"
OLLAMA_MODEL = "llama3.2:latest"

NAMESPACE = "default"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

BASELINE_FILE = os.path.join(
    BASE_DIR,
    "baseline.json"
)

SIGMA_MULTIPLIER = 3


# ============================================================
# PROMETHEUS CLIENT
# ============================================================

class PrometheusClient:

    def __init__(
        self,
        url: str
    ):
        self.url = url.rstrip("/")

    def query(
        self,
        query: str
    ) -> List[Dict[str, Any]]:

        response = requests.get(
            f"{self.url}/api/v1/query",
            params={
                "query": query
            },
            timeout=30
        )

        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise RuntimeError(
                f"Prometheus query failed: {data}"
            )

        return data["data"]["result"]


# ============================================================
# METRICS AGENT
# ============================================================

class MetricsAgent:

    def __init__(
        self,
        prometheus_url: str = PROMETHEUS_URL,
        ollama_url: str = OLLAMA_URL,
        ollama_model: str = OLLAMA_MODEL
    ):

        self.prometheus = PrometheusClient(
            prometheus_url
        )

        self.llm = ChatOllama(
            model=ollama_model,
            base_url=ollama_url,
            temperature=0
        )

        self.baseline = self.load_baseline()

    # ========================================================
    # LOAD BASELINE
    # ========================================================

    def load_baseline(
        self
    ) -> Dict[str, Any]:

        if not os.path.exists(BASELINE_FILE):

            raise FileNotFoundError(
                "\nBaseline file not found:\n"
                f"{BASELINE_FILE}\n\n"
                "Run baseline_calculator.py first."
            )

        with open(
            BASELINE_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            baseline = json.load(file)

        return baseline

    # ========================================================
    # GET SERVICE BASELINE
    # ========================================================

    def get_service_baseline(
        self,
        service: str
    ) -> Dict[str, Any]:

        services = self.baseline.get(
            "services",
            {}
        )

        if service not in services:

            raise ValueError(
                f"No baseline exists for service "
                f"'{service}'."
            )

        service_baseline = services[service]

        if "error" in service_baseline:

            raise ValueError(
                f"Baseline for service "
                f"'{service}' contains an error: "
                f"{service_baseline['error']}"
            )

        return service_baseline

    # ========================================================
    # PROMETHEUS QUERIES
    # ========================================================

    def get_cpu_usage(
        self,
        service: str
    ) -> List[Dict[str, Any]]:

        query = f"""
        sum by (pod) (
            rate(
                container_cpu_usage_seconds_total{{
                    namespace="{NAMESPACE}",
                    pod=~"{service}.*"
                }}[5m]
            )
        )
        """

        return self.prometheus.query(query)

    def get_memory_usage(
        self,
        service: str
    ) -> List[Dict[str, Any]]:

        query = f"""
        sum by (pod) (
            container_memory_working_set_bytes{{
                namespace="{NAMESPACE}",
                pod=~"{service}.*"
            }}
        )
        """

        return self.prometheus.query(query)

    def get_restarts(
        self,
        service: str
    ) -> List[Dict[str, Any]]:

        query = f"""
        sum by (pod) (
            increase(
                kube_pod_container_status_restarts_total{{
                    namespace="{NAMESPACE}",
                    pod=~"{service}.*"
                }}[15m]
            )
        )
        """

        return self.prometheus.query(query)

    def get_cpu_throttling(
        self,
        service: str
    ) -> List[Dict[str, Any]]:

        query = f"""
        100 *
        sum by (pod) (
            rate(
                container_cpu_cfs_throttled_periods_total{{
                    namespace="{NAMESPACE}",
                    pod=~"{service}.*"
                }}[5m]
            )
        )
        /
        clamp_min(
            sum by (pod) (
                rate(
                    container_cpu_cfs_periods_total{{
                        namespace="{NAMESPACE}",
                        pod=~"{service}.*"
                    }}[5m]
                )
            ),
            1
        )
        """

        return self.prometheus.query(query)

    # ========================================================
    # EXTRACT PROMETHEUS RESULTS
    # ========================================================

    def extract_results(
        self,
        results: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:

        output = []

        for result in results:

            metric = result.get(
                "metric",
                {}
            )

            value = result.get(
                "value"
            )

            if not value:
                continue

            try:

                numeric_value = float(
                    value[1]
                )

            except (
                ValueError,
                TypeError,
                IndexError
            ):
                continue

            output.append(
                {
                    "pod": metric.get(
                        "pod",
                        "unknown"
                    ),
                    "value": numeric_value
                }
            )

        return output

    # ========================================================
    # COLLECT CURRENT METRICS
    # ========================================================

    def collect_metrics(
        self,
        service: str
    ) -> Dict[str, List[Dict[str, Any]]]:

        return {

            "cpu_usage_cores":
                self.extract_results(
                    self.get_cpu_usage(
                        service
                    )
                ),

            "memory_usage_bytes":
                self.extract_results(
                    self.get_memory_usage(
                        service
                    )
                ),

            "pod_restarts_15m":
                self.extract_results(
                    self.get_restarts(
                        service
                    )
                ),

            "cpu_throttling_percentage":
                self.extract_results(
                    self.get_cpu_throttling(
                        service
                    )
                )
        }

    # ========================================================
    # COMPARE CURRENT VALUE WITH BASELINE
    # ========================================================

    def compare_metric(
        self,
        metric_name: str,
        current_value: float,
        baseline_data: Dict[str, Any]
    ) -> Dict[str, Any]:

        mean = baseline_data.get(
            "mean"
        )

        stddev = baseline_data.get(
            "stddev"
        )

        lower_bound = baseline_data.get(
            "lower_bound"
        )

        upper_bound = baseline_data.get(
            "upper_bound"
        )

        # ----------------------------------------------------
        # No usable baseline
        # ----------------------------------------------------

        if (
            mean is None
            or lower_bound is None
            or upper_bound is None
        ):

            return {
                "metric": metric_name,
                "current_value": current_value,
                "baseline_available": False,
                "statistical_deviation": False,
                "degradation_anomaly": False,
                "status": "NO_BASELINE_DATA"
            }

        # ----------------------------------------------------
        # Calculate deviation
        # ----------------------------------------------------

        deviation = (
            current_value - mean
        )

        if stddev is not None and stddev > 0:

            z_score = (
                deviation / stddev
            )

        else:

            z_score = None

        # ----------------------------------------------------
        # RESTARTS
        #
        # Any restart within the observation window is
        # treated as a degradation event.
        # ----------------------------------------------------

        if metric_name == "pod_restarts_15m":

            statistical_deviation = (
                current_value != mean
            )

            degradation_anomaly = (
                current_value > 0
            )

            if degradation_anomaly:

                direction = "restart_detected"

                status = "ANOMALY"

            else:

                direction = "no_restart"

                status = "NORMAL"

            return {
                "metric": metric_name,

                "current_value": current_value,

                "baseline_mean": mean,

                "baseline_stddev": stddev,

                "lower_bound": lower_bound,

                "upper_bound": upper_bound,

                "deviation_from_mean": deviation,

                "z_score": z_score,

                "direction": direction,

                "statistical_deviation":
                    statistical_deviation,

                "degradation_anomaly":
                    degradation_anomaly,

                "anomalous":
                    degradation_anomaly,

                "status": status
            }

        # ----------------------------------------------------
        # STATISTICAL DEVIATION
        #
        # This detects whether the value is unusual.
        # ----------------------------------------------------

        statistical_deviation = (
            current_value < lower_bound
            or current_value > upper_bound
        )

        # ----------------------------------------------------
        # DEGRADATION LOGIC
        #
        # For these resource metrics:
        #
        #   Above upper bound = potential degradation
        #
        #   Below lower bound = unusual, but not necessarily
        #                        degradation.
        # ----------------------------------------------------

        if current_value > upper_bound:

            direction = "above_baseline"

            degradation_anomaly = True

            status = "ANOMALY"

        elif current_value < lower_bound:

            direction = "below_baseline"

            degradation_anomaly = False

            status = "UNUSUAL_LOW"

        else:

            direction = "within_baseline"

            degradation_anomaly = False

            status = "NORMAL"

        return {
            "metric": metric_name,

            "current_value": current_value,

            "baseline_mean": mean,

            "baseline_stddev": stddev,

            "lower_bound": lower_bound,

            "upper_bound": upper_bound,

            "deviation_from_mean": deviation,

            "z_score": z_score,

            "direction": direction,

            "statistical_deviation":
                statistical_deviation,

            "degradation_anomaly":
                degradation_anomaly,

            # Kept for compatibility with the previous
            # Metrics Agent output.
            "anomalous":
                degradation_anomaly,

            "status": status
        }

    # ========================================================
    # DETECT ANOMALIES
    # ========================================================

    def detect_anomalies(
        self,
        service: str,
        current_metrics: Dict[
            str,
            List[Dict[str, Any]]
        ]
    ) -> Dict[str, Any]:

        service_baseline = (
            self.get_service_baseline(
                service
            )
        )

        comparisons = []

        for metric_name, results in (
            current_metrics.items()
        ):

            baseline_data = (
                service_baseline.get(
                    metric_name
                )
            )

            if not baseline_data:
                continue

            for result in results:

                comparison = (
                    self.compare_metric(
                        metric_name,
                        result["value"],
                        baseline_data
                    )
                )

                comparison["pod"] = (
                    result["pod"]
                )

                comparisons.append(
                    comparison
                )

        # ----------------------------------------------------
        # Only degradation anomalies are included here.
        #
        # A low CPU value or low throttling value can be
        # statistically unusual without indicating failure.
        # ----------------------------------------------------

        anomalies = [
            item
            for item in comparisons
            if item.get(
                "degradation_anomaly"
            ) is True
        ]

        statistical_deviations = [
            item
            for item in comparisons
            if item.get(
                "statistical_deviation"
            ) is True
        ]

        return {

            "service": service,

            "comparisons": comparisons,

            "statistical_deviations":
                statistical_deviations,

            "statistical_deviation_count":
                len(
                    statistical_deviations
                ),

            "anomalies": anomalies,

            "anomaly_count":
                len(anomalies),

            "anomaly_detected":
                len(anomalies) > 0
        }

    # ========================================================
    # BUILD STRUCTURED EVIDENCE
    # ========================================================

    def build_evidence(
        self,
        service: str,
        current_metrics: Dict[str, Any],
        anomaly_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:

        baseline_metadata = (
            self.baseline.get(
                "metadata",
                {}
            )
        )

        return {

            "agent": "metrics-agent",

            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "namespace": NAMESPACE,

            "service": service,

            "baseline": {

                "created_at":
                    baseline_metadata.get(
                        "created_at"
                    ),

                "duration_minutes":
                    baseline_metadata.get(
                        "duration_minutes"
                    ),

                "sigma_multiplier":
                    baseline_metadata.get(
                        "sigma_multiplier",
                        SIGMA_MULTIPLIER
                    )
            },

            "current_metrics":
                current_metrics,

            "analysis":
                anomaly_analysis
        }

    # ========================================================
    # OLLAMA ANALYSIS
    # ========================================================

    def analyze_with_ollama(
        self,
        evidence: Dict[str, Any]
    ) -> str:

        prompt = f"""
You are the Metrics Analysis Agent in an
automated Kubernetes Root Cause Analysis system.

Your responsibility is to interpret deterministic
metrics evidence.

IMPORTANT RULES:

1. Do not invent metrics.

2. Do not invent thresholds.

3. Do not change the deterministic anomaly
   classification.

4. A "statistical_deviation" does NOT automatically
   mean a service failure.

5. For CPU, memory and CPU throttling:
   - Above the healthy upper bound is potential
     degradation evidence.
   - Below the healthy lower bound is unusual but
     should NOT be treated as a degradation failure
     by itself.
   - Within the baseline is normal.

6. For pod restarts:
   - A restart count greater than zero is a
     degradation anomaly candidate.

7. Metrics alone cannot establish the root cause.

8. Do not claim a root cause unless the evidence
   explicitly supports it.

Here is the deterministic evidence:

{json.dumps(
    evidence,
    indent=2
)}

Provide a concise analysis with these sections:

1. Overall Metric Status
2. Statistical Deviations
3. Degradation Anomalies
4. Affected Pods
5. RCA Implications

Clearly distinguish between:

- unusual statistical behaviour
- actual degradation evidence

If no degradation anomaly is detected, explicitly
state that the metrics do not currently provide
evidence of metric-based degradation.

Do not recommend a remediation based on metrics alone.
Further evidence from logs, traces and Kubernetes
context may be required.
"""

        response = self.llm.invoke(
            prompt
        )

        return response.content

    # ========================================================
    # MAIN ANALYSIS
    # ========================================================

    def analyze(
        self,
        service: str
    ) -> Dict[str, Any]:

        print(
            f"\nAnalyzing service: {service}"
        )

        print(
            "Collecting current metrics..."
        )

        current_metrics = (
            self.collect_metrics(
                service
            )
        )

        print(
            "Comparing against healthy baseline..."
        )

        anomaly_analysis = (
            self.detect_anomalies(
                service,
                current_metrics
            )
        )

        evidence = self.build_evidence(
            service,
            current_metrics,
            anomaly_analysis
        )

        print(
            "Sending evidence to local Ollama..."
        )

        ollama_analysis = (
            self.analyze_with_ollama(
                evidence
            )
        )

        return {

            "service": service,

            "agent": "metrics-agent",

            "evidence": evidence,

            "ollama_analysis":
                ollama_analysis
        }


# ============================================================
# PRINT RESULT
# ============================================================

def print_result(
    result: Dict[str, Any]
) -> None:

    print("\n")

    print("=" * 70)

    print(
        "METRICS AGENT RESULT"
    )

    print("=" * 70)

    print(
        json.dumps(
            result,
            indent=2
        )
    )

    print("=" * 70)


# ============================================================
# CLI
# ============================================================

def main():

    if len(sys.argv) < 2:

        print(
            "Usage:"
        )

        print(
            "python metrics_agent.py <service>"
        )

        print(
            "\nExample:"
        )

        print(
            "python metrics_agent.py adservice"
        )

        sys.exit(1)

    service = sys.argv[1]

    try:

        agent = MetricsAgent()

        result = agent.analyze(
            service
        )

        print_result(
            result
        )

    except Exception as exc:

        print(
            "\nMetrics Agent ERROR:"
        )

        print(
            str(exc)
        )

        sys.exit(1)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()