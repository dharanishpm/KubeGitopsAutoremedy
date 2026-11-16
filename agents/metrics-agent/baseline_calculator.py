import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Any

import requests


PROMETHEUS_URL = "http://localhost:9090"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BASELINE_FILE = os.path.join(BASE_DIR, "baseline.json")

# Healthy observation window
BASELINE_DURATION_MINUTES = 30

# Collect one sample every 30 seconds
PROMETHEUS_STEP_SECONDS = 30

# Statistical threshold
SIGMA_MULTIPLIER = 3


# Online Boutique services
SERVICES = [
    "adservice",
    "cartservice",
    "checkoutservice",
    "currencyservice",
    "emailservice",
    "frontend",
    "paymentservice",
    "productcatalogservice",
    "recommendationservice",
    "shippingservice",
]


class PrometheusClient:
    def __init__(self, url: str):
        self.url = url.rstrip("/")

    def query_range(
        self,
        query: str,
        start: float,
        end: float,
        step: int
    ) -> List[Dict[str, Any]]:

        response = requests.get(
            f"{self.url}/api/v1/query_range",
            params={
                "query": query,
                "start": start,
                "end": end,
                "step": step,
            },
            timeout=30,
        )

        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            raise RuntimeError(
                f"Prometheus query failed: {data}"
            )

        return data["data"]["result"]


def calculate_statistics(values: List[float]) -> Dict[str, Any]:
    """
    Calculate statistical baseline for one metric.

    Uses:
        mean
        standard deviation
        lower bound = mean - 3*std
        upper bound = mean + 3*std
    """

    if not values:
        return {
            "sample_count": 0,
            "mean": None,
            "stddev": None,
            "lower_bound": None,
            "upper_bound": None,
        }

    mean = sum(values) / len(values)

    if len(values) > 1:
        variance = sum(
            (value - mean) ** 2
            for value in values
        ) / (len(values) - 1)

        stddev = variance ** 0.5
    else:
        stddev = 0.0

    lower_bound = max(
        0.0,
        mean - SIGMA_MULTIPLIER * stddev
    )

    upper_bound = (
        mean + SIGMA_MULTIPLIER * stddev
    )

    return {
        "sample_count": len(values),
        "mean": mean,
        "stddev": stddev,
        "lower_bound": lower_bound,
        "upper_bound": upper_bound,
    }


class BaselineCalculator:

    def __init__(
        self,
        prometheus_url: str = PROMETHEUS_URL
    ):
        self.prometheus = PrometheusClient(
            prometheus_url
        )

    def get_cpu_query(self, service: str) -> str:
        return f"""
        sum(
            rate(
                container_cpu_usage_seconds_total{{
                    namespace="default",
                    pod=~"{service}.*"
                }}[5m]
            )
        )
        """

    def get_memory_query(self, service: str) -> str:
        return f"""
        sum(
            container_memory_working_set_bytes{{
                namespace="default",
                pod=~"{service}.*"
            }}
        )
        """

    def get_restart_query(self, service: str) -> str:
        return f"""
        sum(
            kube_pod_container_status_restarts_total{{
                namespace="default",
                pod=~"{service}.*"
            }}
        )
        """

    def get_throttling_query(self, service: str) -> str:
        return f"""
        100 *
        sum(
            rate(
                container_cpu_cfs_throttled_periods_total{{
                    namespace="default",
                    pod=~"{service}.*"
                }}[5m]
            )
        )
        /
        clamp_min(
            sum(
                rate(
                    container_cpu_cfs_periods_total{{
                        namespace="default",
                        pod=~"{service}.*"
                    }}[5m]
                )
            ),
            1
        )
        """

    def collect_metric(
        self,
        query: str,
        start: float,
        end: float
    ) -> List[float]:

        results = self.prometheus.query_range(
            query=query,
            start=start,
            end=end,
            step=PROMETHEUS_STEP_SECONDS,
        )

        values = []

        for result in results:

            for sample in result.get("values", []):

                try:
                    value = float(sample[1])
                    values.append(value)
                except (ValueError, TypeError):
                    continue

        return values

    def calculate_service_baseline(
        self,
        service: str,
        start: float,
        end: float
    ) -> Dict[str, Any]:

        print(
            f"\nCalculating baseline for: {service}"
        )

        cpu_values = self.collect_metric(
            self.get_cpu_query(service),
            start,
            end,
        )

        memory_values = self.collect_metric(
            self.get_memory_query(service),
            start,
            end,
        )

        restart_values = self.collect_metric(
            self.get_restart_query(service),
            start,
            end,
        )

        throttling_values = self.collect_metric(
            self.get_throttling_query(service),
            start,
            end,
        )

        print(
            f"  CPU samples: {len(cpu_values)}"
        )

        print(
            f"  Memory samples: {len(memory_values)}"
        )

        print(
            f"  Restart samples: {len(restart_values)}"
        )

        print(
            f"  Throttling samples: "
            f"{len(throttling_values)}"
        )

        return {
            "cpu_usage_cores": calculate_statistics(
                cpu_values
            ),

            "memory_usage_bytes": calculate_statistics(
                memory_values
            ),

            "pod_restarts": calculate_statistics(
                restart_values
            ),

            "cpu_throttling_percentage": calculate_statistics(
                throttling_values
            ),
        }

    def build_baseline(
        self,
        duration_minutes: int = BASELINE_DURATION_MINUTES
    ) -> Dict[str, Any]:

        end = time.time()

        start = (
            end -
            duration_minutes * 60
        )

        start_datetime = datetime.fromtimestamp(
            start,
            tz=timezone.utc
        ).isoformat()

        end_datetime = datetime.fromtimestamp(
            end,
            tz=timezone.utc
        ).isoformat()

        print("=" * 60)
        print("AutoRemedy - Healthy Baseline Calculator")
        print("=" * 60)

        print(
            f"\nObservation window: "
            f"{duration_minutes} minutes"
        )

        print(
            f"Start: {start_datetime}"
        )

        print(
            f"End:   {end_datetime}"
        )

        print(
            "\nCollecting healthy telemetry..."
        )

        baseline = {
            "metadata": {
                "created_at": datetime.now(
                    timezone.utc
                ).isoformat(),

                "duration_minutes":
                    duration_minutes,

                "step_seconds":
                    PROMETHEUS_STEP_SECONDS,

                "sigma_multiplier":
                    SIGMA_MULTIPLIER,

                "namespace": "default",

                "services": SERVICES,
            },

            "services": {},
        }

        for service in SERVICES:

            try:

                service_baseline = (
                    self.calculate_service_baseline(
                        service,
                        start,
                        end,
                    )
                )

                baseline["services"][service] = (
                    service_baseline
                )

            except Exception as exc:

                print(
                    f"  ERROR: Could not calculate "
                    f"baseline for {service}: {exc}"
                )

                baseline["services"][service] = {
                    "error": str(exc)
                }

        self.save_baseline(baseline)

        return baseline

    def save_baseline(
        self,
        baseline: Dict[str, Any]
    ) -> None:

        with open(
            BASELINE_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                baseline,
                file,
                indent=2
            )

        print(
            "\nBaseline saved to:"
        )

        print(
            BASELINE_FILE
        )


def main():

    calculator = BaselineCalculator()

    duration = BASELINE_DURATION_MINUTES

    if len(sys.argv) > 1:

        try:
            duration = int(sys.argv[1])

        except ValueError:

            print(
                "Usage:"
            )

            print(
                "python baseline_calculator.py [minutes]"
            )

            sys.exit(1)

    calculator.build_baseline(
        duration_minutes=duration
    )


if __name__ == "__main__":
    main()