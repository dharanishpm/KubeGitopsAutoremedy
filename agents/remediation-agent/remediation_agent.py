#!/usr/bin/env python3

"""
AutoRemedyRIC - Remediation Agent V1

Purpose:
    Convert a confirmed Coordinator RCA into a minimal,
    reviewable Kubernetes remediation proposal.

V1 behaviour:
    - Reads Coordinator JSON
    - Reads Kubernetes Agent JSON
    - Verifies RCA confidence
    - Generates a remediation proposal
    - Generates a Kubernetes patch
    - Uses local Ollama for explanation
    - DOES NOT modify the Kubernetes cluster
    - DOES NOT create/merge a GitHub PR

GitOps principle:
    The remediation is represented as a proposed change.
    Human approval / Git PR integration comes later.

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


def normalize_service_name(
    service: Any
) -> Optional[str]:

    if not isinstance(service, str):
        return None

    value = service.strip().lower()

    if not value:
        return None

    return value.replace(
        "_", "-"
    )


def load_json(
    path: str
) -> Dict[str, Any]:

    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(
            "File not found: {}".format(path)
        )

    with file_path.open(
        "r",
        encoding="utf-8"
    ) as file:

        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError(
            "Expected JSON object in {}".format(path)
        )

    return data


# ---------------------------------------------------------------------------
# Coordinator extraction
# ---------------------------------------------------------------------------

def extract_coordinator_result(
    data: Dict[str, Any]
) -> Dict[str, Any]:

    """
    Extract the validated RCA from Coordinator output.

    Expected structure:

        ollama_analysis
            analysis
                incident_status
                root_cause_candidate
                confidence

    Deterministic findings are also retained.
    """

    ollama_analysis = safe_dict(
        data.get("ollama_analysis")
    )

    analysis = safe_dict(
        ollama_analysis.get("analysis")
    )

    deterministic = safe_dict(
        data.get("deterministic_findings")
    )

    # Prefer the validated Ollama result.
    incident_status = analysis.get(
        "incident_status"
    )

    root_cause_candidate = analysis.get(
        "root_cause_candidate"
    )

    confidence = analysis.get(
        "confidence"
    )

    # Fallback to deterministic evidence if required.
    if not incident_status:

        incident_status = deterministic.get(
            "deterministic_incident_status"
        )

    if not root_cause_candidate:

        candidates = safe_list(
            deterministic.get(
                "deterministic_root_cause_candidates"
            )
        )

        if candidates:
            root_cause_candidate = candidates[0]

    if not confidence:

        confidence = deterministic.get(
            "deterministic_confidence"
        )

    affected_services = safe_list(
        analysis.get(
            "affected_services"
        )
    )

    if not affected_services:

        affected_services = safe_list(
            deterministic.get(
                "affected_services"
            )
        )

    supporting_agents = safe_list(
        analysis.get(
            "supporting_agents"
        )
    )

    return {
        "incident_status": incident_status,
        "root_cause_candidate":
            normalize_service_name(
                root_cause_candidate
            ),
        "confidence": confidence,
        "affected_services":
            affected_services,
        "supporting_agents":
            supporting_agents,
        "reasoning":
            safe_list(
                analysis.get(
                    "reasoning"
                )
            ),
        "deterministic_findings":
            deterministic,
    }


# ---------------------------------------------------------------------------
# Kubernetes extraction
# ---------------------------------------------------------------------------

def extract_kubernetes(
    data: Dict[str, Any]
) -> Dict[str, Any]:

    """
    Extract the Kubernetes evidence.

    Supports the current K8s Agent structure.
    """

    # K8s Agent currently stores its evidence at top level.
    evidence = data.get(
        "evidence"
    )

    if isinstance(evidence, dict):
        data = evidence

    deployment = safe_dict(
        data.get("deployment")
    )

    endpoints = safe_dict(
        data.get("endpoints")
    )

    pods = safe_list(
        data.get("pods")
    )

    analysis = safe_dict(
        data.get("analysis")
    )

    service = normalize_service_name(
        data.get("service")
    )

    desired = deployment.get(
        "desired_replicas"
    )

    available = deployment.get(
        "available_replicas"
    )

    ready = deployment.get(
        "ready_replicas"
    )

    ready_endpoints = endpoints.get(
        "ready_count",
        0
    )

    return {
        "service": service,

        "deployment": {
            "found":
                deployment.get(
                    "found"
                ),
            "desired_replicas":
                desired,
            "available_replicas":
                available,
            "ready_replicas":
                ready,
            "updated_replicas":
                deployment.get(
                    "updated_replicas"
                ),
            "unavailable_replicas":
                deployment.get(
                    "unavailable_replicas"
                ),
        },

        "pods": pods,

        "endpoints": {
            "found":
                endpoints.get(
                    "found"
                ),
            "ready_count":
                ready_endpoints,
            "not_ready_count":
                endpoints.get(
                    "not_ready_count",
                    0
                ),
        },

        "analysis": analysis,

        "status":
            data.get(
                "analysis",
                {}
            ).get(
                "status"
            )
            if isinstance(
                data.get("analysis"),
                dict
            )
            else None,
    }


# ---------------------------------------------------------------------------
# Remediation decision
# ---------------------------------------------------------------------------

def determine_remediation(
    coordinator: Dict[str, Any],
    kubernetes: Dict[str, Any]
) -> Dict[str, Any]:

    incident_status = coordinator.get(
        "incident_status"
    )

    confidence = coordinator.get(
        "confidence"
    )

    root_cause = normalize_service_name(
        coordinator.get(
            "root_cause_candidate"
        )
    )

    k8s_service = normalize_service_name(
        kubernetes.get(
            "service"
        )
    )

    deployment = safe_dict(
        kubernetes.get(
            "deployment"
        )
    )

    desired_replicas = deployment.get(
        "desired_replicas"
    )

    ready_replicas = deployment.get(
        "ready_replicas"
    )

    ready_endpoints = safe_dict(
        kubernetes.get(
            "endpoints"
        )
    ).get(
        "ready_count",
        0
    )

    reasons: List[str] = []
    blockers: List[str] = []

    # ---------------------------------------------------------------
    # Safety checks
    # ---------------------------------------------------------------

    if incident_status != "CONFIRMED_INCIDENT":

        blockers.append(
            "Coordinator did not classify the incident as "
            "CONFIRMED_INCIDENT."
        )

    if confidence not in [
        "HIGH",
        "MEDIUM",
    ]:

        blockers.append(
            "Coordinator confidence is not sufficient "
            "for an automatic remediation proposal."
        )

    if not root_cause:

        blockers.append(
            "No root-cause candidate was provided."
        )

    if not k8s_service:

        blockers.append(
            "Kubernetes service name is unavailable."
        )

    if (
        root_cause
        and k8s_service
        and root_cause != k8s_service
    ):

        blockers.append(
            "Coordinator root-cause candidate '{}' does not "
            "match Kubernetes service '{}'."
            .format(
                root_cause,
                k8s_service
            )
        )

    # ---------------------------------------------------------------
    # F01 / unavailable-service remediation
    # ---------------------------------------------------------------

    service_unavailable = (
        isinstance(
            desired_replicas,
            (int, float)
        )
        and desired_replicas == 0
    ) or (
        isinstance(
            ready_replicas,
            (int, float)
        )
        and ready_replicas == 0
    ) or (
        isinstance(
            ready_endpoints,
            (int, float)
        )
        and ready_endpoints == 0
    )

    if service_unavailable:

        reasons.append(
            "The root-cause candidate is currently unavailable "
            "according to Kubernetes."
        )

    else:

        reasons.append(
            "The root-cause candidate currently has available "
            "Kubernetes resources; no availability remediation "
            "is required."
        )

    # ---------------------------------------------------------------
    # Proposal
    # ---------------------------------------------------------------

    proposal_allowed = (
        len(blockers) == 0
        and service_unavailable
    )

    if proposal_allowed:

        target_replicas = 1

        action = "RESTORE_REPLICAS"

        description = (
            "Restore the {} deployment to {} replica."
            .format(
                root_cause,
                target_replicas
            )
        )

        reasons.append(
            "Setting the deployment to one replica is the "
            "minimal change required to restore service availability "
            "for this controlled fault scenario."
        )

    else:

        target_replicas = None

        action = "NO_REMEDIATION_PROPOSAL"

        description = (
            "No remediation proposal generated."
        )

    return {
        "proposal_allowed":
            proposal_allowed,

        "action":
            action,

        "service":
            root_cause,

        "current_replicas":
            desired_replicas,

        "target_replicas":
            target_replicas,

        "description":
            description,

        "reasons":
            reasons,

        "blockers":
            blockers,
    }


# ---------------------------------------------------------------------------
# Kubernetes patch generation
# ---------------------------------------------------------------------------

def generate_patch(
    remediation: Dict[str, Any]
) -> Optional[Dict[str, Any]]:

    if not remediation.get(
        "proposal_allowed"
    ):
        return None

    service = remediation.get(
        "service"
    )

    target_replicas = remediation.get(
        "target_replicas"
    )

    if not service:
        return None

    if target_replicas is None:
        return None

    patch = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": service
        },
        "spec": {
            "replicas": target_replicas
        }
    }

    return patch


# ---------------------------------------------------------------------------
# Human-readable change
# ---------------------------------------------------------------------------

def generate_change_summary(
    remediation: Dict[str, Any]
) -> Dict[str, Any]:

    if not remediation.get(
        "proposal_allowed"
    ):

        return {
            "change_required": False,
            "summary":
                "No safe remediation proposal was generated."
        }

    service = remediation.get(
        "service"
    )

    current = remediation.get(
        "current_replicas"
    )

    target = remediation.get(
        "target_replicas"
    )

    return {
        "change_required": True,

        "resource":
            "Deployment/{}".format(
                service
            ),

        "field":
            "spec.replicas",

        "current_value":
            current,

        "proposed_value":
            target,

        "summary":
            "Change Deployment/{} spec.replicas from {} to {}."
            .format(
                service,
                current,
                target
            ),

        "expected_effect":
            "Restore at least one running replica so the "
            "Kubernetes Service can provide a ready endpoint."
    }


# ---------------------------------------------------------------------------
# Ollama explanation
# ---------------------------------------------------------------------------

def ask_ollama(
    coordinator: Dict[str, Any],
    kubernetes: Dict[str, Any],
    remediation: Dict[str, Any],
    change_summary: Dict[str, Any],
) -> Dict[str, Any]:

    evidence = {
        "coordinator": {
            "incident_status":
                coordinator.get(
                    "incident_status"
                ),

            "root_cause_candidate":
                coordinator.get(
                    "root_cause_candidate"
                ),

            "confidence":
                coordinator.get(
                    "confidence"
                ),

            "supporting_agents":
                coordinator.get(
                    "supporting_agents"
                ),
        },

        "kubernetes": kubernetes,

        "remediation_proposal":
            remediation,

        "change_summary":
            change_summary,
    }

    prompt = """
You are the Remediation Agent in a GitOps-compliant
Kubernetes root-cause-analysis system.

Your task is to explain the proposed remediation.

IMPORTANT RULES:

1. Use ONLY the supplied deterministic evidence.
2. Never invent configuration, replicas, services, errors,
   metrics, or causes.
3. Do not perform the remediation.
4. Do not claim that a change was applied.
5. The proposed change must be minimal.
6. If the proposal is blocked, clearly state why.
7. Human approval is required before applying the change.
8. For the current controlled F01 scenario, restoring one
   currencyservice replica is acceptable because the evidence
   shows the service has zero replicas/endpoints and the
   Coordinator identified currencyservice as the root-cause
   candidate.
9. Distinguish proposed change from applied change.

Return ONLY JSON:

{
  "summary": "brief explanation",
  "evidence": [
    "factual evidence"
  ],
  "proposed_change": [
    "description of proposed change"
  ],
  "safety": [
    "safety considerations"
  ],
  "limitations": [
    "limitations"
  ]
}
"""

    payload = {
        "model": OLLAMA_MODEL,

        "prompt":
            prompt
            + "\n\nDeterministic evidence:\n"
            + json.dumps(
                evidence,
                indent=2,
                default=str
            ),

        "stream": False,

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

        body = response.json()

        raw = body.get(
            "response",
            ""
        )

        try:

            parsed = json.loads(
                raw
            )

            if not isinstance(
                parsed,
                dict
            ):

                raise ValueError(
                    "Ollama returned non-object JSON."
                )

            return {
                "available": True,
                "parsed": True,
                "analysis": parsed,
                "raw_response": raw,
            }

        except Exception as exc:

            return {
                "available": True,
                "parsed": False,
                "raw_response": raw,
                "parse_error": str(exc),
            }

    except Exception as exc:

        return {
            "available": False,
            "parsed": False,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Complete Remediation Agent
# ---------------------------------------------------------------------------

def run_remediation(
    coordinator_path: str,
    k8s_path: str
) -> Dict[str, Any]:

    coordinator_raw = load_json(
        coordinator_path
    )

    k8s_raw = load_json(
        k8s_path
    )

    # ---------------------------------------------------------------
    # Extract evidence
    # ---------------------------------------------------------------

    coordinator = extract_coordinator_result(
        coordinator_raw
    )

    kubernetes = extract_kubernetes(
        k8s_raw
    )

    # ---------------------------------------------------------------
    # Determine remediation
    # ---------------------------------------------------------------

    remediation = determine_remediation(
        coordinator,
        kubernetes
    )

    # ---------------------------------------------------------------
    # Generate patch
    # ---------------------------------------------------------------

    patch = generate_patch(
        remediation
    )

    # ---------------------------------------------------------------
    # Generate change summary
    # ---------------------------------------------------------------

    change_summary = generate_change_summary(
        remediation
    )

    # ---------------------------------------------------------------
    # Ask Ollama for explanation
    # ---------------------------------------------------------------

    ollama = ask_ollama(
        coordinator,
        kubernetes,
        remediation,
        change_summary
    )

    # ---------------------------------------------------------------
    # Final output
    # ---------------------------------------------------------------

    return {
        "version": "V1",

        "agent": "remediation-agent",

        "timestamp": utc_now(),

        "mode": "PROPOSAL_ONLY",

        "cluster_modified": False,

        "git_changes_applied": False,

        "github_pr_created": False,

        "coordinator": coordinator,

        "kubernetes": kubernetes,

        "remediation": remediation,

        "change_summary": change_summary,

        "proposed_patch": patch,

        "ollama_analysis": ollama,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "AutoRemedyRIC Remediation Agent V1"
        )
    )

    parser.add_argument(
        "--coordinator",
        required=True,
        help="Coordinator JSON output"
    )

    parser.add_argument(
        "--k8s",
        required=True,
        help="Kubernetes Agent JSON output"
    )

    parser.add_argument(
        "--output",
        default="remediation.json",
        help="Remediation output JSON"
    )

    parser.add_argument(
        "--patch-output",
        default="remediation-patch.json",
        help="Proposed Kubernetes patch"
    )

    args = parser.parse_args()

    try:

        result = run_remediation(
            coordinator_path=args.coordinator,
            k8s_path=args.k8s,
        )

        # -----------------------------------------------------------
        # Save complete result
        # -----------------------------------------------------------

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

        # -----------------------------------------------------------
        # Save patch only if proposal exists
        # -----------------------------------------------------------

        patch = result.get(
            "proposed_patch"
        )

        if patch:

            patch_path = Path(
                args.patch_output
            )

            with patch_path.open(
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    patch,
                    file,
                    indent=2,
                    ensure_ascii=False
                )

        # -----------------------------------------------------------
        # Print result
        # -----------------------------------------------------------

        print(
            json.dumps(
                result,
                indent=2,
                ensure_ascii=False,
                default=str
            )
        )

        print(
            "\nRemediation result written to: {}".format(
                output_path
            ),
            file=sys.stderr
        )

        if patch:

            print(
                "Proposed patch written to: {}".format(
                    args.patch_output
                ),
                file=sys.stderr
            )

    except Exception as exc:

        print(
            "Remediation Agent failed: {}".format(
                exc
            ),
            file=sys.stderr
        )

        sys.exit(1)


if __name__ == "__main__":
    main()