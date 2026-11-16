#!/usr/bin/env python3
"""AutoRemedyRIC - LangGraph workflow (Stage 1).

metrics/logs/traces/k8s (parallel) -> coordinator -> [remediation -> approval -> validation]
All agents are invoked as subprocesses; folders are not renamed.
Python 3.9 compatible.
"""
import argparse
import json
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Dict, Optional

import yaml
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from typing_extensions import TypedDict

ROOT = Path(__file__).resolve().parent
RUNS = ROOT / "runs"
PY = sys.executable
AGENT_TIMEOUT = 600  # seconds; Ollama can be slow

AGENTS = {
    "metrics": "agents/metrics-agent/metrics_agent.py",
    "logs": "agents/log-agent/log_agent.py",
    "traces": "agents/trace-agent/trace_agent.py",
    "k8s": "agents/k8s-agent/k8s_agent.py",
    "coordinator": "agents/coordinator/coordinator.py",
    "remediation": "agents/remediation-agent/remediation_agent.py",
    "validation": "agents/validation-agent/validation_agent.py",
}


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------
def merge_dicts(a: Optional[dict], b: Optional[dict]) -> dict:
    out = dict(a or {})
    out.update(b or {})
    return out


class State(TypedDict, total=False):
    experiment_id: str
    fault_id: str
    service: str
    trace_service: str
    lookback: int
    stop_after_diagnosis: bool
    run_dir: str
    evidence: Annotated[Dict[str, Any], merge_dicts]   # per-agent run summary
    timings: Annotated[Dict[str, float], merge_dicts]  # seconds per stage
    coordinator: Dict[str, Any]
    remediation: Dict[str, Any]
    approved: bool
    approval: Dict[str, Any]
    validation: Dict[str, Any]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def extract_json(text: str) -> Optional[dict]:
    """Find the first JSON object that starts at the beginning of a line.
    Tolerates banners/progress lines before it and trailing text after it."""
    decoder = json.JSONDecoder()
    for m in re.finditer(r"(?m)^\{", text or ""):
        try:
            obj, _ = decoder.raw_decode(text[m.start():])
        except ValueError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def run_cmd(name: str, cmd: list, run_dir: Path) -> Dict[str, Any]:
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=AGENT_TIMEOUT, cwd=str(ROOT))
        rc, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        rc, out, err = -9, "", "TIMEOUT after {}s".format(AGENT_TIMEOUT)
    dur = round(time.time() - t0, 2)

    (run_dir / "{}.stdout.txt".format(name)).write_text(out or "")
    (run_dir / "{}.stderr.txt".format(name)).write_text(err or "")

    data = extract_json(out)
    ok = rc == 0 and data is not None
    return {"ok": ok, "returncode": rc, "duration_s": dur,
            "data": data, "stdout_tail": (out or "")[-500:],
            "stderr_tail": (err or "")[-500:]}


def save_agent_json(name: str, service: str, res: Dict[str, Any],
                    run_dir: Path) -> str:
    """Write cleaned JSON, or an explicit MISSING_EVIDENCE placeholder."""
    path = run_dir / "{}.json".format(name)
    if res["ok"]:
        payload = res["data"]
    else:
        payload = {
            "agent": name, "service": service,
            "status": "MISSING_EVIDENCE",
            "note": "Agent failed or output unparseable. NOT evidence of health.",
            "returncode": res["returncode"],
            "stdout_tail": res["stdout_tail"],
            "stderr_tail": res["stderr_tail"],
            "parsed_partial": res["data"],
        }
    path.write_text(json.dumps(payload, indent=2, default=str))
    return str(path)


def summarise(res: Dict[str, Any], path: str) -> Dict[str, Any]:
    return {"ok": res["ok"], "returncode": res["returncode"],
            "duration_s": res["duration_s"], "file": path}


def safe(d: Any) -> dict:
    return d if isinstance(d, dict) else {}


def extract_coordinator_view(data: dict) -> Dict[str, Any]:
    """Mirrors the Remediation Agent's extraction; keeps both LLM and
    deterministic values so they can be compared in the evaluation."""
    analysis = safe(safe(data.get("ollama_analysis")).get("analysis"))
    det = safe(data.get("deterministic_findings"))
    cands = det.get("deterministic_root_cause_candidates") or []
    return {
        "incident_status": analysis.get("incident_status")
        or det.get("deterministic_incident_status"),
        "root_cause_candidate": analysis.get("root_cause_candidate")
        or (cands[0] if cands else None),
        "confidence": analysis.get("confidence")
        or det.get("deterministic_confidence"),
        "affected_services": analysis.get("affected_services")
        or det.get("affected_services") or [],
        "deterministic_incident_status": det.get("deterministic_incident_status"),
        "deterministic_root_cause_candidates": cands,
        "deterministic_confidence": det.get("deterministic_confidence"),
    }


# --------------------------------------------------------------------------
# Nodes
# --------------------------------------------------------------------------
def init_node(s: State) -> dict:
    run_dir = RUNS / s["experiment_id"]
    run_dir.mkdir(parents=True, exist_ok=True)
    return {"run_dir": str(run_dir),
            "timings": {"t_start": time.time()}}


def make_evidence_node(name: str):
    def node(s: State) -> dict:
        run_dir = Path(s["run_dir"])
        svc = s["service"]
        lookback = str(s["lookback"])
        if name == "metrics":
            cmd = [PY, AGENTS[name], svc]
        elif name == "logs":
            cmd = [PY, AGENTS[name], svc, lookback]
        elif name == "traces":
            svc = s["trace_service"]
            cmd = [PY, AGENTS[name], svc, lookback]
        else:  # k8s
            cmd = [PY, AGENTS[name], svc]
        res = run_cmd(name, cmd, run_dir)
        path = save_agent_json(name, svc, res, run_dir)
        return {"evidence": {name: summarise(res, path)},
                "timings": {name: res["duration_s"]}}
    return node


def coordinator_node(s: State) -> dict:
    run_dir = Path(s["run_dir"])
    ev = s.get("evidence", {})
    if not any(v.get("ok") for v in ev.values()):
        return {"coordinator": {"incident_status": "INSUFFICIENT_EVIDENCE",
                                "note": "All evidence agents failed."}}
    cmd = [PY, AGENTS["coordinator"],
           "--metrics", str(run_dir / "metrics.json"),
           "--logs", str(run_dir / "logs.json"),
           "--trace", str(run_dir / "traces.json"),
           "--k8s", str(run_dir / "k8s.json")]
    res = run_cmd("coordinator", cmd, run_dir)
    if res["ok"]:
        (run_dir / "coordinator.json").write_text(
            json.dumps(res["data"], indent=2, default=str))
        view = extract_coordinator_view(res["data"])
    else:
        view = {"incident_status": "COORDINATOR_FAILED",
                "returncode": res["returncode"],
                "stderr_tail": res["stderr_tail"]}
    view["ok"] = res["ok"]
    view["duration_s"] = res["duration_s"]
    return {"coordinator": view,
            "timings": {"coordinator": res["duration_s"]}}


def route_after_coordinator(s: State) -> str:
    c = s.get("coordinator", {})
    if s.get("stop_after_diagnosis"):
        return END
    return "remediation" if c.get("incident_status") == "CONFIRMED_INCIDENT" else END


def remediation_node(s: State) -> dict:
    run_dir = Path(s["run_dir"])
    cmd = [PY, AGENTS["remediation"],
           "--coordinator", str(run_dir / "coordinator.json"),
           "--k8s", str(run_dir / "k8s.json"),
           "--output", str(run_dir / "remediation.json"),
           "--patch-output", str(run_dir / "remediation-patch.json")]
    res = run_cmd("remediation", cmd, run_dir)
    data = safe(res["data"])
    out = {"ok": res["ok"], "duration_s": res["duration_s"],
           "mode": data.get("mode"),
           "proposed_patch": data.get("proposed_patch"),
           "change_summary": data.get("change_summary"),
           "blockers": safe(data.get("remediation")).get("blockers")}
    return {"remediation": out, "timings": {"remediation": res["duration_s"]}}


def route_after_remediation(s: State) -> str:
    r = s.get("remediation", {})
    return "approval" if r.get("ok") and r.get("proposed_patch") else END


def approval_node(s: State) -> dict:
    # NOTE: no side effects before interrupt(); node re-runs on resume.
    decision = interrupt({
        "message": "Human approval required before deployment.",
        "change_summary": s["remediation"].get("change_summary"),
        "proposed_patch": s["remediation"].get("proposed_patch"),
    })
    d = safe(decision)
    return {"approved": bool(d.get("approved")),
            "approval": {"approved": bool(d.get("approved")),
                         "note": d.get("note"), "decided_at": utc_now(),
                         "decided_epoch": time.time()}}


def route_after_approval(s: State) -> str:
    return "validation" if s.get("approved") else END


def validation_node(s: State) -> dict:
    run_dir = Path(s["run_dir"])
    cmd = [PY, AGENTS["validation"], s["service"], "--wait", "10"]
    res = run_cmd("validation", cmd, run_dir)
    if res["ok"]:
        (run_dir / "validation.json").write_text(
            json.dumps(res["data"], indent=2, default=str))
    data = safe(res["data"])
    v = safe(data.get("validation"))
    out = {"ok": res["ok"], "status": v.get("status") if res["ok"] else "VALIDATION_ERROR",
           "duration_s": res["duration_s"]}
    return {"validation": out, "timings": {"validation": res["duration_s"]}}


# --------------------------------------------------------------------------
# Graph
# --------------------------------------------------------------------------
def build_app():
    g = StateGraph(State)
    g.add_node("init", init_node)
    ev_nodes = ["metrics", "logs", "traces", "k8s"]
    for n in ev_nodes:
        g.add_node(n, make_evidence_node(n))
        g.add_edge("init", n)
    g.add_node("coordinator", coordinator_node)
    g.add_edge(START, "init")
    g.add_edge(ev_nodes, "coordinator")          # waits for all four
    g.add_node("remediation", remediation_node)
    g.add_node("approval", approval_node)
    g.add_node("validation", validation_node)
    g.add_conditional_edges("coordinator", route_after_coordinator,
                            {"remediation": "remediation", END: END})
    g.add_conditional_edges("remediation", route_after_remediation,
                            {"approval": "approval", END: END})
    g.add_conditional_edges("approval", route_after_approval,
                            {"validation": "validation", END: END})
    g.add_edge("validation", END)
    return g.compile(checkpointer=MemorySaver())


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def git_commit() -> Optional[str]:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                              text=True, cwd=str(ROOT)).stdout.strip() or None
    except Exception:
        return None


def main() -> None:
    ap = argparse.ArgumentParser(description="AutoRemedyRIC LangGraph workflow")
    ap.add_argument("--service", help="Target service (e.g. currencyservice)")
    ap.add_argument("--trace-service", help="Service queried in Jaeger (e.g. frontend)")
    ap.add_argument("--fault", help="Fault ID from faults.yaml (e.g. F01)")
    ap.add_argument("--lookback", type=int, default=15)
    ap.add_argument("--stop-after-diagnosis", action="store_true",
                    help="Run evidence agents + coordinator only")
    args = ap.parse_args()

    fault = {}
    if args.fault:
        faults = yaml.safe_load((ROOT / "faults.yaml").read_text())
        fault = faults.get(args.fault, {})
        if not fault:
            sys.exit("Unknown fault id: {}".format(args.fault))

    service = args.service or fault.get("target_service")
    if not service:
        sys.exit("Provide --service or --fault.")
    trace_service = args.trace_service or fault.get("symptom_service") or service

    exp_id = "{}_{}_{}".format(
        datetime.now().strftime("%Y%m%d-%H%M%S"),
        args.fault or "NOFAULT", uuid.uuid4().hex[:6])

    app = build_app()
    cfg = {"configurable": {"thread_id": exp_id}}
    t0 = time.time()

    init = {"experiment_id": exp_id, "fault_id": args.fault or "NONE",
            "service": service, "trace_service": trace_service,
            "lookback": args.lookback,
            "stop_after_diagnosis": args.stop_after_diagnosis}
    print("Experiment {} | service={} trace_service={}".format(
        exp_id, service, trace_service))
    app.invoke(init, cfg)

    # Human approval gate (graph is paused at the approval node)
    snap = app.get_state(cfg)
    if snap.next:
        payload = snap.tasks[0].interrupts[0].value
        print("\n=== HUMAN APPROVAL REQUIRED ===")
        print(json.dumps(payload, indent=2, default=str))
        print("\nGitOps PR step is not built yet. Apply the proposed change "
              "yourself now (stand-in), e.g.:\n"
              "  kubectl scale deployment {} -n default --replicas=1\n".format(service))
        ans = input("Change applied and approved? [y/N]: ").strip().lower()
        note = input("Optional note: ").strip() if ans == "y" else "rejected"
        app.invoke(Command(resume={"approved": ans == "y", "note": note}), cfg)

    final = app.get_state(cfg).values
    summary = {
        "experiment_id": exp_id,
        "fault_id": args.fault or "NONE",
        "ground_truth_root_cause": fault.get("ground_truth_root_cause"),
        "predicted_root_cause": safe(final.get("coordinator")).get("root_cause_candidate"),
        "service": service, "trace_service": trace_service,
        "lookback_minutes": args.lookback,
        "started_at": datetime.fromtimestamp(t0, timezone.utc).isoformat(),
        "total_wall_seconds": round(time.time() - t0, 2),
        "evidence": final.get("evidence"),
        "timings": final.get("timings"),
        "coordinator": final.get("coordinator"),
        "remediation": final.get("remediation"),
        "approval": final.get("approval"),
        "validation": final.get("validation"),
        "git_commit": git_commit(),
        "python": sys.version.split()[0],
    }
    run_dir = Path(final["run_dir"])
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    print("\nDone. Results in {}".format(run_dir))
    print("Coordinator:", json.dumps(summary["coordinator"], default=str))
    print("Validation :", json.dumps(summary["validation"], default=str))


if __name__ == "__main__":
    main()