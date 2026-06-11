#!/usr/bin/env python3
from __future__ import annotations
"""Run the engineering regression suite for the active skill package."""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "attack_data" / "config" / "default_audit_config.json"


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def run(cmd: list[str], timeout: int = 180) -> dict[str, Any]:
    started = time.time()
    try:
        p = subprocess.run([sys.executable] + cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return {
            "cmd": " ".join([sys.executable] + cmd),
            "returncode": p.returncode,
            "stdout": p.stdout.strip(),
            "stderr": p.stderr.strip(),
            "duration_seconds": round(time.time() - started, 3),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "cmd": " ".join([sys.executable] + cmd),
            "returncode": 124,
            "stdout": (exc.stdout or "").strip() if isinstance(exc.stdout, str) else "",
            "stderr": "timeout",
            "duration_seconds": round(time.time() - started, 3),
        }


def main() -> None:
    ap = argparse.ArgumentParser(description="Run compile, manifest, smoke, scope, depth, quality, lint, and package checks.")
    ap.add_argument("--config", default=str(DEFAULT_CONFIG))
    ap.add_argument("--run-id", default="engineering_verify_smoke")
    ap.add_argument("--skip-smoke", action="store_true")
    ap.add_argument("--output-json", default="laji/attack_data/reports/engineering_verify_summary.json")
    args = ap.parse_args()

    cfg = load_json(Path(args.config))
    verify_cfg = cfg.get("verification", {})
    report_root = verify_cfg.get("report_output_root", "laji/attack_data/reports")
    smoke_input = verify_cfg.get("smoke_input", "laji/test_inputs")
    smoke_scenario = verify_cfg.get("smoke_scenario", "container_escape")
    smoke_output_root = verify_cfg.get("smoke_output_root", "laji/.audit_runs")
    platform = (cfg.get("scope") or {}).get("platform", "Linux,Containers,Network Devices")
    index = (cfg.get("scope") or {}).get("attack_index", "attack_data/index")
    scope_file = (cfg.get("scope") or {}).get("scope_file", "attack_data/index/linux_container_network_scope.jsonl")
    scenario_model = (cfg.get("scope") or {}).get("scenario_model", "attack_data/models/scenario_attack_model.json")

    scripts = [str(p) for p in sorted((ROOT / "scripts").glob("*.py"))]
    results: dict[str, Any] = {}
    results["py_compile"] = run(["-m", "py_compile", *scripts], timeout=180)
    results["script_dependency_check"] = run(["scripts/script_dependency_check.py"], timeout=60)
    results["cache_status"] = run(["scripts/cache_status.py"], timeout=60)
    if not args.skip_smoke:
        results["smoke_audit"] = run([
            "scripts/audit.py",
            "--input", smoke_input,
            "--mode", "folder",
            "--platform", platform,
            "--scenario", smoke_scenario,
            "--index", index,
            "--output-root", smoke_output_root,
            "--run-id", args.run_id,
        ], timeout=240)
    results["scope_lock"] = run([
        "scripts/build_scope_lock.py",
        "--scope", scope_file,
        "--lookup", str(Path(index) / "lookup_by_id.json"),
        "--metadata", str(Path(index) / "metadata.json"),
        "--scenario-model", scenario_model,
        "--output-json", str(Path(report_root) / "scope_lock_verify.json"),
        "--output-md", str(Path(report_root) / "scope_lock_verify.md"),
    ], timeout=120)
    results["depth_gap"] = run([
        "scripts/build_depth_gap_backlog.py",
        "--scope", scope_file,
        "--lookup", str(Path(index) / "lookup_by_id.json"),
        "--scenario-model", scenario_model,
        "--output-dir", str(Path(report_root) / "depth_gap_verify"),
    ], timeout=120)
    results["quality"] = run([
        "scripts/analyze_quality_strict.py",
        "--scenario-model", scenario_model,
        "--scope", scope_file,
        "--output-dir", str(Path(report_root) / "quality_verify"),
    ], timeout=120)
    results["scenario_model_lint"] = run([
        "scripts/scenario_model_lint.py",
        "--scenario-model", scenario_model,
        "--index", index,
        "--platform", platform,
        "--output-jsonl", str(Path(report_root) / "scenario_model_lint_verify.jsonl"),
        "--output-summary", str(Path(report_root) / "scenario_model_lint_verify_summary.json"),
    ], timeout=120)
    results["scenario_attack_id_health"] = run([
        "scripts/scenario_attack_id_health.py",
        "--scenario-model", scenario_model,
        "--index", index,
        "--platform", platform,
        "--output-jsonl", str(Path(report_root) / "scenario_attack_id_health_verify.jsonl"),
        "--output-summary", str(Path(report_root) / "scenario_attack_id_health_verify_summary.json"),
    ], timeout=120)
    results["subtechnique_resolver"] = run([
        "scripts/subtechnique_resolver.py",
        "--scenario-model", scenario_model,
        "--index", index,
        "--platform", platform,
        "--output-jsonl", str(Path(report_root) / "subtechnique_resolution_verify.jsonl"),
        "--output-md", str(Path(report_root) / "subtechnique_resolution_verify.md"),
    ], timeout=120)
    results["clean_runtime_cache"] = run(["scripts/clean_runtime_cache.py"], timeout=60)
    results["package_check"] = run(["scripts/package_check.py"], timeout=60)

    failed = {name: res for name, res in results.items() if res.get("returncode") != 0}
    summary = {
        "status": "pass" if not failed else "fail",
        "failed_checks": sorted(failed),
        "results": results,
    }
    out = ROOT / args.output_json
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": summary["status"], "failed_checks": summary["failed_checks"], "output_json": str(out)}, ensure_ascii=False))
    raise SystemExit(0 if not failed else 1)


if __name__ == "__main__":
    main()
