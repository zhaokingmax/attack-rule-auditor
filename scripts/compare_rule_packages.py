#!/usr/bin/env python3
from __future__ import annotations
"""Formal A/B entry point for comparing two rule packages or two completed audit runs."""

import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str], timeout: int = 180) -> dict:
    p = subprocess.run([sys.executable] + cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    return {"cmd": " ".join([sys.executable] + cmd), "returncode": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare two rule packages by running audits or comparing existing run directories.")
    ap.add_argument("--a-input")
    ap.add_argument("--b-input")
    ap.add_argument("--a-run")
    ap.add_argument("--b-run")
    ap.add_argument("--scenario", default="container_escape")
    ap.add_argument("--platform", default="Linux,Containers,Network Devices")
    ap.add_argument("--output-root", default="laji/.audit_runs")
    ap.add_argument("--run-id-prefix", default="ab_compare")
    ap.add_argument("--output-json", default="laji/attack_data/reports/ab_rule_package_comparison.json")
    ap.add_argument("--output-md", default="laji/attack_data/reports/ab_rule_package_comparison.md")
    args = ap.parse_args()

    a_run = args.a_run
    b_run = args.b_run
    commands = []
    if not a_run:
        if not args.a_input:
            raise SystemExit("--a-input or --a-run is required")
        a_run_id = f"{args.run_id_prefix}_a"
        res = run(["scripts/audit.py", "--input", args.a_input, "--mode", "folder", "--platform", args.platform, "--scenario", args.scenario, "--output-root", args.output_root, "--run-id", a_run_id])
        commands.append(res)
        if res["returncode"] != 0:
            raise SystemExit(json.dumps(res, ensure_ascii=False))
        a_run = str(Path(args.output_root) / a_run_id)
    if not b_run:
        if not args.b_input:
            raise SystemExit("--b-input or --b-run is required")
        b_run_id = f"{args.run_id_prefix}_b"
        res = run(["scripts/audit.py", "--input", args.b_input, "--mode", "folder", "--platform", args.platform, "--scenario", args.scenario, "--output-root", args.output_root, "--run-id", b_run_id])
        commands.append(res)
        if res["returncode"] != 0:
            raise SystemExit(json.dumps(res, ensure_ascii=False))
        b_run = str(Path(args.output_root) / b_run_id)

    res = run(["scripts/ab_resilience_compare.py", "--a-run", a_run, "--b-run", b_run, "--output-json", args.output_json, "--output-md", args.output_md])
    commands.append(res)
    print(json.dumps({"a_run": a_run, "b_run": b_run, "comparison_returncode": res["returncode"], "commands": commands}, ensure_ascii=False, indent=2))
    raise SystemExit(res["returncode"])


if __name__ == "__main__":
    main()
