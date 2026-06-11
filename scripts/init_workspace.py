#!/usr/bin/env python3
"""Initialize an incremental audit workspace for Attack Rule Auditor v3."""
import argparse, json, datetime, re
from pathlib import Path

TEMPLATES = {
    "00_scope_and_assumptions.md": "# 00 Scope and Assumptions\n\n",
    "01_input_inventory.md": "# 01 Input Inventory\n\n",
    "02_intent_inference.md": "# 02 Intent Inference\n\n",
    "03_attack_scope_candidates.md": "# 03 ATT&CK Scope Candidates\n\n",
    "04_rule_or_code_findings.md": "# 04 Rule or Code Findings\n\n",
    "05_coverage_matrix.md": "# 05 Coverage Matrix\n\n",
    "06_data_pipeline_gaps.md": "# 06 Data Pipeline Gaps\n\n",
    "07_data_components_alignment.md": "# 07 Data Components Alignment\n\n",
    "08_ebpf_kernel_collection.md": "# 08 eBPF / Kernel Collection Review\n\nWrite 不适用 when no eBPF/kernel collector is present.\n",
    "09_rule_format_lint.md": "# 09 Rule Format Lint\n\n",
    "10_comparison.md": "# 10 Comparison\n\nWrite 不适用 for single target audits.\n",
    "11_knowledge_sources_and_confidence.md": "# 11 Knowledge Sources and Audit Confidence\n\n",
    "12_final_report.md": "# 12 Final Report\n\n",
}

def slugify(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s).strip("_") or "audit"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--mode", choices=["single_file","folder","compare_two"], required=True)
    ap.add_argument("--input", required=True, help="Input path or target A path")
    ap.add_argument("--input-b", help="Target B path for compare_two")
    ap.add_argument("--platform", default="Linux,Containers,Network Devices")
    ap.add_argument("--attack-index-version", default="19.1")
    ap.add_argument("--out", default=".audit_runs")
    args = ap.parse_args()
    if args.mode == "compare_two" and not args.input_b:
        raise SystemExit("--input-b is required for compare_two")
    now = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_id = f"audit_{now}_{slugify(args.name)[:32]}"
    run_dir = Path(args.out) / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    for fn, content in TEMPLATES.items():
        (run_dir / fn).write_text(content, encoding="utf-8")
    state = {
        "schema_version": "3.0",
        "run_id": run_id,
        "created_at_utc": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "name": args.name,
        "mode": args.mode,
        "input_a": args.input,
        "input_b": args.input_b,
        "platforms": [p.strip() for p in args.platform.split(',') if p.strip()],
        "attack_index_version": args.attack_index_version,
        "assumptions": [],
        "files": {},
        "findings": [],
        "needs_revalidation": [],
        "audit_confidence": {
            "overall": "unknown",
            "attack_index_basis": 0,
            "code_evidence_basis": 0,
            "field_chain_verified": 0,
            "test_evidence_basis": 0,
            "llm_inference_dependency": 0
        }
    }
    (run_dir / "state.json").write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    with (run_dir / "00_scope_and_assumptions.md").open("a", encoding="utf-8") as f:
        f.write(f"- run_id: `{run_id}`\n")
        f.write(f"- mode: `{args.mode}`\n")
        f.write(f"- input_a: `{args.input}`\n")
        if args.input_b: f.write(f"- input_b: `{args.input_b}`\n")
        f.write(f"- platforms: `{args.platform}`\n")
        f.write(f"- attack_index_version: `{args.attack_index_version}`\n")
        f.write("- 初始假设：采集代码不计入 validated coverage；意图推断只作为 advisory。\n")
    print(str(run_dir))

if __name__ == "__main__":
    main()
