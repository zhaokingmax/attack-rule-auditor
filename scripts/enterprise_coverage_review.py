#!/usr/bin/env python3
from __future__ import annotations
"""Summarize current scenario-model coverage against the local Enterprise ATT&CK index."""

import argparse
import json
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def model_scenarios(model: dict[str, Any]):
    for name, scenario in model.items():
        if name.startswith("_") or not isinstance(scenario, dict):
            continue
        yield name, scenario


def collect_model_ids(model: dict[str, Any]) -> tuple[dict[str, list[dict[str, str]]], dict[str, list[dict[str, str]]], set[str]]:
    behavior: dict[str, list[dict[str, str]]] = defaultdict(list)
    bypass: dict[str, list[dict[str, str]]] = defaultdict(list)
    referenced: set[str] = set()
    for scenario_name, scenario in model_scenarios(model):
        for key in ["must_cover_attack_ids", "should_cover_attack_ids"]:
            for tid in scenario.get(key, []) or []:
                referenced.add(str(tid).upper())
        for primitive in scenario.get("behavior_primitives", []) or []:
            for tid in primitive.get("attack_ids", []) or []:
                tid = str(tid).upper()
                referenced.add(tid)
                behavior[tid].append({"scenario": scenario_name, "primitive": primitive.get("id", "")})
        for primitive in scenario.get("bypass_primitives", []) or []:
            for tid in primitive.get("attack_ids", []) or []:
                tid = str(tid).upper()
                referenced.add(tid)
                bypass[tid].append({"scenario": scenario_name, "primitive": primitive.get("id", "")})
    return behavior, bypass, referenced


def tactic_counts(ids: set[str], lookup: dict[str, Any]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for tid in ids:
        for tactic in lookup.get(tid, {}).get("tactics", []) or []:
            counts[tactic] += 1
    return counts


def platform_counts(ids: set[str], lookup: dict[str, Any]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for tid in ids:
        for platform in lookup.get(tid, {}).get("platforms", []) or []:
            counts[platform] += 1
    return counts


def build_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Enterprise ATT&CK Coverage Review",
        "",
        f"- attack_version: `{summary['attack_version']}`",
        f"- collection_modified: `{summary['collection_modified']}`",
        f"- coverage_model_version: `{summary['coverage_model_version']}`",
        f"- quality_enrichment_version: `{summary.get('quality_enrichment_version') or 'N/A'}`",
        "",
        "## Coverage",
        "",
        f"- Enterprise active attack-patterns: `{summary['enterprise_active_attack_pattern_count']}`",
        f"- Full Enterprise direct behavior coverage: `{summary['full_enterprise_direct_behavior_count']}/{summary['enterprise_active_attack_pattern_count']}` (`{summary['full_enterprise_direct_behavior_rate']:.1%}`)",
        f"- Linux/Containers scope: `{summary['linux_container_scope_count']}`",
        f"- Linux/Containers direct behavior coverage: `{summary['linux_container_direct_behavior_count']}/{summary['linux_container_scope_count']}` (`{summary['linux_container_direct_behavior_rate']:.1%}`)",
        f"- Linux/Containers L4 depth coverage: `{summary['linux_container_l4_deep_model_count']}/{summary['linux_container_scope_count']}`",
        f"- Supported-scope strict HIGH quality: `{summary['linux_container_quality_high_count']}/{summary['linux_container_network_scope_count']}`",
        f"- Linux/Containers/Kubernetes/Network Devices scope: `{summary['linux_container_network_scope_count']}`",
        f"- Linux/Containers/Kubernetes/Network Devices direct behavior coverage: `{summary['linux_container_network_direct_behavior_count']}/{summary['linux_container_network_scope_count']}` (`{summary['linux_container_network_direct_behavior_rate']:.1%}`)",
        f"- Network Devices direct behavior gaps: `{summary['network_device_direct_gap_count']}`",
        f"- Non-Linux/Containers active techniques not modeled by behavior primitive: `{summary['non_linux_container_unmodeled_active_count']}`",
        "",
        "## Interpretation",
        "",
        "This skill is scoped to Linux, Containers, Kubernetes scenarios, and Network Devices. It intentionally does not claim full Enterprise ATT&CK coverage. Full Enterprise coverage would still require additional platform packs for Windows, macOS-only, SaaS, IaaS, Identity Provider, Office Suite, PRE, and ESXi-specific techniques.",
        "",
        "## Full Enterprise Uncovered By Tactic",
        "",
        "| Tactic | Uncovered active techniques |",
        "|---|---:|",
    ]
    for tactic, count in summary["full_enterprise_uncovered_by_tactic"]:
        lines.append(f"| {tactic} | {count} |")
    lines += [
        "",
        "## Non-Linux/Containers Uncovered By Platform",
        "",
        "| Platform | Uncovered active techniques |",
        "|---|---:|",
    ]
    for platform, count in summary["non_linux_container_uncovered_by_platform"]:
        lines.append(f"| {platform} | {count} |")
    lines += [
        "",
        "## Network Device Direct Gaps",
        "",
        "| ATT&CK ID | Name | Tactics |",
        "|---|---|---|",
    ]
    for row in summary["network_device_direct_gaps"]:
        lines.append(f"| {row['technique_id']} | {row['name']} | {', '.join(row.get('tactics', []))} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Review scenario model coverage against Enterprise ATT&CK.")
    ap.add_argument("--index", default=str(ROOT / "attack_data" / "index"))
    ap.add_argument("--model", default=str(ROOT / "attack_data" / "models" / "scenario_attack_model.json"))
    ap.add_argument("--depth-summary", default=str(ROOT / "laji" / "attack_data" / "reports" / "depth_gap_summary.json"))
    ap.add_argument("--quality-summary", default=str(ROOT / "laji" / "attack_data" / "reports" / "quality_distribution_summary.json"))
    ap.add_argument("--output-json", default=str(ROOT / "laji" / "attack_data" / "reports" / "enterprise_coverage_review.json"))
    ap.add_argument("--output-md", default=str(ROOT / "laji" / "attack_data" / "reports" / "enterprise_coverage_review.md"))
    args = ap.parse_args()

    index = Path(args.index)
    lookup = read_json(index / "lookup_by_id.json")
    metadata = read_json(index / "metadata.json")
    scope_rows = read_jsonl(index / "linux_container_scope.jsonl")
    scope_ids = {str(row.get("technique_id") or row.get("attack_id") or row.get("id")).upper() for row in scope_rows}
    network_ids = {tid for tid, rec in lookup.items() if "Network Devices" in rec.get("platforms", [])}
    lc_network_ids = scope_ids | network_ids
    model = read_json(Path(args.model))
    depth = read_json(Path(args.depth_summary)) if Path(args.depth_summary).exists() else {}
    quality = read_json(Path(args.quality_summary)) if Path(args.quality_summary).exists() else {}
    behavior, bypass, referenced = collect_model_ids(model)

    active_ids = set(lookup)
    behavior_active = set(behavior) & active_ids
    bypass_active = set(bypass) & active_ids
    referenced_active = referenced & active_ids
    non_lc_ids = active_ids - scope_ids
    full_uncovered = active_ids - behavior_active
    non_lc_uncovered = non_lc_ids - behavior_active
    network_gaps = sorted(network_ids - behavior_active)
    lc_network_gaps = sorted(lc_network_ids - behavior_active)

    summary = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "attack_version": metadata.get("attack_version"),
        "collection_modified": metadata.get("collection_modified"),
        "coverage_model_version": (model.get("_meta") or {}).get("coverage_model_version"),
        "quality_enrichment_version": (model.get("_meta") or {}).get("medium_quality_enrichment_version"),
        "enterprise_active_attack_pattern_count": len(active_ids),
        "enterprise_active_parent_technique_count": metadata.get("active_parent_technique_count"),
        "enterprise_active_subtechnique_count": metadata.get("active_subtechnique_count"),
        "full_enterprise_direct_behavior_count": len(behavior_active),
        "full_enterprise_bypass_proof_count": len(bypass_active),
        "full_enterprise_referenced_count": len(referenced_active),
        "full_enterprise_direct_behavior_rate": round(len(behavior_active) / len(active_ids), 6) if active_ids else 0,
        "full_enterprise_uncovered_count": len(full_uncovered),
        "linux_count": metadata.get("linux_technique_count"),
        "container_count": metadata.get("container_technique_count"),
        "linux_container_scope_count": len(scope_ids),
        "linux_container_direct_behavior_count": len(behavior_active & scope_ids),
        "linux_container_bypass_proof_count": len(bypass_active & scope_ids),
        "linux_container_direct_behavior_rate": round(len(behavior_active & scope_ids) / len(scope_ids), 6) if scope_ids else 0,
        "linux_container_l4_deep_model_count": depth.get("l4_deep_model_count"),
        "linux_container_depth_gate_passed": depth.get("depth_gate_passed"),
        "linux_container_quality_high_count": quality.get("high_count"),
        "linux_container_quality_medium_count": quality.get("medium_count"),
        "linux_container_quality_low_count": quality.get("low_count"),
        "linux_container_quality_gate_passed": quality.get("quality_gate_passed"),
        "network_device_scope_count": len(network_ids),
        "network_device_direct_behavior_count": len(behavior_active & network_ids),
        "network_device_direct_gap_count": len(network_gaps),
        "linux_container_network_scope_count": len(lc_network_ids),
        "linux_container_network_direct_behavior_count": len(behavior_active & lc_network_ids),
        "linux_container_network_direct_behavior_rate": round(len(behavior_active & lc_network_ids) / len(lc_network_ids), 6) if lc_network_ids else 0,
        "linux_container_network_direct_gap_count": len(lc_network_gaps),
        "non_linux_container_active_count": len(non_lc_ids),
        "non_linux_container_unmodeled_active_count": len(non_lc_uncovered),
        "full_enterprise_uncovered_by_tactic": sorted(tactic_counts(full_uncovered, lookup).items(), key=lambda x: (-x[1], x[0])),
        "non_linux_container_uncovered_by_platform": sorted(platform_counts(non_lc_uncovered, lookup).items(), key=lambda x: (-x[1], x[0])),
        "linux_container_scope_by_tactic": sorted(tactic_counts(scope_ids, lookup).items(), key=lambda x: (-x[1], x[0])),
        "linux_container_network_direct_gap_by_tactic": sorted(tactic_counts(set(lc_network_gaps), lookup).items(), key=lambda x: (-x[1], x[0])),
        "network_device_direct_gaps": [
            {
                "technique_id": tid,
                "name": lookup[tid].get("name"),
                "tactics": lookup[tid].get("tactics", []),
                "platforms": lookup[tid].get("platforms", []),
            }
            for tid in network_gaps
        ],
        "safe_use_note": "Coverage review summarizes defensive model scope only; it does not include payloads or operational bypass steps.",
    }
    Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output_json).write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    Path(args.output_md).write_text(build_markdown(summary), encoding="utf-8")
    print(json.dumps({
        "attack_version": summary["attack_version"],
        "full_enterprise_direct_behavior": f"{summary['full_enterprise_direct_behavior_count']}/{summary['enterprise_active_attack_pattern_count']}",
        "linux_container_direct_behavior": f"{summary['linux_container_direct_behavior_count']}/{summary['linux_container_scope_count']}",
        "linux_container_network_direct_behavior": f"{summary['linux_container_network_direct_behavior_count']}/{summary['linux_container_network_scope_count']}",
        "network_device_direct_gaps": summary["network_device_direct_gap_count"],
        "supported_scope_quality_high": f"{summary['linux_container_quality_high_count']}/{summary['linux_container_network_scope_count']}",
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
