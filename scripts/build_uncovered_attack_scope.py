#!/usr/bin/env python3
from __future__ import annotations
"""Build the Wave 2 uncovered Linux/Containers ATT&CK scope backlog.

The output is a defensive modeling backlog. It does not generate payloads,
attack steps, or bypass instructions. It only records which ATT&CK techniques
still need deep scenario-model work.
"""
import argparse
import json
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


TACTIC_PRIORITY = {
    "stealth": 100,
    "persistence": 92,
    "command-and-control": 90,
    "credential-access": 88,
    "discovery": 84,
    "execution": 78,
    "collection": 76,
    "exfiltration": 74,
    "privilege-escalation": 72,
    "impact": 70,
    "initial-access": 68,
    "defense-impairment": 66,
    "lateral-movement": 64,
}


def read_json(path: Path) -> dict[str, Any]:
    return json.load(open(path, encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def display_path(path_text: str) -> str:
    path = Path(path_text)
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def scenario_items(model: dict[str, Any]):
    for scenario, sc in model.items():
        if scenario.startswith("_") or not isinstance(sc, dict):
            continue
        for bp in sc.get("behavior_primitives", []) or []:
            if not isinstance(bp, dict):
                continue
            yield scenario, bp


def build_model_maps(model: dict[str, Any], lookup: dict[str, Any]):
    direct: dict[str, list[dict[str, Any]]] = defaultdict(list)
    parent_to_direct_children: dict[str, set[str]] = defaultdict(set)
    for scenario, bp in scenario_items(model):
        for tid in bp.get("attack_ids", []) or []:
            tid = str(tid).upper()
            if tid not in lookup:
                continue
            direct[tid].append({
                "scenario": scenario,
                "behavior_primitive": bp.get("id"),
                "critical": bool(bp.get("critical")),
                "required_data_components": bp.get("required_data_components", []),
                "required_fields": bp.get("required_fields", []),
            })
            parent = lookup.get(tid, {}).get("parent_id")
            if parent:
                parent_to_direct_children[parent].add(tid)
    return direct, parent_to_direct_children


def linux_container_analytics(rec: dict[str, Any]) -> list[str]:
    analytics: list[str] = []
    for strat in rec.get("detection_strategies", []) or []:
        if not isinstance(strat, dict):
            continue
        for analytic in strat.get("analytics", []) or []:
            platforms = {str(x).lower() for x in analytic.get("platforms", []) or []}
            if platforms & {"linux", "containers", "network devices"} and analytic.get("id"):
                analytics.append(str(analytic.get("id")))
    return sorted(set(analytics))


def coverage_state(tid: str, rec: dict[str, Any], direct: dict[str, list[dict[str, Any]]], parent_to_children: dict[str, set[str]]) -> tuple[str, str]:
    parent = rec.get("parent_id")
    if tid in direct:
        return "direct_primitive", "technique_or_subtechnique_has_direct_behavior_primitive"
    if parent and parent in direct:
        return "parent_rollup_only", "subtechnique_not_directly_modeled_parent_is_modeled"
    if tid in parent_to_children:
        return "child_covered_rollup", "parent_not_directly_modeled_but_child_subtechniques_are"
    return "unmodeled", "no_behavior_primitive_binding"


def priority_score(rec: dict[str, Any], state: str, analytic_count: int) -> int:
    tactics = rec.get("tactics", []) or []
    base = max([TACTIC_PRIORITY.get(t, 50) for t in tactics] or [50])
    if state == "unmodeled":
        base += 20
    elif state == "parent_rollup_only":
        base += 12
    elif state == "child_covered_rollup":
        base += 6
    if rec.get("is_subtechnique"):
        base += 6
    if analytic_count:
        base += min(analytic_count, 5)
    if rec.get("data_components"):
        base += min(len(rec.get("data_components") or []), 5)
    return int(base)


def top_parent_gaps(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        parent = r.get("parent_id") or r.get("technique_id")
        grouped[parent].append(r)
    out = []
    for parent, items in grouped.items():
        out.append({
            "parent_id": parent,
            "parent_name": items[0].get("parent_name") if items[0].get("parent_id") else items[0].get("name"),
            "gap_count": len(items),
            "tactics": sorted({t for item in items for t in item.get("tactics", [])}),
            "sample_ids": [item.get("technique_id") for item in items[:10]],
        })
    return sorted(out, key=lambda x: (-x["gap_count"], str(x["parent_id"])))[:30]


def build_markdown(summary: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    lines = [
        "# Wave 2 Phase 1 Uncovered ATT&CK Scope",
        "",
        f"- scope_count: `{summary['scope_count']}`",
        f"- direct_primitive_count: `{summary['direct_primitive_count']}`",
        f"- strict_deep_gap_count: `{summary['strict_deep_gap_count']}`",
        f"- rollup_associated_count: `{summary['rollup_associated_count']}`",
        f"- unmodeled_count: `{summary['coverage_state_counts'].get('unmodeled', 0)}`",
        f"- parent_rollup_only_count: `{summary['coverage_state_counts'].get('parent_rollup_only', 0)}`",
        f"- child_covered_rollup_count: `{summary['coverage_state_counts'].get('child_covered_rollup', 0)}`",
        "",
        "## Strict Deep Gaps By Tactic",
        "",
        "| Tactic | Gap Count |",
        "|---|---:|",
    ]
    for tactic, count in summary["strict_deep_gap_by_tactic"]:
        lines.append(f"| {tactic} | {count} |")
    lines += [
        "",
        "## Highest Priority Gaps",
        "",
        "| ATT&CK ID | Name | State | Tactics | Priority | Data Components |",
        "|---|---|---|---|---:|---|",
    ]
    for r in rows[:50]:
        lines.append(
            f"| {r['technique_id']} | {r['name']} | {r['model_coverage_state']} | "
            f"{', '.join(r.get('tactics', []))} | {r['expansion_priority_score']} | "
            f"{', '.join(r.get('data_components', [])[:5])} |"
        )
    lines += [
        "",
        "## Interpretation",
        "",
        "`direct_primitive` is the only state counted as deep scenario-model coverage. "
        "`parent_rollup_only` and `child_covered_rollup` are useful relationships, but they remain backlog items until a behavior primitive explicitly binds the ATT&CK ID.",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Build uncovered Linux/Containers ATT&CK scope backlog for scenario-model expansion.")
    ap.add_argument("--scope", default=str(ROOT / "attack_data" / "index" / "linux_container_network_scope.jsonl"))
    ap.add_argument("--lookup", default=str(ROOT / "attack_data" / "index" / "lookup_by_id.json"))
    ap.add_argument("--metadata", default=str(ROOT / "attack_data" / "index" / "metadata.json"))
    ap.add_argument("--scenario-model", default=str(ROOT / "attack_data" / "models" / "scenario_attack_model.json"))
    ap.add_argument("--output-dir", default=str(ROOT / "laji" / "attack_data" / "reports"))
    args = ap.parse_args()

    scope = read_jsonl(Path(args.scope))
    lookup = read_json(Path(args.lookup))
    metadata = read_json(Path(args.metadata)) if Path(args.metadata).exists() else {}
    model = read_json(Path(args.scenario_model))
    direct, parent_to_children = build_model_maps(model, lookup)

    seen: set[str] = set()
    all_rows: list[dict[str, Any]] = []
    gap_rows: list[dict[str, Any]] = []
    for item in scope:
        tid = str(item.get("technique_id") or item.get("attack_id") or item.get("id") or "").upper()
        if not tid or tid in seen or tid not in lookup:
            continue
        seen.add(tid)
        rec = lookup[tid]
        state, reason = coverage_state(tid, rec, direct, parent_to_children)
        analytics = linux_container_analytics(rec)
        direct_entries = direct.get(tid, [])
        parent_entries = direct.get(rec.get("parent_id"), []) if rec.get("parent_id") else []
        child_ids = sorted(parent_to_children.get(tid, set()))
        model_version = (model.get("_meta") or {}).get("coverage_model_version", "V10.5-wave4")
        row = {
            "coverage_model_version": model_version,
            "technique_id": tid,
            "name": rec.get("name"),
            "tactics": rec.get("tactics", []),
            "platforms": rec.get("platforms", []),
            "is_subtechnique": bool(rec.get("is_subtechnique")),
            "parent_id": rec.get("parent_id"),
            "parent_name": rec.get("parent_name"),
            "model_coverage_state": state,
            "model_gap_reason": reason,
            "deep_model_gap": state != "direct_primitive",
            "direct_model_scenarios": sorted({x["scenario"] for x in direct_entries}),
            "direct_behavior_primitives": sorted({x["behavior_primitive"] for x in direct_entries if x.get("behavior_primitive")}),
            "parent_model_scenarios": sorted({x["scenario"] for x in parent_entries}),
            "modeled_child_subtechniques": child_ids,
            "data_components": rec.get("data_components", []),
            "detection_strategy_ids": [s.get("id") for s in rec.get("detection_strategies", []) if isinstance(s, dict) and s.get("id")],
            "detection_strategy_count": len(rec.get("detection_strategies", []) or []),
            "linux_container_analytic_ids": analytics,
            "linux_container_analytic_count": len(analytics),
            "attack_url": rec.get("url"),
            "attack_modified": rec.get("modified"),
        }
        row["expansion_priority_score"] = priority_score(rec, state, len(analytics))
        all_rows.append(row)
        if row["deep_model_gap"]:
            gap_rows.append(row)

    all_rows.sort(key=lambda r: (-r["expansion_priority_score"], str(r["technique_id"])))
    gap_rows.sort(key=lambda r: (-r["expansion_priority_score"], str(r["technique_id"])))

    state_counts = Counter(r["model_coverage_state"] for r in all_rows)
    strict_by_tactic = Counter()
    for r in gap_rows:
        for tactic in r.get("tactics", []) or ["unknown"]:
            strict_by_tactic[tactic] += 1
    summary = {
        "coverage_model_version": (model.get("_meta") or {}).get("coverage_model_version", "V10.5-wave4"),
        "attack_version": metadata.get("attack_version") or metadata.get("collection_name"),
        "scope_source": display_path(args.scope),
        "scenario_model": display_path(args.scenario_model),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope_count": len(all_rows),
        "direct_primitive_count": state_counts.get("direct_primitive", 0),
        "strict_deep_gap_count": len(gap_rows),
        "rollup_associated_count": state_counts.get("direct_primitive", 0) + state_counts.get("child_covered_rollup", 0),
        "coverage_state_counts": dict(sorted(state_counts.items())),
        "strict_deep_gap_by_tactic": sorted(strict_by_tactic.items(), key=lambda x: (-x[1], x[0])),
        "top_parent_gaps": top_parent_gaps(gap_rows),
        "definition": {
            "direct_primitive": "ATT&CK ID appears directly in at least one scenario behavior primitive.",
            "parent_rollup_only": "Sub-technique is not directly modeled, but its parent technique is modeled.",
            "child_covered_rollup": "Parent technique is not directly modeled, but one or more child sub-techniques are modeled.",
            "unmodeled": "No direct, parent, or child behavior primitive relationship is present.",
        },
    }

    out_dir = Path(args.output_dir)
    write_jsonl(out_dir / "attack_scope_model_coverage.jsonl", all_rows)
    write_jsonl(out_dir / "uncovered_attack_scope.jsonl", gap_rows)
    (out_dir / "uncovered_attack_scope_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out_dir / "uncovered_attack_scope.md").write_text(build_markdown(summary, gap_rows), encoding="utf-8")
    print(json.dumps({
        "output_dir": str(out_dir),
        "scope_count": summary["scope_count"],
        "direct_primitive_count": summary["direct_primitive_count"],
        "strict_deep_gap_count": summary["strict_deep_gap_count"],
        "coverage_state_counts": summary["coverage_state_counts"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
