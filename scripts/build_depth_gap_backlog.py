#!/usr/bin/env python3
from __future__ import annotations
"""Build Linux/Containers depth-gap backlog for ATT&CK scenario modeling.

Direct behavior binding is not enough. This report separates direct coverage
from L4 deep-model maturity, bypass proof enrichment, and safe fixture evidence
requirements so model coverage cannot hide shallow or bypass-prone areas.
"""

import argparse
import json
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


TACTIC_PRIORITY = {
    "stealth": 120,
    "credential-access": 116,
    "command-and-control": 112,
    "initial-access": 110,
    "persistence": 104,
    "privilege-escalation": 102,
    "exfiltration": 98,
    "execution": 94,
    "defense-impairment": 82,
    "lateral-movement": 80,
    "collection": 78,
    "discovery": 72,
    "impact": 70,
}

MATURITY_RANK = {
    "L4_deep_model": 4,
    "L3_model_scaffold": 3,
}


def has_items(value: Any) -> bool:
    return isinstance(value, list) and any(str(x).strip() for x in value)


def has_minimum_sets(value: Any) -> bool:
    return isinstance(value, list) and any(isinstance(x, list) and has_items(x) for x in value)


def has_signal_dict(value: Any) -> bool:
    return isinstance(value, dict) and any(v not in (None, "", [], {}) for v in value.values())


def is_l4_behavior(entry: dict[str, Any]) -> bool:
    if entry.get("coverage_maturity") != "L4_deep_model":
        return False
    return all([
        entry.get("has_attack_semantics"),
        entry.get("has_telemetry_feasibility"),
        has_items(entry.get("required_data_components")),
        has_items(entry.get("required_fields")),
        has_minimum_sets(entry.get("data_component_minimum_sets")),
        has_items(entry.get("sensor_requirements")),
        bool(entry.get("has_negative_fixture_requirements")),
    ])


def has_bypass_enrichment(entry: dict[str, Any]) -> bool:
    return bool(
        entry.get("has_wave3_enrichment")
        or entry.get("has_wave4_enrichment")
        or entry.get("has_depth_resilience_enrichment")
        or entry.get("has_network_device_extension")
    )


def is_structured_bypass(entry: dict[str, Any]) -> bool:
    return all([
        bool(entry.get("has_check_requirement")),
        bool(entry.get("has_required_fields")),
        bool(entry.get("has_required_data_components")),
        bool(entry.get("has_behavior_primitive")),
        bool(entry.get("has_safe_use_note")),
        has_bypass_enrichment(entry),
    ])


def is_strict_fixture(entry: dict[str, Any]) -> bool:
    return all([
        bool(entry.get("has_negative_requirements")),
        bool(entry.get("has_variant_requirements")),
        bool(entry.get("has_required_fields")),
        bool(entry.get("has_required_data_components")),
        bool(entry.get("safe_use_note")),
    ])


def read_json(path: Path) -> dict[str, Any]:
    return json.load(open(path, encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def model_scenarios(model: dict[str, Any]):
    for name, scenario in model.items():
        if name.startswith("_") or not isinstance(scenario, dict):
            continue
        yield name, scenario


def collect_model_maps(model: dict[str, Any], scope_ids: set[str]):
    behaviors: dict[str, list[dict[str, Any]]] = defaultdict(list)
    bypasses: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for scenario, sc in model_scenarios(model):
        for bp in sc.get("behavior_primitives", []) or []:
            for tid in bp.get("attack_ids", []) or []:
                tid = str(tid).upper()
                if tid in scope_ids:
                    behaviors[tid].append({
                        "scenario": scenario,
                        "id": bp.get("id"),
                        "coverage_maturity": bp.get("coverage_maturity") or "L2_legacy_direct_model",
                        "has_attack_semantics": bool(bp.get("attack_semantics")),
                        "has_telemetry_feasibility": bool(bp.get("telemetry_feasibility")),
                        "has_negative_fixture_requirements": bool(bp.get("negative_fixture_requirements")),
                        "required_data_components": bp.get("required_data_components", []),
                        "data_component_minimum_sets": bp.get("data_component_minimum_sets", []),
                        "required_fields": bp.get("required_fields", []),
                        "sensor_requirements": bp.get("sensor_requirements", []),
                        "proof_requirements": bp.get("proof_requirements", []),
                    })
        for by in sc.get("bypass_primitives", []) or []:
            for tid in by.get("attack_ids", []) or []:
                tid = str(tid).upper()
                if tid in scope_ids:
                    bypasses[tid].append({
                        "scenario": scenario,
                        "id": by.get("id"),
                        "category": by.get("category"),
                        "has_wave3_enrichment": bool(by.get("wave3_enrichment")),
                        "has_wave4_enrichment": bool(by.get("wave4_enrichment")),
                        "has_depth_resilience_enrichment": bool(by.get("depth_resilience_enrichment")),
                        "has_network_device_extension": bool(by.get("network_device_extension")),
                        "has_check_requirement": bool(by.get("check_requirement")),
                        "has_required_fields": bool(by.get("required_fields")),
                        "has_required_data_components": bool(by.get("required_data_components")),
                        "has_behavior_primitive": bool(by.get("behavior_primitive")),
                        "has_safe_use_note": bool(by.get("safe_use_note")),
                        "safe_use_note": by.get("safe_use_note"),
                    })
    return behaviors, bypasses


def load_fixture_index(paths: list[Path]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in paths:
        for row in read_jsonl(path):
            tid = str(row.get("technique_id") or row.get("attack_id") or "").upper()
            if tid:
                out[tid].append({
                    "fixture_template_id": row.get("fixture_template_id"),
                    "source": display_path(path),
                    "has_negative_requirements": bool(row.get("negative_fixture_requirements")),
                    "has_variant_requirements": bool(row.get("variant_fixture_requirements")),
                    "has_required_fields": bool(row.get("required_fields")),
                    "has_required_data_components": bool(row.get("required_data_components")),
                    "safe_use_note": row.get("safe_use_note"),
                })
    return out


def best_depth(entries: list[dict[str, Any]]) -> str:
    if not entries:
        return "L0_no_direct_model"
    if any(is_l4_behavior(e) for e in entries):
        return "L4_deep_model"
    best = max(MATURITY_RANK.get(e.get("coverage_maturity"), 2) for e in entries)
    if best >= 4:
        return "L4_deep_model"
    if best >= 3:
        return "L3_model_scaffold"
    return "L2_legacy_direct_model"


def priority_score(rec: dict[str, Any], depth: str, bypass_entries: list[dict[str, Any]], fixtures: list[dict[str, Any]]) -> int:
    tactics = rec.get("tactics", []) or []
    score = max([TACTIC_PRIORITY.get(t, 60) for t in tactics] or [60])
    if depth == "L0_no_direct_model":
        score += 50
    elif depth == "L2_legacy_direct_model":
        score += 35
    elif depth == "L3_model_scaffold":
        score += 25
    if not any(is_structured_bypass(x) for x in bypass_entries):
        score += 20
    elif not any(has_bypass_enrichment(x) for x in bypass_entries):
        score += 12
    if not any(is_strict_fixture(x) for x in fixtures):
        score += 14
    if rec.get("is_subtechnique"):
        score += 5
    return score


def required_actions(row: dict[str, Any]) -> list[str]:
    actions = []
    if row["depth_level"] == "L0_no_direct_model":
        actions.append("add direct behavior primitive")
    if row["depth_level"] in {"L2_legacy_direct_model", "L3_model_scaffold"}:
        actions.append("upgrade to L4_deep_model with attack_semantics and telemetry_feasibility")
    if row["depth_level"] == "L2_legacy_direct_model":
        actions.append("add explicit coverage_maturity and technique-specific required fields")
    if not row["has_structured_bypass_proof"]:
        actions.append("add structured bypass-resilience proof primitive")
    elif not row["has_bypass_enrichment"]:
        actions.append("enrich bypass proof with technique-specific variants")
    if not row["has_strict_fixture_template"]:
        actions.append("add safe positive, negative, and variant fixture templates")
    return actions


def build_markdown(summary: dict[str, Any], gap_rows: list[dict[str, Any]]) -> str:
    lines = [
        "# ATT&CK Depth Gap Backlog",
        "",
        f"- coverage_model_version: `{summary['coverage_model_version']}`",
        f"- scope_count: `{summary['scope_count']}`",
        f"- direct_model_count: `{summary['direct_model_count']}`",
        f"- direct_model_gap_count: `{summary['direct_model_gap_count']}`",
        f"- l4_deep_model_count: `{summary['l4_deep_model_count']}`",
        f"- non_l4_depth_gap_count: `{summary['non_l4_depth_gap_count']}`",
        f"- bypass_proof_gap_count: `{summary['bypass_proof_gap_count']}`",
        f"- bypass_enrichment_gap_count: `{summary['bypass_enrichment_gap_count']}`",
        f"- fixture_template_gap_count: `{summary['fixture_template_gap_count']}`",
        "",
        "## Depth Counts",
        "",
        "| Depth | Count |",
        "|---|---:|",
    ]
    for depth, count in summary["depth_counts"].items():
        lines.append(f"| {depth} | {count} |")
    lines += [
        "",
        "## Non-L4 Gaps By Tactic",
        "",
        "| Tactic | Count |",
        "|---|---:|",
    ]
    for tactic, count in summary["non_l4_gap_by_tactic"]:
        lines.append(f"| {tactic} | {count} |")
    lines += [
        "",
        "## Highest Priority Depth Gaps",
        "",
        "| ATT&CK ID | Name | Depth | Tactics | Priority | Required Actions |",
        "|---|---|---|---|---:|---|",
    ]
    for row in gap_rows[:80]:
        lines.append(
            f"| {row['technique_id']} | {row['name']} | {row['depth_level']} | "
            f"{', '.join(row.get('tactics', []))} | {row['depth_priority_score']} | "
            f"{'; '.join(row.get('required_actions', []))} |"
        )
    lines += [
        "",
        "## Interpretation",
        "",
        "`direct_model_count` is not sufficient for bypass resilience. A technique remains a depth gap until it has L4 semantics, technique-specific bypass proof, and safe fixture requirements.",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Build Linux/Containers ATT&CK depth-gap backlog.")
    ap.add_argument("--scope", default=str(ROOT / "attack_data" / "index" / "linux_container_network_scope.jsonl"))
    ap.add_argument("--lookup", default=str(ROOT / "attack_data" / "index" / "lookup_by_id.json"))
    ap.add_argument("--scenario-model", default=str(ROOT / "attack_data" / "models" / "scenario_attack_model.json"))
    ap.add_argument("--fixture-dir", default=str(ROOT / "attack_data" / "fixtures"))
    ap.add_argument("--output-dir", default=str(ROOT / "laji" / "attack_data" / "reports"))
    args = ap.parse_args()

    scope_rows = read_jsonl(Path(args.scope))
    lookup = read_json(Path(args.lookup))
    model = read_json(Path(args.scenario_model))
    model_version = (model.get("_meta") or {}).get("coverage_model_version", "unknown")
    scope_ids = []
    seen = set()
    for row in scope_rows:
        tid = str(row.get("technique_id") or row.get("attack_id") or row.get("id") or "").upper()
        if tid and tid in lookup and tid not in seen:
            scope_ids.append(tid)
            seen.add(tid)
    scope_set = set(scope_ids)
    behaviors, bypasses = collect_model_maps(model, scope_set)
    fixture_paths = [
        path
        for path in sorted(Path(args.fixture_dir).glob("*_templates.jsonl"))
        if not path.name.startswith("wave")
    ]
    fixtures = load_fixture_index(fixture_paths)

    rows = []
    for tid in scope_ids:
        rec = lookup[tid]
        behavior_entries = behaviors.get(tid, [])
        bypass_entries = bypasses.get(tid, [])
        fixture_entries = fixtures.get(tid, [])
        depth = best_depth(behavior_entries)
        row = {
            "coverage_model_version": model_version,
            "technique_id": tid,
            "name": rec.get("name"),
            "tactics": rec.get("tactics", []),
            "platforms": rec.get("platforms", []),
            "is_subtechnique": bool(rec.get("is_subtechnique")),
            "parent_id": rec.get("parent_id"),
            "parent_name": rec.get("parent_name"),
            "depth_level": depth,
            "direct_model_covered": bool(behavior_entries),
            "l4_deep_model": depth == "L4_deep_model",
            "behavior_primitives": behavior_entries,
            "behavior_primitive_count": len(behavior_entries),
            "bypass_primitives": bypass_entries,
            "bypass_primitive_count": len(bypass_entries),
            "has_any_bypass_proof": bool(bypass_entries),
            "has_structured_bypass_proof": any(is_structured_bypass(x) for x in bypass_entries),
            "has_wave3_bypass_enrichment": any(has_bypass_enrichment(x) for x in bypass_entries),
            "has_bypass_enrichment": any(has_bypass_enrichment(x) for x in bypass_entries),
            "fixture_templates": fixture_entries,
            "has_fixture_template": bool(fixture_entries),
            "has_negative_fixture_template": any(x.get("has_negative_requirements") for x in fixture_entries),
            "has_strict_fixture_template": any(is_strict_fixture(x) for x in fixture_entries),
            "data_components": rec.get("data_components", []),
            "attack_url": rec.get("url"),
        }
        row["required_actions"] = required_actions(row)
        row["depth_priority_score"] = priority_score(rec, depth, bypass_entries, fixture_entries)
        rows.append(row)

    gap_rows = [r for r in rows if r["required_actions"]]
    gap_rows.sort(key=lambda r: (-r["depth_priority_score"], str(r["technique_id"])))
    rows.sort(key=lambda r: (-r["depth_priority_score"], str(r["technique_id"])))
    depth_counts = Counter(r["depth_level"] for r in rows)
    non_l4_by_tactic = Counter()
    for row in rows:
        if row["depth_level"] != "L4_deep_model":
            for tactic in row.get("tactics", []) or ["unknown"]:
                non_l4_by_tactic[tactic] += 1
    summary = {
        "coverage_model_version": model_version,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope_count": len(rows),
        "direct_model_count": sum(1 for r in rows if r["direct_model_covered"]),
        "direct_model_gap_count": sum(1 for r in rows if not r["direct_model_covered"]),
        "l4_deep_model_count": depth_counts.get("L4_deep_model", 0),
        "non_l4_depth_gap_count": len(rows) - depth_counts.get("L4_deep_model", 0),
        "bypass_proof_gap_count": sum(1 for r in rows if not r["has_structured_bypass_proof"]),
        "legacy_bypass_row_absent_count": sum(1 for r in rows if not r["has_any_bypass_proof"]),
        "bypass_enrichment_gap_count": sum(1 for r in rows if not r["has_bypass_enrichment"]),
        "wave3_bypass_enrichment_gap_count": sum(1 for r in rows if not r["has_bypass_enrichment"]),
        "fixture_template_gap_count": sum(1 for r in rows if not r["has_strict_fixture_template"]),
        "negative_fixture_gap_count": sum(1 for r in rows if not r["has_negative_fixture_template"]),
        "depth_resilient_model_count": sum(1 for r in rows if r["depth_level"] == "L4_deep_model" and r["has_structured_bypass_proof"] and r["has_strict_fixture_template"]),
        "depth_counts": dict(sorted(depth_counts.items())),
        "non_l4_gap_by_tactic": sorted(non_l4_by_tactic.items(), key=lambda x: (-x[1], x[0])),
        "definition": {
            "L4_deep_model": "Technique has direct behavior primitive with L4 maturity, attack_semantics, technique-specific fields, Data Component minimum sets, telemetry feasibility, sensor requirements, and negative fixture requirements.",
            "L3_model_scaffold": "Technique has direct model scaffold but still lacks full deep semantics.",
            "L2_legacy_direct_model": "Technique is directly modeled by pre-Wave2 primitives but lacks explicit L3/L4 maturity metadata.",
            "bypass_proof_gap": "No structured bypass-resilience proof exists for the ATT&CK ID.",
            "bypass_enrichment_gap": "Bypass proof exists but lacks Wave3/Wave4 technique-specific enrichment.",
        },
    }
    summary["depth_gate_passed"] = all([
        summary["direct_model_gap_count"] == 0,
        summary["non_l4_depth_gap_count"] == 0,
        summary["bypass_proof_gap_count"] == 0,
        summary["bypass_enrichment_gap_count"] == 0,
        summary["fixture_template_gap_count"] == 0,
    ])

    out_dir = Path(args.output_dir)
    write_jsonl(out_dir / "depth_coverage_state.jsonl", rows)
    write_jsonl(out_dir / "depth_gap_backlog.jsonl", gap_rows)
    (out_dir / "depth_gap_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out_dir / "depth_gap_backlog.md").write_text(build_markdown(summary, gap_rows), encoding="utf-8")
    print(json.dumps({
        "coverage_model_version": model_version,
        "scope_count": summary["scope_count"],
        "direct_model_gap_count": summary["direct_model_gap_count"],
        "non_l4_depth_gap_count": summary["non_l4_depth_gap_count"],
        "bypass_proof_gap_count": summary["bypass_proof_gap_count"],
        "bypass_enrichment_gap_count": summary["bypass_enrichment_gap_count"],
        "wave3_bypass_enrichment_gap_count": summary["wave3_bypass_enrichment_gap_count"],
        "fixture_template_gap_count": summary["fixture_template_gap_count"],
        "depth_gate_passed": summary["depth_gate_passed"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
