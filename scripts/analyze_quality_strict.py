#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
from pathlib import Path


def read_json(path: Path):
    return json.load(open(path, encoding="utf-8"))


def read_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description="Analyze strict model quality for the active Linux/Containers/K8S/Network Devices scope.")
    ap.add_argument("--scenario-model", default=str(root / "attack_data" / "models" / "scenario_attack_model.json"))
    ap.add_argument("--scope", default=str(root / "attack_data" / "index" / "linux_container_network_scope.jsonl"))
    ap.add_argument("--output-dir", default=str(root / "laji" / "attack_data" / "reports"))
    args = ap.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    scenario_model = read_json(Path(args.scenario_model))
    scope_details = {item["technique_id"]: item for item in read_jsonl(Path(args.scope))}

    tech_info: dict[str, dict] = {}
    scenario_bypass_map: dict[str, set[str]] = {}
    for sname, sdata in scenario_model.items():
        if sname.startswith("_") or not isinstance(sdata, dict):
            continue
        scenario_bypass_ids = set()
        for bp in sdata.get("bypass_primitives", []) or []:
            for aid in bp.get("attack_ids", []) or []:
                scenario_bypass_ids.add(str(aid))
        scenario_bypass_map[sname] = scenario_bypass_ids

        for prim in sdata.get("behavior_primitives", []) or []:
            for aid in prim.get("attack_ids", []) or []:
                aid = str(aid)
                tech_info.setdefault(aid, {"primitives": [], "scenarios": set()})
                sem = prim.get("attack_semantics", {}) or {}
                technical_field_count = (
                    len(sem.get("syscalls", []) or [])
                    + len(sem.get("tools", []) or [])
                    + len(sem.get("file_paths", []) or [])
                    + len(sem.get("network_indicators", []) or [])
                )
                defensive_semantic_count = technical_field_count + (
                    len(sem.get("semantic_axes", []) or [])
                    + len(sem.get("observable_state_changes", []) or [])
                    + len(sem.get("correlation_requirements", []) or [])
                )
                prim_info = {
                    "scenario": sname,
                    "prim_id": prim.get("id", ""),
                    "has_semantics": "attack_semantics" in prim,
                    "has_bypass": aid in scenario_bypass_map.get(sname, set()),
                    "has_negative_fixture": "negative_fixture_requirements" in prim,
                    "technical_field_count": technical_field_count,
                    "defensive_semantic_count": defensive_semantic_count,
                    "coverage_maturity": prim.get("coverage_maturity"),
                }
                tech_info[aid]["primitives"].append(prim_info)
                tech_info[aid]["scenarios"].add(sname)

    high_count = medium_count = low_count = 0
    medium_techs = []
    for aid in sorted(scope_details):
        if aid not in tech_info:
            low_count += 1
            continue
        prims = tech_info[aid]["primitives"]
        any_high = False
        best_sem = best_bypass = best_negative = False
        for p in prims:
            if (
                p["coverage_maturity"] == "L4_deep_model"
                and p["has_semantics"]
                and p["has_bypass"]
                and p["has_negative_fixture"]
                and (p["technical_field_count"] >= 5 or p["defensive_semantic_count"] >= 10)
            ):
                any_high = True
                break
            if p["has_semantics"]:
                best_sem = True
            if p["has_bypass"]:
                best_bypass = True
            if p["has_negative_fixture"]:
                best_negative = True
        if any_high:
            high_count += 1
        elif best_sem:
            medium_count += 1
            medium_techs.append({
                "id": aid,
                "name": scope_details[aid].get("name", ""),
                "tactic": (scope_details[aid].get("tactics") or ["unknown"])[0],
                "scenarios": sorted(tech_info[aid]["scenarios"]),
                "has_bypass": best_bypass,
                "has_negative_fixture": best_negative,
                "primitive_count": len(prims),
            })
        else:
            low_count += 1

    total = high_count + medium_count + low_count
    summary = {
        "scope_count": total,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "high_rate": high_count / total if total else 0,
        "medium_rate": medium_count / total if total else 0,
        "low_rate": low_count / total if total else 0,
        "quality_gate_passed": medium_count == 0 and low_count == 0,
    }
    (output_dir / "medium_techniques_strict.json").write_text(json.dumps({"total": len(medium_techs), "techniques": medium_techs}, indent=2, ensure_ascii=False), encoding="utf-8")
    (output_dir / "quality_distribution_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
