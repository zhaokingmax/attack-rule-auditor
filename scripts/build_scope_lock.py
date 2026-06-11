#!/usr/bin/env python3
from __future__ import annotations
"""Build a fixed ATT&CK scope lock for Linux/Containers/K8S/Network Devices."""

import argparse
import hashlib
import json
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def fixture_index(paths: list[Path]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in paths:
        for row in read_jsonl(path):
            tid = str(row.get("technique_id") or row.get("attack_id") or "").upper()
            if tid:
                out[tid].append(row)
    return out


def strict_fixture(rows: list[dict[str, Any]]) -> bool:
    return any(
        row.get("required_fields")
        and row.get("required_data_components")
        and row.get("negative_fixture_requirements")
        and row.get("variant_fixture_requirements")
        for row in rows
    )


def model_bindings(model: dict[str, Any], allowed_platforms: set[str]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    behavior: dict[str, list[dict[str, Any]]] = defaultdict(list)
    bypass: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for scenario, obj in model.items():
        if scenario.startswith("_") or not isinstance(obj, dict):
            continue
        platforms = {str(p) for p in obj.get("platform_scope", []) or []}
        if platforms and not (platforms & allowed_platforms):
            continue
        for primitive in obj.get("behavior_primitives", []) or []:
            for tid in primitive.get("attack_ids", []) or []:
                behavior[str(tid).upper()].append({
                    "scenario": scenario,
                    "primitive": primitive.get("id"),
                    "coverage_maturity": primitive.get("coverage_maturity"),
                    "required_data_components": primitive.get("required_data_components", []),
                    "required_fields": primitive.get("required_fields", []),
                    "sensor_requirements": primitive.get("sensor_requirements", []),
                })
        for primitive in obj.get("bypass_primitives", []) or []:
            for tid in primitive.get("attack_ids", []) or []:
                bypass[str(tid).upper()].append({
                    "scenario": scenario,
                    "primitive": primitive.get("id"),
                    "behavior_primitive": primitive.get("behavior_primitive"),
                    "required_data_components": primitive.get("required_data_components", []),
                    "required_fields": primitive.get("required_fields", []),
                    "proof_requirement": primitive.get("check_requirement") or primitive.get("description"),
                })
    return behavior, bypass


def is_l4(rows: list[dict[str, Any]]) -> bool:
    return any(row.get("coverage_maturity") == "L4_deep_model" for row in rows)


def structured_bypass(rows: list[dict[str, Any]]) -> bool:
    return any(row.get("proof_requirement") and row.get("required_fields") and row.get("required_data_components") for row in rows)


def digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description="Build Linux/Containers/K8S/Network Devices ATT&CK scope lock.")
    ap.add_argument("--scope", default=str(root / "attack_data" / "index" / "linux_container_network_scope.jsonl"))
    ap.add_argument("--lookup", default=str(root / "attack_data" / "index" / "lookup_by_id.json"))
    ap.add_argument("--metadata", default=str(root / "attack_data" / "index" / "metadata.json"))
    ap.add_argument("--scenario-model", default=str(root / "attack_data" / "models" / "scenario_attack_model.json"))
    ap.add_argument("--fixture-dir", default=str(root / "attack_data" / "fixtures"))
    ap.add_argument("--output-json", default=str(root / "attack_data" / "index" / "linux_container_k8s_network_scope.lock.json"))
    ap.add_argument("--output-md", default=str(root / "attack_data" / "index" / "linux_container_k8s_network_scope.lock.md"))
    args = ap.parse_args()

    scope_rows = read_jsonl(Path(args.scope))
    lookup = read_json(Path(args.lookup))
    metadata = read_json(Path(args.metadata)) if Path(args.metadata).exists() else {}
    model = read_json(Path(args.scenario_model))
    fixtures = fixture_index(sorted(Path(args.fixture_dir).glob("*_templates.jsonl")))
    allowed = {"Linux", "Containers", "Network Devices"}
    behavior, bypass = model_bindings(model, allowed)

    items = []
    for row in sorted(scope_rows, key=lambda r: str(r.get("technique_id"))):
        tid = str(row.get("technique_id")).upper()
        rec = lookup.get(tid, row)
        b_rows = behavior.get(tid, [])
        by_rows = bypass.get(tid, [])
        f_rows = fixtures.get(tid, [])
        item = {
            "technique_id": tid,
            "name": rec.get("name"),
            "platforms": rec.get("platforms", []),
            "tactics": rec.get("tactics", []),
            "is_subtechnique": rec.get("is_subtechnique"),
            "parent_id": rec.get("parent_id"),
            "behavior_binding_count": len(b_rows),
            "bypass_proof_count": len(by_rows),
            "has_l4_behavior_model": is_l4(b_rows),
            "has_structured_bypass_proof": structured_bypass(by_rows),
            "has_strict_fixture_template": strict_fixture(f_rows),
            "behavior_bindings": b_rows[:8],
            "bypass_bindings": by_rows[:8],
            "fixture_template_count": len(f_rows),
        }
        items.append(item)

    platform_counts = Counter(platform for item in items for platform in item["platforms"])
    tactic_counts = Counter(tactic for item in items for tactic in item["tactics"])
    summary = {
        "scope_name": "linux_containers_k8s_network_devices",
        "scope_count": len(items),
        "linux_count": sum(1 for item in items if "Linux" in item["platforms"]),
        "containers_count": sum(1 for item in items if "Containers" in item["platforms"]),
        "network_devices_count": sum(1 for item in items if "Network Devices" in item["platforms"]),
        "direct_behavior_count": sum(1 for item in items if item["behavior_binding_count"] > 0),
        "l4_behavior_count": sum(1 for item in items if item["has_l4_behavior_model"]),
        "structured_bypass_count": sum(1 for item in items if item["has_structured_bypass_proof"]),
        "strict_fixture_count": sum(1 for item in items if item["has_strict_fixture_template"]),
        "platform_counts": dict(sorted(platform_counts.items())),
        "tactic_counts": dict(sorted(tactic_counts.items())),
        "source_attack_collection": metadata.get("attack_version"),
        "source_attack_modified": metadata.get("collection_modified"),
        "source_sha256": metadata.get("source_sha256"),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    lock = {
        "summary": summary,
        "scope_hash": digest(items),
        "items": items,
    }
    Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output_json).write_text(json.dumps(lock, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Linux / Containers / Kubernetes / Network Devices Scope Lock",
        "",
        f"- scope_count: `{summary['scope_count']}`",
        f"- direct_behavior_count: `{summary['direct_behavior_count']}`",
        f"- l4_behavior_count: `{summary['l4_behavior_count']}`",
        f"- structured_bypass_count: `{summary['structured_bypass_count']}`",
        f"- strict_fixture_count: `{summary['strict_fixture_count']}`",
        f"- scope_hash: `{lock['scope_hash']}`",
        "",
        "## Platform Counts",
        "",
    ]
    lines += [f"- `{platform}`: {count}" for platform, count in summary["platform_counts"].items()]
    lines += ["", "## Tactic Counts", ""]
    lines += [f"- `{tactic}`: {count}" for tactic, count in summary["tactic_counts"].items()]
    gaps = [
        item for item in items
        if not item["behavior_binding_count"] or not item["has_l4_behavior_model"] or not item["has_structured_bypass_proof"] or not item["has_strict_fixture_template"]
    ]
    lines += ["", "## Model Gaps", ""]
    lines += ["- None"] if not gaps else [
        f"- `{item['technique_id']}` {item['name']}: behavior={item['behavior_binding_count']} l4={item['has_l4_behavior_model']} bypass={item['has_structured_bypass_proof']} fixture={item['has_strict_fixture_template']}"
        for item in gaps[:100]
    ]
    Path(args.output_md).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"output_json": args.output_json, "scope_hash": lock["scope_hash"], **summary}, ensure_ascii=False))


if __name__ == "__main__":
    main()
