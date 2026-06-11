#!/usr/bin/env python3
from __future__ import annotations
"""Generate safe minimal synthetic fixture metadata for a selected scenario."""

import argparse
import json
from pathlib import Path
from typing import Any

from common import jsonl_write


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def scenario_rows(model: dict[str, Any], scenario: str) -> list[dict[str, Any]]:
    sc = model.get(scenario) or {}
    rows: list[dict[str, Any]] = []
    for primitive in sc.get("behavior_primitives", []) or []:
        attack_ids = primitive.get("attack_ids") or []
        fields = primitive.get("required_fields") or primitive.get("fields") or []
        for attack_id in attack_ids:
            base = {
                "scenario": scenario,
                "attack_id": attack_id,
                "behavior_primitive": primitive.get("id"),
                "required_fields": fields,
                "safe_use_note": "Synthetic metadata only; do not execute attack behavior.",
            }
            rows.append({**base, "fixture_type": "positive", "expectation": "all required fields present and bound to behavior semantics"})
            rows.append({**base, "fixture_type": "negative", "expectation": "benign administrative lookalike does not upgrade claim"})
            rows.append({**base, "fixture_type": "variant", "expectation": "raw and normalized aliases preserve required fields under a safe metadata variant"})
            rows.append({**base, "fixture_type": "field_chain", "expectation": "collector parser normalizer rule and alert preserve the required fields"})
    return rows


def render_md(rows: list[dict[str, Any]], scenario: str) -> str:
    lines = [
        "# Minimal Synthetic Fixture Suite",
        "",
        f"- scenario: `{scenario}`",
        f"- fixture_count: `{len(rows)}`",
        "",
        "Fixtures are metadata requirements only and must not execute attack behavior.",
        "",
    ]
    for row in rows[:80]:
        lines.append(f"- `{row['fixture_type']}` `{row.get('attack_id')}` `{row.get('behavior_primitive')}`: {row.get('expectation')}")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Build safe positive/negative/variant/field-chain fixture metadata for one scenario.")
    ap.add_argument("--scenario-model", default="attack_data/models/scenario_attack_model.json")
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--output-jsonl", required=True)
    ap.add_argument("--output-md", required=True)
    args = ap.parse_args()

    model = load_json(Path(args.scenario_model))
    rows = scenario_rows(model, args.scenario)
    jsonl_write(Path(args.output_jsonl), rows)
    Path(args.output_md).write_text(render_md(rows, args.scenario), encoding="utf-8")
    print(json.dumps({"scenario": args.scenario, "fixture_count": len(rows), "output_jsonl": args.output_jsonl}, ensure_ascii=False))


if __name__ == "__main__":
    main()
