#!/usr/bin/env python3
from __future__ import annotations
"""Generate field-chain preservation regression test metadata from remediation findings."""

import argparse
import json
from pathlib import Path
from typing import Any

from common import jsonl_read, jsonl_write


def build_test(row: dict[str, Any]) -> dict[str, Any]:
    fields = [str(x) for x in row.get("required_fields") or [] if x]
    return {
        "test_id": f"field_preservation_{row.get('finding_id')}",
        "attack_id": row.get("attack_id"),
        "scenario": row.get("scenario"),
        "candidate_patch_files": row.get("candidate_patch_files") or [],
        "required_fields": fields,
        "raw_event_expectations": [{"field": field, "present": True} for field in fields],
        "normalized_event_expectations": [{"field": field, "preserved": True} for field in fields],
        "alert_expectations": [
            {"property": "claim_strength", "expected": "not_stronger_than_field_chain_proven_until_all_required_fields_exist"},
            {"property": "missing_fields", "expected": "reported_when_any_required_field_is_absent"},
        ],
        "negative_expectations": [
            "single-field matches must not upgrade to strong coverage",
            "tool-name-only matches must remain blocked",
            "benign administrative lookalikes must be explicitly filtered or downgraded",
        ],
    }


def render_md(rows: list[dict[str, Any]]) -> str:
    lines = ["# Field Preservation Regression Plan", ""]
    for row in rows[:100]:
        lines += [
            f"## {row['test_id']}",
            "",
            f"- attack_id: `{row.get('attack_id')}`",
            f"- scenario: `{row.get('scenario')}`",
            f"- required_fields: `{', '.join(row.get('required_fields') or []) or 'none'}`",
            "",
        ]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate parser/normalizer field-preservation regression metadata.")
    ap.add_argument("--remediation-plan", required=True)
    ap.add_argument("--output-jsonl", required=True)
    ap.add_argument("--output-md", required=True)
    args = ap.parse_args()

    tests = [build_test(row) for row in jsonl_read(Path(args.remediation_plan))]
    jsonl_write(Path(args.output_jsonl), tests)
    Path(args.output_md).write_text(render_md(tests), encoding="utf-8")
    print(json.dumps({"test_count": len(tests), "output_jsonl": args.output_jsonl}, ensure_ascii=False))


if __name__ == "__main__":
    main()
