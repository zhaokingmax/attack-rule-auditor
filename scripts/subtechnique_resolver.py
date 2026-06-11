#!/usr/bin/env python3
from __future__ import annotations
"""Resolve parent-technique references to child technique review candidates."""

import argparse
import json
from pathlib import Path
from typing import Any

from common import jsonl_write
from scenario_attack_id_health import children_of, collect_ids, load_json


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate parent/sub-technique resolution candidates for the supported scope.")
    ap.add_argument("--scenario-model", default="attack_data/models/scenario_attack_model.json")
    ap.add_argument("--index", default="attack_data/index")
    ap.add_argument("--platform", default="Linux,Containers,Network Devices")
    ap.add_argument("--output-jsonl", default="laji/attack_data/reports/subtechnique_resolution.jsonl")
    ap.add_argument("--output-md", default="laji/attack_data/reports/subtechnique_resolution.md")
    args = ap.parse_args()

    index = Path(args.index)
    active = load_json(index / "lookup_by_id.json")
    model = load_json(Path(args.scenario_model))
    platforms = {p.strip().lower() for p in args.platform.split(",") if p.strip()}
    refs = collect_ids(model)
    scenario_ids: dict[str, set[str]] = {}
    for ref in refs:
        scenario_ids.setdefault(ref["scenario"], set()).add(ref["attack_id"])
    rows = []
    for ref in refs:
        tid = ref["attack_id"]
        rec = active.get(tid) or {}
        children = children_of(active, tid)
        if not children or rec.get("is_subtechnique"):
            continue
        in_scope_children = [
            child for child in children
            if {p.lower() for p in (active.get(child) or {}).get("platforms", [])} & platforms
        ]
        already_bound = sorted(set(in_scope_children) & scenario_ids.get(ref["scenario"], set()))
        rows.append({
            "scenario": ref["scenario"],
            "source": ref["source"],
            "parent_attack_id": tid,
            "parent_name": rec.get("name"),
            "in_scope_child_count": len(in_scope_children),
            "in_scope_children": in_scope_children,
            "already_bound_children": already_bound,
            "resolution_state": "resolved_by_existing_child_binding" if already_bound else "needs_child_binding_review",
            "safe_use_note": "Resolution is defensive coverage specificity only.",
        })
    jsonl_write(Path(args.output_jsonl), rows)
    needs = sum(1 for r in rows if r["resolution_state"] == "needs_child_binding_review")
    md = [
        "# Parent/Sub-technique Resolution",
        "",
        f"- parent_reference_count: `{len(rows)}`",
        f"- needs_child_binding_review: `{needs}`",
        "",
    ]
    for row in rows[:100]:
        md.append(f"- `{row['scenario']}` `{row['parent_attack_id']}` {row['resolution_state']} child_count={row['in_scope_child_count']}")
    Path(args.output_md).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output_md).write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({"parent_reference_count": len(rows), "needs_child_binding_review": needs}, ensure_ascii=False))


if __name__ == "__main__":
    main()
