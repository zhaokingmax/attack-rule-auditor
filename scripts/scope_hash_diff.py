#!/usr/bin/env python3
from __future__ import annotations
"""Compare two scope lock JSON files or current scope lock summaries."""

import argparse
import json
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("summary") if isinstance(data.get("summary"), dict) else data


def main() -> None:
    ap = argparse.ArgumentParser(description="Diff supported-scope hashes and key counts.")
    ap.add_argument("--old-lock")
    ap.add_argument("--new-lock", required=True)
    ap.add_argument("--output-json", default="laji/attack_data/reports/scope_hash_diff.json")
    ap.add_argument("--output-md", default="laji/attack_data/reports/scope_hash_diff.md")
    args = ap.parse_args()

    new = load(Path(args.new_lock))
    old = load(Path(args.old_lock)) if args.old_lock else {}
    keys = ["scope_hash", "scope_count", "linux_count", "containers_count", "network_devices_count", "direct_behavior_count", "structured_bypass_count", "strict_fixture_count"]
    diff = {key: {"old": old.get(key), "new": new.get(key), "changed": old.get(key) != new.get(key)} for key in keys}
    summary = {"changed": any(v["changed"] for v in diff.values()), "diff": diff}
    out = Path(args.output_json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    md = ["# Scope Hash Diff", "", f"- changed: `{summary['changed']}`", ""]
    for key, value in diff.items():
        md.append(f"- `{key}`: `{value['old']}` -> `{value['new']}`")
    Path(args.output_md).write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({"changed": summary["changed"], "output_json": str(out)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
