#!/usr/bin/env python3
from __future__ import annotations
"""Check that active skill package contains only required runtime assets."""

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ALLOWED_TOP_LEVEL = {"SKILL.md", "README.md", "requirements.txt", "enterprise-attack.json", "attack_data", "schemas", "scripts", "utils", "laji", "evals", "scripts_manifest.json"}
DISALLOWED_ACTIVE_DIRS = {"node_modules", "docs", "tests", "templates", "examples"}
DISALLOWED_ACTIVE_FILES = {"package.json", "package-lock.json", "MANIFEST.json"}


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def main() -> None:
    ap = argparse.ArgumentParser(description="Validate active skill package layout.")
    ap.add_argument("--manifest", default=str(ROOT / "scripts_manifest.json"))
    ap.add_argument("--output-json", default=str(ROOT / "laji" / "attack_data" / "reports" / "package_check.json"))
    ap.add_argument("--output-md", default=str(ROOT / "laji" / "attack_data" / "reports" / "package_check.md"))
    args = ap.parse_args()

    issues = []
    top = {p.name for p in ROOT.iterdir()}
    for name in sorted(top - ALLOWED_TOP_LEVEL):
        issues.append(f"unexpected_top_level_item:{name}")
    for name in sorted(DISALLOWED_ACTIVE_DIRS):
        if (ROOT / name).exists():
            issues.append(f"disallowed_active_directory:{name}")
    for name in sorted(DISALLOWED_ACTIVE_FILES):
        if (ROOT / name).exists():
            issues.append(f"disallowed_active_file:{name}")
    if (ROOT / "attack_data" / "reports").exists():
        issues.append("active_attack_data_reports_directory_present")
    for pycache in ROOT.rglob("__pycache__"):
        if "laji" not in pycache.parts:
            issues.append(f"active_pycache:{pycache.relative_to(ROOT)}")

    manifest = load_manifest(Path(args.manifest))
    active_manifest_names = set()
    for key in ["runtime", "maintenance", "utility", "experimental"]:
        active_manifest_names.update(manifest.get(key, []) or [])
    for name in active_manifest_names:
        if name.endswith(".py") and not (ROOT / "scripts" / name).exists():
            issues.append(f"manifest_script_missing:{name}")

    summary = {
        "status": "pass" if not issues else "fail",
        "issue_count": len(issues),
        "issues": issues,
        "active_top_level": sorted(top),
    }
    out = Path(args.output_json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    md = ["# Package Check", "", f"- status: `{summary['status']}`", f"- issue_count: `{len(issues)}`", "", "## Issues", ""]
    md += [f"- `{issue}`" for issue in issues] or ["- None"]
    Path(args.output_md).write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({"status": summary["status"], "issue_count": len(issues)}, ensure_ascii=False))
    raise SystemExit(0 if not issues else 1)


if __name__ == "__main__":
    main()
