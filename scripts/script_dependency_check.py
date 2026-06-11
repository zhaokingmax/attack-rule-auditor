#!/usr/bin/env python3
from __future__ import annotations
"""Check script manifest, audit DAG script references, and active script files."""

import argparse
import json
from pathlib import Path
from typing import Any

from audit_dag import PHASE_DAG, validate_dag


ROOT = Path(__file__).resolve().parents[1]


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def render_md(summary: dict[str, Any]) -> str:
    lines = [
        "# Script Dependency Check",
        "",
        f"- status: `{summary['status']}`",
        f"- active_script_count: `{summary['active_script_count']}`",
        f"- manifest_script_count: `{summary['manifest_script_count']}`",
        f"- audit_dag_script_count: `{summary['audit_dag_script_count']}`",
        "",
        "## Issues",
        "",
    ]
    lines += [f"- `{issue}`" for issue in summary["issues"]] or ["- None"]
    lines += ["", "## Unclassified Active Scripts", ""]
    lines += [f"- `{name}`" for name in summary["unclassified_active_scripts"]] or ["- None"]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Validate scripts_manifest.json and audit DAG references.")
    ap.add_argument("--manifest", default=str(ROOT / "scripts_manifest.json"))
    ap.add_argument("--scripts-dir", default=str(ROOT / "scripts"))
    ap.add_argument("--output-json", default=str(ROOT / "laji" / "attack_data" / "reports" / "script_dependency_check.json"))
    ap.add_argument("--output-md", default=str(ROOT / "laji" / "attack_data" / "reports" / "script_dependency_check.md"))
    args = ap.parse_args()

    manifest = load_json(Path(args.manifest))
    scripts_dir = Path(args.scripts_dir)
    active = sorted(p.name for p in scripts_dir.glob("*.py"))
    manifest_names = set()
    for key in ["runtime", "maintenance", "utility", "experimental"]:
        manifest_names.update(manifest.get(key, []) or [])
    dag_names = {str(row.get("script")) for row in PHASE_DAG if row.get("script")}

    issues = []
    issues.extend(validate_dag())
    for name in sorted(dag_names):
        if not (scripts_dir / name).exists():
            issues.append(f"dag_script_missing:{name}")
    for name in sorted(manifest_names):
        if name.endswith(".py") and not (scripts_dir / name).exists():
            issues.append(f"manifest_active_script_missing:{name}")
    for name in sorted(dag_names - manifest_names):
        issues.append(f"dag_script_not_in_manifest:{name}")
    unclassified = [name for name in active if name not in manifest_names]

    summary = {
        "status": "pass" if not issues else "fail",
        "active_script_count": len(active),
        "manifest_script_count": len(manifest_names),
        "audit_dag_script_count": len(dag_names),
        "issues": issues,
        "unclassified_active_scripts": unclassified,
        "runtime_scripts": manifest.get("runtime", []),
        "maintenance_scripts": manifest.get("maintenance", []),
        "utility_scripts": manifest.get("utility", []),
    }
    write_json(Path(args.output_json), summary)
    Path(args.output_md).write_text(render_md(summary), encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ["status", "active_script_count", "manifest_script_count", "audit_dag_script_count", "issues"]}, ensure_ascii=False))
    raise SystemExit(0 if summary["status"] == "pass" else 1)


if __name__ == "__main__":
    main()
