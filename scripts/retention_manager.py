#!/usr/bin/env python3
from __future__ import annotations
"""Archive older audit run directories to laji while keeping recent runs active."""

import argparse
import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    ap = argparse.ArgumentParser(description="Archive old audit run directories under laji.")
    ap.add_argument("--output-root", default=".audit_runs")
    ap.add_argument("--archive-root", default="laji/audit_runs")
    ap.add_argument("--keep-latest", type=int, default=10)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    output_root = (ROOT / args.output_root).resolve()
    archive_root = (ROOT / args.archive_root).resolve()
    if not output_root.exists():
        print(json.dumps({"status": "pass", "archived_count": 0, "reason": "output_root_missing"}, ensure_ascii=False))
        return
    if not str(output_root).lower().startswith(str(ROOT).lower()):
        raise SystemExit(f"refusing output root outside workspace: {output_root}")
    if not str(archive_root).lower().startswith(str((ROOT / "laji").resolve()).lower()):
        raise SystemExit(f"refusing archive root outside laji: {archive_root}")

    runs = [p for p in output_root.iterdir() if p.is_dir()]
    runs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    archive = runs[max(args.keep_latest, 0):]
    moved = []
    for run in archive:
        dest = archive_root / run.name
        moved.append({"from": str(run), "to": str(dest)})
        if not args.dry_run:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                dest = archive_root / f"{run.name}_{int(run.stat().st_mtime)}"
            shutil.move(str(run), str(dest))
    print(json.dumps({"status": "pass", "archived_count": len(moved), "dry_run": args.dry_run, "runs": moved}, ensure_ascii=False))


if __name__ == "__main__":
    main()
