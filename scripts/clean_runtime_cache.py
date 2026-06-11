#!/usr/bin/env python3
from __future__ import annotations
"""Move active Python __pycache__ directories under laji."""

import argparse
import json
import shutil
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    ap = argparse.ArgumentParser(description="Archive active __pycache__ directories to laji.")
    ap.add_argument("--archive-root", default="laji/scripts")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    archive_root = (ROOT / args.archive_root).resolve()
    if not str(archive_root).lower().startswith(str((ROOT / "laji").resolve()).lower()):
        raise SystemExit(f"refusing archive root outside laji: {archive_root}")
    moved = []
    for cache in sorted(ROOT.rglob("__pycache__")):
        if "laji" in cache.parts:
            continue
        rel = cache.relative_to(ROOT)
        dest = archive_root / ("__pycache___" + time.strftime("%Y%m%d_%H%M%S") + "_" + "_".join(rel.parts[:-1] or ["root"]))
        moved.append({"from": str(cache), "to": str(dest)})
        if not args.dry_run:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(cache), str(dest))
    print(json.dumps({"moved_count": len(moved), "dry_run": args.dry_run, "moved": moved}, ensure_ascii=False))


if __name__ == "__main__":
    main()
