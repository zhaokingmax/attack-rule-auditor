#!/usr/bin/env python3
from __future__ import annotations
"""Report whether expensive generated artifacts are current enough to reuse."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def main() -> None:
    ap = argparse.ArgumentParser(description="Check cache status for ATT&CK index and model lint artifacts.")
    ap.add_argument("--enterprise-attack", default="enterprise-attack.json")
    ap.add_argument("--index-metadata", default="attack_data/index/metadata.json")
    ap.add_argument("--scope-lock", default="attack_data/index/linux_container_k8s_network_scope.lock.json")
    ap.add_argument("--output-json", default="laji/attack_data/reports/cache_status.json")
    args = ap.parse_args()

    src = ROOT / args.enterprise_attack
    metadata = load_json(ROOT / args.index_metadata)
    source_hash = sha256(src)
    index_hash = metadata.get("source_sha256")
    scope_lock_exists = (ROOT / args.scope_lock).exists()
    status = {
        "enterprise_attack": str(src),
        "source_sha256": source_hash,
        "index_source_sha256": index_hash,
        "index_cache_current": bool(source_hash and index_hash and source_hash == index_hash),
        "scope_lock_exists": scope_lock_exists,
        "recommendations": [],
    }
    if not status["index_cache_current"]:
        status["recommendations"].append("rebuild attack_data/index with build_attack_index.py")
    if not scope_lock_exists:
        status["recommendations"].append("rebuild scope lock with build_scope_lock.py")
    out = ROOT / args.output_json
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(status, ensure_ascii=False))


if __name__ == "__main__":
    main()
