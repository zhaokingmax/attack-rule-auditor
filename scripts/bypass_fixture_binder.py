#!/usr/bin/env python3
from __future__ import annotations
"""Bind user-provided bypass fixtures to V8/V8.1 attack paths.

A binding is conservative: a fixture must match the same ATT&CK ID and either the
same bypass variant or the same behavior primitive. This avoids treating generic
positive tests as bypass-resilience proof.
"""
import argparse, json, re
from pathlib import Path
from typing import Any, Dict, List


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path or not path.exists(): return []
    rows=[]
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        if not line.strip(): continue
        try: rows.append(json.loads(line))
        except Exception: pass
    return rows


def write_jsonl(path: Path, rows: List[Dict[str, Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False)+'\n')


def norm(x: Any) -> str:
    return re.sub(r'[^a-z0-9]+','_', str(x or '').lower()).strip('_')


def main():
    ap=argparse.ArgumentParser(description='Bind bypass fixtures to attack_path_matrix rows.')
    ap.add_argument('--attack-paths', required=True)
    ap.add_argument('--fixture-coverage', required=True)
    ap.add_argument('--output-jsonl', default='bypass_fixture_bindings.jsonl')
    ap.add_argument('--output-summary', default='bypass_fixture_binding_summary.json')
    args=ap.parse_args()
    paths=read_jsonl(Path(args.attack_paths)); fixtures=read_jsonl(Path(args.fixture_coverage))
    bindings=[]
    for p in paths:
        tid=p.get('technique_id')
        pprim=norm(p.get('behavior_primitive'))
        pvar=norm(p.get('bypass_variant'))
        for f in fixtures:
            if f.get('technique_id') != tid: continue
            if f.get('fixture_type') not in ['bypass','variant','field_chain','positive','negative']: continue
            fprim=norm(f.get('expected_behavior_primitive'))
            fvar=norm(f.get('expected_bypass_variant'))
            match_variant=bool(pvar and fvar and (pvar==fvar or pvar in fvar or fvar in pvar))
            match_primitive=bool(pprim and fprim and (pprim==fprim or pprim in fprim or fprim in pprim))
            if match_variant or match_primitive:
                bindings.append({
                    'coverage_model_version':'V8.1',
                    'attack_path_id': p.get('attack_path_id'),
                    'technique_id': tid,
                    'behavior_primitive': p.get('behavior_primitive'),
                    'bypass_variant': p.get('bypass_variant'),
                    'fixture_id': f.get('fixture_id'),
                    'fixture_type': f.get('fixture_type'),
                    'fixture_path': f.get('path'),
                    'binding_reason': 'variant_match' if match_variant else 'primitive_match',
                    'binding_strength': 'strong' if match_variant and f.get('fixture_type')=='bypass' else 'medium',
                    'safe_static_only': True,
                })
    covered_paths={b.get('attack_path_id') for b in bindings if b.get('binding_strength')=='strong'}
    critical_paths={p.get('attack_path_id') for p in paths if p.get('attack_path_critical') or p.get('critical')}
    summary={
        'coverage_model_version':'V8.1',
        'attack_path_count': len(paths),
        'binding_count': len(bindings),
        'strong_binding_count': sum(1 for b in bindings if b.get('binding_strength')=='strong'),
        'critical_attack_path_count': len([x for x in critical_paths if x]),
        'critical_attack_path_with_bypass_fixture_count': len([x for x in critical_paths if x in covered_paths]),
        'critical_bypass_fixture_rate': round(len([x for x in critical_paths if x in covered_paths]) / len([x for x in critical_paths if x]),4) if len([x for x in critical_paths if x]) else None,
        'safe_static_only': True,
    }
    write_jsonl(Path(args.output_jsonl), bindings)
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__=='__main__': main()
