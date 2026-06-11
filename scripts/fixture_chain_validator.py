#!/usr/bin/env python3
from __future__ import annotations
"""V8.1 fixture-chain validator.

Consumes safe static fixtures produced by fixture_ingest.py and checks whether a
claim has evidence across raw_event -> parsed_event -> normalized_event -> expected_alert.
It never executes payloads and never generates attack steps; it only evaluates user-provided
fixture metadata and event-shaped JSON/YAML.
"""
import argparse, json
from pathlib import Path
from typing import Any, Dict, List

REQUIRED_STAGES = ['raw_event','parsed_event','normalized_event','expected_alert']


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


def norm_stage(s: str) -> str:
    s=(s or '').lower()
    if s in ['raw','raw_event','collector','collector_event']: return 'raw_event'
    if s in ['parsed','parsed_event','parser']: return 'parsed_event'
    if s in ['normalized','normalized_event','normalizer']: return 'normalized_event'
    if s in ['alert','expected_alert','expected','detection_alert']: return 'expected_alert'
    return s


def main():
    ap=argparse.ArgumentParser(description='Validate user-provided fixture chains without executing anything.')
    ap.add_argument('--fixture-inventory', required=True)
    ap.add_argument('--fixture-coverage', required=True)
    ap.add_argument('--coverage', required=True)
    ap.add_argument('--output-jsonl', default='fixture_chain_validation.jsonl')
    ap.add_argument('--output-summary', default='fixture_chain_validation_summary.json')
    args=ap.parse_args()
    inv=read_jsonl(Path(args.fixture_inventory)); cov_map=read_jsonl(Path(args.fixture_coverage)); coverage=read_jsonl(Path(args.coverage))
    cov_tids={r.get('technique_id') for r in coverage if r.get('technique_id')}
    inv_by_id={r.get('fixture_id'):r for r in inv}
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for m in cov_map:
        tid=m.get('technique_id')
        if tid: groups.setdefault(tid, []).append(m)
    rows=[]
    for tid, maps in sorted(groups.items()):
        stages=set(); types=set(); paths=[]; primitives=set(); variants=set()
        for m in maps:
            fid=m.get('fixture_id'); item=inv_by_id.get(fid,{})
            types.add(m.get('fixture_type') or item.get('fixture_type') or 'unknown')
            primitives.add(m.get('expected_behavior_primitive') or item.get('expected_behavior_primitive') or '')
            variants.add(m.get('expected_bypass_variant') or item.get('expected_bypass_variant') or '')
            paths.append(m.get('path') or item.get('path'))
            for st in item.get('event_stages') or []:
                stages.add(norm_stage(st))
        missing=[s for s in REQUIRED_STAGES if s not in stages]
        positive='positive' in types
        negative='negative' in types
        bypass='bypass' in types
        field_chain=('field_chain' in types) or not missing
        chain_status='complete' if not missing else ('partial' if stages else 'missing')
        max_upgrade='resilience_validated' if positive and negative and bypass and field_chain and not missing else ('tested_validated' if positive and negative and field_chain else ('field_chain_validated' if field_chain else 'condition_present'))
        rows.append({
            'coverage_model_version':'V8.1',
            'technique_id': tid,
            'matches_existing_coverage': tid in cov_tids,
            'fixture_count': len(maps),
            'fixture_types': sorted(x for x in types if x),
            'event_stages_present': sorted(stages),
            'event_stages_missing': missing,
            'fixture_chain_status': chain_status,
            'has_positive_fixture': positive,
            'has_negative_fixture': negative,
            'has_bypass_fixture': bypass,
            'has_field_chain_fixture': field_chain,
            'expected_behavior_primitives': sorted(x for x in primitives if x),
            'expected_bypass_variants': sorted(x for x in variants if x),
            'max_claim_upgrade': max_upgrade,
            'fixture_paths': [p for p in paths if p],
            'safe_static_only': True,
        })
    summary={
        'coverage_model_version':'V8.1',
        'technique_count_with_fixtures': len(rows),
        'complete_chain_count': sum(1 for r in rows if r['fixture_chain_status']=='complete'),
        'positive_fixture_technique_count': sum(1 for r in rows if r['has_positive_fixture']),
        'negative_fixture_technique_count': sum(1 for r in rows if r['has_negative_fixture']),
        'bypass_fixture_technique_count': sum(1 for r in rows if r['has_bypass_fixture']),
        'resilience_upgrade_candidate_count': sum(1 for r in rows if r['max_claim_upgrade']=='resilience_validated'),
        'safe_static_only': True,
    }
    write_jsonl(Path(args.output_jsonl), rows)
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__=='__main__': main()
