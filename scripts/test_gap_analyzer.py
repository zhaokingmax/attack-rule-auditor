#!/usr/bin/env python3
from __future__ import annotations
"""V8 test requirement and gap analyzer for ATT&CK coverage claims.

Generates safe test requirements only. It does not generate exploit payloads.
"""
import argparse, json
from pathlib import Path
from typing import Any, Dict, List


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists(): return []
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


def main():
    ap=argparse.ArgumentParser(description='Generate safe ATT&CK coverage test requirements and test gaps.')
    ap.add_argument('--coverage', required=True)
    ap.add_argument('--behavior-primitives')
    ap.add_argument('--bypass-matrix')
    ap.add_argument('--scenario-model', default='attack_data/models/scenario_attack_model.json')
    ap.add_argument('--scenario', required=True)
    ap.add_argument('--output-jsonl', default='test_gap_analysis.jsonl')
    ap.add_argument('--output-summary', default='test_gap_summary.json')
    args=ap.parse_args()
    coverage=read_jsonl(Path(args.coverage))
    primitives=read_jsonl(Path(args.behavior_primitives)) if args.behavior_primitives else []
    bypass=read_jsonl(Path(args.bypass_matrix)) if args.bypass_matrix else []
    by_tid={}
    for c in coverage:
        if c.get('in_denominator'):
            by_tid.setdefault(c.get('technique_id'), []).append(c)
    rows=[]
    for tid, recs in by_tid.items():
        best=max(recs, key=lambda r: (r.get('coverage_score',0), (r.get('depth_vector') or {}).get('final_depth',0)))
        related_bypass=[b for b in bypass if b.get('technique_id')==tid]
        unchecked=[b for b in related_bypass if b.get('critical') and not b.get('checked')]
        test_status='missing'
        if best.get('coverage_type')=='tested_validated': test_status='positive_fixture_present'
        required=['positive_fixture','negative_fixture','field_chain_fixture']
        if related_bypass: required.append('bypass_variant_fixture')
        gaps=[]
        if best.get('coverage_type')!='tested_validated': gaps.append('missing_positive_or_replay_test')
        gaps.append('missing_negative_test')
        if unchecked or related_bypass: gaps.append('missing_bypass_variant_test')
        if best.get('field_chain_status') not in ['proven','partial']: gaps.append('missing_field_chain_test')
        rows.append({
            'coverage_model_version':'V8',
            'technique_id': tid,
            'technique_name': best.get('technique_name'),
            'scenario': best.get('scenario') or args.scenario,
            'coverage_type': best.get('coverage_type'),
            'test_status': test_status,
            'required_positive_tests': [f'safe fixture that exercises the rule condition for {tid} without executing a real attack'],
            'required_negative_tests': [f'benign administrative or baseline event that should not alert for {tid}'],
            'required_bypass_tests': [f"safe variant fixture for {b.get('bypass_variant')}" for b in related_bypass[:20]],
            'required_field_chain_tests': ['raw event -> parsed event -> normalized event -> rule condition check'],
            'test_gaps': sorted(set(gaps)),
            'unchecked_critical_bypass_variants': [b.get('bypass_variant') for b in unchecked],
            'safe_fixture_policy': 'Generate event fixtures or replay records only; do not generate destructive payloads or exploit code.'
        })
    total=len(rows)
    summary={
        'coverage_model_version':'V8',
        'scenario': args.scenario,
        'attack_test_requirement_count': total,
        'missing_positive_or_replay_test_count': sum(1 for r in rows if 'missing_positive_or_replay_test' in r['test_gaps']),
        'missing_negative_test_count': sum(1 for r in rows if 'missing_negative_test' in r['test_gaps']),
        'missing_bypass_variant_test_count': sum(1 for r in rows if 'missing_bypass_variant_test' in r['test_gaps']),
        'missing_field_chain_test_count': sum(1 for r in rows if 'missing_field_chain_test' in r['test_gaps']),
    }
    write_jsonl(Path(args.output_jsonl), rows)
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__=='__main__': main()
