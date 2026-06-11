#!/usr/bin/env python3
from __future__ import annotations
"""V6 Detection Strategy / Analytic alignment summary."""
import argparse, json
from pathlib import Path
from typing import Any, Dict, List

VALIDATED={'field_chain_validated','tested_validated'}


def read_jsonl(p: Path) -> List[Dict[str, Any]]:
    if not p.exists(): return []
    rows=[]
    for line in p.read_text(encoding='utf-8', errors='ignore').splitlines():
        if line.strip():
            try: rows.append(json.loads(line))
            except Exception: pass
    return rows


def write_jsonl(p: Path, rows: List[Dict[str, Any]]):
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open('w', encoding='utf-8') as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False)+'\n')


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--index', default='attack_data/index')
    ap.add_argument('--coverage', required=True)
    ap.add_argument('--denominator', required=True)
    ap.add_argument('--output-jsonl', default='attack_strategy_alignment.jsonl')
    ap.add_argument('--output-summary', default='attack_strategy_alignment_summary.json')
    args=ap.parse_args()
    lookup=json.load(open(Path(args.index)/'lookup_by_id.json', encoding='utf-8'))
    coverage=read_jsonl(Path(args.coverage)); denominator=read_jsonl(Path(args.denominator))
    best={}
    for r in coverage:
        if not r.get('in_denominator'): continue
        tid=r.get('technique_id')
        if not tid: continue
        if tid not in best or r.get('coverage_score',0)>best[tid].get('coverage_score',0): best[tid]=r
    rows=[]; total_strategy=0; validated_strategy=0; partial_strategy=0; missing_strategy=0
    for d in denominator:
        tid=d.get('technique_id'); rec=lookup.get(tid,{})
        strategies=rec.get('detection_strategies', []) or []
        cov=best.get(tid,{})
        for s in strategies:
            if not isinstance(s, dict): continue
            total_strategy += 1
            if cov.get('coverage_type') in VALIDATED:
                state='covered'
                validated_strategy += 1
            elif cov.get('coverage_type') in ['rule_condition_present','telemetry_supportable','inferred_semantic']:
                state='partial'
                partial_strategy += 1
            else:
                state='missing'
                missing_strategy += 1
            rows.append({
                'technique_id': tid,
                'technique_name': rec.get('name'),
                'detection_strategy_id': s.get('id'),
                'detection_strategy_name': s.get('name'),
                'alignment_state': state,
                'coverage_type': cov.get('coverage_type','none'),
                'required_data_components': rec.get('data_components', []),
                'gap_reason': 'no_validated_rule_for_strategy' if state=='missing' else None,
                'source':'attack_index_detection_strategies'
            })
    summary={
        'strategy_count': total_strategy,
        'strategy_covered_count': validated_strategy,
        'strategy_partial_count': partial_strategy,
        'strategy_missing_count': missing_strategy,
        'strategy_coverage_rate': round(validated_strategy/total_strategy,4) if total_strategy else None,
        'strategy_partial_or_covered_rate': round((validated_strategy+partial_strategy)/total_strategy,4) if total_strategy else None,
    }
    write_jsonl(Path(args.output_jsonl), rows)
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__=='__main__': main()
