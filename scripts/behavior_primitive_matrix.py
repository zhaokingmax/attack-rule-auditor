#!/usr/bin/env python3
from __future__ import annotations
"""V8 behavior primitive coverage matrix.

Maps scenario behavior primitives to ATT&CK IDs, coverage records, data components,
and bypass checks. This prevents one ATT&CK ID match from hiding missing attack paths.
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


def best_by_attack(coverage: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    order={'none':0,'declared_only':1,'candidate_mapping':1,'inferred_semantic':2,'telemetry_supportable':3,'rule_condition_present':4,'field_chain_validated':5,'tested_validated':6}
    best={}
    for r in coverage:
        tid=r.get('technique_id')
        if not tid: continue
        score=(order.get(r.get('coverage_type'),0), (r.get('depth_vector') or {}).get('final_depth',0), r.get('coverage_score',0))
        prev=best.get(tid)
        prevscore=(order.get(prev.get('coverage_type'),0), (prev.get('depth_vector') or {}).get('final_depth',0), prev.get('coverage_score',0)) if prev else (-1,-1,-1)
        if score>prevscore: best[tid]=r
    return best


def main():
    ap=argparse.ArgumentParser(description='Generate scenario behavior primitive coverage matrix.')
    ap.add_argument('--scenario-model', default='attack_data/models/scenario_attack_model.json')
    ap.add_argument('--scenario', required=True)
    ap.add_argument('--coverage', required=True)
    ap.add_argument('--bypass-matrix')
    ap.add_argument('--output-jsonl', default='behavior_primitive_matrix.jsonl')
    ap.add_argument('--output-summary', default='behavior_primitive_summary.json')
    args=ap.parse_args()
    model=json.load(open(args.scenario_model, encoding='utf-8')) if Path(args.scenario_model).exists() else {}
    cfg=model.get(args.scenario, {})
    primitives=cfg.get('behavior_primitives', [])
    bypass=read_jsonl(Path(args.bypass_matrix)) if args.bypass_matrix else []
    cov=best_by_attack(read_jsonl(Path(args.coverage)))
    rows=[]
    for p in primitives:
        aids=p.get('attack_ids', []) or []
        related=[cov[a] for a in aids if a in cov]
        best_type='none'; best_depth=0; evidence=[]; blockers=[]
        for r in related:
            ct=r.get('coverage_type') or 'none'
            order=['none','declared_only','candidate_mapping','inferred_semantic','telemetry_supportable','rule_condition_present','field_chain_validated','tested_validated']
            if order.index(ct) > order.index(best_type): best_type=ct
            best_depth=max(best_depth, (r.get('depth_vector') or {}).get('final_depth',0))
            evidence += r.get('evidence_ids', []) or []
            blockers += r.get('gap_reason_codes', []) or []
        bypass_related=[b for b in bypass if b.get('behavior_primitive')==p.get('id') or b.get('behavior_primitive_id')==p.get('id') or b.get('bypass_variant')==p.get('id')]
        critical_total=sum(1 for b in bypass_related if b.get('critical'))
        critical_checked=sum(1 for b in bypass_related if b.get('critical') and b.get('checked'))
        resilience='not_modeled'
        if bypass_related:
            resilience='resilience_checked' if critical_total and critical_checked==critical_total else 'bypass_gap'
        if best_type in ['none','declared_only','candidate_mapping','inferred_semantic']:
            primitive_claim='not_effectively_covered'
        elif best_type in ['telemetry_supportable','rule_condition_present']:
            primitive_claim='supportable_or_condition_only'
        elif resilience=='resilience_checked' and best_type=='tested_validated':
            primitive_claim='resilience_validated'
        else:
            primitive_claim='validated_but_not_resilience_validated'
        rows.append({
            'scenario': args.scenario,
            'behavior_primitive_id': p.get('id'),
            'description': p.get('description'),
            'attack_ids': aids,
            'required_data_components': p.get('required_data_components', []),
            'required_fields': p.get('required_fields', []),
            'data_component_minimum_sets': p.get('data_component_minimum_sets', []),
            'critical': bool(p.get('critical')),
            'coverage_type_best': best_type,
            'final_depth_best': best_depth,
            'evidence_ids': sorted(set(evidence)),
            'coverage_blockers': sorted(set(blockers)),
            'bypass_variant_total': len(bypass_related),
            'critical_bypass_total': critical_total,
            'critical_bypass_checked': critical_checked,
            'resilience_status': resilience,
            'primitive_claim': primitive_claim,
            'source': 'scenario_attack_model',
        })
    total=len(rows)
    resilience=sum(1 for r in rows if r['primitive_claim']=='resilience_validated')
    effective=sum(1 for r in rows if r['coverage_type_best'] in ['field_chain_validated','tested_validated'])
    summary={
        'coverage_model_version':'V8',
        'scenario': args.scenario,
        'behavior_primitive_count': total,
        'effective_behavior_primitive_count': effective,
        'effective_behavior_primitive_rate': round(effective/total,4) if total else None,
        'resilience_validated_behavior_primitive_count': resilience,
        'resilience_validated_behavior_primitive_rate': round(resilience/total,4) if total else None,
        'not_effectively_covered_count': sum(1 for r in rows if r['primitive_claim']=='not_effectively_covered'),
        'bypass_gap_primitive_count': sum(1 for r in rows if r['resilience_status']=='bypass_gap'),
    }
    write_jsonl(Path(args.output_jsonl), rows)
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__=='__main__': main()
