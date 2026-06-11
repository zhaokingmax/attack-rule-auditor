#!/usr/bin/env python3
from __future__ import annotations
"""Compare two completed V8/V8.0 audit runs on shared ATT&CK denominator and bypass resilience."""
import argparse, json
from pathlib import Path
from typing import Any, Dict, List

def read_jsonl(p: Path) -> List[Dict[str, Any]]:
    if not p.exists(): return []
    out=[]
    for line in p.read_text(encoding='utf-8', errors='ignore').splitlines():
        if line.strip():
            try: out.append(json.loads(line))
            except Exception: pass
    return out

def load_json(p: Path, default=None):
    try: return json.load(open(p, encoding='utf-8'))
    except Exception: return default

def claim_map(run: Path):
    rows=read_jsonl(run/'attack_coverage_truth.jsonl') or read_jsonl(run/'attack_coverage_claims.jsonl')
    return {r.get('technique_id'):r for r in rows if r.get('technique_id')}

def den_set(run: Path):
    return {r.get('technique_id') for r in read_jsonl(run/'attack_denominator.jsonl') if r.get('technique_id')}

def strength(c):
    order={'not_covered':0,'declared_only':1,'supportable_only':2,'field_chain_validated':3,'tested_validated':4,'resilience_validated':5}
    return order.get((c or {}).get('final_claim') or (c or {}).get('claim_strength'),0)

def main():
    ap=argparse.ArgumentParser(description='A/B comparison using shared denominator and resilience-normalized claims.')
    ap.add_argument('--a-run', required=True)
    ap.add_argument('--b-run', required=True)
    ap.add_argument('--output-json', default='ab_resilience_comparison.json')
    ap.add_argument('--output-md', default='ab_resilience_comparison.md')
    args=ap.parse_args()
    a=Path(args.a_run); b=Path(args.b_run)
    da, db=den_set(a), den_set(b); shared=sorted(da & db)
    ca, cb=claim_map(a), claim_map(b)
    rows=[]
    for tid in shared:
        aa, bb=ca.get(tid,{}), cb.get(tid,{})
        sa, sb=strength(aa), strength(bb)
        if sa>sb: winner='A'
        elif sb>sa: winner='B'
        else: winner='tie'
        rows.append({'technique_id':tid,'a_claim':aa.get('final_claim'),'b_claim':bb.get('final_claim'),'a_blockers':aa.get('coverage_blockers',[]),'b_blockers':bb.get('coverage_blockers',[]),'winner':winner})
    summary={
        'coverage_model_version':'V8.0',
        'a_run': str(a), 'b_run': str(b),
        'a_denominator_count': len(da), 'b_denominator_count': len(db), 'shared_denominator_count': len(shared),
        'a_only_denominator_count': len(da-db), 'b_only_denominator_count': len(db-da),
        'a_stronger_count': sum(1 for r in rows if r['winner']=='A'),
        'b_stronger_count': sum(1 for r in rows if r['winner']=='B'),
        'tie_count': sum(1 for r in rows if r['winner']=='tie'),
        'comparison_mode': 'shared_denominator' if shared else 'complementary_only',
        'shared_results': rows,
    }
    Path(args.output_json).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    md=['# A/B Resilience-Normalized ATT&CK Coverage Comparison','',f"- A denominator: `{len(da)}`",f"- B denominator: `{len(db)}`",f"- Shared denominator: `{len(shared)}`",f"- Comparison mode: `{summary['comparison_mode']}`",'', '| ATT&CK ID | A claim | B claim | Winner |', '|---|---|---|---|']
    for r in rows[:200]: md.append(f"| {r['technique_id']} | {r.get('a_claim')} | {r.get('b_claim')} | {r['winner']} |")
    Path(args.output_md).write_text('\n'.join(md)+'\n', encoding='utf-8')
    print(json.dumps({k:v for k,v in summary.items() if k!='shared_results'}, ensure_ascii=False))
if __name__=='__main__': main()
