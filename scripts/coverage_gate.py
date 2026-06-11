#!/usr/bin/env python3
from __future__ import annotations
"""V6 coverage gate and resilience claim generator."""
import argparse, json
from pathlib import Path
from typing import Any, Dict, List

VALIDATED_TYPES={'field_chain_validated','tested_validated'}
STRONG={'strong','deep'}


def read_jsonl(p: Path) -> List[Dict[str, Any]]:
    if not p.exists(): return []
    rows=[]
    for line in p.read_text(encoding='utf-8', errors='ignore').splitlines():
        if not line.strip(): continue
        try: rows.append(json.loads(line))
        except Exception: pass
    return rows


def write_jsonl(p: Path, rows: List[Dict[str, Any]]):
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open('w', encoding='utf-8') as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False)+'\n')


def best_records(coverage: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    best={}
    for r in coverage:
        if not r.get('in_denominator'): continue
        tid=r.get('technique_id')
        if not tid: continue
        prev=best.get(tid)
        if prev is None or r.get('coverage_score',0) > prev.get('coverage_score',0):
            best[tid]=r
    return best


def blockers_for_record(r: Dict[str, Any], bypass_rows: List[Dict[str, Any]]) -> List[str]:
    blockers=[]
    gap=set(r.get('gap_reason_codes', []) or [])
    for g in ['parent_only','ioc_only','tool_name_only','missing_field_chain','log_source_mismatch','wrong_platform','no_evidence_ids']:
        if g in gap: blockers.append(g)
    if r.get('coverage_type') not in VALIDATED_TYPES:
        blockers.append('not_field_chain_or_test_validated')
    if (r.get('depth_vector') or {}).get('final_depth',0) < 3:
        blockers.append('insufficient_depth')
    related=[b for b in bypass_rows if b.get('technique_id')==r.get('technique_id')]
    if any(b.get('blocking_coverage') for b in related):
        blockers.append('critical_bypass_unchecked')
    if not related and r.get('denominator_tier')=='must_cover':
        blockers.append('no_bypass_model_for_must_cover')
    if r.get('coverage_type') != 'tested_validated':
        blockers.append('missing_tested_validation')
    return sorted(set(blockers))


def final_claim(r: Dict[str, Any], blockers: List[str]) -> str:
    if r.get('coverage_type')=='none': return 'not_covered'
    if r.get('coverage_type') in ['declared_only','candidate_mapping','inferred_semantic']: return 'declared_or_inferred_only'
    if r.get('coverage_type') in ['telemetry_supportable','rule_condition_present']: return 'supportable_or_condition_only'
    if not blockers or blockers==['missing_tested_validation']:
        return 'resilience_validated' if r.get('coverage_type')=='tested_validated' else 'field_chain_validated_not_resilience_tested'
    if 'critical_bypass_unchecked' in blockers:
        return 'validated_but_bypass_gap'
    return 'validated_with_blockers'


def render_blockers(claims: List[Dict[str, Any]], summary: Dict[str, Any]) -> str:
    lines=['# ATT&CK Coverage Blockers', '', f"- scenario: `{summary.get('scenario')}`", f"- denominator_count: `{summary.get('denominator_count')}`", f"- resilience_validated_rate: `{summary.get('resilience_validated_rate')}`", f"- critical_resilience_rate: `{summary.get('critical_resilience_rate')}`", '', '## Blocking claims', '', '| ATT&CK ID | Name | Tier | Final claim | Blockers |', '|---|---|---|---|---|']
    for c in claims:
        if c.get('coverage_blockers'):
            lines.append(f"| {c.get('technique_id')} | {c.get('technique_name')} | {c.get('denominator_tier')} | {c.get('final_claim')} | {', '.join(c.get('coverage_blockers'))} |")
    return '\n'.join(lines)+'\n'


def render_falsifiability(claims: List[Dict[str, Any]]) -> str:
    lines=['# Coverage Falsifiability Questions', '', 'Strong or deep ATT&CK coverage claims must remain falsifiable. For each claim, validate whether the rule triggers and whether common variants bypass it.', '']
    for c in claims:
        if c.get('final_claim') in ['resilience_validated','field_chain_validated_not_resilience_tested','validated_but_bypass_gap'] or c.get('denominator_tier')=='must_cover':
            lines += [f"## {c.get('technique_id')} {c.get('technique_name')}", '', f"- Current final claim: `{c.get('final_claim')}`", f"- Coverage type: `{c.get('coverage_type')}`", f"- Evidence IDs: `{', '.join(c.get('evidence_ids', [])) or 'none'}`", '- Falsify trigger claim: produce a benign/safe fixture with the expected fields and confirm whether the alert condition fires.', '- Falsify resilience claim: replay safe variant fixtures for the listed unchecked bypass primitives.', '- Field-chain failure mode: remove or rename one must-have field and confirm the coverage drops instead of silently passing.', '']
    return '\n'.join(lines)+'\n'


def main():
    ap=argparse.ArgumentParser(description='Apply V6 resilience coverage gates and generate claim artifacts.')
    ap.add_argument('--coverage', required=True)
    ap.add_argument('--denominator', required=True)
    ap.add_argument('--bypass-matrix', required=True)
    ap.add_argument('--summary')
    ap.add_argument('--output-claims', default='attack_coverage_claims.jsonl')
    ap.add_argument('--output-summary', default='resilient_coverage_summary.json')
    ap.add_argument('--output-blockers-md', default='attack_coverage_blockers.md')
    ap.add_argument('--output-falsifiability-md', default='coverage_falsifiability.md')
    args=ap.parse_args()
    cov=read_jsonl(Path(args.coverage)); den=read_jsonl(Path(args.denominator)); bypass=read_jsonl(Path(args.bypass_matrix))
    den_ids=[d.get('technique_id') for d in den if d.get('technique_id')]
    den_map={d.get('technique_id'):d for d in den}
    best=best_records(cov)
    claims=[]
    for tid in den_ids:
        r=best.get(tid, {'technique_id':tid,'technique_name':den_map.get(tid,{}).get('technique_name'),'coverage_type':'none','strength':'none','confidence':'none','depth_vector':{'final_depth':0},'evidence_ids':[],'gap_reason_codes':['no_rule'],'denominator_tier':den_map.get(tid,{}).get('tier')})
        b=blockers_for_record(r,bypass)
        claim=final_claim(r,b)
        related=[x for x in bypass if x.get('technique_id')==tid]
        checked=sum(1 for x in related if x.get('checked'))
        claims.append({
            'technique_id': tid,
            'technique_name': r.get('technique_name'),
            'scenario': r.get('scenario') or den_map.get(tid,{}).get('scenario'),
            'denominator_tier': r.get('denominator_tier') or den_map.get(tid,{}).get('tier'),
            'coverage_type': r.get('coverage_type'),
            'strength': r.get('strength'),
            'confidence': r.get('confidence'),
            'depth_vector': r.get('depth_vector'),
            'evidence_ids': r.get('evidence_ids', []),
            'field_chain_status': r.get('field_chain_status'),
            'test_status': 'tested' if r.get('coverage_type')=='tested_validated' else 'not_tested',
            'bypass_primitives_total': len(related),
            'bypass_primitives_checked': checked,
            'critical_bypass_unchecked': sum(1 for x in related if x.get('critical') and not x.get('checked')),
            'coverage_blockers': b,
            'final_claim': claim,
        })
    total=len(den_ids)
    validated=sum(1 for c in claims if c.get('coverage_type') in VALIDATED_TYPES)
    resilience=sum(1 for c in claims if c.get('final_claim')=='resilience_validated')
    must=[c for c in claims if c.get('denominator_tier')=='must_cover']
    must_resilience=sum(1 for c in must if c.get('final_claim')=='resilience_validated')
    bypass_gap=sum(c.get('critical_bypass_unchecked',0) for c in claims)
    summary={
        'coverage_model_version':'V6',
        'scenario': claims[0].get('scenario') if claims else None,
        'denominator_count': total,
        'effective_validated_count': validated,
        'effective_validated_rate': round(validated/total,4) if total else None,
        'resilience_validated_count': resilience,
        'resilience_validated_rate': round(resilience/total,4) if total else None,
        'critical_denominator_count': len(must),
        'critical_resilience_count': must_resilience,
        'critical_resilience_rate': round(must_resilience/len(must),4) if must else None,
        'bypass_gap_count': bypass_gap,
        'complete_coverage_gate_passed': bool(total and resilience==total and bypass_gap==0 and (not must or must_resilience==len(must))),
        'blocking_reasons': []
    }
    if summary['bypass_gap_count']: summary['blocking_reasons'].append('critical_bypass_unchecked')
    if total and resilience < total: summary['blocking_reasons'].append('not_all_denominator_resilience_validated')
    if must and must_resilience < len(must): summary['blocking_reasons'].append('must_cover_not_resilience_validated')
    write_jsonl(Path(args.output_claims), claims)
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    Path(args.output_blockers_md).write_text(render_blockers(claims, summary), encoding='utf-8')
    Path(args.output_falsifiability_md).write_text(render_falsifiability(claims), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__=='__main__': main()
