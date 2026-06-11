#!/usr/bin/env python3
from __future__ import annotations
"""V8.0 ATT&CK coverage truth gate.

Produces conservative final claims using denominator, subtechnique, data-component,
strategy, field-chain, test, and bypass gates. Raw tags do not become effective
coverage and keyword mentions do not become bypass-resilient coverage.
"""
import argparse, json
from pathlib import Path
from typing import Any, Dict, List

VALIDATED={'field_chain_validated','tested_validated'}
EFFECTIVE={'field_chain_validated','tested_validated'}


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists(): return []
    rows=[]
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        if not line.strip(): continue
        try: rows.append(json.loads(line))
        except Exception: pass
    return rows


def read_json(path: Path, default=None):
    try: return json.load(open(path, encoding='utf-8'))
    except Exception: return default


def write_jsonl(path: Path, rows: List[Dict[str, Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False)+'\n')


def best_records(coverage: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    order={'none':0,'declared_only':1,'candidate_mapping':1,'inferred_semantic':2,'telemetry_supportable':3,'rule_condition_present':4,'field_chain_validated':5,'tested_validated':6}
    best={}
    for r in coverage:
        if not r.get('in_denominator'): continue
        tid=r.get('technique_id')
        if not tid: continue
        score=(order.get(r.get('coverage_type'),0), (r.get('depth_vector') or {}).get('final_depth',0), r.get('coverage_score',0))
        prev=best.get(tid)
        prevscore=(order.get(prev.get('coverage_type'),0), (prev.get('depth_vector') or {}).get('final_depth',0), prev.get('coverage_score',0)) if prev else (-1,-1,-1)
        if score>prevscore: best[tid]=r
    return best


def blockers(record: Dict[str, Any], den: Dict[str, Any], bypass_rows: List[Dict[str, Any]], strategy_rows: List[Dict[str, Any]], test_rows: List[Dict[str, Any]]) -> List[str]:
    out=set(record.get('gap_reason_codes', []) or [])
    ct=record.get('coverage_type')
    if ct in ['none']: out.add('no_rule')
    if ct in ['declared_only','candidate_mapping','inferred_semantic']: out.add('tag_or_inference_only')
    if ct not in EFFECTIVE: out.add('not_field_chain_validated')
    if record.get('field_chain_status') not in ['proven','partial'] and ct in EFFECTIVE:
        out.add('field_chain_status_not_proven')
    if (record.get('depth_vector') or {}).get('final_depth',0) < 3: out.add('insufficient_depth')
    if record.get('coverage_type')!='tested_validated': out.add('test_missing')
    # Denominator issues.
    if den.get('candidate_requires_review') or den.get('review_required'): out.add('candidate_denominator_unreviewed')
    if den.get('coverage_object')=='technique' and '.' not in str(den.get('technique_id','')) and den.get('tier')=='must_cover':
        out.add('parent_or_technique_level_must_cover_requires_subtechnique_review')
    # Data component must set.
    req=den.get('required_data_components') or []
    if req and record.get('coverage_type') in EFFECTIVE and not record.get('matched_required_fields'):
        out.add('data_component_or_required_field_unproven')
    related_b=[b for b in bypass_rows if b.get('technique_id')==record.get('technique_id')]
    if any(b.get('critical') and not b.get('checked') for b in related_b): out.add('critical_bypass_unchecked')
    if related_b and not any(b.get('bypass_check_level') in ['field_chain_checked','resilience_validated','test_checked'] for b in related_b):
        out.add('bypass_only_mentioned_or_unchecked')
    related_s=[s for s in strategy_rows if s.get('technique_id')==record.get('technique_id')]
    if den.get('tier')=='must_cover' and related_s and not any(s.get('alignment') in ['exact','partial','covered','aligned'] or s.get('covered') for s in related_s):
        out.add('strategy_gap')
    related_t=[t for t in test_rows if t.get('technique_id')==record.get('technique_id')]
    if any('missing_bypass_variant_test' in (t.get('test_gaps') or []) for t in related_t): out.add('bypass_test_missing')
    if any('missing_negative_test' in (t.get('test_gaps') or []) for t in related_t): out.add('negative_test_missing')
    return sorted(out)


def final_claim(record: Dict[str, Any], blockers: List[str], related_b: List[Dict[str, Any]]) -> str:
    ct=record.get('coverage_type')
    if ct=='none': return 'not_covered'
    if ct in ['declared_only','candidate_mapping','inferred_semantic']: return 'declared_only'
    if ct in ['telemetry_supportable','rule_condition_present']: return 'supportable_only'
    if ct=='field_chain_validated' and not blockers: return 'field_chain_validated'
    if ct=='tested_validated':
        if 'critical_bypass_unchecked' not in blockers and 'bypass_test_missing' not in blockers and related_b and all((not b.get('critical')) or b.get('checked') for b in related_b):
            return 'resilience_validated'
        return 'tested_validated'
    return 'field_chain_validated' if ct=='field_chain_validated' else 'supportable_only'


def render_truth_report(summary: Dict[str, Any], claims: List[Dict[str, Any]]) -> str:
    lines=['# V8.0 ATT&CK Coverage Truth Report','',
           f"- raw_attack_coverage_rate: `{summary.get('raw_attack_coverage_rate')}`",
           f"- effective_attack_coverage_rate: `{summary.get('effective_attack_coverage_rate')}`",
           f"- tested_coverage_rate: `{summary.get('tested_coverage_rate')}`",
           f"- resilience_validated_rate: `{summary.get('resilience_validated_rate')}`",
           f"- critical_resilience_rate: `{summary.get('critical_resilience_rate')}`",
           f"- critical_bypass_gap_count: `{summary.get('critical_bypass_gap_count')}`",
           f"- complete_coverage_claim: `{summary.get('complete_coverage_claim')}`",
           '', '## Blocking claims', '', '| ATT&CK ID | Tier | Final claim | Blockers |', '|---|---|---|---|']
    for c in claims:
        if c.get('coverage_blockers'):
            lines.append(f"| {c.get('technique_id')} | {c.get('denominator_tier')} | {c.get('final_claim')} | {', '.join(c.get('coverage_blockers'))} |")
    return '\n'.join(lines)+'\n'


def main():
    ap=argparse.ArgumentParser(description='Apply V8 coverage truth gate.')
    ap.add_argument('--coverage', required=True)
    ap.add_argument('--denominator', required=True)
    ap.add_argument('--bypass-matrix', required=True)
    ap.add_argument('--strategy-alignment')
    ap.add_argument('--test-gaps')
    ap.add_argument('--fixture-coverage', help='Optional fixture_coverage.jsonl from fixture_ingest.py')
    ap.add_argument('--alias-findings', help='Optional data_component_alias_findings.jsonl from data_component_alias.py')
    ap.add_argument('--denominator-guard')
    ap.add_argument('--output-claims', default='attack_coverage_truth.jsonl')
    ap.add_argument('--output-summary', default='attack_coverage_truth_summary.json')
    ap.add_argument('--output-report', default='coverage_truth_report.md')
    args=ap.parse_args()
    coverage=read_jsonl(Path(args.coverage)); den_rows=read_jsonl(Path(args.denominator)); bypass=read_jsonl(Path(args.bypass_matrix))
    strategies=read_jsonl(Path(args.strategy_alignment)) if args.strategy_alignment else []
    tests=read_jsonl(Path(args.test_gaps)) if args.test_gaps else []
    fixture_cov=read_jsonl(Path(args.fixture_coverage)) if args.fixture_coverage else []
    alias_rows=read_jsonl(Path(args.alias_findings)) if args.alias_findings else []
    fixture_by_tid={}
    for fx in fixture_cov:
        fixture_by_tid.setdefault(fx.get('technique_id'), []).append(fx)
    alias_by_rule={str(a.get('rule_id')):a for a in alias_rows if a.get('rule_id')}
    den_guard=read_json(Path(args.denominator_guard), {}) if args.denominator_guard else {}
    best=best_records(coverage)
    den_map={d.get('technique_id'):d for d in den_rows if d.get('technique_id')}
    claims=[]
    for d in den_rows:
        tid=d.get('technique_id')
        if not tid: continue
        rec=best.get(tid, {'technique_id':tid,'technique_name':d.get('technique_name'),'coverage_type':'none','strength':'none','confidence':'none','depth_vector':{'final_depth':0},'evidence_ids':[],'gap_reason_codes':['no_rule'],'scenario':d.get('scenario')})
        related_b=[b for b in bypass if b.get('technique_id')==tid]
        bl=blockers(rec, d, bypass, strategies, tests)
        related_fx=fixture_by_tid.get(tid, [])
        fx_types={x.get('fixture_type') or x.get('test_evidence_level') for x in related_fx}
        if related_fx:
            if 'positive' in fx_types and 'test_missing' in bl:
                bl=[x for x in bl if x!='test_missing']
            if 'bypass' in fx_types and 'bypass_test_missing' in bl:
                bl=[x for x in bl if x!='bypass_test_missing']
            if 'negative' in fx_types and 'negative_test_missing' in bl:
                bl=[x for x in bl if x!='negative_test_missing']
        fc=final_claim(rec, bl, related_b)
        if related_fx and fc=='field_chain_validated' and {'positive','negative'} <= fx_types:
            fc='tested_validated'
        if related_fx and fc=='tested_validated' and 'bypass' in fx_types and related_b and all((not b.get('critical')) or b.get('checked') for b in related_b):
            fc='resilience_validated'
        claims.append({
            'coverage_model_version':'V8.0',
            'technique_id': tid,
            'technique_name': rec.get('technique_name'),
            'scenario': rec.get('scenario') or d.get('scenario'),
            'denominator_tier': d.get('tier') or rec.get('denominator_tier'),
            'coverage_object': d.get('coverage_object'),
            'coverage_type': rec.get('coverage_type'),
            'claim_strength': fc,
            'final_claim': fc,
            'depth_vector': rec.get('depth_vector'),
            'confidence': rec.get('confidence'),
            'evidence_ids': rec.get('evidence_ids', []),
            'field_chain_status': rec.get('field_chain_status'),
            'strategy_status': 'aligned_or_not_applicable' if any(s.get('technique_id')==tid for s in strategies) else 'not_aligned_or_not_modeled',
            'test_status': 'fixture_supported' if related_fx else ('tested' if rec.get('coverage_type')=='tested_validated' else 'not_tested'),
            'fixture_evidence_count': len(related_fx),
            'fixture_types': sorted(x for x in fx_types if x),
            'bypass_variant_total': len(related_b),
            'critical_bypass_total': sum(1 for b in related_b if b.get('critical')),
            'critical_bypass_checked': sum(1 for b in related_b if b.get('critical') and b.get('checked')),
            'coverage_blockers': bl,
            'falsifiable_claim': f"Covers {tid} only when behavior evidence, condition evidence, required Data Components, field chain, checked critical bypass variants, and fixture evidence where claimed are present for the declared scenario.",
        })
    total=len(claims)
    raw=sum(1 for c in claims if c['coverage_type'] not in ['none'])
    effective=sum(1 for c in claims if c['final_claim'] in ['field_chain_validated','tested_validated','resilience_validated'])
    tested=sum(1 for c in claims if c['final_claim'] in ['tested_validated','resilience_validated'])
    resilient=sum(1 for c in claims if c['final_claim']=='resilience_validated')
    must=[c for c in claims if c.get('denominator_tier')=='must_cover']
    must_res=sum(1 for c in must if c['final_claim']=='resilience_validated')
    critical_gap=sum(max(0, c.get('critical_bypass_total',0)-c.get('critical_bypass_checked',0)) for c in claims)
    field_block=sum(1 for c in claims if 'missing_field_chain' in c.get('coverage_blockers', []) or 'not_field_chain_validated' in c.get('coverage_blockers', []))
    summary={
        'coverage_model_version':'V8.0',
        'denominator_count': total,
        'denominator_confidence': den_guard.get('denominator_confidence'),
        'denominator_hash': den_guard.get('denominator_hash'),
        'raw_attack_coverage_rate': round(raw/total,4) if total else None,
        'effective_attack_coverage_rate': round(effective/total,4) if total else None,
        'tested_coverage_rate': round(tested/total,4) if total else None,
        'resilience_validated_rate': round(resilient/total,4) if total else None,
        'critical_denominator_count': len(must),
        'critical_resilience_count': must_res,
        'critical_resilience_rate': round(must_res/len(must),4) if must else None,
        'critical_bypass_gap_count': critical_gap,
        'weak_only_critical_count': sum(1 for c in must if c.get('coverage_type') in ['declared_only','candidate_mapping','inferred_semantic','telemetry_supportable','rule_condition_present']),
        'missing_test_count': sum(1 for c in claims if c.get('test_status')!='tested'),
        'field_chain_blocker_count': field_block,
        'parent_only_count': sum(1 for c in claims if 'parent_only' in c.get('coverage_blockers', []) or 'parent_or_technique_level_must_cover_requires_subtechnique_review' in c.get('coverage_blockers', [])),
        'data_component_gap_count': sum(1 for c in claims if 'data_component_or_required_field_unproven' in c.get('coverage_blockers', [])),
        'strategy_gap_count': sum(1 for c in claims if 'strategy_gap' in c.get('coverage_blockers', [])),
        'fixture_supported_claim_count': sum(1 for c in claims if c.get('fixture_evidence_count',0)>0),
    }
    complete = bool(total and resilient==total and critical_gap==0 and (not must or must_res==len(must)) and den_guard.get('denominator_confidence')=='high')
    summary['complete_coverage_claim']='Yes' if complete else ('Partial' if resilient else 'No')
    summary['complete_coverage_gate_passed']=complete
    write_jsonl(Path(args.output_claims), claims)
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    Path(args.output_report).write_text(render_truth_report(summary, claims), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__=='__main__': main()
