#!/usr/bin/env python3
from __future__ import annotations
"""V8 ATT&CK claim falsification engine.

Combines coverage, denominator, Data Component, attack paths, bypass variants,
condition AST, field-chain/test evidence into conservative final claims.
"""
import argparse, json, hashlib
from pathlib import Path
from typing import Any, Dict, List

FINAL_ORDER=['not_covered','declared_only','supportable_only','condition_present','field_chain_validated','tested_validated','resilience_validated']


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists(): return []
    rows=[]
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        if not line.strip(): continue
        try: rows.append(json.loads(line))
        except Exception: pass
    return rows


def read_json(path: Path, default=None):
    try: return json.load(open(path,encoding='utf-8'))
    except Exception: return default if default is not None else {}


def write_jsonl(path: Path, rows: List[Dict[str, Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False)+'\n')


def claim_id(*parts): return hashlib.sha256('|'.join(str(p or '') for p in parts).encode()).hexdigest()[:20]


def best_coverage(rows):
    score={'none':0,'candidate_mapping':1,'declared_only':1,'inferred_semantic':2,'telemetry_supportable':3,'rule_condition_present':4,'field_chain_validated':5,'tested_validated':6}
    out={}
    for r in rows:
        tid=r.get('technique_id')
        if not tid: continue
        if tid not in out or score.get(r.get('coverage_type'),0)>score.get(out[tid].get('coverage_type'),0):
            out[tid]=r
    return out


def base_claim(c):
    ct=(c or {}).get('coverage_type','none')
    if ct in ['none','candidate_mapping']: return 'not_covered'
    if ct in ['declared_only','inferred_semantic']: return 'declared_only'
    if ct in ['telemetry_supportable']: return 'supportable_only'
    if ct in ['rule_condition_present']: return 'condition_present'
    if ct=='field_chain_validated': return 'field_chain_validated'
    if ct=='tested_validated': return 'tested_validated'
    return 'not_covered'


def downgrade(claim, target):
    return FINAL_ORDER[min(FINAL_ORDER.index(claim), FINAL_ORDER.index(target))]


def main():
    ap=argparse.ArgumentParser(description='Falsify and downgrade ATT&CK coverage claims based on V8 gates.')
    ap.add_argument('--coverage', required=True)
    ap.add_argument('--denominator', required=True)
    ap.add_argument('--attack-paths', required=True)
    ap.add_argument('--data-component-gate')
    ap.add_argument('--condition-ast')
    ap.add_argument('--fixture-coverage')
    ap.add_argument('--strategy-alignment')
    ap.add_argument('--denominator-guard')
    ap.add_argument('--output-claims', default='attack_claim_falsification.jsonl')
    ap.add_argument('--output-summary', default='attack_claim_falsification_summary.json')
    ap.add_argument('--output-md', default='attack_claim_falsification.md')
    args=ap.parse_args()
    coverage=read_jsonl(Path(args.coverage)); den=read_jsonl(Path(args.denominator)); paths=read_jsonl(Path(args.attack_paths))
    dc_rows=read_jsonl(Path(args.data_component_gate)) if args.data_component_gate else []
    fixtures=read_jsonl(Path(args.fixture_coverage)) if args.fixture_coverage else []
    strategies=read_jsonl(Path(args.strategy_alignment)) if args.strategy_alignment else []
    den_guard=read_json(Path(args.denominator_guard), {}) if args.denominator_guard else {}
    cov=best_coverage(coverage)
    dc_by_tid={r.get('technique_id'):r for r in dc_rows}
    fx_by_tid={}
    for f in fixtures: fx_by_tid.setdefault(f.get('technique_id'), []).append(f)
    strat_tids={s.get('technique_id') for s in strategies if s.get('technique_id')}
    paths_by_tid={}
    for p in paths: paths_by_tid.setdefault(p.get('technique_id'), []).append(p)
    claims=[]
    for d in den:
        tid=d.get('technique_id')
        if not tid: continue
        c=cov.get(tid, {'coverage_type':'none','strength':'none','confidence':'none','depth_vector':{'final_depth':0}})
        related_paths=paths_by_tid.get(tid, [])
        critical_paths=[p for p in related_paths if p.get('attack_path_critical')]
        unchecked_crit=[p for p in critical_paths if not p.get('bypass_checked')]
        dc=dc_by_tid.get(tid, {})
        fx=fx_by_tid.get(tid, [])
        fx_types={x.get('fixture_type') for x in fx if x.get('fixture_type')}
        blockers=[]
        if d.get('candidate_requires_review') or d.get('review_required'): blockers.append('candidate_denominator_unreviewed')
        if not (d.get('behavior_primitive') or d.get('behavior_primitive_id')): blockers.append('primitive_missing')
        if c.get('coverage_type') in ['declared_only','candidate_mapping','inferred_semantic','none']: blockers.append('not_effective_detection')
        if c.get('detection_style') in ['ioc_match','tool_name_match']: blockers.append(c.get('detection_style'))
        if c.get('coverage_type') not in ['field_chain_validated','tested_validated']: blockers.append('field_chain_missing_or_unverified')
        if dc and not dc.get('data_component_gate_passed'): blockers.extend(dc.get('blockers') or ['data_component_missing'])
        if related_paths and unchecked_crit: blockers.append('critical_bypass_unchecked')
        if tid not in strat_tids: blockers.append('strategy_gap')
        if 'positive' not in fx_types and c.get('coverage_type')=='tested_validated': blockers.append('positive_test_unproven')
        if 'bypass' not in fx_types and related_paths: blockers.append('bypass_test_missing')
        claim=base_claim(c)
        if dc and not dc.get('data_component_gate_passed'): claim=downgrade(claim, 'condition_present')
        if 'field_chain_missing_or_unverified' in blockers: claim=downgrade(claim, 'condition_present')
        if unchecked_crit: claim=downgrade(claim, 'field_chain_validated')
        if c.get('coverage_type')=='tested_validated' and 'bypass' in fx_types and not unchecked_crit and dc.get('data_component_gate_passed', True): claim='resilience_validated'
        claims.append({
            'coverage_model_version':'V8.0','claim_id':claim_id(tid,d.get('scenario'),d.get('tier'),d.get('behavior_primitive')),
            'technique_id':tid,'technique_name':c.get('technique_name') or d.get('technique_name'),
            'scenario':d.get('scenario') or c.get('scenario'), 'denominator_tier': d.get('tier') or d.get('denominator_tier'),
            'coverage_type':c.get('coverage_type'),'final_claim':claim,'confidence':c.get('confidence'),
            'data_component_gate_passed':dc.get('data_component_gate_passed'),
            'attack_path_count':len(related_paths),'critical_attack_path_count':len(critical_paths),'unchecked_critical_path_count':len(unchecked_crit),
            'fixture_types':sorted(x for x in fx_types if x), 'strategy_aligned': tid in strat_tids,
            'coverage_blockers':sorted(set(blockers)),
            'falsifiable_statement': f"Claim {tid} remains valid only if its scenario denominator is valid, rule condition is executable, required Data Components are used by the condition, field-chain is preserved, critical bypass paths are checked, and fixture evidence exists for tested/resilient claims.",
            'disproof_variants': [p.get('bypass_variant') for p in unchecked_crit[:10]],
        })
    total=len(claims); effective=sum(1 for c in claims if c['final_claim'] in ['field_chain_validated','tested_validated','resilience_validated']); resilient=sum(1 for c in claims if c['final_claim']=='resilience_validated')
    must=[c for c in claims if c.get('denominator_tier')=='must_cover']
    crit_gap=sum(c.get('unchecked_critical_path_count',0) for c in claims)
    summary={'coverage_model_version':'V8.0','claim_count':total,'denominator_confidence':den_guard.get('denominator_confidence'),
             'effective_attack_coverage_rate':round(effective/total,4) if total else None,
             'resilience_validated_rate':round(resilient/total,4) if total else None,
             'critical_resilience_rate':round(sum(1 for c in must if c['final_claim']=='resilience_validated')/len(must),4) if must else None,
             'critical_bypass_gap_count':crit_gap,
             'field_chain_blocker_count':sum(1 for c in claims if 'field_chain_missing_or_unverified' in c['coverage_blockers']),
             'data_component_blocker_count':sum(1 for c in claims if 'data_component_missing' in c['coverage_blockers']),
             'strategy_gap_count':sum(1 for c in claims if 'strategy_gap' in c['coverage_blockers']),
             'weak_only_critical_count':sum(1 for c in must if c['final_claim'] in ['declared_only','supportable_only','condition_present','not_covered']),
             'complete_coverage_claim':'Yes' if total and resilient==total and crit_gap==0 else ('Partial' if resilient else 'No')}
    write_jsonl(Path(args.output_claims), claims)
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    lines=['# V8 ATT&CK Claim Falsification','',f"- effective_attack_coverage_rate: `{summary['effective_attack_coverage_rate']}`",f"- resilience_validated_rate: `{summary['resilience_validated_rate']}`",f"- critical_bypass_gap_count: `{summary['critical_bypass_gap_count']}`",f"- complete_coverage_claim: `{summary['complete_coverage_claim']}`",'', '| ATT&CK ID | Final claim | Blockers | Disproof variants |','|---|---|---|---|']
    for c in claims:
        if c['coverage_blockers']:
            lines.append(f"| {c['technique_id']} | {c['final_claim']} | {', '.join(c['coverage_blockers'])} | {', '.join(str(x) for x in c.get('disproof_variants', []))} |")
    Path(args.output_md).write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__=='__main__': main()
