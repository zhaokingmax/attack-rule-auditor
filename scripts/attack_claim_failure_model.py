#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
from common import jsonl_read, jsonl_write, sha256_text

ORDER = ['not_covered','declared_only','supportable_only','condition_present','field_chain_validated','tested_validated','resilience_validated']

def norm_claim(c: str) -> str:
    if not c: return 'not_covered'
    c=str(c)
    if c in ORDER: return c
    mapping={'declared':'declared_only','supportable':'supportable_only','field_chain':'field_chain_validated','tested':'tested_validated','resilient':'resilience_validated'}
    for k,v in mapping.items():
        if k in c: return v
    if 'condition' in c or 'rule_condition' in c: return 'condition_present'
    return 'not_covered'

def main():
    ap=argparse.ArgumentParser(description='V9 claim failure conditions, negative space, and proof sufficiency model.')
    ap.add_argument('--claims', required=True, help='attack_claim_falsification_v8_1.jsonl or equivalent')
    ap.add_argument('--coverage')
    ap.add_argument('--bypass-matrix')
    ap.add_argument('--data-component-gate')
    ap.add_argument('--fixture-chain')
    ap.add_argument('--output-jsonl', required=True)
    ap.add_argument('--output-summary', required=True)
    ap.add_argument('--output-md', required=True)
    args=ap.parse_args()
    claims=jsonl_read(Path(args.claims))
    cov=jsonl_read(Path(args.coverage)) if args.coverage else []
    bypass=jsonl_read(Path(args.bypass_matrix)) if args.bypass_matrix else []
    dc=jsonl_read(Path(args.data_component_gate)) if args.data_component_gate else []
    fixtures=jsonl_read(Path(args.fixture_chain)) if args.fixture_chain else []
    cov_by_tid={str(x.get('technique_id') or x.get('attack_id')):x for x in cov}
    bypass_by_tid={}
    for b in bypass:
        tid=str(b.get('technique_id') or b.get('attack_id') or '')
        bypass_by_tid.setdefault(tid,[]).append(b)
    dc_by_tid={}
    for d in dc:
        tid=str(d.get('technique_id') or d.get('attack_id') or '')
        dc_by_tid.setdefault(tid,[]).append(d)
    fx_by_tid={}
    for f in fixtures:
        tid=str(f.get('technique_id') or f.get('attack_id') or f.get('expected_attack_id') or '')
        fx_by_tid.setdefault(tid,[]).append(f)
    rows=[]; counts={k:0 for k in ORDER}; overclaimed=0
    for c in claims:
        tid=str(c.get('technique_id') or c.get('attack_id') or '')
        primitive=c.get('behavior_primitive') or c.get('primitive') or (cov_by_tid.get(tid,{}).get('behavior_primitive')) or 'unknown'
        claim_id=c.get('claim_id') or sha256_text(json.dumps([tid,primitive,c.get('scenario')], ensure_ascii=False))[:16]
        base=norm_claim(c.get('final_claim') or c.get('claim') or c.get('coverage_type'))
        blockers=set(c.get('coverage_blockers') or c.get('blockers') or [])
        failure=[]; negative=[]; proof_score=0
        if base=='declared_only': proof_score=max(proof_score,1)
        if base in ['condition_present','field_chain_validated','tested_validated','resilience_validated']: proof_score=max(proof_score,2)
        cb=bypass_by_tid.get(tid,[])
        unchecked=[b for b in cb if str(b.get('bypass_check_level') or b.get('checked')).lower() in ['false','unchecked','mentioned_only','none']]
        critical_unchecked=[b for b in unchecked if b.get('critical') or b.get('criticality')=='critical']
        if critical_unchecked:
            blockers.add('critical_bypass_unchecked')
            failure += [f"critical bypass `{x.get('bypass_variant') or x.get('variant')}` not proven" for x in critical_unchecked[:5]]
            negative += [f"not covered: bypass variant {x.get('bypass_variant') or x.get('variant')}" for x in critical_unchecked[:5]]
        if cb and not critical_unchecked: proof_score=max(proof_score,3)
        dcs=dc_by_tid.get(tid,[])
        dc_block=[d for d in dcs if d.get('gate_passed') is False or d.get('data_component_gate') in ['fail','partial','missing'] or d.get('missing_data_components')]
        if dc_block:
            blockers.add('data_component_minimum_set_missing')
            failure.append('required Data Component minimum set is incomplete')
        elif dcs:
            proof_score=max(proof_score,4)
        fxs=fx_by_tid.get(tid,[])
        has_positive=any('positive' in str(f.get('fixture_types') or f.get('fixture_type') or '') for f in fxs)
        has_negative=any('negative' in str(f.get('fixture_types') or f.get('fixture_type') or '') for f in fxs)
        has_bypass=any('bypass' in str(f.get('fixture_types') or f.get('fixture_type') or '') for f in fxs)
        if base in ['tested_validated','resilience_validated'] and not has_positive:
            blockers.add('positive_fixture_missing')
            failure.append('tested claim lacks positive fixture evidence')
        if base in ['tested_validated','resilience_validated'] and not has_negative:
            blockers.add('negative_fixture_missing')
            failure.append('tested claim lacks negative fixture evidence')
        if base=='resilience_validated' and not has_bypass:
            blockers.add('bypass_fixture_missing')
            failure.append('resilience claim lacks bypass fixture evidence')
        if has_positive and has_negative: proof_score=max(proof_score,5 if has_bypass else 4)
        # conservative final claim downgrade
        final=base
        if 'critical_bypass_unchecked' in blockers or 'bypass_fixture_missing' in blockers:
            if ORDER.index(final)>ORDER.index('tested_validated'): final='tested_validated'
            if 'critical_bypass_unchecked' in blockers and ORDER.index(final)>ORDER.index('field_chain_validated'):
                final='field_chain_validated'
        if 'data_component_minimum_set_missing' in blockers and ORDER.index(final)>ORDER.index('condition_present'):
            final='condition_present'
        if 'negative_fixture_missing' in blockers and final=='tested_validated':
            final='field_chain_validated'
        if ORDER.index(final) < ORDER.index(base): overclaimed += 1
        counts[final]+=1
        if not failure:
            failure.append('not proven against unmodeled environment, parser, sensor-health, or future scenario-model changes')
        covers=[primitive]
        does_not_cover=[x.replace('not covered: ','') for x in negative] or ['unmodeled variants outside scenario_attack_model']
        row={
            'coverage_model_version':'V9.0',
            'claim_id':claim_id,
            'technique_id':tid,
            'scenario':c.get('scenario') or cov_by_tid.get(tid,{}).get('scenario'),
            'behavior_primitive':primitive,
            'base_claim':base,
            'final_claim':final,
            'claim_scope_boundary':{'covers':covers,'does_not_cover':does_not_cover},
            'failure_conditions':failure,
            'negative_space':does_not_cover,
            'evidence_sufficiency_score':proof_score,
            'primary_blocker': sorted(blockers)[0] if blockers else None,
            'secondary_blockers': sorted(blockers)[1:] if len(blockers)>1 else [],
            'required_bypass_variants':[b.get('bypass_variant') or b.get('variant') for b in cb],
            'covered_bypass_variants':[b.get('bypass_variant') or b.get('variant') for b in cb if str(b.get('bypass_check_level') or b.get('checked')).lower() in ['condition_checked','field_chain_checked','test_checked','resilience_validated','true']],
            'unchecked_bypass_variants':[b.get('bypass_variant') or b.get('variant') for b in unchecked],
            'overclaimed': ORDER.index(final) < ORDER.index(base),
            'source_claim': c,
        }
        rows.append(row)
    jsonl_write(Path(args.output_jsonl), rows)
    total=len(rows) or 1
    summary={'coverage_model_version':'V9.0','claim_count':len(rows),'claim_counts':counts,'overclaimed_count':overclaimed,'overclaimed_rate':round(overclaimed/total,4),'resilience_validated_rate':round(counts['resilience_validated']/total,4),'effective_validated_rate':round(sum(counts[k] for k in ['field_chain_validated','tested_validated','resilience_validated'])/total,4),'critical_bypass_gap_count':sum(1 for r in rows if 'critical_bypass_unchecked' in [r.get('primary_blocker')]+r.get('secondary_blockers',[]))}
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    md=['# V9 Claim Failure Model','',f"- claims: `{len(rows)}`",f"- overclaimed: `{overclaimed}`",f"- resilience_validated_rate: `{summary['resilience_validated_rate']}`",'', '## Top Failure Conditions']
    for r in rows[:50]:
        if r['failure_conditions']:
            md.append(f"- `{r['claim_id']}` `{r['technique_id']}` final=`{r['final_claim']}` blocker=`{r['primary_blocker']}`: {r['failure_conditions'][0]}")
    Path(args.output_md).write_text('\n'.join(md)+'\n', encoding='utf-8')
if __name__=='__main__': main()
