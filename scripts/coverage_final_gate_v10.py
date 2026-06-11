#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, time
from pathlib import Path
from common import jsonl_read, jsonl_write, sha256_text

ORDER = {
  'not_covered':0, 'declared_only':1, 'supportable_only':2, 'condition_supported':3, 'condition_present':3,
  'field_chain_supported':4, 'field_chain_validated':4, 'fixture_supported':5, 'tested_validated':5,
  'bypass_resilient':6, 'resilience_validated':6
}
REV = ['not_covered','declared_only','supportable_only','condition_supported','field_chain_supported','fixture_supported','bypass_resilient']

def load_json(path, default=None):
    try: return json.load(open(path, encoding='utf-8'))
    except Exception: return default if default is not None else {}

def norm_claim(c):
    c=str(c or 'not_covered')
    if c == 'condition_present': return 'condition_supported'
    if c == 'field_chain_validated': return 'field_chain_supported'
    if c == 'tested_validated': return 'fixture_supported'
    if c == 'resilience_validated': return 'bypass_resilient'
    if c in ORDER: return c
    if 'resilien' in c: return 'bypass_resilient'
    if 'test' in c or 'fixture' in c: return 'fixture_supported'
    if 'field' in c: return 'field_chain_supported'
    if 'condition' in c: return 'condition_supported'
    if 'support' in c: return 'supportable_only'
    if 'declare' in c: return 'declared_only'
    return 'not_covered'

def cap(state, max_state):
    return REV[min(ORDER.get(norm_claim(state),0), ORDER.get(norm_claim(max_state),0))]

def main():
    ap=argparse.ArgumentParser(description='V10 final seven-gate ATT&CK coverage truth evaluator and blocker-first report generator.')
    ap.add_argument('--claim-failure', required=True)
    ap.add_argument('--denominator-proof-summary')
    ap.add_argument('--field-chain-proof-summary')
    ap.add_argument('--data-component-minset-summary')
    ap.add_argument('--bypass-cutset-summary')
    ap.add_argument('--fixture-chain-summary')
    ap.add_argument('--runtime-sensor-context')
    ap.add_argument('--coverage-score-v9')
    ap.add_argument('--model-depth-summary')
    ap.add_argument('--output-claims-jsonl', required=True)
    ap.add_argument('--output-dashboard-json', required=True)
    ap.add_argument('--output-dashboard-md', required=True)
    ap.add_argument('--output-blocker-report-md', required=True)
    args=ap.parse_args()
    claims=jsonl_read(Path(args.claim_failure))
    denom=load_json(args.denominator_proof_summary,{})
    field=load_json(args.field_chain_proof_summary,{})
    dc=load_json(args.data_component_minset_summary,{})
    bypass=load_json(args.bypass_cutset_summary,{})
    fixture=load_json(args.fixture_chain_summary,{})
    runtime=load_json(args.runtime_sensor_context,{})
    v9=load_json(args.coverage_score_v9,{})
    model_depth=load_json(args.model_depth_summary,{}) if args.model_depth_summary else {}
    model_depth_gate_failed=bool(model_depth) and not bool(model_depth.get('depth_gate_passed'))
    field_count=field.get('field_count') or 0
    field_pass=field.get('field_chain_pass_count') or 0
    field_rate=(field_pass/(field_count or 1)) if field_count else 0.0
    dc_rate=float(dc.get('data_component_minimum_set_rate',0) or 0)
    denom_ok=bool(denom.get('complete_coverage_allowed_by_denominator', False))
    out=[]; blockers_counter={}
    for c in claims:
        base=norm_claim(c.get('final_claim') or c.get('claim_truth_state') or c.get('coverage_type'))
        blockers=list(c.get('secondary_blockers') or c.get('blockers') or c.get('failure_conditions') or [])
        primary=c.get('primary_blocker')
        if primary: blockers.append(primary)
        # Global gate-derived blockers.
        if not denom_ok: blockers.append('denominator_gate_failed')
        if field_count and field_rate == 0: blockers.append('field_chain_proof_incomplete_global')
        elif field_count and field_rate < 1: blockers.append('field_chain_proof_partial_global')
        if dc_rate == 0: blockers.append('data_component_minimum_set_incomplete')
        elif dc_rate < 1: blockers.append('data_component_minimum_set_partial')
        if (bypass.get('critical_bypass_unchecked_count') or 0) > 0: blockers.append('critical_bypass_cutset_unchecked')
        if not (fixture.get('complete_chain_count') or fixture.get('fixture_count') or 0): blockers.append('fixture_chain_missing')
        if runtime.get('sensor_blockers'): blockers.append('sensor_health_blockers_present')
        if runtime.get('missing_context_inputs'): blockers.append('runtime_or_sensor_context_missing')
        if model_depth_gate_failed: blockers.append('model_depth_resilience_gate_failed')
        # Seven hard gates: denominator, subtechnique/primitive, data, field, condition, bypass, fixture.
        final=base
        if 'denominator_gate_failed' in blockers: final=cap(final,'condition_supported')
        if 'data_component_minimum_set_incomplete' in blockers: final=cap(final,'condition_supported')
        if 'field_chain_proof_incomplete_global' in blockers: final=cap(final,'condition_supported')
        if 'critical_bypass_cutset_unchecked' in blockers: final=cap(final,'fixture_supported')
        if 'fixture_chain_missing' in blockers: final=cap(final,'field_chain_supported')
        if 'sensor_health_blockers_present' in blockers or 'runtime_or_sensor_context_missing' in blockers: final=cap(final,'fixture_supported')
        if 'model_depth_resilience_gate_failed' in blockers: final=cap(final,'fixture_supported')
        if c.get('overclaimed') and ORDER.get(final,0) > ORDER['field_chain_supported']:
            final=cap(final,'field_chain_supported')
        for b in blockers: blockers_counter[str(b)] = blockers_counter.get(str(b),0)+1
        claim_id=c.get('claim_id') or sha256_text(json.dumps(c, ensure_ascii=False, sort_keys=True))[:16]
        out.append({
            'coverage_model_version':'V10.5-wave4',
            'claim_id': claim_id,
            'attack_id': c.get('technique_id') or c.get('attack_id'),
            'behavior_primitive': c.get('behavior_primitive') or c.get('primitive'),
            'v9_claim': base,
            'v10_final_claim': final,
            'overclaimed': bool(c.get('overclaimed') or (ORDER.get(final,0) < ORDER.get(base,0))),
            'primary_blocker': blockers[0] if blockers else None,
            'blockers': sorted(set(str(x) for x in blockers)),
            'non_coverage_statement': c.get('negative_space') or c.get('non_coverage_statement') or c.get('failure_conditions') or [],
            'next_required_artifacts': sorted(set([b.replace('_missing','').replace('_failed','') for b in blockers]))[:10],
            'source_claim': c,
        })
    jsonl_write(Path(args.output_claims_jsonl), out)
    n=len(out) or 1
    counts={}
    for r in out: counts[r['v10_final_claim']] = counts.get(r['v10_final_claim'],0)+1
    effective=sum(counts.get(k,0) for k in ['field_chain_supported','fixture_supported','bypass_resilient'])/n
    resilience=counts.get('bypass_resilient',0)/n
    fixture_rate=1.0 if (fixture.get('complete_chain_count') or fixture.get('fixture_count') or 0) else 0.0
    sensor_multiplier=0.7 if runtime.get('missing_context_inputs') else 0.8 if runtime.get('sensor_blockers') else 1.0
    critical_bypass=bypass.get('critical_bypass_unchecked_count',0) or blockers_counter.get('critical_bypass_cutset_unchecked',0)
    cutset_multiplier=max(0.0, 1.0 - min(critical_bypass,10)*0.08)
    denom_multiplier=1.0 if denom_ok else max(0.0, 1 - ((denom.get('candidate_denominator_items',0) + denom.get('invalid_or_review_denominator_items',0)) / (denom.get('total_denominator_items',1) or 1)))
    final_score=effective * denom_multiplier * max(dc_rate,0) * max(field_rate,0) * (fixture_rate if fixture_rate else 0.35) * sensor_multiplier * cutset_multiplier
    complete='Yes' if final_score >= 0.9 and not critical_bypass and not runtime.get('missing_context_inputs') and not model_depth_gate_failed else 'Partial' if final_score >= 0.45 else 'No'
    dashboard={
        'coverage_model_version':'V10.5-wave4',
        'claim_count':len(out),
        'claim_counts':counts,
        'minimum_viable_denominator_count': denom.get('formal_denominator_items') or denom.get('total_denominator_items'),
        'effective_attack_coverage': round(effective,4),
        'resilience_validated_coverage': round(resilience,4),
        'critical_resilience_rate': round(resilience,4),
        'critical_bypass_cutset_count': critical_bypass,
        'field_chain_proof_rate': round(field_rate,4),
        'data_component_minimum_set_rate': round(dc_rate,4),
        'denominator_proof_rate': round(denom_multiplier,4),
        'bypass_weighted_score': bypass.get('weighted_bypass_score'),
        'fixture_proof_rate': round(fixture_rate,4),
        'sensor_health_multiplier': round(sensor_multiplier,4),
        'runtime_context_confidence': runtime.get('runtime_context_confidence'),
        'sensor_context_confidence': runtime.get('sensor_context_confidence'),
        'resilient_score_v10': round(final_score,4),
        'complete_coverage_claim': complete,
        'overclaimed_count': sum(1 for r in out if r['overclaimed']),
        'top_blockers': sorted(blockers_counter.items(), key=lambda x:x[1], reverse=True)[:20],
        'v9_resilient_score': v9.get('resilient_score'),
        'model_depth_gate_passed': None if not model_depth else bool(model_depth.get('depth_gate_passed')),
        'model_l4_deep_model_count': model_depth.get('l4_deep_model_count'),
        'model_non_l4_depth_gap_count': model_depth.get('non_l4_depth_gap_count'),
        'model_bypass_proof_gap_count': model_depth.get('bypass_proof_gap_count'),
        'model_bypass_enrichment_gap_count': model_depth.get('bypass_enrichment_gap_count'),
        'model_fixture_template_gap_count': model_depth.get('fixture_template_gap_count'),
        'model_depth_resilient_model_count': model_depth.get('depth_resilient_model_count'),
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    Path(args.output_dashboard_json).write_text(json.dumps(dashboard, ensure_ascii=False, indent=2), encoding='utf-8')
    md=['# V10 Coverage Truth Dashboard','',
        f"- complete_coverage_claim: `{complete}`",
        f"- resilient_score_v10: `{dashboard['resilient_score_v10']}`",
        f"- effective_attack_coverage: `{dashboard['effective_attack_coverage']}`",
        f"- resilience_validated_coverage: `{dashboard['resilience_validated_coverage']}`",
        f"- critical_bypass_cutset_count: `{critical_bypass}`",
        f"- field_chain_proof_rate: `{dashboard['field_chain_proof_rate']}`",
        f"- data_component_minimum_set_rate: `{dashboard['data_component_minimum_set_rate']}`",
        f"- fixture_proof_rate: `{dashboard['fixture_proof_rate']}`",
        f"- model_depth_gate_passed: `{dashboard['model_depth_gate_passed']}`",
        '', '## Top Blockers']
    md += [f'- `{k}`: {v}' for k,v in dashboard['top_blockers']] or ['- None']
    Path(args.output_dashboard_md).write_text('\n'.join(md)+'\n', encoding='utf-8')
    br=['# V10 Blocker-first Coverage Report','', 'This report intentionally lists blockers before coverage rates. Raw ATT&CK tag coverage is not evidence of detection capability.', '', '## Critical Blockers']
    for k,v in dashboard['top_blockers'][:30]: br.append(f'- `{k}`: {v}')
    br += ['', '## Coverage Rates', f"- effective_attack_coverage: `{dashboard['effective_attack_coverage']}`", f"- resilience_validated_coverage: `{dashboard['resilience_validated_coverage']}`", f"- complete_coverage_claim: `{complete}`", '', '## Lowest Claims']
    for r in sorted(out, key=lambda x: ORDER.get(x['v10_final_claim'],0))[:25]:
        br.append(f"- `{r.get('attack_id')}` `{r.get('behavior_primitive')}` => `{r['v10_final_claim']}` blockers={r['blockers'][:5]}")
    Path(args.output_blocker_report_md).write_text('\n'.join(br)+'\n', encoding='utf-8')
if __name__=='__main__': main()
