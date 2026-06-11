#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
from common import jsonl_read
ORDER={'not_covered':0,'declared_only':0.05,'supportable_only':0.15,'condition_present':0.35,'field_chain_validated':0.55,'tested_validated':0.75,'resilience_validated':1.0}

def load(p, default=None):
    try: return json.load(open(p,encoding='utf-8'))
    except Exception: return default if default is not None else {}

def main():
    ap=argparse.ArgumentParser(description='V9 multiplicative ATT&CK coverage truth scoring.')
    ap.add_argument('--claim-failure', required=True)
    ap.add_argument('--denominator-proof-summary')
    ap.add_argument('--bypass-cutset-summary')
    ap.add_argument('--data-component-minset-summary')
    ap.add_argument('--fixture-summary')
    ap.add_argument('--output-json', required=True)
    ap.add_argument('--output-md', required=True)
    args=ap.parse_args()
    claims=jsonl_read(Path(args.claim_failure))
    denom=load(args.denominator_proof_summary,{}) if args.denominator_proof_summary else {}
    bypass=load(args.bypass_cutset_summary,{}) if args.bypass_cutset_summary else {}
    dc=load(args.data_component_minset_summary,{}) if args.data_component_minset_summary else {}
    fixture=load(args.fixture_summary,{}) if args.fixture_summary else {}
    n=len(claims) or 1
    claim_score=sum(ORDER.get(c.get('final_claim','not_covered'),0) for c in claims)/n
    denom_score=1.0 if denom.get('complete_coverage_allowed_by_denominator') else max(0.0, 1 - (denom.get('candidate_denominator_items',0)+denom.get('invalid_or_review_denominator_items',0))/(denom.get('total_denominator_items',1) or 1))
    bypass_score=float(bypass.get('weighted_bypass_score',0))
    dc_score=float(dc.get('data_component_minimum_set_rate',0))
    # fixture score: if no fixtures supplied, this remains 0 for resilience but does not erase effective coverage narrative.
    fixture_count=fixture.get('fixture_count') or fixture.get('complete_chain_count') or 0
    fixture_score=1.0 if fixture_count else 0.0
    resilience_score=claim_score*denom_score*bypass_score*dc_score*(fixture_score if fixture_score else 0.35)
    counts={}
    for c in claims: counts[c.get('final_claim','unknown')]=counts.get(c.get('final_claim','unknown'),0)+1
    over=sum(1 for c in claims if c.get('overclaimed'))
    summary={
      'coverage_model_version':'V9.0',
      'claim_count':len(claims),
      'claim_counts':counts,
      'claim_score':round(claim_score,4),
      'denominator_score':round(denom_score,4),
      'bypass_score':round(bypass_score,4),
      'data_component_score':round(dc_score,4),
      'fixture_score':round(fixture_score,4),
      'resilient_score':round(resilience_score,4),
      'resilience_validated_rate':round(counts.get('resilience_validated',0)/n,4),
      'effective_validated_rate':round(sum(counts.get(k,0) for k in ['field_chain_validated','tested_validated','resilience_validated'])/n,4),
      'overclaimed_count':over,
      'critical_bypass_gap_count':bypass.get('critical_bypass_unchecked_count',0),
      'data_component_minimum_set_rate':dc_score,
      'complete_coverage_claim':'Yes' if resilience_score>=0.9 and bypass.get('critical_bypass_unchecked_count',0)==0 and over==0 else 'Partial' if resilience_score>=0.5 else 'No',
    }
    Path(args.output_json).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    md=f"""# V9 Coverage Truth Score\n\n- resilient_score: `{summary['resilient_score']}`\n- effective_validated_rate: `{summary['effective_validated_rate']}`\n- resilience_validated_rate: `{summary['resilience_validated_rate']}`\n- critical_bypass_gap_count: `{summary['critical_bypass_gap_count']}`\n- data_component_minimum_set_rate: `{summary['data_component_minimum_set_rate']}`\n- complete_coverage_claim: `{summary['complete_coverage_claim']}`\n\n## Score Decomposition\n\n```json\n{json.dumps(summary, ensure_ascii=False, indent=2)}\n```\n"""
    Path(args.output_md).write_text(md, encoding='utf-8')
if __name__=='__main__': main()
