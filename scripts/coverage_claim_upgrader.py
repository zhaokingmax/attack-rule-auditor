#!/usr/bin/env python3
from __future__ import annotations
"""V8.1 claim upgrader.

Uses fixture-chain validation and bypass fixture bindings to conservatively upgrade
or downgrade V8 claim falsification results. It never creates payloads; it only
uses user-supplied fixture metadata.
"""
import argparse, json
from pathlib import Path
from typing import Any, Dict, List

CLAIM_ORDER=['not_covered','declared_only','supportable_only','condition_present','field_chain_validated','tested_validated','resilience_validated']


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path or not path.exists(): return []
    rows=[]
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        if not line.strip(): continue
        try: rows.append(json.loads(line))
        except Exception: pass
    return rows


def read_json(path: Path, default=None):
    try: return json.load(open(path, encoding='utf-8'))
    except Exception: return default if default is not None else {}


def write_jsonl(path: Path, rows: List[Dict[str, Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False)+'\n')


def max_claim(a: str, b: str) -> str:
    return CLAIM_ORDER[max(CLAIM_ORDER.index(a), CLAIM_ORDER.index(b))]


def min_claim(a: str, b: str) -> str:
    return CLAIM_ORDER[min(CLAIM_ORDER.index(a), CLAIM_ORDER.index(b))]


def main():
    ap=argparse.ArgumentParser(description='Upgrade V8 ATT&CK claims using V8.1 fixture evidence.')
    ap.add_argument('--claims', required=True)
    ap.add_argument('--fixture-chain', required=True)
    ap.add_argument('--bypass-fixture-bindings', required=True)
    ap.add_argument('--data-component-gate')
    ap.add_argument('--output-claims', default='attack_claim_falsification_v8_1.jsonl')
    ap.add_argument('--output-summary', default='attack_claim_falsification_v8_1_summary.json')
    ap.add_argument('--output-md', default='attack_claim_falsification_v8_1.md')
    args=ap.parse_args()
    claims=read_jsonl(Path(args.claims)); chains=read_jsonl(Path(args.fixture_chain)); bindings=read_jsonl(Path(args.bypass_fixture_bindings)); dc=read_jsonl(Path(args.data_component_gate)) if args.data_component_gate else []
    chain_by_tid={r.get('technique_id'):r for r in chains}
    dc_by_tid={r.get('technique_id'):r for r in dc}
    bind_by_tid: Dict[str, List[Dict[str, Any]]] = {}
    for b in bindings: bind_by_tid.setdefault(b.get('technique_id'), []).append(b)
    out=[]
    for c in claims:
        tid=c.get('technique_id')
        chain=chain_by_tid.get(tid,{})
        binds=bind_by_tid.get(tid,[])
        dcrow=dc_by_tid.get(tid,{})
        old=c.get('final_claim','not_covered') if c.get('final_claim') in CLAIM_ORDER else 'not_covered'
        new=old
        upgrade_reasons=[]; downgrade_reasons=[]
        if old in ['field_chain_validated','tested_validated','condition_present'] and chain.get('has_positive_fixture') and chain.get('has_negative_fixture') and chain.get('fixture_chain_status') in ['complete','partial']:
            new=max_claim(new,'tested_validated'); upgrade_reasons.append('positive_negative_fixture_chain_present')
        strong_binds=[b for b in binds if b.get('binding_strength')=='strong']
        if new in ['tested_validated','field_chain_validated'] and strong_binds and chain.get('has_bypass_fixture') and chain.get('fixture_chain_status')=='complete' and dcrow.get('data_component_gate_passed', True):
            new=max_claim(new,'resilience_validated'); upgrade_reasons.append('bypass_fixture_bound_to_attack_path')
        if old=='resilience_validated' and not strong_binds:
            new=min_claim(new,'tested_validated'); downgrade_reasons.append('no_bound_bypass_fixture_for_resilience_claim')
        if dcrow and not dcrow.get('data_component_gate_passed'):
            new=min_claim(new,'condition_present'); downgrade_reasons.append('data_component_gate_failed')
        blockers=list(c.get('coverage_blockers') or [])
        if downgrade_reasons: blockers=sorted(set(blockers + downgrade_reasons))
        rec=dict(c)
        rec.update({
            'coverage_model_version':'V8.1',
            'previous_final_claim': old,
            'final_claim': new,
            'claim_upgraded': CLAIM_ORDER.index(new)>CLAIM_ORDER.index(old),
            'claim_downgraded': CLAIM_ORDER.index(new)<CLAIM_ORDER.index(old),
            'upgrade_reasons': upgrade_reasons,
            'downgrade_reasons': downgrade_reasons,
            'fixture_chain_status': chain.get('fixture_chain_status'),
            'fixture_types': chain.get('fixture_types') or c.get('fixture_types'),
            'bound_bypass_fixture_count': len(strong_binds),
            'coverage_blockers': blockers,
        })
        out.append(rec)
    total=len(out); effective=sum(1 for r in out if r['final_claim'] in ['field_chain_validated','tested_validated','resilience_validated']); tested=sum(1 for r in out if r['final_claim'] in ['tested_validated','resilience_validated']); resilient=sum(1 for r in out if r['final_claim']=='resilience_validated')
    must=[r for r in out if r.get('denominator_tier')=='must_cover']
    summary={
        'coverage_model_version':'V8.1',
        'claim_count': total,
        'effective_attack_coverage_rate': round(effective/total,4) if total else None,
        'tested_coverage_rate': round(tested/total,4) if total else None,
        'resilience_validated_rate': round(resilient/total,4) if total else None,
        'critical_resilience_rate': round(sum(1 for r in must if r['final_claim']=='resilience_validated')/len(must),4) if must else None,
        'upgraded_claim_count': sum(1 for r in out if r.get('claim_upgraded')),
        'downgraded_claim_count': sum(1 for r in out if r.get('claim_downgraded')),
        'bound_bypass_fixture_count': sum(r.get('bound_bypass_fixture_count',0) for r in out),
        'complete_coverage_claim': 'Yes' if total and resilient==total else ('Partial' if resilient else 'No'),
        'safe_static_only': True,
    }
    write_jsonl(Path(args.output_claims), out)
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    lines=['# V8.1 Fixture-Driven Claim Upgrade','',f"- effective_attack_coverage_rate: `{summary['effective_attack_coverage_rate']}`",f"- tested_coverage_rate: `{summary['tested_coverage_rate']}`",f"- resilience_validated_rate: `{summary['resilience_validated_rate']}`",f"- upgraded_claim_count: `{summary['upgraded_claim_count']}`",'', '| ATT&CK ID | Previous | V8.1 final | Reasons |','|---|---|---|---|']
    for r in out:
        if r.get('claim_upgraded') or r.get('claim_downgraded') or r.get('coverage_blockers'):
            reasons=', '.join((r.get('upgrade_reasons') or []) + (r.get('downgrade_reasons') or []) + (r.get('coverage_blockers') or [])[:3])
            lines.append(f"| {r.get('technique_id')} | {r.get('previous_final_claim')} | {r.get('final_claim')} | {reasons} |")
    Path(args.output_md).write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__=='__main__': main()
