#!/usr/bin/env python3
from __future__ import annotations
"""V8 denominator truth guard.

Checks whether ATT&CK denominator rows are explainable, tiered, platform/scenario
scoped, hashable, and free of unreviewed keyword candidates. This is a static
coverage-quality gate; it does not claim attack coverage.
"""
import argparse, json, hashlib
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


def stable_hash(rows: List[Dict[str, Any]]) -> str:
    keep=[]
    for r in rows:
        keep.append({
            'technique_id': r.get('technique_id'),
            'tier': r.get('tier') or r.get('denominator_tier'),
            'scenario': r.get('scenario'),
            'coverage_object': r.get('coverage_object'),
            'include_reason': r.get('include_reason') or r.get('include_reason_type'),
            'candidate_requires_review': bool(r.get('candidate_requires_review') or r.get('review_required')),
        })
    blob=json.dumps(sorted(keep, key=lambda x: (str(x.get('scenario')), str(x.get('technique_id')))), ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(blob.encode('utf-8')).hexdigest()

def load_model(path: Path) -> dict:
    try:
        return json.load(open(path, encoding='utf-8'))
    except Exception:
        return {}

def scenario_obj(model: dict, name: str) -> dict:
    if isinstance(model.get(name), dict):
        return model.get(name, {})
    scenarios=model.get('scenarios', {})
    if isinstance(scenarios, dict):
        return scenarios.get(name, {})
    return {}

def has_primitive_for(model: dict, scenario: str, tid: str) -> bool:
    sc=scenario_obj(model, scenario)
    parent=str(tid).split('.', 1)[0] if '.' in str(tid) else None
    for p in sc.get('behavior_primitives', []) or []:
        aids={str(x).upper() for x in p.get('attack_ids', []) or []}
        if str(tid).upper() in aids or (parent and parent in aids):
            return True
        if any(str(a).upper().startswith(str(tid).upper()+'.') for a in aids):
            return True
    return False


def render_review(summary: Dict[str, Any], rows: List[Dict[str, Any]], invalid: List[Dict[str, Any]]) -> str:
    lines=['# V8 Denominator Truth Review','',
           f"- denominator_hash: `{summary.get('denominator_hash')}`",
           f"- denominator_count: `{summary.get('denominator_count')}`",
           f"- candidate_requires_review_count: `{summary.get('candidate_requires_review_count')}`",
           f"- invalid_denominator_item_count: `{summary.get('invalid_denominator_item_count')}`",
           f"- low_confidence_rate: `{summary.get('low_confidence_rate')}`",
           f"- denominator_confidence: `{summary.get('denominator_confidence')}`", '',
           '## Tier distribution', '', '```json', json.dumps(summary.get('tier_distribution', {}), ensure_ascii=False, indent=2), '```', '',
           '## Invalid / review-required denominator rows', '',
           '| ATT&CK ID | Name | Tier | Issue | Include reason |', '|---|---|---|---|---|']
    for r in invalid[:200]:
        lines.append(f"| {r.get('technique_id')} | {r.get('technique_name')} | {r.get('tier') or r.get('denominator_tier')} | {', '.join(r.get('denominator_guard_issues', []))} | {r.get('include_reason') or r.get('include_reason_type')} |")
    if not invalid:
        lines.append('| N/A | N/A | N/A | no blocking denominator issues detected | N/A |')
    return '\n'.join(lines)+'\n'


def main():
    ap=argparse.ArgumentParser(description='Validate ATT&CK scenario denominator truthfulness.')
    ap.add_argument('--denominator', required=True)
    ap.add_argument('--negative-denominator')
    ap.add_argument('--scenario-model', default='attack_data/models/scenario_attack_model.json')
    ap.add_argument('--output-summary', default='denominator_guard.json')
    ap.add_argument('--output-md', default='denominator_review.md')
    args=ap.parse_args()
    rows=read_jsonl(Path(args.denominator))
    model=load_model(Path(args.scenario_model))
    invalid=[]; tier_counts={}; low=0; candidate=0; derived_primitive=0
    for r in rows:
        issues=[]
        tid=r.get('technique_id')
        tier=r.get('tier') or r.get('denominator_tier') or 'unclassified'
        tier_counts[tier]=tier_counts.get(tier,0)+1
        reason=r.get('include_reason') or r.get('include_reason_type')
        if not tid: issues.append('missing_attack_id')
        if not reason: issues.append('missing_include_reason')
        if tier == 'unclassified': issues.append('missing_denominator_tier')
        if r.get('candidate_requires_review') or r.get('review_required'):
            candidate += 1
            issues.append('candidate_requires_review')
        conf=(r.get('denominator_confidence') or r.get('confidence') or '').lower()
        if conf in ['low','medium-low','']:
            low += 1
        # Behavior primitive is not always available in V6 denominators; in V8 this is a review issue, not a hard parse failure.
        if not (r.get('behavior_primitive') or r.get('behavior_primitive_id')):
            if tid and has_primitive_for(model, str(r.get('scenario') or ''), str(tid)):
                derived_primitive += 1
            else:
                issues.append('missing_behavior_primitive_link')
        if issues:
            rr=dict(r); rr['denominator_guard_issues']=issues; invalid.append(rr)
    total=len(rows)
    low_rate=round(low/total,4) if total else None
    confidence='high'
    if not total or candidate or invalid:
        confidence='medium'
    if low_rate is not None and low_rate > 0.2:
        confidence='low'
    summary={
        'coverage_model_version':'V8',
        'denominator_count': total,
        'denominator_hash': stable_hash(rows),
        'tier_distribution': tier_counts,
        'candidate_requires_review_count': candidate,
        'invalid_denominator_item_count': len(invalid),
        'derived_behavior_primitive_link_count': derived_primitive,
        'low_confidence_count': low,
        'low_confidence_rate': low_rate,
        'denominator_confidence': confidence,
        'coverage_rate_unstable_due_to_denominator_uncertainty': bool(low_rate is not None and low_rate > 0.2),
        'formal_coverage_allowed': bool(total and candidate == 0 and len(invalid) == 0),
        'guard_note': 'Behavior primitive links may be explicit on denominator rows or derived from scenario_attack_model.json.'
    }
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    Path(args.output_md).write_text(render_review(summary, rows, invalid), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__ == '__main__':
    main()
