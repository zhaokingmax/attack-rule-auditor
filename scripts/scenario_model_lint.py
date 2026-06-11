#!/usr/bin/env python3
from __future__ import annotations
"""Lint scenario_attack_model.json for coverage-truth readiness."""
import argparse, json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List
from common import normalize_data_component

REQUIRED_COMPLETE_GATE_KEYS = {
    'requires_denominator_confidence',
    'requires_subtechnique_review',
    'requires_data_component_gate',
    'requires_strategy_gate',
    'requires_field_chain_gate',
    'requires_test_gate',
    'requires_bypass_gate',
}


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def load_lookup(index: str | None):
    if not index:
        return {}, {}
    p = Path(index)
    active = json.load(open(p / 'lookup_by_id.json', encoding='utf-8')) if (p / 'lookup_by_id.json').exists() else {}
    all_ids = json.load(open(p / 'lookup_all_by_id.json', encoding='utf-8')) if (p / 'lookup_all_by_id.json').exists() else active
    return active, all_ids


def load_data_components(index: str | None) -> set[str]:
    if not index:
        return set()
    return {r.get('name') for r in read_jsonl(Path(index) / 'data_components.jsonl') if r.get('name')}


def attack_id_issues(tid: str, active: Dict[str, Any], all_ids: Dict[str, Any], platforms: set[str]) -> List[str]:
    if not active and not all_ids:
        return []
    rec = active.get(tid)
    all_rec = all_ids.get(tid)
    issues = []
    if not all_rec:
        return [f'unknown_attack_id:{tid}']
    if not rec:
        if all_rec.get('revoked') or all_rec.get('deprecated'):
            issues.append(f'revoked_or_deprecated_attack_id:{tid}')
        else:
            issues.append(f'inactive_attack_id:{tid}')
    else:
        if platforms and not ({p.lower() for p in rec.get('platforms', [])} & platforms):
            issues.append(f'platform_mismatch_attack_id:{tid}')
    return issues

def main():
    ap=argparse.ArgumentParser(description='Lint scenario attack model for V8.0 coverage gates.')
    ap.add_argument('--scenario-model', default='attack_data/models/scenario_attack_model.json')
    ap.add_argument('--index', default='attack_data/index')
    ap.add_argument('--platform', default='Linux,Containers,Network Devices')
    ap.add_argument('--output-jsonl', default='scenario_model_lint.jsonl')
    ap.add_argument('--output-summary', default='scenario_model_lint_summary.json')
    args=ap.parse_args()
    model=json.load(open(args.scenario_model, encoding='utf-8'))
    active, all_ids = load_lookup(args.index)
    valid_components = load_data_components(args.index)
    platform_scope = {p.strip().lower() for p in args.platform.split(',') if p.strip()}
    rows=[]
    for name, sc in model.items():
        if name.startswith('_'): continue
        scenario_platform_scope = {p.strip().lower() for p in sc.get('platform_scope', []) or [] if str(p).strip()}
        if platform_scope and scenario_platform_scope and not (scenario_platform_scope & platform_scope):
            continue
        issues=[]
        bps=sc.get('behavior_primitives') or []
        bypass=sc.get('bypass_primitives') or []
        bp_ids=[bp.get('id') for bp in bps if bp.get('id')]
        bp_id_set=set(bp_ids)
        if len(bp_ids) != len(bp_id_set):
            issues.append('duplicate_behavior_primitive_id')
        if not bps: issues.append('missing_behavior_primitives')
        if not bypass: issues.append('missing_bypass_primitives')
        if not sc.get('must_cover_attack_ids'): issues.append('missing_must_cover_attack_ids')
        if not sc.get('complete_gate'): issues.append('missing_complete_gate')
        else:
            missing_gate = REQUIRED_COMPLETE_GATE_KEYS - set(sc.get('complete_gate') or {})
            for key in sorted(missing_gate):
                issues.append(f'missing_complete_gate_key:{key}')
        for key in ['must_cover_attack_ids', 'should_cover_attack_ids']:
            for tid in sc.get(key, []) or []:
                issues.extend(attack_id_issues(str(tid).upper(), active, all_ids, platform_scope))
        for bp in bps:
            bid=bp.get('id')
            if not bid: issues.append('behavior_primitive_missing_id')
            if not bp.get('keywords'): issues.append(f"behavior_primitive_missing_keywords:{bid}")
            if not bp.get('attack_ids'): issues.append(f"behavior_primitive_missing_attack_ids:{bid}")
            for tid in bp.get('attack_ids', []) or []:
                issues.extend(attack_id_issues(str(tid).upper(), active, all_ids, platform_scope))
            if not bp.get('required_data_components'): issues.append(f"behavior_primitive_missing_required_data_components:{bid}")
            for dc in bp.get('required_data_components', []) or []:
                canonical = normalize_data_component(dc)
                if valid_components and canonical not in valid_components:
                    issues.append(f"behavior_primitive_invalid_data_component:{bid}:{dc}")
                if canonical != dc:
                    issues.append(f"behavior_primitive_noncanonical_data_component:{bid}:{dc}->{canonical}")
            if not bp.get('required_fields'): issues.append(f"behavior_primitive_missing_required_fields:{bid}")
            if bp.get('critical') and bid not in (sc.get('critical_behavior_primitives') or []):
                issues.append(f"critical_behavior_not_listed:{bid}")
        for by in bypass:
            byid=by.get('id')
            behavior_primitive=by.get('behavior_primitive')
            if not behavior_primitive: issues.append(f"bypass_missing_behavior_primitive:{byid}")
            elif behavior_primitive not in bp_id_set: issues.append(f"bypass_unknown_behavior_primitive:{byid}:{behavior_primitive}")
            if not by.get('category'): issues.append(f"bypass_missing_category:{by.get('id')}")
            if not by.get('attack_ids'): issues.append(f"bypass_missing_attack_ids:{by.get('id')}")
            for tid in by.get('attack_ids', []) or []:
                issues.extend(attack_id_issues(str(tid).upper(), active, all_ids, platform_scope))
            if not by.get('keywords'): issues.append(f"bypass_missing_keywords:{byid}")
            if not by.get('required_fields'): issues.append(f"bypass_missing_required_fields:{byid}")
            if not by.get('check_requirement'): issues.append(f"bypass_missing_check_requirement:{byid}")
            for dc in by.get('required_data_components', []) or []:
                canonical = normalize_data_component(dc)
                if valid_components and canonical not in valid_components:
                    issues.append(f"bypass_invalid_data_component:{byid}:{dc}")
                if canonical != dc:
                    issues.append(f"bypass_noncanonical_data_component:{byid}:{dc}->{canonical}")
        rows.append({
            'scenario': name,
            'behavior_primitive_count': len(bps),
            'critical_behavior_primitive_count': sum(1 for x in bps if x.get('critical')),
            'bypass_primitive_count': len(bypass),
            'critical_bypass_primitive_count': sum(1 for x in bypass if x.get('critical')),
            'issues': sorted(set(issues)),
            'status': 'pass' if not issues else 'review_required',
        })
    Path(args.output_jsonl).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output_jsonl,'w',encoding='utf-8') as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False)+'\n')
    issue_counts=Counter(issue.split(':', 1)[0] for r in rows for issue in r['issues'])
    summary={
        'coverage_model_version': (model.get('_meta') or {}).get('coverage_model_version', 'V10.5-wave4'),
        'scenario_count': len(rows),
        'scenarios_requiring_review': sum(1 for r in rows if r['issues']),
        'total_behavior_primitives': sum(r['behavior_primitive_count'] for r in rows),
        'total_bypass_primitives': sum(r['bypass_primitive_count'] for r in rows),
        'issue_counts': dict(sorted(issue_counts.items())),
    }
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__=='__main__': main()
