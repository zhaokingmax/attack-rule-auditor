#!/usr/bin/env python3
from __future__ import annotations
"""Validate scenario model ATT&CK IDs against the local Enterprise ATT&CK index."""
import argparse, json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

KNOWN_REPLACEMENTS = {
    'T1562': ['T1685'],
    'T1562.012': ['T1685.004'],
    'T1562.013': ['T1686.002'],
}


def load_json(path: Path) -> Dict[str, Any]:
    return json.load(open(path, encoding='utf-8'))


def model_scenarios(model: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    for name, obj in model.items():
        if name.startswith('_') or not isinstance(obj, dict):
            continue
        yield name, obj


def children_of(lookup: Dict[str, Dict[str, Any]], parent: str) -> List[str]:
    return sorted(tid for tid, row in lookup.items() if row.get('parent_id') == parent or tid.startswith(parent + '.'))


def add_id(rows: List[Dict[str, Any]], scenario: str, source: str, attack_id: str):
    rows.append({'scenario': scenario, 'source': source, 'attack_id': str(attack_id).upper()})


def collect_ids(model: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for scenario, sc in model_scenarios(model):
        for key in ['must_cover_attack_ids', 'should_cover_attack_ids']:
            for attack_id in sc.get(key, []) or []:
                add_id(rows, scenario, key, attack_id)
        for bp in sc.get('behavior_primitives', []) or []:
            for attack_id in bp.get('attack_ids', []) or []:
                add_id(rows, scenario, f"behavior:{bp.get('id')}", attack_id)
        for by in sc.get('bypass_primitives', []) or []:
            for attack_id in by.get('attack_ids', []) or []:
                add_id(rows, scenario, f"bypass:{by.get('id')}", attack_id)
    return rows


def main():
    ap = argparse.ArgumentParser(description='Check scenario_attack_model ATT&CK IDs for v19.1 health.')
    ap.add_argument('--scenario-model', default='attack_data/models/scenario_attack_model.json')
    ap.add_argument('--index', default='attack_data/index')
    ap.add_argument('--platform', default='Linux,Containers,Network Devices')
    ap.add_argument('--parent-review-mode', choices=['resolved','strict'], default='resolved')
    ap.add_argument('--output-jsonl', default='scenario_attack_id_health.jsonl')
    ap.add_argument('--output-summary', default='scenario_attack_id_health_summary.json')
    args = ap.parse_args()

    index = Path(args.index)
    active = load_json(index / 'lookup_by_id.json')
    all_ids = load_json(index / 'lookup_all_by_id.json')
    platforms = {p.strip().lower() for p in args.platform.split(',') if p.strip()}
    model = load_json(Path(args.scenario_model))
    model_version = (model.get('_meta') or {}).get('coverage_model_version', 'V10.5-wave4')
    refs = collect_ids(model)
    scenario_ids: Dict[str, set[str]] = {}
    for item in refs:
        scenario_ids.setdefault(item['scenario'], set()).add(item['attack_id'])
    rows = []
    issue_counts: Counter[str] = Counter()
    resolved_parent_count = 0
    for item in refs:
        tid = item['attack_id']
        rec = active.get(tid)
        all_rec = all_ids.get(tid)
        issues: List[str] = []
        parent_resolution = None
        status = 'pass'
        if not all_rec:
            issues.append('unknown_attack_id')
            status = 'fail'
        elif not rec:
            status = 'fail'
            if all_rec.get('revoked') or all_rec.get('deprecated'):
                issues.append('revoked_or_deprecated')
            else:
                issues.append('not_in_active_index')
        else:
            rec_platforms = {p.lower() for p in rec.get('platforms', [])}
            if platforms and not (rec_platforms & platforms):
                issues.append('platform_mismatch')
                status = 'review'
            children = children_of(active, tid)
            if not rec.get('is_subtechnique') and children:
                in_scope_children = [
                    child for child in children
                    if {p.lower() for p in active.get(child, {}).get('platforms', [])} & platforms
                ]
                bound_children = sorted(set(in_scope_children) & scenario_ids.get(item['scenario'], set()))
                if args.parent_review_mode == 'resolved' and bound_children:
                    parent_resolution = {
                        'state': 'resolved_by_existing_child_binding',
                        'bound_children': bound_children,
                        'in_scope_child_count': len(in_scope_children),
                    }
                    resolved_parent_count += 1
                else:
                    issues.append('parent_technique_requires_subtechnique_review')
                    parent_resolution = {
                        'state': 'needs_child_binding_review',
                        'bound_children': bound_children,
                        'in_scope_child_count': len(in_scope_children),
                    }
                    if status == 'pass':
                        status = 'review'
        for issue in issues:
            issue_counts[issue] += 1
        rows.append({
            **item,
            'status': status,
            'name': (rec or all_rec or {}).get('name'),
            'active': bool(rec),
            'revoked': bool((all_rec or {}).get('revoked')),
            'deprecated': bool((all_rec or {}).get('deprecated')),
            'platforms': (rec or all_rec or {}).get('platforms', []),
            'tactics': (rec or all_rec or {}).get('tactics', []),
            'issues': issues,
            'parent_resolution': parent_resolution,
            'known_replacements': KNOWN_REPLACEMENTS.get(tid, []),
        })

    Path(args.output_jsonl).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output_jsonl, 'w', encoding='utf-8') as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + '\n')
    summary = {
        'coverage_model_version': model_version,
        'attack_index': str(index),
        'platform_scope': sorted(platforms),
        'reference_count': len(rows),
        'unique_attack_id_count': len({r['attack_id'] for r in rows}),
        'failing_reference_count': sum(1 for r in rows if r['status'] == 'fail'),
        'review_reference_count': sum(1 for r in rows if r['status'] == 'review'),
        'resolved_parent_reference_count': resolved_parent_count,
        'issue_counts': dict(sorted(issue_counts.items())),
        'known_replacement_count': sum(1 for r in rows if r['known_replacements']),
    }
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == '__main__':
    main()
