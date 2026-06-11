#!/usr/bin/env python3
from __future__ import annotations
"""V8 ATT&CK attack-path matrix.

Builds a scenario-level matrix at technique x behavior primitive x bypass point.
It is a safe static model: it never generates payloads and never executes tests.
"""
import argparse, json, hashlib
from pathlib import Path
from typing import Any, Dict, List


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists(): return []
    rows=[]
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        line=line.strip()
        if not line: continue
        try: rows.append(json.loads(line))
        except Exception: pass
    return rows


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False)+'\n')
    return len(rows)


def stable_id(*parts: Any) -> str:
    return hashlib.sha256('|'.join(str(x or '') for x in parts).encode()).hexdigest()[:16]


def load_model(path: Path) -> Dict[str, Any]:
    try: return json.load(open(path, encoding='utf-8'))
    except Exception: return {}


def tier_for_attack(tid: str, cfg: Dict[str, Any]) -> str:
    if tid in set(cfg.get('must_cover_attack_ids', []) or []): return 'must_cover'
    if tid in set(cfg.get('should_cover_attack_ids', []) or []): return 'should_cover'
    return 'optional_cover'


def main():
    ap=argparse.ArgumentParser(description='Generate V8 attack-path matrix: technique x behavior primitive x bypass variant.')
    ap.add_argument('--scenario-model', required=True)
    ap.add_argument('--scenario', required=True)
    ap.add_argument('--coverage')
    ap.add_argument('--bypass-matrix')
    ap.add_argument('--behavior-matrix')
    ap.add_argument('--output-jsonl', default='attack_path_matrix.jsonl')
    ap.add_argument('--output-summary', default='attack_path_summary.json')
    args=ap.parse_args()
    model=load_model(Path(args.scenario_model)); cfg=model.get(args.scenario, {})
    cov=read_jsonl(Path(args.coverage)) if args.coverage else []
    bp=read_jsonl(Path(args.bypass_matrix)) if args.bypass_matrix else []
    beh=read_jsonl(Path(args.behavior_matrix)) if args.behavior_matrix else []
    cov_by_tid={c.get('technique_id'):c for c in cov if c.get('technique_id')}
    bp_index={(b.get('technique_id'), b.get('behavior_primitive'), b.get('bypass_variant')):b for b in bp}
    behavior_status={b.get('behavior_primitive'):b for b in beh if b.get('behavior_primitive')}
    rows=[]
    bps=cfg.get('bypass_primitives', []) or []
    for prim in cfg.get('behavior_primitives', []) or []:
        prim_id=prim.get('id') or prim.get('behavior_primitive')
        attack_ids=prim.get('attack_ids', []) or []
        related_bp=[b for b in bps if (b.get('behavior_primitive')==prim_id) or any(t in (b.get('attack_ids') or []) for t in attack_ids)]
        if not related_bp:
            related_bp=[{'id':'no_modeled_bypass_variant','category':'unmodeled','critical':bool(prim.get('critical')), 'keywords':[], 'attack_ids':attack_ids, 'behavior_primitive':prim_id}]
        for tid in attack_ids:
            for b in related_bp:
                bid=b.get('id') or b.get('bypass_variant')
                bm=bp_index.get((tid, prim_id, bid)) or bp_index.get((tid, b.get('behavior_primitive'), bid)) or {}
                c=cov_by_tid.get(tid, {})
                level=bm.get('bypass_check_level') or ('unchecked' if b.get('critical') else 'not_checked')
                checked=bool(bm.get('checked'))
                critical=bool(prim.get('critical') or b.get('critical'))
                rows.append({
                    'coverage_model_version':'V8.0',
                    'attack_path_id': stable_id(args.scenario, tid, prim_id, bid),
                    'scenario': args.scenario,
                    'technique_id': tid,
                    'denominator_tier': tier_for_attack(tid, cfg),
                    'behavior_primitive': prim_id,
                    'primitive_critical': bool(prim.get('critical')),
                    'required_data_components': prim.get('required_data_components', []),
                    'required_fields': prim.get('required_fields', []),
                    'bypass_variant': bid,
                    'bypass_category': b.get('category') or 'unspecified',
                    'bypass_critical': bool(b.get('critical')),
                    'attack_path_critical': critical,
                    'bypass_check_level': level,
                    'bypass_checked': checked,
                    'coverage_type': c.get('coverage_type','none'),
                    'final_depth': ((c.get('depth_vector') or {}).get('final_depth') if isinstance(c.get('depth_vector'), dict) else None),
                    'behavior_coverage_status': (behavior_status.get(prim_id, {}) or {}).get('coverage_status'),
                    'blocking_path': bool(critical and not checked),
                    'required_events': prim.get('required_events', []),
                    'source': 'scenario_attack_model',
                })
    total=len(rows); checked=sum(1 for r in rows if r['bypass_checked']); critical=sum(1 for r in rows if r['attack_path_critical']); crit_checked=sum(1 for r in rows if r['attack_path_critical'] and r['bypass_checked'])
    by_cat={}
    for r in rows:
        by_cat[r['bypass_category']]=by_cat.get(r['bypass_category'],0)+1
    summary={
        'coverage_model_version':'V8.0','scenario':args.scenario,
        'attack_path_count':total,'checked_path_count':checked,'unchecked_path_count':total-checked,
        'critical_attack_path_count':critical,'critical_checked_path_count':crit_checked,
        'attack_path_resilience_rate':round(checked/total,4) if total else None,
        'critical_attack_path_resilience_rate':round(crit_checked/critical,4) if critical else None,
        'blocking_attack_path_count':sum(1 for r in rows if r['blocking_path']),
        'by_bypass_category':by_cat,
        'note':'V8 uses technique × behavior primitive × bypass variant as the main coverage truth grain.'
    }
    write_jsonl(Path(args.output_jsonl), rows)
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))

if __name__=='__main__': main()
