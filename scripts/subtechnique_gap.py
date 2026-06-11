#!/usr/bin/env python3
from __future__ import annotations
"""V6 parent/sub-technique gap checker."""
import argparse, json
from pathlib import Path
from typing import Any, Dict, List


def read_jsonl(p: Path) -> List[Dict[str, Any]]:
    if not p.exists(): return []
    out=[]
    for line in p.read_text(encoding='utf-8', errors='ignore').splitlines():
        if line.strip():
            try: out.append(json.loads(line))
            except Exception: pass
    return out


def write_jsonl(p: Path, rows: List[Dict[str, Any]]):
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open('w', encoding='utf-8') as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False)+'\n')


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--index', default='attack_data/index')
    ap.add_argument('--coverage', required=True)
    ap.add_argument('--denominator', required=True)
    ap.add_argument('--platform', default='Linux,Containers,Network Devices')
    ap.add_argument('--output-jsonl', default='subtechnique_gaps.jsonl')
    ap.add_argument('--output-md', default='missing_subtechniques.md')
    args=ap.parse_args()
    lookup=json.load(open(Path(args.index)/'lookup_by_id.json', encoding='utf-8'))
    cov=read_jsonl(Path(args.coverage)); den=read_jsonl(Path(args.denominator))
    platforms={p.strip().lower() for p in args.platform.split(',') if p.strip()}
    den_ids={d.get('technique_id') for d in den}
    covered={r.get('technique_id') for r in cov if r.get('coverage_type') in ['field_chain_validated','tested_validated']}
    # Parent candidates: explicit parent in denominator or parent tags in coverage.
    parents=set()
    for tid in den_ids | {r.get('technique_id') for r in cov if r.get('gap_reason_codes') and 'parent_only' in r.get('gap_reason_codes',[])}:
        if not tid: continue
        rec=lookup.get(tid,{})
        if tid and '.' not in tid and any(x.startswith(tid+'.') for x in lookup):
            parents.add(tid)
    rows=[]
    for parent in sorted(parents):
        children=[]
        for tid,rec in lookup.items():
            if not tid.startswith(parent+'.'): continue
            rplats={x.lower() for x in rec.get('platforms', [])}
            if platforms and not (platforms & rplats): continue
            children.append(tid)
        missing=[c for c in children if c not in covered]
        rows.append({
            'parent_technique_id': parent,
            'parent_name': lookup.get(parent,{}).get('name'),
            'applicable_subtechniques': children,
            'covered_subtechniques': sorted(set(children)&covered),
            'missing_subtechniques': missing,
            'rollup_policy':'subtechnique_first_parent_only_blocked',
            'coverage_ratio': round((len(children)-len(missing))/len(children),4) if children else None,
            'gap_blocks_complete_coverage': bool(missing),
        })
    write_jsonl(Path(args.output_jsonl), rows)
    lines=['# Missing Sub-techniques', '', 'Parent techniques do not imply coverage of their sub-techniques. V6 uses sub-technique-first roll-up.', '', '| Parent | Covered / Applicable | Missing sub-techniques |', '|---|---:|---|']
    for r in rows:
        lines.append(f"| {r['parent_technique_id']} {r.get('parent_name')} | {len(r['covered_subtechniques'])}/{len(r['applicable_subtechniques'])} | {', '.join(r['missing_subtechniques']) or 'None'} |")
    Path(args.output_md).write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(json.dumps({'parents_checked':len(rows),'parents_with_gaps':sum(1 for r in rows if r['missing_subtechniques'])}, ensure_ascii=False))
if __name__=='__main__': main()
