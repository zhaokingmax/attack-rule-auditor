#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, hashlib
from pathlib import Path

def read_jsonl(p):
    path=Path(p)
    if not path.exists(): return []
    rows=[]
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        if line.strip():
            try: rows.append(json.loads(line))
            except Exception: pass
    return rows

def key(r): return (r.get('scenario'), r.get('technique_id'), r.get('behavior_primitive') or r.get('behavior_primitive_id'))
def digest(rows):
    keep=[{'scenario':k[0],'technique_id':k[1],'behavior_primitive':k[2],'tier':r.get('tier') or r.get('denominator_tier'),'reason':r.get('include_reason') or r.get('include_reason_type')} for r in rows for k in [key(r)]]
    return hashlib.sha256(json.dumps(sorted(keep,key=lambda x: str(x)), sort_keys=True, ensure_ascii=False).encode()).hexdigest()

def main():
    ap=argparse.ArgumentParser(description='Compare ATT&CK denominator between runs.')
    ap.add_argument('--current', required=True)
    ap.add_argument('--previous')
    ap.add_argument('--output-json', default='scenario_denominator_diff.json')
    ap.add_argument('--output-md', default='scenario_denominator_diff.md')
    args=ap.parse_args()
    cur=read_jsonl(args.current); prev=read_jsonl(args.previous) if args.previous else []
    curm={key(r):r for r in cur}; prevm={key(r):r for r in prev}
    added=[curm[k] for k in curm.keys()-prevm.keys()]
    removed=[prevm[k] for k in prevm.keys()-curm.keys()]
    tier_changed=[]
    for k in curm.keys() & prevm.keys():
        if (curm[k].get('tier') or curm[k].get('denominator_tier')) != (prevm[k].get('tier') or prevm[k].get('denominator_tier')):
            tier_changed.append({'key':k,'previous':prevm[k],'current':curm[k]})
    summary={'coverage_model_version':'V8.0','current_hash':digest(cur),'previous_hash':digest(prev) if prev else None,'current_count':len(cur),'previous_count':len(prev),'added_count':len(added),'removed_count':len(removed),'tier_changed_count':len(tier_changed),'denominator_changed':bool(added or removed or tier_changed)}
    Path(args.output_json).write_text(json.dumps({**summary,'added':added,'removed':removed,'tier_changed':tier_changed}, ensure_ascii=False, indent=2), encoding='utf-8')
    lines=['# V8 Scenario Denominator Diff','',f"- current_hash: `{summary['current_hash']}`",f"- previous_hash: `{summary['previous_hash']}`",f"- added_count: `{summary['added_count']}`",f"- removed_count: `{summary['removed_count']}`",f"- tier_changed_count: `{summary['tier_changed_count']}`"]
    Path(args.output_md).write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__=='__main__': main()
