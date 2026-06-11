#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, re
from pathlib import Path

def load_json(path): return json.load(open(path, encoding='utf-8'))
def load(index, status='active'):
    p=Path(index)/('lookup_all_by_id.json' if status=='all' else 'lookup_by_id.json')
    return load_json(p)

def expand_ids(lookup, ids, expand_subtechs=False, platform=None):
    out=[]
    for tid in ids:
        tid=tid.upper().strip()
        if tid in lookup: out.append(tid)
        if expand_subtechs and '.' not in tid:
            out += [k for k,v in lookup.items() if v.get('parent_id')==tid or k.startswith(tid+'.')]
    out=sorted(set(out), key=lambda x:(x.split('.')[0], x))
    recs=[lookup[i] for i in out]
    if platform:
        plats=[p.strip().lower() for p in platform.split(',')]
        recs=[r for r in recs if any(p in [x.lower() for x in r.get('platforms',[])] for p in plats)]
    return recs

def scenario_records(index, lookup, scenario, platform=None, expand_subtechs=True):
    sm_path=Path(index).parent/'models'/'scenario_seed_map.json'
    if not sm_path.exists():
        sm_path=Path(index)/'scenario_seed_map.json'
    if not sm_path.exists(): return []
    sm=load_json(sm_path); cfg=sm.get(scenario,{})
    ids=cfg.get('seed_attack_ids') or cfg.get('candidate_ids') or []
    recs=expand_ids(lookup, ids, expand_subtechs, platform)
    # Add keyword matches inside platform scope.
    kws=[k.lower() for k in cfg.get('keywords',[])]
    for r in lookup.values():
        blob=(r.get('technique_id','')+' '+r.get('name','')+' '+r.get('description','')).lower()
        if any(k in blob for k in kws):
            if platform and not any(p.strip().lower() in [x.lower() for x in r.get('platforms',[])] for p in platform.split(',')): continue
            recs.append(r)
    seen={};
    for r in recs: seen[r['technique_id']]=r
    return [seen[k] for k in sorted(seen, key=lambda x:(x.split('.')[0], x))]

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--index', default='attack_data/index')
    ap.add_argument('--id', action='append')
    ap.add_argument('--platform')
    ap.add_argument('--tactic')
    ap.add_argument('--keyword')
    ap.add_argument('--scenario')
    ap.add_argument('--expand-subtechs', action='store_true')
    ap.add_argument('--status', choices=['active','all'], default='active')
    ap.add_argument('--limit', type=int, default=100)
    ap.add_argument('--json', action='store_true')
    args=ap.parse_args()
    lookup=load(args.index,args.status)
    if args.scenario:
        recs=scenario_records(args.index, lookup, args.scenario, args.platform, True)
    elif args.id:
        recs=expand_ids(lookup, args.id, args.expand_subtechs, args.platform)
    else:
        recs=list(lookup.values())
    if args.platform and not args.scenario and not args.id:
        plats=[p.strip().lower() for p in args.platform.split(',')]
        recs=[r for r in recs if any(p in [x.lower() for x in r.get('platforms',[])] for p in plats)]
    if args.tactic:
        recs=[r for r in recs if args.tactic.lower() in [t.lower() for t in r.get('tactics',[])]]
    if args.keyword:
        kw=args.keyword.lower(); recs=[r for r in recs if kw in (r.get('technique_id','')+' '+r.get('name','')+' '+r.get('description','')).lower()]
    recs=recs[:args.limit]
    if args.json:
        for r in recs: print(json.dumps(r, ensure_ascii=False))
    else:
        print('| ID | Name | Tactics | Platforms | Sub | Strategies | Data Components |')
        print('|---|---|---|---|---:|---:|---:|')
        for r in recs:
            print(f"| {r.get('technique_id')} | {r.get('name')} | {', '.join(r.get('tactics',[]))} | {', '.join(r.get('platforms',[]))} | {r.get('is_subtechnique')} | {len(r.get('detection_strategies',[]))} | {len(r.get('data_components',[]))} |")
if __name__=='__main__': main()
