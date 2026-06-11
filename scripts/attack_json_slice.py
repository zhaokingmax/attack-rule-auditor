#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, re
from collections import defaultdict
from pathlib import Path

def ext_id(o):
    for r in o.get('external_references') or []:
        if r.get('source_name')=='mitre-attack' and r.get('external_id'): return r['external_id']
    return None

def active(o): return not o.get('revoked') and not o.get('x_mitre_deprecated')
def clean(s,n=900): return re.sub(r'\s+',' ',s or '').strip()[:n]

def main():
    ap=argparse.ArgumentParser(description='Slice enterprise-attack.json by IDs, platform, tactic, keyword, and sub-techniques without loading all content into prompt output.')
    ap.add_argument('enterprise_attack_json')
    ap.add_argument('--ids', nargs='*')
    ap.add_argument('--platform')
    ap.add_argument('--tactic')
    ap.add_argument('--keyword')
    ap.add_argument('--expand-subtechs', action='store_true')
    ap.add_argument('--limit', type=int, default=50)
    ap.add_argument('--json', action='store_true')
    args=ap.parse_args()
    bundle=json.load(open(args.enterprise_attack_json, encoding='utf-8'))
    objs=bundle.get('objects',[]); id2={o.get('id'):o for o in objs if o.get('id')}
    parent={}
    for r in objs:
        if r.get('type')=='relationship' and r.get('relationship_type')=='subtechnique-of' and active(r): parent[r['source_ref']]=r['target_ref']
    data_comp={o['id']:o.get('name') for o in objs if o.get('type')=='x-mitre-data-component'}
    analytic={o['id']:o for o in objs if o.get('type')=='x-mitre-analytic' and active(o)}
    strategy={o['id']:o for o in objs if o.get('type')=='x-mitre-detection-strategy' and active(o)}
    tech_to_strategy=defaultdict(list)
    for r in objs:
        if r.get('type')=='relationship' and r.get('relationship_type')=='detects' and active(r) and r.get('source_ref') in strategy:
            tech_to_strategy[r.get('target_ref')].append(r.get('source_ref'))
    rows=[]; by_tid={}
    for o in objs:
        if o.get('type')!='attack-pattern' or not active(o): continue
        tid=ext_id(o)
        if not tid: continue
        par=id2.get(parent.get(o.get('id'),''),{})
        tactics=[p.get('phase_name') for p in o.get('kill_chain_phases') or [] if p.get('kill_chain_name')=='mitre-attack']
        ds_rows=[]; comps=[]; logs=[]
        for sid in tech_to_strategy.get(o.get('id'),[]):
            s=strategy.get(sid, {})
            ars=[]
            for arid in s.get('x_mitre_analytic_refs') or []:
                a=analytic.get(arid)
                if not a: continue
                lrs=[]
                for lr in a.get('x_mitre_log_source_references') or []:
                    comp=data_comp.get(lr.get('x_mitre_data_component_ref'), lr.get('x_mitre_data_component_ref'))
                    comps.append(comp); lrs.append({'name':lr.get('name'),'channel':lr.get('channel'),'data_component':comp})
                ars.append({'id':ext_id(a),'name':a.get('name'),'platforms':a.get('x_mitre_platforms') or [],'description':clean(a.get('description'),600),'log_source_references':lrs,'mutable_elements':a.get('x_mitre_mutable_elements') or []})
            ds_rows.append({'id':ext_id(s),'name':s.get('name'),'description':clean(s.get('description'),600),'analytics':ars})
        rec={'technique_id':tid,'name':o.get('name'),'is_subtechnique':bool(o.get('x_mitre_is_subtechnique') or '.' in tid),'parent_id':ext_id(par) if par else None,'platforms':o.get('x_mitre_platforms') or [],'tactics':tactics,'description':clean(o.get('description'),900),'data_components':sorted(set(x for x in comps if x)),'detection_strategies':ds_rows[:8],'modified':o.get('modified'),'version':o.get('x_mitre_version')}
        by_tid[tid]=rec
    selected=[]
    if args.ids:
        ids=[x.upper() for x in args.ids]
        for tid in ids:
            if tid in by_tid: selected.append(by_tid[tid])
            if args.expand_subtechs and '.' not in tid:
                selected += [r for k,r in by_tid.items() if r.get('parent_id')==tid or k.startswith(tid+'.')]
    else:
        selected=list(by_tid.values())
    if args.platform:
        ps=[p.strip().lower() for p in args.platform.split(',')]
        selected=[r for r in selected if any(p in [x.lower() for x in r.get('platforms',[])] for p in ps)]
    if args.tactic:
        selected=[r for r in selected if args.tactic.lower() in [t.lower() for t in r.get('tactics',[])]]
    if args.keyword:
        kw=args.keyword.lower(); selected=[r for r in selected if kw in (r.get('technique_id','')+' '+r.get('name','')+' '+r.get('description','')).lower()]
    seen={};
    for r in selected: seen[r['technique_id']]=r
    selected=[seen[k] for k in sorted(seen, key=lambda x:(x.split('.')[0], x))][:args.limit]
    for r in selected:
        print(json.dumps(r, ensure_ascii=False) if args.json else f"{r['technique_id']} {r['name']} platforms={','.join(r['platforms'])} tactics={','.join(r['tactics'])} strategies={len(r.get('detection_strategies',[]))} components={len(r.get('data_components',[]))}")
if __name__=='__main__': main()
