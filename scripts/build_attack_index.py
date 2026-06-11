#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build compact MITRE ATT&CK Enterprise indexes without overwriting the external scenario map.

Usage:
  python scripts/build_attack_index.py /path/to/enterprise-attack.json attack_data/index --scenario-map attack_data/models/scenario_seed_map.json
"""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

def load_json(path: Path):
    return json.load(open(path, encoding='utf-8'))

def external_id(obj: Dict[str,Any]) -> Optional[str]:
    for ref in obj.get('external_references') or []:
        if ref.get('source_name') == 'mitre-attack' and ref.get('external_id'):
            return ref['external_id']
    return None

def external_url(obj):
    for ref in obj.get('external_references') or []:
        if ref.get('source_name') == 'mitre-attack' and ref.get('url'):
            return ref['url']
    return None

def active(obj): return not obj.get('revoked') and not obj.get('x_mitre_deprecated')
def clean(s, n=1200): return re.sub(r'\s+',' ',s or '').strip()[:n]
def sha256_file(path: Path):
    h=hashlib.sha256();
    with open(path,'rb') as f:
        for c in iter(lambda:f.read(1024*1024), b''): h.update(c)
    return h.hexdigest()

def write_jsonl(path: Path, rows: Iterable[Dict[str,Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    count=0
    with open(path,'w',encoding='utf-8') as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, separators=(',',':'))+'\n'); count+=1
    return count

def build(src: Path, out_dir: Path, scenario_map: Optional[Path]=None):
    bundle=load_json(src); objs=bundle.get('objects',[]); id2={o.get('id'):o for o in objs if o.get('id')}
    collection=next((o for o in objs if o.get('type')=='x-mitre-collection'), {})
    source_sha=sha256_file(src)
    parent_stix={}
    rels=[]
    for rel in objs:
        if rel.get('type')=='relationship':
            rels.append(rel)
            if rel.get('relationship_type')=='subtechnique-of' and active(rel):
                parent_stix[rel['source_ref']]=rel['target_ref']
    data_component_name={o['id']:o.get('name',o['id']) for o in objs if o.get('type')=='x-mitre-data-component'}
    data_components=[]
    for o in objs:
        if o.get('type')=='x-mitre-data-component':
            data_components.append({'stix_id':o.get('id'),'id':external_id(o),'name':o.get('name'),'description':clean(o.get('description'),500),'modified':o.get('modified'),'version':o.get('x_mitre_version'),'active':active(o)})
    strategies=[]; analytics=[]
    strategy_by_stix={}; analytic_by_stix={}
    for o in objs:
        if o.get('type')=='x-mitre-analytic':
            rec={'stix_id':o.get('id'),'id':external_id(o),'name':o.get('name'),'description':clean(o.get('description'),900),'platforms':o.get('x_mitre_platforms') or [],'log_source_references':[], 'mutable_elements':o.get('x_mitre_mutable_elements') or [], 'modified':o.get('modified'),'version':o.get('x_mitre_version'),'active':active(o)}
            for lr in o.get('x_mitre_log_source_references') or []:
                comp=data_component_name.get(lr.get('x_mitre_data_component_ref'), lr.get('x_mitre_data_component_ref'))
                rec['log_source_references'].append({'name':lr.get('name'),'channel':lr.get('channel'),'data_component':comp,'data_component_ref':lr.get('x_mitre_data_component_ref')})
            analytics.append(rec); analytic_by_stix[o.get('id')]=rec
        if o.get('type')=='x-mitre-detection-strategy':
            rec={'stix_id':o.get('id'),'id':external_id(o),'name':o.get('name'),'description':clean(o.get('description'),900),'analytic_refs':o.get('x_mitre_analytic_refs') or [],'analytics':[], 'modified':o.get('modified'),'version':o.get('x_mitre_version'),'active':active(o)}
            strategies.append(rec); strategy_by_stix[o.get('id')]=rec
    for s in strategies:
        s['analytics']=[analytic_by_stix[a] for a in s['analytic_refs'] if a in analytic_by_stix and analytic_by_stix[a].get('active')][:10]
    tech_to_strategy=defaultdict(list)
    for rel in rels:
        if rel.get('relationship_type')=='detects' and active(rel):
            src_obj=id2.get(rel.get('source_ref'), {})
            if src_obj.get('type')=='x-mitre-detection-strategy':
                tech_to_strategy[rel.get('target_ref')].append(rel.get('source_ref'))
    rows=[]; inactive=[]
    for o in objs:
        if o.get('type')!='attack-pattern': continue
        tid=external_id(o)
        if not tid or not tid.startswith('T'): continue
        parent=id2.get(parent_stix.get(o.get('id'),''),{})
        tactics=[p.get('phase_name') for p in o.get('kill_chain_phases') or [] if p.get('kill_chain_name')=='mitre-attack']
        dss=[]; logs=[]; comps=[]
        for dsid in tech_to_strategy.get(o.get('id'),[]):
            ds=strategy_by_stix.get(dsid)
            if not ds or not ds.get('active'): continue
            dss.append({'id':ds.get('id'),'name':ds.get('name'),'description':ds.get('description'),'analytics':[{'id':a.get('id'),'name':a.get('name'),'platforms':a.get('platforms'),'summary':a.get('description'),'log_source_references':a.get('log_source_references'),'mutable_elements':a.get('mutable_elements')} for a in ds.get('analytics',[])[:8]]})
            for a in ds.get('analytics',[]):
                for lr in a.get('log_source_references') or []:
                    logs.append(lr)
                    if lr.get('data_component'): comps.append(lr.get('data_component'))
        seen=set(); dedup=[]
        for lr in logs:
            key=(lr.get('name'),lr.get('channel'),lr.get('data_component'))
            if key not in seen: seen.add(key); dedup.append(lr)
        rec={'technique_id':tid,'name':o.get('name'),'stix_id':o.get('id'),'active':active(o),'revoked':bool(o.get('revoked')),'deprecated':bool(o.get('x_mitre_deprecated')),'is_subtechnique':bool(o.get('x_mitre_is_subtechnique') or '.' in tid),'parent_id':external_id(parent) if parent else None,'parent_name':parent.get('name') if parent else None,'tactics':tactics,'platforms':o.get('x_mitre_platforms') or [],'description':clean(o.get('description'),1600),'url':external_url(o),'detection_strategies':dss[:10],'log_sources':dedup[:30],'data_components':sorted(set(x for x in comps if x))[:50],'modified':o.get('modified'),'version':o.get('x_mitre_version'),'source_sha256':source_sha,'attack_collection_version':collection.get('x_mitre_version'),'attack_collection_modified':collection.get('modified')}
        (rows if active(o) else inactive).append(rec)
    rows.sort(key=lambda r:(r['technique_id'].split('.')[0], r['technique_id']))
    inactive.sort(key=lambda r:(r['technique_id'].split('.')[0], r['technique_id']))
    out_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(out_dir/'techniques_min.jsonl', rows)
    write_jsonl(out_dir/'inactive_techniques.jsonl', inactive)
    write_jsonl(out_dir/'detection_strategies.jsonl', [s for s in strategies if s.get('active')])
    write_jsonl(out_dir/'analytics.jsonl', [a for a in analytics if a.get('active')])
    write_jsonl(out_dir/'data_components.jsonl', [d for d in data_components if d.get('active')])
    lookup={r['technique_id']:r for r in rows}
    lookup_all={r['technique_id']:r for r in rows+inactive}
    (out_dir/'lookup_by_id.json').write_text(json.dumps(lookup, indent=2, ensure_ascii=False), encoding='utf-8')
    (out_dir/'lookup_all_by_id.json').write_text(json.dumps(lookup_all, indent=2, ensure_ascii=False), encoding='utf-8')
    platforms=sorted({p for r in rows for p in r.get('platforms',[])})
    tactics=sorted({t for r in rows for t in r.get('tactics',[])})
    for p in platforms:
        safe=re.sub(r'[^A-Za-z0-9_.-]+','_',p)
        write_jsonl(out_dir/'by_platform'/f'{safe}.jsonl', (r for r in rows if p in r.get('platforms',[])))
    for t in tactics:
        safe=re.sub(r'[^A-Za-z0-9_.-]+','_',t)
        write_jsonl(out_dir/'by_tactic'/f'{safe}.jsonl', (r for r in rows if t in r.get('tactics',[])))
    write_jsonl(out_dir/'linux_container_scope.jsonl', (r for r in rows if 'Linux' in r.get('platforms',[]) or 'Containers' in r.get('platforms',[])))
    write_jsonl(out_dir/'linux_container_network_scope.jsonl', (r for r in rows if 'Linux' in r.get('platforms',[]) or 'Containers' in r.get('platforms',[]) or 'Network Devices' in r.get('platforms',[])))
    # Scenario maps live under attack_data/models. The ATT&CK index directory
    # should remain a pure index so index rebuilds cannot overwrite models.
    linux_container_network_scope = [
        r for r in rows
        if 'Linux' in r.get('platforms',[]) or 'Containers' in r.get('platforms',[]) or 'Network Devices' in r.get('platforms',[])
    ]
    meta={'source_file':str(src),'source_sha256':source_sha,'collection_name':collection.get('name'),'attack_version':collection.get('x_mitre_version'),'attack_spec_version':collection.get('x_mitre_attack_spec_version'),'collection_modified':collection.get('modified'),'generated_at_utc':dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),'active_attack_pattern_count':len(rows),'inactive_attack_pattern_count':len(inactive),'active_parent_technique_count':sum(1 for r in rows if not r['is_subtechnique']),'active_subtechnique_count':sum(1 for r in rows if r['is_subtechnique']),'linux_technique_count':sum(1 for r in rows if 'Linux' in r.get('platforms',[])),'container_technique_count':sum(1 for r in rows if 'Containers' in r.get('platforms',[])),'network_device_technique_count':sum(1 for r in rows if 'Network Devices' in r.get('platforms',[])),'linux_container_network_scope_count':len(linux_container_network_scope),'platforms':platforms,'tactics':tactics,'detection_strategy_count':sum(1 for s in strategies if s.get('active')),'analytic_count':sum(1 for a in analytics if a.get('active')),'data_component_count':sum(1 for d in data_components if d.get('active'))}
    (out_dir/'metadata.json').write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps(meta, indent=2, ensure_ascii=False))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('enterprise_attack_json')
    ap.add_argument('out_dir')
    ap.add_argument(
        '--scenario-map',
        help='Compatibility only. Scenario maps live under attack_data/models and are not copied into attack_data/index.',
    )
    args=ap.parse_args()
    build(Path(args.enterprise_attack_json), Path(args.out_dir), Path(args.scenario_map) if args.scenario_map else None)
if __name__=='__main__': main()
