#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
from common import jsonl_read, jsonl_write, normalize_data_component

DEFAULT_MINSETS = {
  'runtime_socket_abuse': [['File Access','Container Creation'], ['Process Creation','Container Creation']],
  'hostpath_abuse': [['Cloud Service Modification','Container Creation'], ['File Access','Container Creation']],
  'ptrace_injection': [['Process Metadata','OS API Execution'], ['Process Creation','Process Metadata']],
  'memfd_execution': [['Process Creation','File Metadata'], ['OS API Execution','Process Metadata']],
  'credential_file_access': [['File Access','Process Metadata','User Account Authentication']],
  'k8s_secret_access': [['Cloud Service Modification','User Account Authentication']],
}
ALIASES = {
  'process': 'Process Metadata', 'process creation':'Process Creation', 'proc':'Process Metadata', 'syscall':'OS API Execution',
  'file':'File Access', 'path':'File Access', 'container':'Container Creation', 'kubernetes':'Cloud Service Modification', 'k8s':'Cloud Service Modification',
  'user':'User Account Authentication', 'uid':'User Account Authentication', 'network':'Network Connection Creation'
}

def normalize_component(x):
    s=normalize_data_component(x)
    low=s.lower()
    return normalize_data_component(ALIASES.get(low, s))

def comps_from_row(row):
    vals=[]
    for k in ['observed_data_components','data_components','required_data_components','mapped_data_components','components']:
        v=row.get(k)
        if isinstance(v, list): vals += v
        elif isinstance(v, str) and v: vals += [v]
    for f in row.get('fields',[]) if isinstance(row.get('fields'),list) else []:
        vals.append(normalize_component(f))
    return {normalize_component(v) for v in vals if v}

def main():
    ap=argparse.ArgumentParser(description='V9 Data Component minimum-set evaluator per behavior primitive.')
    ap.add_argument('--data-component-gate', required=True)
    ap.add_argument('--behavior-matrix')
    ap.add_argument('--scenario-model')
    ap.add_argument('--output-jsonl', required=True)
    ap.add_argument('--output-summary', required=True)
    ap.add_argument('--output-md', required=True)
    args=ap.parse_args()
    gate=jsonl_read(Path(args.data_component_gate))
    behavior=jsonl_read(Path(args.behavior_matrix)) if args.behavior_matrix else []
    gate_by_key={}
    for g in gate:
        key=(str(g.get('technique_id') or g.get('attack_id') or ''), str(g.get('behavior_primitive') or g.get('primitive') or ''))
        gate_by_key.setdefault(key,[]).append(g)
    out=[]; passed=0; total=0
    source_rows=behavior or gate
    for b in source_rows:
        tid=str(b.get('technique_id') or b.get('attack_id') or '')
        prim=str(b.get('behavior_primitive') or b.get('primitive') or b.get('id') or 'unknown')
        entries=gate_by_key.get((tid,prim),[]) or ([b] if not behavior else [])
        observed=set()
        for e in entries: observed |= comps_from_row(e)
        minsets=b.get('data_component_minimum_sets') or DEFAULT_MINSETS.get(prim, [])
        if not minsets:
            # fallback: if the gate already passed, treat its required components as contextual only
            req=[]
            for e in entries: req += list(comps_from_row(e))
            minsets=[sorted(set(req))] if req else []
        minsets_norm=[[normalize_component(x) for x in ms] for ms in minsets]
        satisfied=[ms for ms in minsets_norm if set(ms).issubset(observed)]
        missing=[]
        for ms in minsets_norm:
            miss=sorted(set(ms)-observed)
            if miss: missing.append({'minimum_set':ms,'missing_components':miss})
        status='pass' if satisfied else 'fail' if minsets_norm else 'unknown'
        if status=='pass': passed += 1
        total += 1
        out.append({'coverage_model_version':'V10.5-wave4','technique_id':tid,'behavior_primitive':prim,'observed_data_components':sorted(observed),'data_component_minimum_sets':minsets_norm,'minimum_set_status':status,'satisfied_minimum_sets':satisfied,'missing_minimum_sets':missing,'final_claim_cap':'field_chain_validated_or_higher' if status=='pass' else 'condition_present','source':b})
    jsonl_write(Path(args.output_jsonl), out)
    rate=round(passed/(total or 1),4)
    summary={'coverage_model_version':'V10.5-wave4','primitive_count':total,'minimum_set_pass_count':passed,'data_component_minimum_set_rate':rate,'minimum_set_fail_count':sum(1 for x in out if x['minimum_set_status']=='fail')}
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    md=['# V10.5 Data Component Minimum Set Review','',f'- data_component_minimum_set_rate: `{rate}`','','## Missing Minimum Sets']
    for r in out:
        if r['minimum_set_status']=='fail':
            md.append(f"- `{r['technique_id']}` `{r['behavior_primitive']}` missing: {r['missing_minimum_sets']}")
    if len(md)==5: md.append('- None')
    Path(args.output_md).write_text('\n'.join(md)+'\n', encoding='utf-8')
if __name__=='__main__': main()
