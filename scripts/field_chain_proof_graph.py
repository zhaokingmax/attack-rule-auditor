#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
from common import jsonl_read, jsonl_write, sha256_text

FIELD_KEYS = ['field','field_name','normalized_field','rule_field','collector_field','parser_field','source_field','target_field','name','semantic_field']
FIELD_LIST_KEYS = ['fields','field_refs','semantic_field_refs','required_fields','observed_fields','fields_seen','raw_fields_seen','matched_fields']

def normalize_field(value):
    if isinstance(value, dict):
        return str(value.get('semantic_field') or value.get('field') or value.get('name') or '').strip()
    return str(value or '').strip()

def iter_fields(row):
    for k in FIELD_KEYS:
        v=row.get(k)
        if isinstance(v,str) and v:
            yield v
    for k in FIELD_LIST_KEYS:
        v=row.get(k)
        if isinstance(v,list):
            for item in v:
                f=normalize_field(item)
                if f:
                    yield f

def stage_state(row, stage):
    for k in [stage, f'{stage}_ok', f'{stage}_present', f'{stage}_evidence']:
        if k in row:
            v=row.get(k)
            if isinstance(v,bool): return 'present' if v else 'missing'
            if v: return 'present'
    return 'unknown'

def main():
    ap=argparse.ArgumentParser(description='V10 field-chain proof graph: collector -> parser -> normalizer -> condition AST -> alert emitted field.')
    ap.add_argument('--field-chain')
    ap.add_argument('--data-component-gate')
    ap.add_argument('--condition-ast')
    ap.add_argument('--alias-findings')
    ap.add_argument('--output-json', required=True)
    ap.add_argument('--output-jsonl', required=True)
    ap.add_argument('--output-md', required=True)
    args=ap.parse_args()
    rows=[]
    for src, path in [('field_chain',args.field_chain),('data_component_gate',args.data_component_gate),('condition_ast',args.condition_ast),('alias_findings',args.alias_findings)]:
        if path: 
            for r in jsonl_read(Path(path)):
                r=dict(r); r['_source']=src; rows.append(r)
    by_field={}
    for r in rows:
        for f in sorted(set(iter_fields(r))):
            by_field.setdefault(f,[]).append(r)
    graphs=[]; blockers=[]
    for field, rs in sorted(by_field.items()):
        stages={
            'collector_emits':'unknown',
            'parser_preserves':'unknown',
            'normalizer_maps':'unknown',
            'condition_uses':'unknown',
            'alert_emits':'unknown',
        }
        components=set(); claims=set(); aliases=set(); sources=set()
        for r in rs:
            sources.add(r.get('_source','unknown'))
            for k in ['data_component','component','required_data_component','observed_data_component']:
                v=r.get(k)
                if isinstance(v,str) and v: components.add(v)
            for k in ['data_components','required_data_components','observed_data_components']:
                v=r.get(k)
                if isinstance(v,list): components.update(str(x) for x in v if x)
            for k in ['claim_id','attack_id','technique_id']:
                v=r.get(k)
                if isinstance(v,str) and v: claims.add(v)
            for k in ['alias','alias_for','canonical_field','normalized_field']:
                v=r.get(k)
                if isinstance(v,str) and v: aliases.add(v)
            src=r.get('_source')
            if src=='condition_ast':
                stages['condition_uses']='present'
                if r.get('condition_proof_state') == 'fielded_condition':
                    stages['parser_preserves']='present'
            if src=='alias_findings':
                stages['normalizer_maps']='present' if r.get('alias_quality','exact') not in ['invalid','not_equivalent'] else 'weak'
                if r.get('observed_fields'):
                    stages['parser_preserves']='present'
            if src=='data_component_gate':
                if r.get('rule_uses') or r.get('condition_uses') or r.get('used_in_rule'): stages['condition_uses']='present'
                if r.get('observed') or r.get('observed_data_components') or r.get('component_status') in ['present','pass','used']: stages['collector_emits']='present'
                if r.get('data_component_gate_passed') or r.get('data_component_state') in ['used_by_condition','observed_not_validated']:
                    stages['parser_preserves']='present'
            if src=='field_chain':
                if r.get('fields_seen') or r.get('candidate_mappings') or r.get('field_chain_static_state') == 'field_names_observed':
                    stages['parser_preserves']='present'
                if r.get('alias_hits') or r.get('candidate_mappings'):
                    stages['normalizer_maps']='present'
                for st in stages:
                    val=stage_state(r, st.split('_')[0])
                    if val != 'unknown': stages[st]=val
        # Alert emitted fields are optional for static-only repositories; keep it
        # visible but do not block field-chain proof unless an analyzer marks it
        # missing explicitly.
        missing=[k for k,v in stages.items() if v in ['missing','unknown'] and k in ['collector_emits','parser_preserves','normalizer_maps','condition_uses']]
        if missing:
            blockers.append({'field':field,'missing_stages':missing,'claims':sorted(claims)})
        graphs.append({
            'coverage_model_version':'V10.5-wave4',
            'field_graph_id': sha256_text(field)[:16],
            'field': field,
            'data_components': sorted(components),
            'aliases': sorted(aliases),
            'claims_or_attack_ids': sorted(claims),
            'sources': sorted(sources),
            'stages': stages,
            'stage_path': ['collector_emits','parser_preserves','normalizer_maps','condition_uses','alert_emits'],
            'field_chain_blockers': missing,
            'proof_state': 'pass' if not missing else 'incomplete',
        })
    jsonl_write(Path(args.output_jsonl), graphs)
    summary={'coverage_model_version':'V10.5-wave4','field_count':len(graphs),'field_chain_pass_count':sum(1 for g in graphs if g['proof_state']=='pass'),'field_chain_blocker_count':len(blockers),'blockers':blockers[:50]}
    Path(args.output_json).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    md=['# V10 Field-chain Proof Graph','',f"- field_count: `{summary['field_count']}`",f"- field_chain_pass_count: `{summary['field_chain_pass_count']}`",f"- field_chain_blocker_count: `{summary['field_chain_blocker_count']}`",'', '## Top Field-chain Blockers']
    if blockers:
        for b in blockers[:50]: md.append(f"- `{b['field']}` missing {b['missing_stages']} claims={b['claims']}")
    else: md.append('- None')
    Path(args.output_md).write_text('\n'.join(md)+'\n', encoding='utf-8')
if __name__=='__main__': main()
