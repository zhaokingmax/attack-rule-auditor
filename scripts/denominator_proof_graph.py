#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, hashlib, time
from pathlib import Path
from common import jsonl_read, jsonl_write, sha256_text

FALSE_FRIENDS = {
    'container_escape': ['container_discovery','generic_container_inventory','image_inventory'],
    'credential_access': ['generic_file_read','backup_file_access','scanner_file_access'],
    'defense_impairment_stealth': ['generic_process_stop','benign_log_rotation','admin_history_cleanup'],
    'process_injection_memory': ['generic_process_creation','suspicious_process_name'],
}

def load_model(path: Path) -> dict:
    try:
        return json.load(open(path, encoding='utf-8'))
    except Exception:
        return {}

def scenario_obj(model: dict, name: str) -> dict:
    if not name:
        return {}
    if isinstance(model.get(name), dict):
        return model.get(name, {})
    sc = model.get('scenarios', {})
    if isinstance(sc, dict):
        return sc.get(name, {})
    if isinstance(sc, list):
        for x in sc:
            if x.get('id') == name or x.get('scenario') == name or x.get('name') == name:
                return x
    return {}

def extract_primitives(sobj: dict) -> list[dict]:
    for key in ['behavior_primitives','primitives','behavior_primitive_matrix']:
        val = sobj.get(key)
        if isinstance(val, list):
            out=[]
            for item in val:
                if isinstance(item, str): out.append({'id': item})
                elif isinstance(item, dict): out.append(item)
            return out
        if isinstance(val, dict):
            return [dict({'id': k}, **(v if isinstance(v, dict) else {})) for k,v in val.items()]
    return []

def related_primitives(sobj: dict, tid: str) -> list[dict]:
    if not tid:
        return []
    out=[]
    parent = tid.split('.', 1)[0] if '.' in tid else None
    for p in extract_primitives(sobj):
        aids={str(x).upper() for x in p.get('attack_ids', []) or []}
        if tid.upper() in aids or (parent and parent in aids):
            out.append(p)
            continue
        if any(str(a).upper().startswith(tid.upper()+'.') for a in aids):
            out.append(p)
    return out

def related_bypasses(sobj: dict, tid: str, primitives: list[dict]) -> list[dict]:
    primitive_ids={p.get('id') for p in primitives if p.get('id')}
    out=[]
    for b in sobj.get('bypass_primitives', []) or []:
        aids={str(x).upper() for x in b.get('attack_ids', []) or []}
        behavior=b.get('behavior_primitive')
        if behavior in primitive_ids or tid.upper() in aids or any(str(a).upper().startswith(tid.upper()+'.') for a in aids):
            out.append(b)
    return out

def main():
    ap=argparse.ArgumentParser(description='V9 denominator proof graph and anti-inclusion checker.')
    ap.add_argument('--denominator', required=True)
    ap.add_argument('--negative-denominator')
    ap.add_argument('--scenario-model', required=True)
    ap.add_argument('--scenario', default='unknown')
    ap.add_argument('--alias-pack')
    ap.add_argument('--attack-version', default='unknown')
    ap.add_argument('--output-jsonl', required=True)
    ap.add_argument('--output-summary', required=True)
    ap.add_argument('--output-lockfile', required=True)
    ap.add_argument('--output-md', required=True)
    args=ap.parse_args()
    denom=jsonl_read(Path(args.denominator))
    neg=jsonl_read(Path(args.negative_denominator)) if args.negative_denominator else []
    model=load_model(Path(args.scenario_model))
    sobj=scenario_obj(model, args.scenario)
    primitives=extract_primitives(sobj)
    primitive_ids={str(p.get('id') or p.get('name') or p.get('primitive') or '').lower() for p in primitives}
    model_version=str(model.get('model_version') or model.get('version') or (model.get('_meta') or {}).get('coverage_model_version') or 'unknown')
    alias_hash='none'
    if args.alias_pack and Path(args.alias_pack).exists():
        alias_hash=hashlib.sha256(Path(args.alias_pack).read_bytes()).hexdigest()[:16]
    rows=[]; invalid=0; candidate=0; low_conf=0; formal=0
    for d in denom:
        tid=d.get('technique_id') or d.get('attack_id') or d.get('id') or d.get('technique')
        scenario=d.get('scenario') or args.scenario or 'unknown'
        primitive=d.get('behavior_primitive') or d.get('primitive') or d.get('behavior_primitive_id') or ''
        include_reason=d.get('include_reason_type') or d.get('include_reason') or d.get('reason') or ''
        tier=d.get('tier') or d.get('denominator_source') or d.get('coverage_tier') or 'candidate'
        req_dc=d.get('required_data_components') or d.get('data_components') or []
        rel_primitives = related_primitives(sobj, str(tid)) if not primitive else [p for p in primitives if p.get('id') == primitive]
        if not primitive and rel_primitives:
            primitive = rel_primitives[0].get('id') or ''
        rel_bypasses = related_bypasses(sobj, str(tid), rel_primitives)
        req_bypass=d.get('required_bypass_variants') or d.get('bypass_variants') or [b.get('id') for b in rel_bypasses if b.get('id')]
        if not req_dc and rel_primitives:
            seen_dc=[]
            for p in rel_primitives:
                for dc in p.get('required_data_components', []) or []:
                    if dc not in seen_dc:
                        seen_dc.append(dc)
            req_dc=seen_dc
        confidence=d.get('confidence') or d.get('denominator_confidence') or 'medium'
        proof_edges=[]; blockers=[]; anti=[]
        if scenario and scenario!='unknown': proof_edges.append('scenario -> primitive')
        else: blockers.append('missing_scenario')
        if primitive: proof_edges.append('primitive -> ATT&CK')
        else: blockers.append('missing_behavior_primitive')
        if tid: proof_edges.append('ATT&CK -> denominator item')
        else: blockers.append('missing_attack_id')
        if req_dc: proof_edges.append('ATT&CK -> data components')
        else: blockers.append('missing_required_data_components')
        if req_bypass: proof_edges.append('primitive -> bypass variants')
        else: blockers.append('missing_required_bypass_variants')
        if include_reason: proof_edges.append('include_reason -> denominator item')
        else: blockers.append('missing_include_reason')
        if str(confidence).lower() in ['low','candidate','unknown']:
            low_conf += 1; blockers.append('low_confidence_denominator')
        if 'keyword' in str(include_reason).lower() or str(tier).lower() == 'candidate':
            candidate += 1; blockers.append('candidate_requires_review')
        # anti-inclusion checks
        anti.append({'check':'wrong_scenario','result':'pass' if scenario==args.scenario or args.scenario=='unknown' else 'review','reason':scenario})
        anti.append({'check':'platform_mismatch','result':'unknown','reason':'platform compatibility is evaluated upstream'})
        anti.append({'check':'merely_related_not_required','result':'pass' if primitive else 'fail','reason':'behavior primitive binding required'})
        if primitive and primitive.lower() not in primitive_ids and primitive_ids:
            blockers.append('primitive_not_found_in_scenario_model')
        status='formal_denominator' if not blockers or all(b in ['missing_required_bypass_variants'] for b in blockers) else 'candidate_denominator'
        if status=='formal_denominator': formal += 1
        else: invalid += 1
        row={
            'coverage_model_version':'V9.0',
            'proof_graph_id': sha256_text(json.dumps([scenario, primitive, tid, tier], ensure_ascii=False))[:16],
            'scenario': scenario,
            'behavior_primitive': primitive,
            'related_behavior_primitives': [p.get('id') for p in rel_primitives if p.get('id')],
            'attack_id': tid,
            'tier': tier,
            'criticality': d.get('criticality') or ('critical' if tier=='must_cover' else 'important' if tier=='should_cover' else 'optional'),
            'observable_required': d.get('observable_required','unknown'),
            'required_data_components': req_dc,
            'required_bypass_variants': req_bypass,
            'include_reason_type': include_reason,
            'proof_edges': proof_edges,
            'anti_inclusion_check': anti,
            'denominator_status': status,
            'denominator_blockers': sorted(set(blockers)),
            'same_tactic_false_friends': FALSE_FRIENDS.get(args.scenario, []),
            'source_record': d,
        }
        rows.append(row)
    jsonl_write(Path(args.output_jsonl), rows)
    hash_input=json.dumps(rows, ensure_ascii=False, sort_keys=True)
    denom_hash=hashlib.sha256(hash_input.encode()).hexdigest()
    summary={
        'coverage_model_version':'V9.0',
        'attack_version':args.attack_version,
        'scenario_model_version':model_version,
        'alias_pack_hash':alias_hash,
        'coverage_gate_version':'V9.0',
        'denominator_hash':denom_hash,
        'total_denominator_items':len(denom),
        'formal_denominator_items':formal,
        'candidate_denominator_items':candidate,
        'invalid_or_review_denominator_items':invalid,
        'low_confidence_denominator_items':low_conf,
        'negative_denominator_items':len(neg),
        'complete_coverage_allowed_by_denominator': candidate==0 and invalid==0 and len(denom)>0,
        'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    lock={'coverage_model_version':'V9.0','denominator_hash':denom_hash,'attack_version':args.attack_version,'scenario_model_version':model_version,'alias_pack_hash':alias_hash,'items':[{'attack_id':r['attack_id'],'primitive':r['behavior_primitive'],'tier':r['tier'],'status':r['denominator_status']} for r in rows]}
    Path(args.output_lockfile).write_text(json.dumps(lock, ensure_ascii=False, indent=2), encoding='utf-8')
    md=['# V9 Denominator Proof Graph Review','',f'- denominator_hash: `{denom_hash}`',f'- formal items: `{formal}`',f'- candidate items: `{candidate}`',f'- invalid/review items: `{invalid}`','','## Blocking Findings']
    for r in rows:
        if r['denominator_status']!='formal_denominator':
            md.append(f"- `{r['attack_id']}` / `{r['behavior_primitive']}`: {', '.join(r['denominator_blockers'])}")
    if len(md)==8: md.append('- None')
    Path(args.output_md).write_text('\n'.join(md)+'\n', encoding='utf-8')
if __name__=='__main__': main()
