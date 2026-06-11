#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
from common import jsonl_read, jsonl_write

CONTROL = {
    'path_variant':'high','argument_variant':'high','tool_variant':'high','namespace_variant':'high',
    'runtime_variant':'medium','syscall_variant':'medium','timing_variant':'medium',
    'log_source_variant':'medium','parser_variant':'medium','sensor_health':'low',
    'protocol_variant':'high','identity_variant':'high','image_variant':'medium',
    'k8s_subresource_variant':'high','data_volume_variant':'medium',
    'field_chain_variant':'medium','semantic_bypass':'medium',
}

def classify_variant(v: str) -> str:
    s=(v or '').lower()
    if s in CONTROL: return s
    if any(x in s for x in ['path','sock','socket','hostpath','subpath','shadow','authorized','profile']): return 'path_variant'
    if any(x in s for x in ['arg','quote','base64','unicode','encoded','cmdline','contains']): return 'argument_variant'
    if any(x in s for x in ['curl','wget','kubectl','docker','nerdctl','crictl','tool']): return 'tool_variant'
    if any(x in s for x in ['pid','namespace','nsenter','setns','hostpid','hostnetwork']): return 'namespace_variant'
    if any(x in s for x in ['containerd','cri-o','runc','kata','gvisor','runtime']): return 'runtime_variant'
    if any(x in s for x in ['protocol','dns','http','ftp','scp','sftp','proxy','tunnel']): return 'protocol_variant'
    if any(x in s for x in ['identity','token','account','serviceaccount','rbac','role','auth']): return 'identity_variant'
    if any(x in s for x in ['image','registry','digest','tag','dependency','package']): return 'image_variant'
    if any(x in s for x in ['k8s','pods/','subresource','attach','portforward','tokenrequest']): return 'k8s_subresource_variant'
    if any(x in s for x in ['volume','bytes','chunk','rate','size']): return 'data_volume_variant'
    if any(x in s for x in ['syscall','ptrace','process_vm','memfd','mprotect','mmap','openat']): return 'syscall_variant'
    if any(x in s for x in ['window','timing','slow','sequence','order']): return 'timing_variant'
    if any(x in s for x in ['audit','ebpf','falco','log','source']): return 'log_source_variant'
    if any(x in s for x in ['parser','normalizer','alias','truncate']): return 'parser_variant'
    return 'semantic_bypass'

def main():
    ap=argparse.ArgumentParser(description='V9 bypass minimal cut-set and weighted bypass risk analyzer.')
    ap.add_argument('--bypass-matrix', required=True)
    ap.add_argument('--claims')
    ap.add_argument('--output-jsonl', required=True)
    ap.add_argument('--output-summary', required=True)
    ap.add_argument('--output-md', required=True)
    args=ap.parse_args()
    rows=jsonl_read(Path(args.bypass_matrix))
    claims=jsonl_read(Path(args.claims)) if args.claims else []
    claim_by_tid={str(c.get('technique_id') or c.get('attack_id') or ''):c for c in claims}
    out=[]; high_unchecked=0; critical_unchecked=0; total_weight=0.0; covered_weight=0.0
    for b in rows:
        tid=str(b.get('technique_id') or b.get('attack_id') or '')
        primitive=b.get('behavior_primitive') or b.get('primitive') or 'unknown'
        variant=b.get('bypass_variant') or b.get('variant') or b.get('bypass') or 'unknown'
        category=classify_variant(str(b.get('bypass_category') or b.get('category') or variant))
        level=str(b.get('bypass_check_level') or b.get('checked') or 'unchecked').lower()
        checked=level in ['condition_checked','field_chain_checked','test_checked','resilience_validated','true','checked']
        critical=bool(b.get('critical') or b.get('criticality')=='critical')
        attacker_control=b.get('attacker_control_level') or CONTROL.get(category,'medium')
        triviality='trivial' if attacker_control=='high' and category in ['path_variant','argument_variant','tool_variant'] else 'moderate' if attacker_control in ['high','medium'] else 'hard'
        weight=(3 if critical else 1) * (3 if attacker_control=='high' else 2 if attacker_control=='medium' else 1) * (2 if triviality=='trivial' else 1)
        total_weight += weight
        if checked: covered_weight += weight
        if not checked and attacker_control=='high': high_unchecked += 1
        if not checked and critical: critical_unchecked += 1
        missing=[]
        if not checked: missing.append('no_condition_or_fixture_proof')
        if level=='mentioned_only': missing.append('mentioned_only_is_not_checked')
        if not b.get('field_chain_evidence_ids') and not b.get('field_chain_checked'): missing.append('no_field_chain_proof')
        if not b.get('fixture_id') and level not in ['test_checked','resilience_validated']: missing.append('no_bypass_fixture')
        cut=[]
        if 'no_condition_or_fixture_proof' in missing: cut.append('add semantic condition for variant')
        if 'no_field_chain_proof' in missing: cut.append('prove field chain for variant fields')
        if 'no_bypass_fixture' in missing: cut.append('add safe bypass fixture bound to attack_path_id')
        out.append({
            'coverage_model_version':'V9.0',
            'technique_id':tid,
            'claim_id': claim_by_tid.get(tid,{}).get('claim_id'),
            'behavior_primitive':primitive,
            'bypass_variant':variant,
            'bypass_category':category,
            'attacker_control_level':attacker_control,
            'triviality':triviality,
            'critical':critical,
            'bypass_check_level':level,
            'checked':checked,
            'weighted_risk':weight,
            'bypass_unchecked_reason':missing,
            'minimal_cut_set_to_close_gap':cut,
            'direct_or_observability': 'observability_bypass' if category in ['log_source_variant','parser_variant'] else 'direct_bypass',
            'source_bypass':b,
        })
    jsonl_write(Path(args.output_jsonl), out)
    score=round(covered_weight/total_weight,4) if total_weight else 0
    summary={'coverage_model_version':'V9.0','bypass_item_count':len(out),'weighted_bypass_score':score,'critical_bypass_unchecked_count':critical_unchecked,'high_control_bypass_unchecked_count':high_unchecked,'total_bypass_weight':total_weight,'covered_bypass_weight':covered_weight}
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    md=['# V9 Bypass Minimal Cut-Set Analysis','',f"- weighted_bypass_score: `{score}`",f"- critical_bypass_unchecked_count: `{critical_unchecked}`",f"- high_control_bypass_unchecked_count: `{high_unchecked}`",'', '## Highest Priority Gaps']
    for r in sorted([x for x in out if not x['checked']], key=lambda x:x['weighted_risk'], reverse=True)[:25]:
        md.append(f"- `{r['technique_id']}` `{r['behavior_primitive']}` / `{r['bypass_variant']}` weight={r['weighted_risk']}: {', '.join(r['minimal_cut_set_to_close_gap'])}")
    Path(args.output_md).write_text('\n'.join(md)+'\n', encoding='utf-8')
if __name__=='__main__': main()
