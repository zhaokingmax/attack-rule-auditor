#!/usr/bin/env python3
from __future__ import annotations
"""V8.0 Data Component alias mapper.

Maps observed rule fields to canonical semantic fields and ATT&CK Data Component
hints. This reduces false field-chain gaps across ECS/OCSF/Falco/auditd/eBPF/K8s
schemas.
"""
import argparse, json, re
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

def norm(s: str) -> str:
    return re.sub(r'[^a-z0-9]+','', str(s).lower())

def build_alias(pack: Dict[str, Any]):
    alias={}
    for sem, names in (pack.get('semantic_fields') or {}).items():
        for n in names:
            alias[norm(n)]=sem
    return alias

def main():
    ap=argparse.ArgumentParser(description='Map observed fields to canonical semantic fields and Data Component hints.')
    ap.add_argument('--parsed-rules', required=True)
    ap.add_argument('--alias-pack', default='attack_data/field_aliases/common_linux_container_k8s_network.json')
    ap.add_argument('--output-jsonl', default='data_component_alias_findings.jsonl')
    ap.add_argument('--output-summary', default='data_component_alias_summary.json')
    args=ap.parse_args()
    rules=read_jsonl(Path(args.parsed_rules))
    pack=json.load(open(args.alias_pack, encoding='utf-8'))
    alias=build_alias(pack)
    component_hints=pack.get('attack_data_component_hints') or {}
    rows=[]
    component_seen={c:set() for c in component_hints}
    for r in rules:
        observed=[]
        for f in r.get('required_fields') or []:
            sem=alias.get(norm(f))
            observed.append({'field':f,'semantic_field':sem,'alias_matched':bool(sem)})
            if sem:
                for dc, sems in component_hints.items():
                    if sem in sems: component_seen.setdefault(dc,set()).add(sem)
        rows.append({
            'rule_id': r.get('rule_id'),
            'rule_name': r.get('rule_name'),
            'file_path': r.get('file_path'),
            'observed_field_count': len(r.get('required_fields') or []),
            'mapped_semantic_field_count': sum(1 for x in observed if x['alias_matched']),
            'observed_fields': observed,
            'potential_data_components': sorted([dc for dc,sems in component_hints.items() if any(x.get('semantic_field') in sems for x in observed)]),
        })
    write_jsonl(Path(args.output_jsonl), rows)
    summary={
        'coverage_model_version':'V8.0',
        'rule_count': len(rules),
        'alias_pack_version': pack.get('version'),
        'mapped_rule_count': sum(1 for r in rows if r['mapped_semantic_field_count']>0),
        'data_component_semantic_coverage': {dc: sorted(vals) for dc, vals in component_seen.items() if vals},
    }
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__=='__main__': main()
