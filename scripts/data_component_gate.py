#!/usr/bin/env python3
from __future__ import annotations
"""V8 Data Component coverage gate.

Checks whether ATT&CK/primitive required Data Components are observed, aliased,
used by rule conditions, and emitted for investigation.
"""
import argparse, json
from pathlib import Path
from typing import Any, Dict, List
from common import normalize_data_component


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists(): return []
    out=[]
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        if not line.strip(): continue
        try: out.append(json.loads(line))
        except Exception: pass
    return out


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False)+'\n')
    return len(rows)


def fields_from_rule(r: Dict[str, Any]) -> set[str]:
    vals=set(str(x).lower() for x in r.get('required_fields', []) or [])
    for frag in r.get('condition_fragments', []) or []:
        vals.add(str(frag.get('path','')).lower())
        vals.add(str(frag.get('value','')).lower()[:500])
    return vals


def build_component_aliases(pack: Dict[str, Any]) -> Dict[str, List[str]]:
    component_hints = pack.get('attack_data_component_hints') or {}
    semantic_fields = pack.get('semantic_fields') or {}
    aliases: Dict[str, List[str]] = {}
    for component, semantic_names in component_hints.items():
        canonical = normalize_data_component(component)
        vals = {canonical, component}
        for sem in semantic_names or []:
            vals.add(str(sem))
            vals.update(str(x) for x in semantic_fields.get(sem, []) or [])
        aliases.setdefault(canonical, [])
        aliases[canonical].extend(sorted(vals))
    for component, vals in (pack.get('data_component_aliases') or {}).items():
        canonical = normalize_data_component(component)
        aliases.setdefault(canonical, [])
        aliases[canonical].extend(str(x) for x in vals or [])
    return {k: sorted(set(v)) for k, v in aliases.items()}


def component_observed(component: str, aliases: Dict[str, List[str]], field_blob: str) -> bool:
    canonical = normalize_data_component(component)
    keys=[canonical, component]
    keys.extend(aliases.get(canonical, []) or [])
    lo=field_blob.lower()
    for k in keys:
        kk=str(k).lower()
        if kk and kk in lo:
            return True
    return False


def main():
    ap=argparse.ArgumentParser(description='Apply V8 Data Component gate to ATT&CK coverage claims.')
    ap.add_argument('--coverage', required=True)
    ap.add_argument('--parsed-rules', required=True)
    ap.add_argument('--behavior-matrix')
    ap.add_argument('--alias-pack')
    ap.add_argument('--data-component-coverage')
    ap.add_argument('--output-jsonl', default='data_component_gate.jsonl')
    ap.add_argument('--output-summary', default='data_component_gate_summary.json')
    args=ap.parse_args()
    coverage=read_jsonl(Path(args.coverage)); rules=read_jsonl(Path(args.parsed_rules)); behavior=read_jsonl(Path(args.behavior_matrix)) if args.behavior_matrix else []
    aliases={}
    if args.alias_pack and Path(args.alias_pack).exists():
        pack=json.load(open(args.alias_pack, encoding='utf-8'))
        aliases=build_component_aliases(pack)
    field_blob='\n'.join([' '.join(fields_from_rule(r)) for r in rules])
    required_by_tid={}
    for b in behavior:
        tid=b.get('technique_id')
        if not tid: continue
        for dc in b.get('required_data_components', []) or []:
            required_by_tid.setdefault(tid,set()).add(normalize_data_component(dc))
    # Fallback from coverage/data_component_coverage files.
    for c in coverage:
        tid=c.get('technique_id')
        for dc in c.get('required_data_components', []) or []:
            required_by_tid.setdefault(tid,set()).add(normalize_data_component(dc))
    rows=[]
    for c in coverage:
        tid=c.get('technique_id')
        if not tid or not c.get('in_denominator'): continue
        req=sorted(required_by_tid.get(tid,set()))
        observed=[dc for dc in req if component_observed(dc, aliases, field_blob)]
        missing=[dc for dc in req if dc not in observed]
        condition_used=bool(c.get('evidence_ids')) or c.get('coverage_type') in ['rule_condition_present','field_chain_validated','tested_validated']
        gate_pass=bool(req) and not missing and condition_used and c.get('coverage_type') in ['field_chain_validated','tested_validated']
        rows.append({
            'coverage_model_version':'V8.0','technique_id':tid,'technique_name':c.get('technique_name'),
            'scenario':c.get('scenario'),'coverage_type':c.get('coverage_type'),
            'required_data_components':req,'observed_data_components':observed,'missing_data_components':missing,
            'data_component_state':'used_by_condition' if gate_pass else ('observed_not_validated' if observed else 'missing_or_unmapped'),
            'data_component_gate_passed':gate_pass,
            'blockers': (['data_component_missing'] if missing else []) + ([] if condition_used else ['condition_use_unproven']),
        })
    total=len(rows); passed=sum(1 for r in rows if r['data_component_gate_passed'])
    summary={'coverage_model_version':'V8.0','claim_count':total,'data_component_gate_passed_count':passed,'data_component_gate_rate':round(passed/total,4) if total else None,'missing_data_component_claim_count':sum(1 for r in rows if r['missing_data_components'])}
    write_jsonl(Path(args.output_jsonl), rows)
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__=='__main__': main()
