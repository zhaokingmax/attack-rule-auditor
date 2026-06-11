#!/usr/bin/env python3
from __future__ import annotations
"""V8 semantic bypass matrix generator.

This is still safe static analysis: it does not generate payloads. Unlike V6, it
separates mere mentions from condition-checked variants and requires condition
or field evidence before a bypass primitive is treated as checked.
"""
import argparse, json, re
from pathlib import Path
from typing import Any, Dict, List, Tuple


def read_jsonl(p: Path) -> List[Dict[str, Any]]:
    if not p.exists(): return []
    out=[]
    for line in p.read_text(encoding='utf-8', errors='ignore').splitlines():
        if not line.strip(): continue
        try: out.append(json.loads(line))
        except Exception: pass
    return out


def write_jsonl(p: Path, rows: List[Dict[str, Any]]):
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open('w', encoding='utf-8') as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False)+'\n')


def norm(s: str) -> str:
    return re.sub(r'[^a-z0-9]+','', s.lower())


def kw_match(text: str, kws: List[str]) -> bool:
    t=text.lower(); nt=norm(t)
    for kw in kws:
        k=str(kw).lower().strip()
        if not k: continue
        if k in t: return True
        nk=norm(k)
        if nk and nk in nt: return True
    return False


def condition_blob(rule: Dict[str, Any], ast_by_rule: Dict[str, Dict[str, Any]] | None = None) -> str:
    parts=[]
    parts += [str(x) for x in rule.get('syscalls', []) or []]
    parts += [str(x) for x in rule.get('required_fields', []) or []]
    for c in rule.get('condition_fragments', []) or []:
        parts.append(str(c.get('path',''))); parts.append(str(c.get('value','')))
    if ast_by_rule:
        ast=ast_by_rule.get(str(rule.get('rule_id'))) or ast_by_rule.get(str(rule.get('file_path')))
        if ast:
            parts.append(json.dumps(ast.get('condition_ast', ast), ensure_ascii=False))
            parts.extend(ast.get('risk_signals', []) or [])
    return '\n'.join(parts)


def mention_blob(rule: Dict[str, Any], evidence_by_file: Dict[str, List[Dict[str, Any]]]) -> str:
    parts=[rule.get('file_path',''), rule.get('rule_name',''), rule.get('rule_id',''), json.dumps(rule, ensure_ascii=False)]
    for e in evidence_by_file.get(rule.get('file_path',''), [])[:40]:
        parts.append(e.get('excerpt',''))
        parts.append(json.dumps(e.get('signals',[]), ensure_ascii=False))
    return '\n'.join(str(x) for x in parts if x)


def field_chain_level(rule: Dict[str, Any], b: Dict[str, Any]) -> bool:
    req={str(x).lower() for x in (b.get('required_fields') or b.get('required_data_components') or [])}
    fields={str(x).lower() for x in rule.get('required_fields', []) or []}
    if not req: return bool(fields)
    return bool(req & fields)


def check_level(rule: Dict[str, Any], b: Dict[str, Any], evidence_by_file: Dict[str, List[Dict[str, Any]]], ast_by_rule: Dict[str, Dict[str, Any]] | None = None) -> Tuple[str, bool, Dict[str, Any]]:
    kws=b.get('keywords', []) or []
    cblob=condition_blob(rule, ast_by_rule)
    mblob=mention_blob(rule, evidence_by_file)
    condition_checked=kw_match(cblob, kws)
    mentioned=kw_match(mblob, kws)
    field_checked=field_chain_level(rule, b) and (condition_checked or mentioned)
    # This static analyzer cannot prove test coverage; test_gap_analyzer handles it.
    if condition_checked and field_checked:
        return 'field_chain_checked', True, {'condition_checked': True, 'field_chain_checked': True, 'mentioned': mentioned}
    if condition_checked:
        return 'condition_checked', True, {'condition_checked': True, 'field_chain_checked': False, 'mentioned': mentioned}
    if mentioned:
        return 'mentioned_only', False, {'condition_checked': False, 'field_chain_checked': False, 'mentioned': True}
    return 'unchecked', False, {'condition_checked': False, 'field_chain_checked': False, 'mentioned': False}


def main():
    ap=argparse.ArgumentParser(description='Generate V8 semantic bypass matrix for ATT&CK coverage claims.')
    ap.add_argument('--coverage', required=True)
    ap.add_argument('--parsed-rules', required=True)
    ap.add_argument('--evidence')
    ap.add_argument('--condition-ast', help='Optional condition_ast.jsonl from condition_ast_parser.py')
    ap.add_argument('--scenario-model', default='attack_data/models/scenario_attack_model.json')
    ap.add_argument('--scenario', required=True)
    ap.add_argument('--output', default='bypass_matrix.jsonl')
    ap.add_argument('--summary-output', default='bypass_summary.json')
    args=ap.parse_args()
    model=json.load(open(args.scenario_model, encoding='utf-8')) if Path(args.scenario_model).exists() else {}
    cfg=model.get(args.scenario, {})
    bypasses=cfg.get('bypass_primitives', [])
    cover=read_jsonl(Path(args.coverage))
    rules=read_jsonl(Path(args.parsed_rules))
    evs=read_jsonl(Path(args.evidence)) if args.evidence else []
    ast_rows=read_jsonl(Path(args.condition_ast)) if args.condition_ast else []
    ast_by_rule={}
    for a in ast_rows:
        if a.get('rule_id'): ast_by_rule[str(a.get('rule_id'))]=a
        if a.get('file_path'): ast_by_rule[str(a.get('file_path'))]=a
    ev_by_file={}
    for e in evs: ev_by_file.setdefault(e.get('file_path',''), []).append(e)
    rows=[]
    for c in cover:
        tid=c.get('technique_id')
        if not tid or not c.get('in_denominator'):
            continue
        applicable=[]
        for b in bypasses:
            aids=b.get('attack_ids', []) or []
            if tid in aids or any(str(tid).startswith(str(x)+'.') or str(x).startswith(str(tid)+'.') for x in aids):
                applicable.append(b)
        if not applicable and c.get('denominator_tier')=='must_cover':
            applicable=[b for b in bypasses if b.get('critical')]
        for b in applicable:
            best_level='unchecked'; checked=False; matched_rules=[]; details=[]
            rank={'unchecked':0,'mentioned_only':1,'condition_checked':2,'field_chain_checked':3,'test_checked':4,'resilience_validated':5}
            for rule in rules:
                lvl, ok, detail = check_level(rule, b, ev_by_file, ast_by_rule)
                if rank[lvl] > rank[best_level]:
                    best_level=lvl; checked=ok
                if lvl != 'unchecked':
                    matched_rules.append(rule.get('rule_id') or rule.get('file_path'))
                    detail['rule_id']=rule.get('rule_id'); detail['file_path']=rule.get('file_path')
                    detail['condition_fragment_id']='condition_fragments' if rule.get('condition_fragments') else None
                    details.append(detail)
            rows.append({
                'coverage_model_version':'V8.0',
                'technique_id': tid,
                'technique_name': c.get('technique_name'),
                'scenario': args.scenario,
                'behavior_primitive': b.get('behavior_primitive') or b.get('primitive') or b.get('id'),
                'bypass_variant': b.get('id'),
                'bypass_category': b.get('category') or 'unspecified',
                'bypass_keywords': b.get('keywords', []),
                'required_fields': b.get('required_fields', []),
                'critical': bool(b.get('critical')),
                'bypass_check_level': best_level,
                'status': 'checked' if checked else best_level,
                'checked': bool(checked),
                'blocking_coverage': bool(b.get('critical')) and not checked,
                'matched_rules': sorted(set(matched_rules)),
                'check_details': details[:10],
                'source': 'scenario_attack_model',
                'note': 'mentioned_only is not treated as checked; V8.0 can use condition AST plus field-chain evidence when available.'
            })
    total=len(rows); checked=sum(1 for r in rows if r['checked']); critical=sum(1 for r in rows if r['critical']); critical_checked=sum(1 for r in rows if r['critical'] and r['checked'])
    by_level={}
    for r in rows: by_level[r['bypass_check_level']]=by_level.get(r['bypass_check_level'],0)+1
    summary={
        'coverage_model_version':'V8.0',
        'scenario': args.scenario,
        'bypass_primitive_count': total,
        'checked_count': checked,
        'unchecked_count': total-checked,
        'critical_bypass_count': critical,
        'critical_checked_count': critical_checked,
        'bypass_weighted_coverage': round(checked/total,4) if total else None,
        'critical_bypass_coverage': round(critical_checked/critical,4) if critical else None,
        'by_bypass_check_level': by_level,
        'semantic_gate_note': 'Only condition_checked or field_chain_checked rows are counted as checked. Mentioned-only rows are blockers for critical bypasses. V8.0 supports optional condition AST input.'
    }
    write_jsonl(Path(args.output), rows)
    Path(args.summary_output).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__ == '__main__': main()
