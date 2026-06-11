#!/usr/bin/env python3
from __future__ import annotations
"""V8.0 condition AST normalizer.

Safe static analysis only. It converts common rule/query fragments into a small,
lossy AST that downstream bypass checks can reason over. It never executes rules
or generates payloads.
"""
import argparse, json, re
from pathlib import Path
from typing import Any, Dict, List

LOGICAL = re.compile(r"\b(and|or|not)\b", re.I)
FIELD_OP = re.compile(r"(?P<field>[A-Za-z_][A-Za-z0-9_.\-/]*)\s*(?P<op>==|=~|!=|=|contains|startswith|endswith|in|exists|regex|matches)\s*(?P<value>[^\n\r]+)", re.I)
KQL_OPS = re.compile(r"\b(where|join|summarize|stats|by|bin|lookup|regex|rex|eval|table)\b", re.I)
AUDIT_FLAG = re.compile(r"(?P<flag>-[SaFwkpF])\s+(?P<value>[^\s]+)")
RISK_PATTERNS = {
    'contains_literal': re.compile(r"\bcontains\b", re.I),
    'regex_present': re.compile(r"\b(regex|matches|=~)\b", re.I),
    'negative_filter': re.compile(r"\bnot\b|exception|filter", re.I),
    'threshold_or_window': re.compile(r"\b(count|threshold|within|window|bin|stats|summarize)\b", re.I),
    'lookup_dependency': re.compile(r"\blookup\b|list\s*:", re.I),
}

def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists(): return []
    rows=[]
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        if not line.strip(): continue
        try: rows.append(json.loads(line))
        except Exception: pass
    return rows

def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False)+'\n')
    return len(rows)

def split_logical(expr: str) -> Dict[str, Any]:
    expr = (expr or '').strip()
    if not expr:
        return {'type':'empty'}
    # Preserve original and extract obvious field comparisons.
    comps=[]
    for m in FIELD_OP.finditer(expr):
        comps.append({'type':'comparison','field':m.group('field'),'op':m.group('op').lower(),'value':m.group('value').strip().strip('"\'')[:500]})
    toks=[t.lower() for t in LOGICAL.findall(expr)]
    if comps:
        op='and' if 'and' in toks else ('or' if 'or' in toks else 'single')
        return {'type':op,'children':comps,'raw':expr[:2000],'logical_tokens':toks}
    if KQL_OPS.search(expr):
        return {'type':'query_pipeline','operators':sorted(set(x.lower() for x in KQL_OPS.findall(expr))),'raw':expr[:2000]}
    flags=[m.groupdict() for m in AUDIT_FLAG.finditer(expr)]
    if flags:
        return {'type':'auditd_flags','flags':flags,'raw':expr[:2000]}
    return {'type':'raw_condition','raw':expr[:2000],'logical_tokens':toks}

def regex_quality(expr: str) -> Dict[str, Any]:
    has_regex = bool(RISK_PATTERNS['regex_present'].search(expr or ''))
    return {
        'regex_present': has_regex,
        'has_anchor': bool(re.search(r'\^|\$', expr or '')) if has_regex else False,
        'case_handling_visible': bool(re.search(r'(?i)|lower\(|tolower\(|nocase', expr or '', re.I)) if has_regex else False,
        'path_separator_handling_visible': bool(re.search(r'\\/|/|\\\\', expr or '')) if has_regex else False,
        'argument_boundary_visible': bool(re.search(r'\b|\s|(^|[^A-Za-z0-9_])', expr or '')) if has_regex else False,
    }

def risk_signals(expr: str) -> List[str]:
    out=[]
    for name, pat in RISK_PATTERNS.items():
        if pat.search(expr or ''): out.append(name)
    if re.search(r'\b(curl|wget|bash|sh|kubectl|docker|nc|ncat|python)\b', expr or '', re.I): out.append('tool_name_literal')
    if re.search(r'/(tmp|var|etc|proc|sys|dev|run)/', expr or '', re.I): out.append('path_literal')
    return sorted(set(out))

def ast_for_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    fragments=rule.get('condition_fragments') or []
    nodes=[]; raw=[]
    for i, frag in enumerate(fragments):
        v=str(frag.get('value',''))
        raw.append(v)
        node=split_logical(v)
        node['fragment_path']=frag.get('path')
        node['fragment_index']=i
        nodes.append(node)
    blob='\n'.join(raw)
    fmt=rule.get('rule_format')
    ast_quality='structured' if nodes and any(n.get('type') not in ['raw_condition','empty'] for n in nodes) else ('fragment_only' if nodes else 'missing')
    if fmt in ['sigma_yaml','falco_yaml','yaml'] and ast_quality!='missing': ast_quality='semi_structured_'+ast_quality
    return {
        'type':'rule_condition_ast',
        'ast_quality': ast_quality,
        'nodes': nodes[:50],
        'risk_signals': risk_signals(blob),
        'regex_quality': regex_quality(blob),
        'raw_fragment_count': len(fragments),
    }

def main():
    ap=argparse.ArgumentParser(description='Build lossy condition AST records from parsed rules.')
    ap.add_argument('--parsed-rules', required=True)
    ap.add_argument('--output-jsonl', default='condition_ast.jsonl')
    ap.add_argument('--output-summary', default='condition_ast_summary.json')
    args=ap.parse_args()
    rules=read_jsonl(Path(args.parsed_rules))
    rows=[]
    for r in rules:
        ast=ast_for_rule(r)
        rows.append({
            'rule_id': r.get('rule_id'),
            'rule_name': r.get('rule_name'),
            'file_path': r.get('file_path'),
            'rule_format': r.get('rule_format'),
            'ast_quality': ast['ast_quality'],
            'risk_signals': ast['risk_signals'],
            'regex_quality': ast['regex_quality'],
            'condition_ast': ast,
        })
    write_jsonl(Path(args.output_jsonl), rows)
    summary={
        'coverage_model_version':'V8.0',
        'rule_count': len(rows),
        'with_ast': sum(1 for r in rows if r['ast_quality']!='missing'),
        'risk_signal_counts': {},
    }
    for r in rows:
        for s in r['risk_signals']:
            summary['risk_signal_counts'][s]=summary['risk_signal_counts'].get(s,0)+1
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__=='__main__': main()
