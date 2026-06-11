#!/usr/bin/env python3
from __future__ import annotations
"""V8.1 condition AST enricher.

Adds condition quality, literal/contains/regex risk, and field-reference summaries to
lossy AST rows. This helps bypass analysis distinguish mention-only from condition-checked claims.
"""
import argparse, json, re
from pathlib import Path
from typing import Any, Dict, List

RISK_OPS={'contains','startswith','endswith','matches','regex','in','eq','equals'}
FIELD_TOKEN_RE=re.compile(r'\b(?:evt|proc|process|container|k8s|fd|file|user|group|syscall|network|net|dns|http|tls|image|service|host|auth|source)\.[A-Za-z0-9_.-]+\b|\b(?:cmdline|comm|exe|argv|pid|ppid|uid|gid|container_id|pod_name|namespace|file_path)\b', re.I)
SEMANTIC_FIELD_ALIASES={
    'proc.cmdline':'process.command_line',
    'cmdline':'process.command_line',
    'argv':'process.command_line',
    'proc.name':'process.executable',
    'comm':'process.executable',
    'exe':'process.executable',
    'evt.type':'event.type',
    'fd.name':'file.path',
    'file_path':'file.path',
    'container.id':'container.id',
    'container_id':'container.id',
    'k8s.ns.name':'k8s.namespace',
    'namespace':'k8s.namespace',
    'user.name':'user.name',
}


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path or not path.exists(): return []
    rows=[]
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        if not line.strip(): continue
        try: rows.append(json.loads(line))
        except Exception: pass
    return rows


def write_jsonl(path: Path, rows: List[Dict[str, Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False)+'\n')


def walk(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values(): yield from walk(v)
    elif isinstance(obj, list):
        for v in obj: yield from walk(v)

def semantic_field(field: str) -> str:
    f=str(field or '').strip()
    return SEMANTIC_FIELD_ALIASES.get(f.lower(), f)


def main():
    ap=argparse.ArgumentParser(description='Enrich condition AST with quality and bypass-risk signals.')
    ap.add_argument('--condition-ast', required=True)
    ap.add_argument('--output-jsonl', default='condition_ast_enriched.jsonl')
    ap.add_argument('--output-summary', default='condition_ast_enriched_summary.json')
    args=ap.parse_args()
    rows=read_jsonl(Path(args.condition_ast)); out=[]
    for r in rows:
        raw_text=json.dumps(r, ensure_ascii=False)
        text=raw_text.lower()
        fields=set(); semantic_fields=set(); ops=set(); literals=[]
        for node in walk(r):
            for key in ['field','field_name','left','path']:
                if isinstance(node.get(key), str) and re.search(r'(proc|process|cmd|path|container|pod|k8s|user|uid|pid|syscall|evt|event|net|dns|http|tls|image|service|auth)', node.get(key), re.I):
                    fields.add(node.get(key))
                    semantic_fields.add(semantic_field(node.get(key)))
            op=node.get('op') or node.get('operator') or node.get('modifier')
            if isinstance(op, str): ops.add(op.lower())
            val=node.get('value')
            if isinstance(val, str) and len(val)<160: literals.append(val)
        for m in FIELD_TOKEN_RE.finditer(raw_text):
            fields.add(m.group(0))
            semantic_fields.add(semantic_field(m.group(0)))
        contains_risk=bool(re.search(r'contains|substr|substring', text))
        regex_risk=bool(re.search(r'regex|matches|re:', text))
        literal_risk=len([x for x in literals if any(tok in x.lower() for tok in ['curl','wget','bash','docker','kubectl','/tmp','/var/run/docker.sock','--privileged','hostpid','hostpath','token','secret'])])>0
        risky_ops=sorted(op for op in ops if op in RISK_OPS)
        if len(semantic_fields) >= 3 and ops and not literal_risk:
            quality='high'
        elif len(semantic_fields) >= 2 and ops:
            quality='medium'
        elif semantic_fields:
            quality='low'
        else:
            quality='none'
        rec=dict(r)
        rec.update({
            'coverage_model_version':'V10.5-wave4',
            'field_refs':sorted(fields),
            'semantic_field_refs':sorted(semantic_fields),
            'operators':sorted(ops),
            'risky_operators':risky_ops,
            'condition_quality':quality,
            'contains_risk':contains_risk,
            'regex_risk':regex_risk,
            'literal_or_tool_risk':literal_risk,
            'literal_samples':literals[:20],
            'condition_proof_state':'fielded_condition' if semantic_fields and ops else 'textual_or_unparsed_condition',
        })
        out.append(rec)
    summary={'coverage_model_version':'V10.5-wave4','ast_count':len(out),'high_quality_count':sum(1 for r in out if r['condition_quality']=='high'),'medium_or_high_quality_count':sum(1 for r in out if r['condition_quality'] in ['medium','high']),'contains_risk_count':sum(1 for r in out if r['contains_risk']),'literal_or_tool_risk_count':sum(1 for r in out if r['literal_or_tool_risk'])}
    write_jsonl(Path(args.output_jsonl), out)
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__=='__main__': main()
