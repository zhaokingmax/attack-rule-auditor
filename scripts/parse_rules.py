#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, re
from pathlib import Path
from common import ATTACK_RE, SYS_CALLS, FIELD_WORDS, iter_input_files, is_text_file, read_text, detect_language, role_hint, sha256_text, jsonl_write
try:
    import yaml  # type: ignore
except Exception:
    yaml = None

COND_KEYS = ['condition','selection','filter','detection','expr','query','where','when','rules','rule']

def flatten_values(obj, prefix=''):
    out=[]
    if isinstance(obj, dict):
        for k,v in obj.items(): out.extend(flatten_values(v, f'{prefix}.{k}' if prefix else str(k)))
    elif isinstance(obj, list):
        for i,v in enumerate(obj): out.extend(flatten_values(v, f'{prefix}[{i}]'))
    else:
        out.append((prefix, str(obj)))
    return out

def yaml_parse(text):
    if not yaml: return None
    try: return yaml.safe_load(text)
    except Exception: return None

def extract_required_fields(text: str):
    fields=set()
    # dot notation and common keys
    for m in re.findall(r'\b(?:proc|process|file|evt|container|k8s|user|network|net|source|target|cloud|device|interface|syslog|snmp|netflow|ipfix|aaa|config|route|acl)\.[A-Za-z0-9_.-]+', text):
        fields.add(m)
    low=text.lower()
    for f in FIELD_WORDS:
        if re.search(r'\b'+re.escape(f)+r'\b', low): fields.add(f)
    return sorted(fields)

def detection_style(text: str, fields):
    low=text.lower()
    attack_ids=ATTACK_RE.findall(text)
    ioc_terms=sum(bool(re.search(p, low)) for p in [r'sha256|sha1|md5', r'\bhash\b', r'\bdomain\b', r'\bip\b', r'\bioc\b'])
    tool_terms=sum(t in low for t in ['curl','wget','nc ','ncat','bash','powershell','kubectl','docker'])
    if ioc_terms and len(fields) <= 2: return 'ioc_match'
    if tool_terms and len(fields) <= 2: return 'tool_name_match'
    if any(x in low for x in ['within','sequence','followed by','time_window','join','correlat','ancestor','parent','graph']): return 'sequence_correlation'
    if len(fields) >= 4: return 'behavioral_multi_field'
    if len(fields) >= 2 or any(s in low for s in SYS_CALLS): return 'behavioral_single_event'
    return 'unknown'

def parse_file(path: Path):
    if not is_text_file(path): return []
    text=read_text(path)
    lang=detect_language(path, text)
    role=role_hint(path, text)
    obj=None
    if lang in ['yaml','sigma_yaml','falco_yaml']:
        obj=yaml_parse(text)
    elif lang=='json':
        try: obj=json.loads(text)
        except Exception: obj=None
    flat=flatten_values(obj) if obj is not None else []
    attack_ids=sorted(set(x.upper() for x in ATTACK_RE.findall(text)))
    fields=extract_required_fields(text)
    syscalls=sorted(set(s for s in SYS_CALLS if s.lower() in text.lower()))
    cond=[]
    for k,v in flat:
        kl=k.lower()
        if any(c in kl for c in COND_KEYS): cond.append({'path':k,'value':v[:1000]})
    if not cond:
        for i,line in enumerate(text.splitlines(),1):
            if any(x in line.lower() for x in ['condition','where','if ','alert','detect','evt.type','syscall']):
                cond.append({'path':f'line:{i}','value':line.strip()[:1000]})
    rule_name=None
    rule_id=None
    if isinstance(obj, dict):
        rule_name=obj.get('title') or obj.get('name') or obj.get('rule') or obj.get('id')
        rule_id=obj.get('id') or obj.get('rule_id') or obj.get('uuid')
    if not rule_name: rule_name=path.stem
    rec={
        'rule_id': str(rule_id or sha256_text(str(path))[:12]),
        'rule_name': str(rule_name),
        'file_path': str(path),
        'rule_format': lang,
        'role_hint': role,
        'declared_attack_ids': attack_ids,
        'required_fields': fields,
        'syscalls': syscalls,
        'detection_style': detection_style(text, fields),
        'condition_fragments': cond[:30],
        'parser_note': 'yaml_json_parsed' if obj is not None else 'regex_static_parse'
    }
    return [rec]

def main():
    ap=argparse.ArgumentParser(description='Parse security rules and detection source into normalized records.')
    ap.add_argument('input')
    ap.add_argument('--output', default='parsed_rules.jsonl')
    args=ap.parse_args()
    rows=[]
    for p in iter_input_files(Path(args.input)):
        rows.extend(parse_file(p))
    n=jsonl_write(Path(args.output), rows)
    print(json.dumps({'output':args.output,'parsed_rule_count':n}, ensure_ascii=False))
if __name__=='__main__': main()
