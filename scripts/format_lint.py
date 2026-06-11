#!/usr/bin/env python3
"""Lightweight format lint for common detection rule formats.
Does not replace official validators; flags missing high-value fields.
"""
import argparse, json, re
from pathlib import Path

def read(p):
    try: return p.read_text(errors='replace')
    except Exception: return ''

def has_key(text, key):
    return bool(re.search(rf"(?m)^\s*{re.escape(key)}\s*:", text))

def lint_file(p: Path):
    txt=read(p)
    ext=p.suffix.lower()
    lower=txt.lower()
    fmt='unknown'; required=[]; warnings=[]
    if ext in {'.yml','.yaml'}:
        if has_key(txt,'logsource') or has_key(txt,'detection'):
            fmt='sigma'; required=['title','id','status','description','logsource','detection','falsepositives','level','tags']
            if 'condition:' not in lower: warnings.append('sigma_missing_detection_condition')
        elif has_key(txt,'rule') and has_key(txt,'condition') and has_key(txt,'output'):
            fmt='falco'; required=['rule','desc','condition','output','priority']
            if not has_key(txt,'source'): warnings.append('falco_missing_source')
        else:
            fmt='custom_yaml'; required=['author','version','date','references','required_fields','attack_tags']
    elif ext in {'.yar','.yara'} or re.search(r"\brule\s+\w+\s*\{", txt):
        fmt='yara'; required=[]
        if 'strings:' not in lower: warnings.append('yara_missing_strings')
        if 'condition:' not in lower: warnings.append('yara_missing_condition')
        if 'meta:' not in lower: warnings.append('yara_missing_meta')
    elif ext == '.json':
        fmt='custom_json'; required=['author','version','date','references','required_fields','attack_tags']
    elif ext in {'.rules','.audit'}:
        fmt='auditd'; required=[]
        if '-a ' not in txt and '-w ' not in txt: warnings.append('auditd_no_watch_or_syscall_rule')
    missing=[]
    for k in required:
        if not has_key(txt,k) and f'"{k}"' not in txt:
            missing.append(k)
    return {'file':str(p),'format':fmt,'missing_required_fields':missing,'warnings':warnings,'lint_status':'pass' if not missing and not warnings else 'warn'}

def iter_files(p):
    if p.is_file(): yield p
    else:
        for x in p.rglob('*'):
            if x.is_file() and x.suffix.lower() in {'.yml','.yaml','.json','.yar','.yara','.rules','.audit'}:
                yield x

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('path'); ap.add_argument('--json',action='store_true')
    args=ap.parse_args(); rows=[lint_file(f) for f in iter_files(Path(args.path))]
    if args.json:
        for r in rows: print(json.dumps(r, ensure_ascii=False))
    else:
        print('| file | format | status | missing | warnings |')
        print('|---|---|---|---|---|')
        for r in rows: print(f"| {r['file']} | {r['format']} | {r['lint_status']} | {', '.join(r['missing_required_fields']) or '-'} | {', '.join(r['warnings']) or '-'} |")
if __name__ == '__main__': main()
