#!/usr/bin/env python3
"""Validate declared MITRE ATT&CK IDs in rules/code against a local attack_index."""
import argparse, json, re
from pathlib import Path
ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

def iter_files(p: Path):
    if p.is_file():
        yield p
    else:
        for x in p.rglob('*'):
            if x.is_file() and '.git' not in x.parts:
                yield x

def extract_ids(path: Path):
    try:
        txt = path.read_text(errors='replace')
    except Exception:
        return []
    return sorted(set(ATTACK_RE.findall(txt)))

def children_of(lookup, parent):
    return sorted([tid for tid,r in lookup.items() if r.get('parent_id') == parent or tid.startswith(parent+'.')])

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('path')
    ap.add_argument('--index', default='attack_data/index')
    ap.add_argument('--platform', action='append', default=[])
    ap.add_argument('--expand-subtechs', action='store_true')
    ap.add_argument('--json', action='store_true')
    args=ap.parse_args()
    lookup=json.load(open(Path(args.index)/'lookup_by_id.json', encoding='utf-8'))
    rows=[]
    for f in iter_files(Path(args.path)):
        ids=extract_ids(f)
        if not ids: continue
        for tid in ids:
            rec=lookup.get(tid)
            status='valid' if rec else 'unknown'
            issues=[]
            expanded=[]
            if rec:
                if rec.get('deprecated') or rec.get('revoked'):
                    status='deprecated_or_revoked'; issues.append(status)
                if not rec.get('is_subtechnique') and children_of(lookup, tid):
                    issues.append('parent_only_check_subtechniques')
                    if args.expand_subtechs:
                        expanded=children_of(lookup, tid)
                if args.platform:
                    plats={p.lower() for p in rec.get('platforms',[])}
                    if not (plats & {p.lower() for p in args.platform}):
                        issues.append('platform_mismatch')
            rows.append({'file':str(f),'declared_id':tid,'status':status,'name':rec.get('name') if rec else None,'platforms':rec.get('platforms') if rec else [],'tactics':rec.get('tactics') if rec else [],'issues':issues,'expanded_subtechniques':expanded})
    if args.json:
        for r in rows: print(json.dumps(r, ensure_ascii=False))
    else:
        print('| file | declared_id | status | issues | expanded_subtechniques |')
        print('|---|---|---|---|---|')
        for r in rows:
            print(f"| {r['file']} | {r['declared_id']} | {r['status']} | {', '.join(r['issues']) or '-'} | {', '.join(r['expanded_subtechniques'][:20])} |")
if __name__ == '__main__': main()
