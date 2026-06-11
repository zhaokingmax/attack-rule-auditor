#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, shutil, zipfile
from pathlib import Path

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('run_dir')
    ap.add_argument('--output')
    args=ap.parse_args(); rd=Path(args.run_dir)
    out=Path(args.output) if args.output else rd.with_suffix('.zip')
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        for p in rd.rglob('*'):
            if p.is_file(): z.write(p, p.relative_to(rd.parent))
    print(json.dumps({'output':str(out),'file_count':len([p for p in rd.rglob('*') if p.is_file()])}, ensure_ascii=False))
if __name__=='__main__': main()
