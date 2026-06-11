#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
from common import iter_input_files, is_text_file, read_text, sha256_file, detect_language, role_hint, jsonl_write

def scan(input_path: Path):
    for p in iter_input_files(input_path):
        st=p.stat()
        text=''
        text_ok=is_text_file(p)
        if text_ok:
            try: text=read_text(p, max_bytes=200_000)
            except Exception: text=''
        yield {
            'path': str(p), 'sha256': sha256_file(p), 'size': st.st_size, 'mtime': int(st.st_mtime),
            'is_text': text_ok, 'language': detect_language(p, text), 'role_hint': role_hint(p, text),
            'parse_status': 'candidate' if text_ok else 'unsupported_binary_or_non_utf8'
        }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('input')
    ap.add_argument('--output', default='input_manifest.jsonl')
    args=ap.parse_args()
    n=jsonl_write(Path(args.output), scan(Path(args.input)))
    print(json.dumps({'output':args.output,'file_count':n}, ensure_ascii=False))
if __name__=='__main__': main()
