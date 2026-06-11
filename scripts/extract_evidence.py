#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path
from common import ATTACK_RE, DET_RE, AN_RE, SYS_CALLS, FIELD_WORDS, SCENARIO_SIGNAL_HINTS, iter_input_files, is_text_file, read_text, sha256_text, jsonl_write

def line_signals(line: str):
    low = line.lower()
    signals = []
    for m in ATTACK_RE.findall(line): signals.append({'type':'attack_id','value':m.upper()})
    for m in DET_RE.findall(line): signals.append({'type':'detection_strategy_id','value':m.upper()})
    for m in AN_RE.findall(line): signals.append({'type':'analytic_id','value':m.upper()})
    for s in SYS_CALLS:
        if s.lower() in low: signals.append({'type':'syscall','value':s})
    for f in FIELD_WORDS:
        if re.search(r'\b'+re.escape(f)+r'\b', low): signals.append({'type':'field_hint','value':f})
    for sc, kws in SCENARIO_SIGNAL_HINTS.items():
        if any(k.lower() in low for k in kws): signals.append({'type':'scenario_hint','value':sc})
    if any(x in low for x in ['condition:', 'selection', 'filter:', 'evt.type', 'alert', 'detect']): signals.append({'type':'rule_logic','value':'condition_or_alert'})
    if any(x in low for x in ['ringbuf','perf_event','lost','drop','backpressure','audit_backlog']): signals.append({'type':'telemetry_loss','value':'drop_or_buffer_signal'})
    return signals

def extract(path: Path, max_bytes: int=2_000_000):
    if not is_text_file(path):
        return []
    text = read_text(path, max_bytes=max_bytes)
    rows=[]
    for i, line in enumerate(text.splitlines(), 1):
        sig = line_signals(line)
        if not sig: continue
        excerpt=line.strip()[:500]
        rows.append({
            'evidence_id': f"E{len(rows)+1:06d}_{sha256_text(str(path)+str(i)+excerpt)[:10]}",
            'file_path': str(path),
            'start_line': i,
            'end_line': i,
            'evidence_type': 'line_signal',
            'signals': sig,
            'excerpt': excerpt,
            'excerpt_sha256': sha256_text(excerpt),
        })
    return rows

def main():
    ap=argparse.ArgumentParser(description='Extract line-level evidence from rule/source files.')
    ap.add_argument('input')
    ap.add_argument('--output', default='evidence.jsonl')
    ap.add_argument('--max-bytes', type=int, default=2_000_000)
    args=ap.parse_args()
    all_rows=[]
    for p in iter_input_files(Path(args.input)):
        all_rows.extend(extract(p, args.max_bytes))
    n=jsonl_write(Path(args.output), all_rows)
    print(json.dumps({'output':args.output,'evidence_count':n}, ensure_ascii=False))
if __name__=='__main__': main()
