#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, re
from pathlib import Path
from common import SCENARIO_SIGNAL_HINTS, iter_input_files, is_text_file, read_text, jsonl_write

def infer_file(path: Path):
    if not is_text_file(path): return []
    text=read_text(path, max_bytes=2_000_000)
    low=text.lower(); path_low=str(path).lower()
    rows=[]
    scores={}
    evidence={}
    for sc,kws in SCENARIO_SIGNAL_HINTS.items():
        score=0; ev=[]
        for kw in kws:
            k=kw.lower()
            c=low.count(k)
            pc=path_low.count(k)
            if c:
                score += min(c,5)*3
                ev.append({'signal':kw,'source':'code','count':c})
            if pc:
                score += pc*1  # lower path weight
                ev.append({'signal':kw,'source':'path','count':pc})
        if score:
            scores[sc]=score; evidence[sc]=ev[:20]
    if not scores:
        rows.append({'file_path':str(path),'primary_scenario':None,'confidence':'none','top_scenarios':[],'negative_scenarios':list(SCENARIO_SIGNAL_HINTS.keys()),'note':'no scenario signals found'})
    else:
        mx=max(scores.values())
        top=sorted(scores.items(), key=lambda x:x[1], reverse=True)[:5]
        conf='low'
        if mx>=30: conf='high'
        elif mx>=12: conf='medium'
        rows.append({'file_path':str(path),'primary_scenario':top[0][0],'confidence':conf,'top_scenarios':[{'scenario':s,'score':v,'evidence':evidence[s]} for s,v in top],'negative_scenarios':[s for s in SCENARIO_SIGNAL_HINTS if s not in scores],'advisory_only':True})
    return rows

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('input')
    ap.add_argument('--output')
    ap.add_argument('--json', action='store_true')
    args=ap.parse_args()
    rows=[]
    for p in iter_input_files(Path(args.input)):
        rows.extend(infer_file(p))
    if args.output:
        jsonl_write(Path(args.output), rows)
    if args.json or not args.output:
        for r in rows: print(json.dumps(r, ensure_ascii=False))
    else:
        print(json.dumps({'output':args.output,'intent_record_count':len(rows)}, ensure_ascii=False))
if __name__=='__main__': main()
