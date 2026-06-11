#!/usr/bin/env python3
from __future__ import annotations
"""V8.1 safe fixture ingester.

Reads user-provided test fixtures or fixture plans. It does not create payloads or
execute anything. It only classifies supplied fixture files and maps them to
ATT&CK IDs, behavior primitives, bypass variants, and expected outcomes.
"""
import argparse, json, re
from pathlib import Path
from typing import Any, Dict, List
try:
    import yaml  # type: ignore
except Exception:
    yaml=None

ATTACK_RE=re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.I)
SAFE_EXTS={'.json','.yaml','.yml','.ndjson','.jsonl','.txt','.md','.event','.fixture'}

def safe_read(path: Path, limit=2_000_000) -> str:
    try: return path.read_bytes()[:limit].decode('utf-8', errors='replace')
    except Exception: return ''

def iter_files(path: Path):
    if not path.exists(): return
    if path.is_file():
        yield path
    elif path.is_dir():
        for p in sorted(path.rglob('*')):
            if p.is_file() and p.suffix.lower() in SAFE_EXTS: yield p

def load_structured(path: Path, text: str):
    if path.suffix.lower() in ['.json']:
        try: return json.loads(text)
        except Exception: return None
    if path.suffix.lower() in ['.jsonl','.ndjson']:
        vals=[]
        for line in text.splitlines():
            if not line.strip(): continue
            try: vals.append(json.loads(line))
            except Exception: pass
        return vals if vals else None
    if yaml and path.suffix.lower() in ['.yaml','.yml']:
        try: return yaml.safe_load(text)
        except Exception: return None
    return None

def flatten(obj, prefix=''):
    out=[]
    if isinstance(obj, dict):
        for k,v in obj.items(): out.extend(flatten(v, f'{prefix}.{k}' if prefix else str(k)))
    elif isinstance(obj, list):
        for i,v in enumerate(obj): out.extend(flatten(v, f'{prefix}[{i}]'))
    else:
        out.append((prefix, str(obj)))
    return out

def infer_fixture_type(path: Path, text: str, obj: Any) -> str:
    blob=(str(path)+'\n'+text[:5000]).lower()
    if isinstance(obj, dict):
        for key in ['fixture_type','type','test_type','case_type']:
            v=obj.get(key)
            if isinstance(v, str) and v.lower() in ['positive','negative','bypass','variant','field_chain','replay','integration']:
                return 'bypass' if v.lower()=='variant' else v.lower()
    if 'bypass' in blob or 'variant' in blob or 'evasion' in blob: return 'bypass'
    if 'negative' in blob or 'benign' in blob or 'should_not_alert' in blob: return 'negative'
    if 'field_chain' in blob or 'raw_event' in blob or 'normalized_event' in blob: return 'field_chain'
    if 'positive' in blob or 'should_alert' in blob or 'expected_alert' in blob: return 'positive'
    return 'unknown'

def first_key(obj: Any, keys: List[str]):
    if isinstance(obj, dict):
        for k in keys:
            if k in obj: return obj[k]
    return None

def extract(path: Path) -> Dict[str, Any]:
    text=safe_read(path)
    obj=load_structured(path,text)
    flats=flatten(obj) if obj is not None else []
    blob='\n'.join([text[:20000]]+[f'{k}={v}' for k,v in flats[:200]])
    ids=sorted(set(x.upper() for x in ATTACK_RE.findall(blob)))
    fixture_type=infer_fixture_type(path,text,obj)
    expected_attack=first_key(obj, ['expected_attack_id','attack_id','technique_id','expected_technique']) if isinstance(obj, dict) else None
    if expected_attack and isinstance(expected_attack, str): ids=sorted(set(ids+[expected_attack.upper()]))
    expected_primitive=first_key(obj, ['expected_behavior_primitive','behavior_primitive','primitive']) if isinstance(obj, dict) else None
    expected_bypass=first_key(obj, ['expected_bypass_variant','bypass_variant','variant']) if isinstance(obj, dict) else None
    expected_outcome=first_key(obj, ['expected_outcome','expected_alert','outcome','should_alert']) if isinstance(obj, dict) else None
    event_stages=[]
    for token in ['raw_event','parsed_event','normalized_event','expected_alert','requestObject','responseObject']:
        if token.lower() in blob.lower(): event_stages.append(token)
    return {
        'fixture_id': re.sub(r'[^A-Za-z0-9_.-]+','_', str(path))[-160:],
        'path': str(path),
        'fixture_type': fixture_type,
        'attack_ids': ids,
        'expected_behavior_primitive': expected_primitive,
        'expected_bypass_variant': expected_bypass,
        'expected_outcome': expected_outcome,
        'event_stages': sorted(set(event_stages)),
        'structured': obj is not None,
        'safe_static_only': True,
    }

def read_jsonl(p: Path) -> List[Dict[str, Any]]:
    if not p or not p.exists(): return []
    out=[]
    for line in p.read_text(encoding='utf-8', errors='ignore').splitlines():
        if not line.strip(): continue
        try: out.append(json.loads(line))
        except Exception: pass
    return out

def write_jsonl(path: Path, rows: List[Dict[str, Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False)+'\n')

def main():
    ap=argparse.ArgumentParser(description='Ingest safe user-provided fixtures and map them to ATT&CK coverage claims.')
    ap.add_argument('--fixtures')
    ap.add_argument('--coverage')
    ap.add_argument('--output-inventory', default='fixture_inventory.jsonl')
    ap.add_argument('--output-coverage', default='fixture_coverage.jsonl')
    ap.add_argument('--output-summary', default='fixture_summary.json')
    args=ap.parse_args()
    fixtures=[]
    if args.fixtures:
        for p in iter_files(Path(args.fixtures)) or []:
            fixtures.append(extract(p))
    coverage=read_jsonl(Path(args.coverage)) if args.coverage else []
    cov_ids={c.get('technique_id') for c in coverage}
    mappings=[]
    for f in fixtures:
        for tid in f.get('attack_ids') or []:
            mappings.append({
                'fixture_id': f['fixture_id'],
                'path': f['path'],
                'technique_id': tid,
                'fixture_type': f['fixture_type'],
                'expected_behavior_primitive': f.get('expected_behavior_primitive'),
                'expected_bypass_variant': f.get('expected_bypass_variant'),
                'expected_outcome': f.get('expected_outcome'),
                'matches_existing_coverage': tid in cov_ids,
                'test_evidence_level': 'bypass_variant' if f['fixture_type']=='bypass' else ('negative' if f['fixture_type']=='negative' else ('positive' if f['fixture_type']=='positive' else f['fixture_type'])),
                'safe_static_only': True,
            })
    write_jsonl(Path(args.output_inventory), fixtures)
    write_jsonl(Path(args.output_coverage), mappings)
    by_type={}
    for f in fixtures: by_type[f['fixture_type']]=by_type.get(f['fixture_type'],0)+1
    summary={
        'coverage_model_version':'V8.1',
        'fixture_count': len(fixtures),
        'fixture_by_type': by_type,
        'fixture_attack_mapping_count': len(mappings),
        'positive_fixture_count': by_type.get('positive',0),
        'negative_fixture_count': by_type.get('negative',0),
        'bypass_fixture_count': by_type.get('bypass',0),
        'field_chain_fixture_count': by_type.get('field_chain',0),
        'safe_static_only': True,
    }
    Path(args.output_summary).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
if __name__=='__main__': main()
