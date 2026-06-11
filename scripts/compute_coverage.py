#!/usr/bin/env python3
from __future__ import annotations
"""V6 base ATT&CK coverage computation.

This module is intentionally conservative. It separates index knowledge, scenario
membership, telemetry support, rule-condition evidence, field-chain validation,
and tested validation. Declared ATT&CK tags alone never produce validated coverage.
"""
import argparse, json, re, math
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from common import jsonl_read, jsonl_write, ATTACK_RE, SYS_CALLS

COVERAGE_TYPES = [
    'none',
    'declared_only',
    'candidate_mapping',
    'inferred_semantic',
    'telemetry_supportable',
    'rule_condition_present',
    'field_chain_validated',
    'tested_validated',
]
CONF_ORDER = ['none','low','medium-low','medium','medium-high','high']
DEPTH_WEIGHTS = {0:0.0, 1:0.10, 2:0.30, 3:0.55, 4:0.80, 5:1.00}
CONF_MULT = {'none':0.0,'low':0.4,'medium-low':0.6,'medium':0.75,'medium-high':0.9,'high':1.0}

HIGH_SIGNAL_MAP = {
    'ptrace': ['T1055.008','T1055'],
    'process_vm_writev': ['T1055','T1055.008'],
    'process_vm_readv': ['T1055','T1055.008'],
    'memfd_create': ['T1620','T1055'],
    'mprotect': ['T1055','T1620'],
    'mmap': ['T1055','T1620'],
    'vdso': ['T1055.014'],
    'ld_preload': ['T1574.006','T1574'],
    'ld.so.preload': ['T1574.006','T1574'],
    'docker.sock': ['T1611','T1610'],
    '/var/run/docker.sock': ['T1611','T1610'],
    'containerd.sock': ['T1611','T1610'],
    'privileged': ['T1611','T1610'],
    'hostpath': ['T1611','T1610'],
    'hostpid': ['T1611'],
    'hostnetwork': ['T1611'],
    'nsenter': ['T1611'],
    'cap_sys_admin': ['T1611'],
    'serviceaccount': ['T1552.007','T1552'],
    'service account': ['T1552.007','T1552'],
    'pods/exec': ['T1611','T1613'],
    'clusterrole': ['T1069','T1087'],
    '/etc/shadow': ['T1003','T1552'],
    'id_rsa': ['T1552'],
    'authorized_keys': ['T1098','T1556'],
    'crontab': ['T1053.003','T1053'],
    'systemd': ['T1543.002','T1543'],
    'systemctl enable': ['T1543.002','T1543'],
    '.timer': ['T1053.006','T1053'],
    'kubectl exec': ['T1609','T1613'],
    'pods/exec': ['T1609','T1613'],
    'docker exec': ['T1609'],
    'docker run': ['T1610'],
    'crictl exec': ['T1609'],
    'nerdctl exec': ['T1609'],
    'tokenrequest': ['T1552.007','T1528'],
    'serviceaccounts/token': ['T1552.007','T1528'],
    'curl': ['T1105','T1071.001'],
    'wget': ['T1105','T1071.001'],
    'base64': ['T1027'],
    'ssh ': ['T1021.004'],
    'scp ': ['T1021.004','T1570','T1048.003'],
    'rsync': ['T1570','T1020'],
    'tar ': ['T1560.001'],
    'zip': ['T1560.001'],
    'rm -rf': ['T1485'],
    'shred': ['T1485'],
    'xmrig': ['T1496.001'],
    'cryptominer': ['T1496.001'],
    'auditctl -e 0': ['T1685.004','T1685'],
    'history -c': ['T1690','T1070.003'],
    'network device cli': ['T1059.008','T1059'],
    'cli.command': ['T1059.008','T1059'],
    'config change': ['T1601','T1602.002','T1686.002'],
    'running_config': ['T1602.002','T1601'],
    'startup_config': ['T1602.002','T1601'],
    'tacacs': ['T1556.004','T1078'],
    'radius': ['T1556.004','T1078'],
    'aaa': ['T1556.004','T1078'],
    'netflow': ['T1020.001','T1599'],
    'ipfix': ['T1020.001','T1599'],
    'snmp': ['T1599','T1602.002'],
    'access-list': ['T1686.002','T1686'],
    'route-map': ['T1599','T1016'],
    'firmware': ['T1495','T1542.001','T1601'],
    'boot image': ['T1542.005','T1601.002'],
}

ROLE_VALIDATED = {'detection_rule', 'network_device_detector'}
ROLE_TELEMETRY = {'collector_ebpf','parser','normalizer'}


def load_lookup(index: str | Path) -> Dict[str, Dict[str, Any]]:
    return json.load(open(Path(index)/'lookup_by_id.json', encoding='utf-8'))


def load_scenarios(index: str | Path, root: Path | None = None) -> Dict[str, Dict[str, Any]]:
    paths = []
    if root:
        paths.append(root/'attack_data'/'models'/'scenario_seed_map.json')
    paths.append(Path(index)/'scenario_seed_map.json')
    for p in paths:
        if p.exists():
            return json.load(open(p, encoding='utf-8'))
    return {}


def platform_match(rec: Dict[str, Any], platform_csv: str) -> bool:
    plats = [p.strip().lower() for p in (platform_csv or '').split(',') if p.strip()]
    if not plats:
        return True
    rplats = {p.lower() for p in rec.get('platforms', [])}
    return bool(rplats & set(plats))


def children_of(lookup: Dict[str, Dict[str, Any]], parent: str) -> List[str]:
    return sorted([tid for tid,r in lookup.items() if r.get('parent_id') == parent or tid.startswith(parent + '.')])


def add_den_row(rows: List[Dict[str, Any]], seen: set, lookup: Dict[str, Any], tid: str, scenario: str, reason: str, tier: str='should_cover', confidence: str='medium', review: bool=False, keyword: str | None=None, denominator_role: str='minimum_viable'):
    rec = lookup.get(tid)
    if not rec or tid in seen:
        return
    seen.add(tid)
    rows.append({
        'technique_id': tid,
        'technique_name': rec.get('name'),
        'scenario': scenario,
        'coverage_object': 'subtechnique' if rec.get('is_subtechnique') else 'technique',
        'included': True,
        'tier': tier,
        'include_reason': reason,
        'include_keyword': keyword,
        'candidate_requires_review': review,
        'denominator_role': denominator_role,
        'denominator_confidence': confidence,
        'platforms': rec.get('platforms', []),
        'tactics': rec.get('tactics', []),
        'required_data_components': rec.get('data_components', []),
        'detection_strategy_count': len(rec.get('detection_strategies', [])),
        'detection_strategies': [s.get('id') for s in rec.get('detection_strategies', []) if isinstance(s, dict)],
        'attack_url': rec.get('url'),
        'attack_modified': rec.get('modified'),
        'source_type': 'attack_index',
    })


def expand_denominator(lookup: Dict[str, Dict[str, Any]], scenario_cfg: Dict[str, Any], platforms: str='') -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    scenario = scenario_cfg.get('_name') or 'unknown'
    rows: List[Dict[str, Any]] = []
    optional: List[Dict[str, Any]] = []
    seen: set = set()
    optional_seen: set = set()
    for tid in scenario_cfg.get('must_cover_attack_ids', []):
        add_den_row(rows, seen, lookup, tid, scenario, 'must_cover_manual_seed', 'must_cover', 'high')
    for tid in scenario_cfg.get('seed_attack_ids') or scenario_cfg.get('candidate_ids') or []:
        tier = 'must_cover' if tid in scenario_cfg.get('critical_attack_ids', []) else 'should_cover'
        add_den_row(rows, seen, lookup, tid, scenario, 'seed_exact', tier, 'high')
        if '.' not in tid:
            for c in children_of(lookup, tid):
                add_den_row(rows, seen, lookup, c, scenario, 'parent_expanded', 'should_cover', 'medium')
    # Keyword matches are candidates requiring review by default.
    kws = [k.lower() for k in scenario_cfg.get('keywords', [])]
    for tid, rec in lookup.items():
        if tid in seen:
            continue
        blob_name = (rec.get('name','') or '').lower()
        blob_desc = (rec.get('description','') or '').lower()
        matched = None
        match_type = None
        for k in kws:
            if not k or len(k) < 3:
                continue
            if k in blob_name:
                matched, match_type = k, 'keyword_name_match'
                break
            if k in blob_desc:
                matched, match_type = k, 'keyword_description_match'
                break
        if matched:
            if tid not in seen:
                add_den_row(optional, optional_seen, lookup, tid, scenario, match_type, 'optional_cover', 'low', True, matched, 'optional_review_candidate')
    # Platform filter is applied after preserving explainability fields.
    filtered=[]
    for row in rows:
        rec = lookup.get(row['technique_id'], {})
        if platform_match(rec, platforms):
            filtered.append(row)
    optional_filtered=[]
    for row in optional:
        rec = lookup.get(row['technique_id'], {})
        if platform_match(rec, platforms):
            optional_filtered.append(row)
    # Negative denominator: same platform and same tactic but not selected, capped to avoid huge artifacts.
    selected = {r['technique_id'] for r in filtered} | {r['technique_id'] for r in optional_filtered}
    scenario_tactics = {t.lower() for t in scenario_cfg.get('tactic_scope', [])}
    negative=[]
    for tid, rec in sorted(lookup.items()):
        if tid in selected or not platform_match(rec, platforms):
            continue
        if scenario_tactics and not (scenario_tactics & {t.lower() for t in rec.get('tactics', [])}):
            continue
        negative.append({
            'technique_id': tid,
            'technique_name': rec.get('name'),
            'scenario': scenario,
            'included': False,
            'exclude_reason': 'not_selected_by_scenario_seed_or_behavior_primitives',
            'platforms': rec.get('platforms', []),
            'tactics': rec.get('tactics', []),
            'source_type': 'attack_index',
        })
    return filtered, negative[:1000], optional_filtered


def evidence_index(rows: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        out.setdefault(r.get('file_path',''), []).append(r)
    return out


def signals_for_file(evs: List[Dict[str, Any]]) -> Dict[str, set]:
    d = {'attack_id': set(), 'field_hint': set(), 'rule_logic': set(), 'syscall': set(), 'scenario_hint': set(), 'telemetry_loss': set(), 'detection_strategy_id': set(), 'analytic_id': set()}
    for e in evs:
        for s in e.get('signals', []):
            t = s.get('type'); v = s.get('value')
            if t in d and v is not None:
                d[t].add(str(v))
    return d


def select_evidence_ids(evs: List[Dict[str, Any]], attack_id: str | None=None, max_ids: int=30) -> List[str]:
    selected=[]
    for e in evs:
        sigs=e.get('signals', [])
        if attack_id and any(s.get('type')=='attack_id' and str(s.get('value')).upper()==attack_id.upper() for s in sigs):
            selected.append(e.get('evidence_id'))
        elif any(s.get('type') in ['rule_logic','field_hint','syscall','scenario_hint'] for s in sigs):
            selected.append(e.get('evidence_id'))
        if len(selected) >= max_ids:
            break
    return [x for x in selected if x]


def file_field_chain_status(field_rows: List[Dict[str, Any]], file_path: str, required_fields: List[str]) -> Tuple[str, List[str]]:
    req = {str(f).lower() for f in required_fields}
    matched=[]
    candidate_maps=0
    alias_hits=0
    for r in field_rows:
        if r.get('file') != file_path:
            continue
        fields = {str(f).lower() for f in r.get('fields_seen', [])}
        matched.extend(sorted(req & fields))
        candidate_maps += len(r.get('candidate_mappings', []) or [])
        alias_hits += len(r.get('alias_hits', []) or [])
    matched=sorted(set(matched))
    if candidate_maps and matched:
        return 'proven', matched
    if matched or alias_hits:
        return 'partial', matched
    if required_fields:
        return 'missing', []
    return 'not_applicable', []


def style_semantic_depth(style: str, has_behavior: bool) -> int:
    if style in ['ioc_match','tool_name_match']:
        return 1
    if style == 'behavioral_single_event':
        return 2
    if style == 'behavioral_multi_field':
        return 3
    if style == 'sequence_correlation':
        return 4
    return 2 if has_behavior else 0


def compute_depth_vector(rule: Dict[str, Any], evs: List[Dict[str, Any]], field_status: str, matched_fields: List[str], parent_only: bool) -> Dict[str, int]:
    sig = signals_for_file(evs)
    style = rule.get('detection_style','unknown')
    has_behavior = bool(sig['syscall'] or sig['rule_logic'] or rule.get('condition_fragments'))
    semantic = style_semantic_depth(style, has_behavior)
    fields = rule.get('required_fields', []) or []
    telemetry = 0
    if fields:
        telemetry = 2
    if len(fields) >= 3:
        telemetry = 3
    if field_status in ['partial','proven']:
        telemetry = 4 if field_status == 'proven' else max(telemetry, 3)
    if sig['telemetry_loss'] and field_status == 'proven':
        telemetry = 5
    blob = json.dumps(rule.get('condition_fragments', []), ensure_ascii=False).lower()
    if any(x in blob for x in ['join','within','time_window','sequence','correlat']):
        correlation = 4
    elif any(x in blob for x in ['parent','ancestor','ppid','process tree','container','pod','namespace','cgroup']):
        correlation = 3
    elif has_behavior:
        correlation = 1
    else:
        correlation = 0
    path_blob = (rule.get('file_path','') + ' ' + rule.get('rule_name','')).lower()
    test_depth = 0
    if any(x in path_blob for x in ['test','fixture','sample']):
        test_depth = 1
    if any(x in blob for x in ['expected_alert','negative','positive','fixture','replay']):
        test_depth = max(test_depth, 2)
    resilience = 1 if style in ['ioc_match','tool_name_match'] else 2
    if any(x in blob for x in ['regex','startswith','contains','endswith','wildcard','allowlist','exception']):
        resilience = max(resilience, 2)
    if any(x in blob for x in ['variant','obfuscat','encoded','namespace','runtime','containerd','cri-o','docker']):
        resilience = max(resilience, 3)
    final = min(semantic, telemetry if telemetry else semantic, max(1, test_depth + 2), resilience + 1)
    if not has_behavior:
        final = min(final, 1)
    if parent_only:
        final = min(final, 2)
    if style in ['ioc_match','tool_name_match']:
        final = min(final, 1)
    return {
        'semantic_depth': int(max(0,min(5,semantic))),
        'telemetry_depth': int(max(0,min(5,telemetry))),
        'correlation_depth': int(max(0,min(5,correlation))),
        'test_depth': int(max(0,min(5,test_depth))),
        'resilience_depth': int(max(0,min(5,resilience))),
        'final_depth': int(max(0,min(5,final))),
    }


def strength_from_depth(depth: int) -> str:
    if depth <= 0: return 'none'
    if depth == 1: return 'weak'
    if depth == 2: return 'partial'
    if depth == 3: return 'strong'
    if depth == 4: return 'strong'
    return 'deep'


def confidence_from_components(depth: int, penalties: List[str], bonuses: List[str]) -> str:
    base_idx = min(max(depth,0),5)
    # map depth to confidence before penalties
    mapping = ['none','low','medium-low','medium','medium-high','high']
    idx = CONF_ORDER.index(mapping[base_idx])
    idx += min(len(bonuses), 1)
    # severe penalties count double
    for p in penalties:
        idx -= 2 if p in ['no_evidence_ids','missing_field_chain','wrong_platform','ioc_only','tool_name_only'] else 1
    idx = max(0, min(len(CONF_ORDER)-1, idx))
    return CONF_ORDER[idx]


def infer_candidates_from_rule(rule: Dict[str, Any], lookup: Dict[str, Any], denominator_ids: set) -> List[Tuple[str, str]]:
    text_bits = [rule.get('rule_name',''), ' '.join(rule.get('syscalls',[]) or []), json.dumps(rule.get('condition_fragments', []), ensure_ascii=False), ' '.join(rule.get('required_fields',[]) or [])]
    blob = ' '.join(text_bits).lower()
    out=[]
    for signal, ids in HIGH_SIGNAL_MAP.items():
        if signal in blob:
            for tid in ids:
                if tid in lookup and (not denominator_ids or tid in denominator_ids or lookup[tid].get('parent_id') in denominator_ids):
                    out.append((tid, f'high_signal:{signal}'))
    # fallback: syscall-to-description matching against denominator only
    for s in rule.get('syscalls', []) or []:
        sl=s.lower()
        for tid in list(denominator_ids)[:500]:
            rec=lookup.get(tid,{})
            if sl in (rec.get('name','')+' '+rec.get('description','')).lower():
                out.append((tid, f'syscall_description_match:{s}'))
    # de-duplicate in order
    seen=set(); dedup=[]
    for tid, reason in out:
        if tid not in seen:
            seen.add(tid); dedup.append((tid, reason))
    return dedup[:10]


def log_source_compatibility(rule: Dict[str, Any], rec: Dict[str, Any]) -> str:
    fmt=(rule.get('rule_format') or '').lower()
    fields=' '.join(rule.get('required_fields',[]) or []).lower()
    dcs=' '.join(rec.get('data_components',[]) or []).lower()
    if not dcs:
        return 'unknown'
    if any(x in fields for x in ['process','proc','pid','cmd','exe','argv']) and 'process' in dcs:
        return 'compatible'
    if any(x in fields for x in ['file','path','inode']) and 'file' in dcs:
        return 'compatible'
    if any(x in fields for x in ['container','pod','namespace','cgroup']) and any(x in dcs for x in ['container','pod','cloud','image']):
        return 'compatible'
    if 'auditd' in fmt and any(x in dcs for x in ['process','file','user']):
        return 'partial'
    if 'falco' in fmt and any(x in dcs for x in ['process','file','container']):
        return 'partial'
    return 'partial' if fields else 'mismatch'


def determine_coverage_type(rule: Dict[str, Any], tid: str, in_den: bool, declared: bool, inferred: bool, role: str, depth_vec: Dict[str,int], field_status: str, evidence_ids: List[str], log_compat: str, platform_ok: bool) -> str:
    if not in_den:
        return 'declared_only' if declared else 'candidate_mapping'
    if not evidence_ids:
        return 'declared_only' if declared else 'candidate_mapping'
    has_condition = bool(rule.get('condition_fragments'))
    if role in ROLE_TELEMETRY and not has_condition:
        return 'telemetry_supportable'
    if role not in ROLE_VALIDATED and role in ROLE_TELEMETRY:
        return 'telemetry_supportable'
    if inferred and not declared and depth_vec['semantic_depth'] >= 2:
        base = 'inferred_semantic'
    else:
        base = 'declared_only' if declared else 'candidate_mapping'
    if has_condition and depth_vec['semantic_depth'] >= 2:
        base = 'rule_condition_present'
    if role in ROLE_VALIDATED and platform_ok and log_compat != 'mismatch' and field_status in ['partial','proven'] and depth_vec['final_depth'] >= 2:
        base = 'field_chain_validated'
    if base == 'field_chain_validated' and depth_vec['test_depth'] >= 3:
        base = 'tested_validated'
    return base


def compute(args: argparse.Namespace):
    root=Path(__file__).resolve().parents[1]
    lookup=load_lookup(args.index)
    scenarios=load_scenarios(args.index, root)
    parsed=jsonl_read(Path(args.parsed_rules))
    evidence=jsonl_read(Path(args.evidence)) if args.evidence and Path(args.evidence).exists() else []
    field_rows=jsonl_read(Path(args.field_chain)) if args.field_chain and Path(args.field_chain).exists() else []
    intents=jsonl_read(Path(args.intent_hints)) if args.intent_hints and Path(args.intent_hints).exists() else []
    ev_by_file=evidence_index(evidence)
    selected=args.scenario
    if not selected and intents:
        counts={}
        for i in intents:
            s=i.get('primary_scenario')
            if s: counts[s]=counts.get(s,0)+1
        if counts: selected=max(counts, key=counts.get)
    if not selected: selected='unknown'
    cfg=dict(scenarios.get(selected,{})); cfg['_name']=selected
    denominator, negative, optional_candidates = expand_denominator(lookup, cfg, args.platform) if cfg else ([], [], [])
    den_ids={d['technique_id'] for d in denominator}
    records=[]
    strategy_rows=[]
    dc_rows=[]
    declared_ids=set()
    seen_rule_tid=set()

    for rule in parsed:
        file_path=rule.get('file_path','')
        evs=ev_by_file.get(file_path, [])
        declared = [x.upper() for x in rule.get('declared_attack_ids',[]) or []]
        declared_ids.update(declared)
        inferred = infer_candidates_from_rule(rule, lookup, den_ids)
        candidates=[]
        for tid in declared:
            candidates.append((tid, True, False, 'declared_tag'))
        for tid, reason in inferred:
            if tid not in declared:
                candidates.append((tid, False, True, reason))
        if not candidates and rule.get('required_fields'):
            # Preserve supportable telemetry records at scenario level rather than fabricating ATT&CK mapping.
            continue
        for tid, is_declared, is_inferred, map_reason in candidates:
            rec=lookup.get(tid)
            if not rec:
                records.append({'technique_id':tid,'technique_name':None,'scenario':selected,'coverage_object':'unknown','rule_id':rule.get('rule_id'),'file_path':file_path,'coverage_type':'declared_only','depth':0,'depth_vector':{'semantic_depth':0,'telemetry_depth':0,'correlation_depth':0,'test_depth':0,'resilience_depth':0,'final_depth':0},'strength':'none','confidence':'low','gap_reason_codes':['unknown_attack_id'],'declared':is_declared,'inferred':is_inferred,'in_denominator':False,'evidence_status':'not_verified','evidence_ids':select_evidence_ids(evs, tid),'mapping_reason':map_reason})
                continue
            in_den = tid in den_ids or rec.get('parent_id') in den_ids
            parent_only = ('.' not in tid) and bool(children_of(lookup, tid))
            field_status, matched_fields = file_field_chain_status(field_rows, file_path, rule.get('required_fields',[]) or [])
            depth_vec = compute_depth_vector(rule, evs, field_status, matched_fields, parent_only)
            log_compat = log_source_compatibility(rule, rec)
            platform_ok = platform_match(rec, args.platform)
            ev_ids = select_evidence_ids(evs, tid)
            cov_type = determine_coverage_type(rule, tid, in_den, is_declared, is_inferred, rule.get('role_hint','unknown'), depth_vec, field_status, ev_ids, log_compat, platform_ok)
            gap=[]; bonuses=[]
            if not in_den: gap.append('outside_scenario_denominator')
            if not platform_ok: gap.append('wrong_platform')
            if parent_only: gap.append('parent_only')
            if rule.get('detection_style') == 'ioc_match': gap.append('ioc_only')
            if rule.get('detection_style') == 'tool_name_match': gap.append('tool_name_only')
            if field_status == 'missing': gap.append('missing_field_chain')
            if log_compat == 'mismatch': gap.append('log_source_mismatch')
            if not ev_ids: gap.append('no_evidence_ids')
            if cov_type in ['tested_validated','field_chain_validated']: bonuses.append('validated_gate_passed')
            conf=confidence_from_components(depth_vec['final_depth'], gap, bonuses)
            evidence_status = 'verified' if cov_type in ['field_chain_validated','tested_validated'] else ('partially_verified' if ev_ids else 'not_verified')
            strength = strength_from_depth(depth_vec['final_depth'])
            coverage_score = DEPTH_WEIGHTS[depth_vec['final_depth']] * CONF_MULT[conf]
            den_meta = next((d for d in denominator if d['technique_id']==tid), None)
            row={
                'technique_id': tid,
                'technique_name': rec.get('name'),
                'scenario': selected,
                'coverage_object': 'subtechnique' if rec.get('is_subtechnique') else 'technique',
                'rule_id': rule.get('rule_id'),
                'rule_name': rule.get('rule_name'),
                'file_path': file_path,
                'coverage_type': cov_type,
                'depth': depth_vec['final_depth'],
                'depth_vector': depth_vec,
                'strength': strength,
                'confidence': conf,
                'coverage_score': round(coverage_score, 4),
                'gap_reason_codes': gap,
                'declared': is_declared,
                'inferred': is_inferred,
                'in_denominator': bool(in_den),
                'denominator_tier': den_meta.get('tier') if den_meta else None,
                'denominator_confidence': den_meta.get('denominator_confidence') if den_meta else None,
                'evidence_status': evidence_status,
                'evidence_ids': ev_ids,
                'mapping_reason': map_reason,
                'field_chain_status': field_status,
                'matched_fields': matched_fields,
                'log_source_compatibility': log_compat,
                'platform_match': platform_ok,
                'required_data_components': rec.get('data_components', []),
                'detection_strategies': [s.get('id') for s in rec.get('detection_strategies', []) if isinstance(s, dict)],
                'attack_url': rec.get('url'),
            }
            records.append(row)
            if in_den:
                for dc in rec.get('data_components', []) or []:
                    dc_rows.append({'technique_id':tid,'rule_id':rule.get('rule_id'),'file_path':file_path,'data_component':dc,'observability_state':'used_in_rule' if matched_fields else ('parsed_or_observed' if rule.get('required_fields') else 'not_observed'),'field_chain_status':field_status})
                for s in rec.get('detection_strategies', []) or []:
                    if isinstance(s, dict):
                        strategy_rows.append({'technique_id':tid,'rule_id':rule.get('rule_id'),'file_path':file_path,'detection_strategy_id':s.get('id'),'detection_strategy_name':s.get('name'),'alignment_state':'partial' if cov_type in ['rule_condition_present','field_chain_validated','tested_validated'] else 'candidate','coverage_type':cov_type})

    # Denominator gaps: only validated-like coverage counts as covered for scenario validated coverage.
    validated_types={'field_chain_validated','tested_validated'}
    covered_validated={r['technique_id'] for r in records if r.get('in_denominator') and r.get('coverage_type') in validated_types}
    any_records_by_tid={}
    for r in records:
        if r.get('in_denominator'):
            any_records_by_tid.setdefault(r['technique_id'], []).append(r)
    for d in denominator:
        tid=d['technique_id']
        if tid not in any_records_by_tid:
            records.append({
                'technique_id': tid,
                'technique_name': d.get('technique_name'),
                'scenario': selected,
                'coverage_object': d.get('coverage_object'),
                'coverage_type': 'none',
                'depth': 0,
                'depth_vector': {'semantic_depth':0,'telemetry_depth':0,'correlation_depth':0,'test_depth':0,'resilience_depth':0,'final_depth':0},
                'strength': 'none',
                'confidence': 'none',
                'coverage_score': 0.0,
                'gap_reason_codes': ['no_rule'],
                'declared': False,
                'inferred': False,
                'in_denominator': True,
                'denominator_tier': d.get('tier'),
                'denominator_confidence': d.get('denominator_confidence'),
                'evidence_status': 'not_verified',
                'evidence_ids': [],
                'required_data_components': d.get('required_data_components', []),
                'detection_strategy_count': d.get('detection_strategy_count', 0),
                'detection_strategies': d.get('detection_strategies', []),
                'gap_explanation': 'Technique is in scenario denominator but no parsed rule/code evidence mapped to it.'
            })

    # Write artifacts.
    out=Path(args.output); jsonl_write(out, records)
    jsonl_write(Path(args.denominator_output), denominator)
    jsonl_write(Path(args.negative_denominator_output), negative)
    jsonl_write(Path(args.optional_denominator_output), optional_candidates)
    jsonl_write(Path(args.strategy_output), strategy_rows)
    jsonl_write(Path(args.data_component_output), dc_rows)

    total=len(denominator)
    den_tids={d['technique_id'] for d in denominator}
    in_den_records=[r for r in records if r.get('in_denominator')]
    best_by_tid={}
    for r in in_den_records:
        tid=r['technique_id']
        if tid not in den_tids:
            continue
        prev=best_by_tid.get(tid)
        if prev is None or r.get('coverage_score',0) > prev.get('coverage_score',0):
            best_by_tid[tid]=r
    best=list(best_by_tid.values())
    by_strength={k:sum(1 for r in best if r.get('strength')==k) for k in ['none','weak','partial','strong','deep']}
    by_type={k:sum(1 for r in best if r.get('coverage_type')==k) for k in COVERAGE_TYPES}
    declared_rate=sum(1 for r in best if r.get('declared'))/total if total else None
    supportable_rate=sum(1 for r in best if r.get('coverage_type') in ['telemetry_supportable','rule_condition_present','field_chain_validated','tested_validated'])/total if total else None
    validated_rate=sum(1 for r in best if r.get('coverage_type') in ['field_chain_validated','tested_validated'])/total if total else None
    tested_rate=sum(1 for r in best if r.get('coverage_type')=='tested_validated')/total if total else None
    weighted=sum(r.get('coverage_score',0.0) for r in best)
    weak_only=[r for r in best if r.get('strength')=='weak']
    none=[r for r in best if r.get('strength')=='none']
    critical=[d for d in denominator if d.get('tier')=='must_cover']
    critical_ids={d['technique_id'] for d in critical}
    critical_best=[r for r in best if r['technique_id'] in critical_ids]
    critical_strong=sum(1 for r in critical_best if r.get('strength') in ['strong','deep'])
    denominator_confidence = 'high' if denominator and all(d.get('denominator_confidence')=='high' or not d.get('candidate_requires_review') for d in denominator) else ('medium' if denominator else 'none')
    full_enterprise_claim='No'
    full_platform_claim='No'
    blockers=[]
    if denominator_confidence != 'high': blockers.append('denominator_uncertainty')
    if none: blockers.append('uncovered_denominator_ids')
    if weak_only: blockers.append('weak_only_mappings')
    if critical and critical_strong < len(critical): blockers.append('critical_techniques_not_strong_or_deep')
    if tested_rate is not None and tested_rate < 0.2: blockers.append('insufficient_test_evidence')
    if validated_rate is not None and validated_rate >= 0.8 and not blockers:
        scenario_claim='comprehensively_covered'
    elif validated_rate is not None and validated_rate >= 0.5 and 'uncovered_denominator_ids' not in blockers:
        scenario_claim='operationally_covered'
    elif any(r.get('coverage_type') in ['field_chain_validated','tested_validated','rule_condition_present'] for r in best):
        scenario_claim='partially_covered'
    else:
        scenario_claim='not_covered'
    claim={
        'can_claim_full_enterprise_attack_coverage': full_enterprise_claim,
        'can_claim_full_linux_containers_attack_coverage': full_platform_claim,
        'scenario_coverage_claim': scenario_claim,
        'complete_coverage_gate_passed': scenario_claim == 'comprehensively_covered',
        'blocking_reasons': blockers,
        'notes': [
            'Full Enterprise ATT&CK coverage is prohibited unless explicit full-matrix mode is used and every applicable gate passes.',
            'Declared-only, IOC-only, tool-name-only, and parent-only mappings cannot satisfy validated coverage gates.'
        ]
    }
    Path(args.claim_output).write_text(json.dumps(claim, ensure_ascii=False, indent=2), encoding='utf-8')
    Path(args.claim_markdown_output).write_text(render_claim_markdown(claim), encoding='utf-8')
    explainer=render_denominator_explainer(selected, args.platform, denominator, negative[:50], optional_candidates[:100])
    Path(args.denominator_markdown_output).write_text(explainer, encoding='utf-8')
    summary={
        'coverage_model_version': 'V10.5-wave4',
        'scenario': selected,
        'platform_scope': args.platform,
        'denominator_count': total,
        'minimum_viable_denominator_count': total,
        'optional_denominator_candidate_count': len(optional_candidates),
        'denominator_confidence': denominator_confidence,
        'declared_rate': round(declared_rate,4) if declared_rate is not None else None,
        'supportable_rate': round(supportable_rate,4) if supportable_rate is not None else None,
        'validated_rate': round(validated_rate,4) if validated_rate is not None else None,
        'tested_validated_rate': round(tested_rate,4) if tested_rate is not None else None,
        'depth_weighted_coverage': round(weighted/total,4) if total else None,
        'strong_or_deep_rate': round(sum(1 for r in best if r.get('strength') in ['strong','deep'])/total,4) if total else None,
        'weak_only_count': len(weak_only),
        'none_count': len(none),
        'by_strength': by_strength,
        'by_coverage_type': by_type,
        'declared_id_count': len(declared_ids),
        'critical_denominator_count': len(critical),
        'critical_strong_or_deep_count': critical_strong,
        'complete_coverage_claim': claim,
        'warnings': [],
    }
    if not cfg: summary['warnings'].append('unknown_scenario_no_denominator')
    if optional_candidates: summary['warnings'].append('optional_denominator_candidates_require_review')
    if total and len(none)/total > 0.5: summary['warnings'].append('large_uncovered_denominator')
    Path(args.summary_output).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))


def render_denominator_explainer(scenario: str, platform: str, denominator: List[Dict[str, Any]], negative: List[Dict[str, Any]], optional_candidates: List[Dict[str, Any]] | None=None) -> str:
    optional_candidates = optional_candidates or []
    lines=[f"# ATT&CK Denominator Explainer\n", f"- scenario: `{scenario}`", f"- platform_scope: `{platform}`", f"- minimum_viable_included_count: `{len(denominator)}`", f"- optional_review_candidate_count: `{len(optional_candidates)}`", f"- excluded_sample_count: `{len(negative)}`", "", "## Minimum viable denominator", "", "| ATT&CK ID | Name | Tier | Reason | Confidence | Review? |", "|---|---|---|---|---|---|"]
    for d in denominator:
        lines.append(f"| {d.get('technique_id')} | {d.get('technique_name')} | {d.get('tier')} | {d.get('include_reason')} | {d.get('denominator_confidence')} | {d.get('candidate_requires_review')} |")
    lines += ["", "## Optional review candidates", "", "| ATT&CK ID | Name | Reason | Keyword | Confidence |", "|---|---|---|---|---|"]
    for d in optional_candidates[:100]:
        lines.append(f"| {d.get('technique_id')} | {d.get('technique_name')} | {d.get('include_reason')} | {d.get('include_keyword')} | {d.get('denominator_confidence')} |")
    if not optional_candidates:
        lines.append("| N/A | N/A | no optional candidates | N/A | N/A |")
    lines += ["", "## Excluded sample", "", "| ATT&CK ID | Name | Reason |", "|---|---|---|"]
    for d in negative[:50]:
        lines.append(f"| {d.get('technique_id')} | {d.get('technique_name')} | {d.get('exclude_reason')} |")
    return "\n".join(lines)+"\n"


def render_claim_markdown(claim: Dict[str, Any]) -> str:
    return f"""# Complete Coverage Claim Assessment

- Can claim full Enterprise ATT&CK coverage: **{claim.get('can_claim_full_enterprise_attack_coverage')}**
- Can claim full Linux/Containers ATT&CK coverage: **{claim.get('can_claim_full_linux_containers_attack_coverage')}**
- Scenario coverage claim: **{claim.get('scenario_coverage_claim')}**
- Complete coverage gate passed: **{claim.get('complete_coverage_gate_passed')}**

## Blocking reasons

{chr(10).join('- '+b for b in claim.get('blocking_reasons', [])) or '- None'}

## Notes

{chr(10).join('- '+n for n in claim.get('notes', []))}
"""


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--index', default='attack_data/index')
    ap.add_argument('--parsed-rules', default='parsed_rules.jsonl')
    ap.add_argument('--intent-hints', default='intent_hints.jsonl')
    ap.add_argument('--evidence', default='evidence.jsonl')
    ap.add_argument('--field-chain', default='field_chain.jsonl')
    ap.add_argument('--scenario')
    ap.add_argument('--platform', default='Linux,Containers,Network Devices')
    ap.add_argument('--output', default='coverage.jsonl')
    ap.add_argument('--denominator-output', default='attack_denominator.jsonl')
    ap.add_argument('--negative-denominator-output', default='negative_denominator.jsonl')
    ap.add_argument('--optional-denominator-output', default='optional_denominator_candidates.jsonl')
    ap.add_argument('--denominator-markdown-output', default='denominator_explainer.md')
    ap.add_argument('--summary-output', default='coverage_summary.json')
    ap.add_argument('--strategy-output', default='strategy_alignment.jsonl')
    ap.add_argument('--data-component-output', default='data_component_coverage.jsonl')
    ap.add_argument('--claim-output', default='complete_coverage_assessment.json')
    ap.add_argument('--claim-markdown-output', default='complete_coverage_assessment.md')
    args=ap.parse_args(); compute(args)
if __name__=='__main__': main()
