#!/usr/bin/env python3
"""Heuristic field alias and chain analyzer for collector/parser/normalizer/detection files."""
import argparse, json, re
from pathlib import Path
FIELD_RE = re.compile(r"\b(?:evt|proc|process|container|k8s|fd|file|user|group|syscall|network|net|dns|http|tls|image|service|host|auth|source|device|interface|syslog|snmp|netflow|ipfix|aaa|config|route|acl)\.[A-Za-z0-9_.-]+\b|\b(pid|ppid|tgid|uid|gid|auid|comm|cmdline|exe|argv|file_path|path|inode|container_id|pod_name|namespace|cgroup|src_ip|dst_ip|dport|sport|syscall|event_type|process_name|device_id|device_name|hostname|interface_name|ifname|vrf|vlan|acl_name|route_prefix|next_hop|aaa_user|auth_result|tacacs_user|radius_user|snmp_oid|syslog_facility|netflow_bytes|ipfix_bytes|config_hash)\b", re.I)
ASSIGN_RE = re.compile(r"['\"](?P<src>[A-Za-z0-9_.-]+)['\"]\s*[:=]\s*['\"](?P<dst>[A-Za-z0-9_.-]+)['\"]|(?P<a>\w+)\s*=\s*(?:event|get|record|row|data).*?[\[\.]\s*['\"]?(?P<b>[A-Za-z0-9_.-]+)", re.I)
ALIASES = {
  'process_name':['comm','exe','image','proc_name'], 'cmdline':['argv','args','command_line'], 'container_id':['cid','container','k8s.container.id'],
  'pod_name':['pod','k8s.pod.name'], 'file_path':['path','filename','target_path','fd.name'], 'src_ip':['source_ip','remote_ip'], 'dst_ip':['destination_ip','dest_ip'],
  'process.command_line':['proc.cmdline','cmdline','argv','args'], 'process.executable':['proc.name','comm','exe'],
  'file.path':['fd.name','file_path','path'], 'event.type':['evt.type','event_type','syscall'],
  'k8s.namespace':['namespace','k8s.ns.name'], 'k8s.pod.name':['pod_name','pod'], 'user.name':['user','user.name'],
  'device.id':['device_id','device.id','host.id','node.id'], 'device.name':['device_name','device.name','hostname','host.name','node.name'],
  'network_device.interface.name':['interface_name','ifname','interface.name','network.interface.name'],
  'network_device.config.hash':['config_hash','config.hash','running_config_hash','startup_config_hash'],
  'network_device.config.action':['config.action','event.action','command','cli.command','change.action'],
  'network_device.aaa.user':['aaa_user','tacacs_user','radius_user','user.name','auth.user'],
  'network_device.aaa.result':['auth_result','aaa.result','authentication.result','login.result'],
  'network_device.route.prefix':['route_prefix','route.prefix','network.prefix','destination.prefix'],
  'network_device.route.next_hop':['next_hop','route.next_hop','gateway','nexthop'],
  'network_device.acl.name':['acl_name','access_list','access-list','policy.name'],
  'network_device.snmp.oid':['snmp_oid','snmp.oid','oid'],
  'network_device.flow.bytes':['netflow_bytes','ipfix_bytes','network.bytes','bytes']
}
CANONICAL = {alias.lower(): canonical for canonical, aliases in ALIASES.items() for alias in aliases}
for canonical in ALIASES:
    CANONICAL[canonical.lower()] = canonical

def canonical_field(name: str) -> str:
    return CANONICAL.get(str(name or '').lower(), str(name or '').lower())

def analyze(p: Path):
    try: txt=p.read_text(errors='replace')
    except Exception: txt=''
    fields_raw=sorted(set(m.group(0).lower() for m in FIELD_RE.finditer(txt)))
    fields=sorted(set(canonical_field(x) for x in fields_raw))
    maps=[]
    for m in ASSIGN_RE.finditer(txt):
        if m.group('src') and m.group('dst'): maps.append({'source':m.group('src'),'target':m.group('dst'),'evidence':'literal_mapping'})
        elif m.group('a') and m.group('b'): maps.append({'source':m.group('b'),'target':m.group('a'),'evidence':'assignment'})
    alias_hits=[]
    for canonical, aliases in ALIASES.items():
        seen=[x for x in [canonical]+aliases if re.search(rf"\b{re.escape(x)}\b", txt, re.I)]
        if seen: alias_hits.append({'canonical':canonical,'seen':seen,'status':'needs_chain_validation' if len(seen)>1 else 'single_name'})
    return {
        'file':str(p),
        'fields_seen':fields,
        'raw_fields_seen':fields_raw,
        'candidate_mappings':maps[:100],
        'alias_hits':alias_hits,
        'field_chain_static_state':'field_names_observed' if fields else 'no_fields_observed',
    }

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('path'); ap.add_argument('--json',action='store_true')
    args=ap.parse_args(); p=Path(args.path)
    files=[p] if p.is_file() else [x for x in p.rglob('*') if x.is_file()]
    rows=[analyze(f) for f in files]
    for r in rows:
        print(json.dumps(r, ensure_ascii=False) if args.json else f"{r['file']} fields={','.join(r['fields_seen'])}")
if __name__ == '__main__': main()
