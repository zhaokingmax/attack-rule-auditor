#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, os, re, time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

TEXT_EXTS = {'.yml','.yaml','.json','.py','.go','.c','.h','.cc','.cpp','.cxx','.hpp','.hh','.rs','.java','.js','.ts','.sh','.bash','.txt','.rule','.rules','.conf','.audit','.sigma','.yar','.yara','.md'}
ATTACK_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.I)
DET_RE = re.compile(r'\bDET\d{4}\b', re.I)
AN_RE = re.compile(r'\bAN\d{4}\b', re.I)

FIELD_WORDS = ['process','proc','pid','ppid','parent','cmd','command','command_line','args','argv','exe','image','path','file','uid','gid','user','container','container_id','pod','namespace','image','cgroup','syscall','event','socket','ip','domain','url','hash','sha256','sha1','md5','device','interface','syslog','snmp','netflow','ipfix','aaa','tacacs','radius','config','route','acl','firmware']
SYS_CALLS = ['execve','execveat','open','openat','creat','write','rename','renameat','unlink','unlinkat','chmod','fchmod','chown','fchown','setxattr','ptrace','process_vm_writev','process_vm_readv','mmap','mprotect','memfd_create','clone','unshare','setns','mount','umount2','socket','connect','accept','bind','listen','kill','bpf']

SCENARIO_SIGNAL_HINTS = {
 'process_injection_memory':['ptrace','process_vm_writev','/proc/','memfd','mprotect','mmap','LD_PRELOAD','ld.so.preload','vdso','rwx','dlopen'],
 'container_escape':['privileged','hostpath','docker.sock','containerd.sock','cap_sys_admin','hostpid','hostnetwork','nsenter','cgroup','runc'],
 'container_runtime':['docker','containerd','cri-o','runc','kata','container_id','kubepods','pod','image'],
 'kubernetes_api_abuse':['kubectl','kubernetes','k8s','serviceaccount','clusterrole','rolebinding','pods/exec','daemonset','secret','audit.k8s.io'],
 'file_write_malware_collection':['openat','write','rename','unlink','fanotify','inotify','elf','dropper','chmod +x','download'],
 'collection_staging_archive':['tar','zip','gzip','archive','staging','/tmp','find -exec','xargs','data collection'],
 'lotl_command_chain':['bash -c','sh -c','python -c','curl','wget','nc ','ncat','socat','ssh','scp','rsync','base64'],
 'credential_access':['/etc/shadow','id_rsa','.ssh','aws_access_key','credentials','token','serviceaccount','gcore','/proc/'],
 'privilege_escalation':['sudo','setuid','setgid','cap_sys_admin','chmod 4755','pkexec','dirtycow','overlayfs'],
 'linux_persistence':['cron','crontab','systemd','.service','.timer','authorized_keys','pam','ld_preload','clusterrolebinding','cronjob'],
 'persistence':['cron','crontab','systemd','.service','rc.local','.bashrc','authorized_keys','pam','ld_preload','daemonset'],
 'network_c2':['reverse shell','socket','connect','curl','wget','dns','http','https','proxy','tunnel','beacon','egress'],
 'exfiltration':['exfil','upload','scp','sftp','ftp','rclone','rsync','split','chunk','tar','zip','egress bytes'],
 'discovery':['uname','whoami','netstat','ss -','ip addr','ifconfig','kubectl get','docker ps','metadata'],
 'lateral_movement':['ssh','scp','rsync','sftp','proxycommand','valid account','remote service','bearer token','vnc','lateral'],
 'initial_access':['public-facing','web exploit','rce','webshell','ssh login','valid account','default account','dependency','registry'],
 'impact':['rm -rf','shred','wipe','encrypt','ransom','miner','xmrig','fork bomb','shutdown','reboot','userdel','truncate'],
 'defense_impairment_stealth':['auditctl -e 0','auditd','history -c','unset histfile','clear logs','masquerade','hidden','timestomp','disable'],
 'container_supply_chain':['dockerfile','registry','build context','entrypoint','image layer','docker build','from ','run curl','dependency'],
 'supply_chain_container':['dockerfile','registry','build context','entrypoint','image layer','docker build','from ','run curl'],
}

DATA_COMPONENT_ALIASES = {
    'container metadata': 'Container Creation',
    'container image metadata': 'Image Metadata',
    'container image': 'Image Metadata',
    'image layer metadata': 'Image Metadata',
    'kubernetes audit': 'Cloud Service Modification',
    'k8s audit': 'Cloud Service Modification',
    'kubernetes api audit': 'Cloud Service Modification',
    'syscall': 'OS API Execution',
    'system call': 'OS API Execution',
    'network connection': 'Network Connection Creation',
    'network flow': 'Network Traffic Flow',
    'user account': 'User Account Authentication',
    'process metadata': 'Process Metadata',
}

def normalize_data_component(value: Any) -> str:
    text = str(value or '').strip()
    if not text:
        return ''
    return DATA_COMPONENT_ALIASES.get(text.lower(), text)

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8', 'ignore')).hexdigest()

def is_text_file(path: Path, max_probe: int = 4096) -> bool:
    if path.suffix.lower() in TEXT_EXTS:
        return True
    try:
        data = path.read_bytes()[:max_probe]
        if b'\x00' in data:
            return False
        data.decode('utf-8')
        return True
    except Exception:
        return False

def read_text(path: Path, max_bytes: int = 2_000_000) -> str:
    data = path.read_bytes()[:max_bytes]
    return data.decode('utf-8', errors='replace')

def iter_input_files(input_path: Path) -> Iterable[Path]:
    if input_path.is_file():
        yield input_path
    elif input_path.is_dir():
        for p in sorted(input_path.rglob('*')):
            if p.is_file() and not any(part.startswith('.audit_runs') for part in p.parts):
                yield p

def jsonl_write(path: Path, rows: Iterable[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open('w', encoding='utf-8') as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, separators=(',', ':'))+'\n')
            n += 1
    return n

def jsonl_read(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    with path.open('r', encoding='utf-8') as f:
        for line in f:
            line=line.strip()
            if line:
                rows.append(json.loads(line))
    return rows

def detect_language(path: Path, text: str='') -> str:
    ext = path.suffix.lower()
    low = text.lower()
    if 'condition:' in low and 'output:' in low and 'priority:' in low: return 'falco_yaml'
    if 'logsource:' in low and 'detection:' in low and 'condition:' in low: return 'sigma_yaml'
    if '-a ' in text and '-S ' in text: return 'auditd'
    if ext in ['.yml','.yaml']:
        return 'yaml'
    if ext == '.json': return 'json'
    if ext == '.py': return 'python'
    if ext == '.go': return 'go'
    if ext == '.c': return 'c'
    if ext in ['.h','.cc','.cpp','.cxx','.hpp','.hh']: return 'c_cpp'
    if ext == '.rs': return 'rust'
    if ext == '.java': return 'java'
    if ext in ['.yar','.yara']: return 'yara'
    if ext in ['.sh','.bash']: return 'shell'
    return 'text'

def role_hint(path: Path, text: str) -> str:
    low = (str(path)+'\n'+text[:5000]).lower()
    if any(x in low for x in ['kprobe','tracepoint','ringbuf','perf_event','sec("','bpf_map','ebpf']): return 'collector_ebpf'
    if any(x in low for x in ['normalize','normalizer','rename','schema','mapping']): return 'normalizer'
    if any(x in low for x in ['parser','parse_','grok','regex']): return 'parser'
    if any(x in low for x in ['syslog','netflow','ipfix','snmp','aaa','tacacs','radius','config change','interface','route-map','access-list']): return 'network_device_detector'
    if any(x in low for x in ['alert','detect','condition:','rule:','rules:','sigma','falco']): return 'detection_rule'
    return 'unknown'

def now_id(prefix='run') -> str:
    return prefix + '_' + time.strftime('%Y%m%d_%H%M%S')
