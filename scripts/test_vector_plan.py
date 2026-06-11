#!/usr/bin/env python3
"""Generate a test vector plan skeleton from static detection signals. It does not generate real exploit payloads."""
import argparse, json, re
from pathlib import Path

def plan(p: Path):
    txt=p.read_text(errors='replace') if p.exists() else ''
    syscalls=sorted(set(re.findall(r"\b(execve|openat|mprotect|mmap|memfd_create|ptrace|process_vm_writev|connect|bind|mount|setns)\b", txt, re.I)))
    paths=sorted(set(re.findall(r"/(?:etc|proc|sys|var|tmp|dev|home)[A-Za-z0-9_./-]*", txt)))[:20]
    needs_kernel=bool(re.search(r"ebpf|kprobe|tracepoint|syscall|auditd|fanotify", txt, re.I))
    needs_container=bool(re.search(r"container|docker|kubernetes|k8s|runc|containerd|namespace|cgroup", txt, re.I))
    return {
      'coverage_model_version':'V10.5-wave4',
      'file':str(p), 'executable_now':'partial', 'requires_kernel_event':needs_kernel, 'requires_container_runtime':needs_container,
      'fixture_types_required':['positive','negative','bypass_variant','field_chain'],
      'positive_cases':[{'name':'positive_trigger_minimal','signals':{'syscalls':syscalls,'paths':paths},'note':'Construct benign/sandboxed event replay matching detection condition; do not run destructive payloads.'}],
      'negative_cases':[{'name':'negative_benign_variant','note':'Same fields with benign path/user/container context; should not alert.'},{'name':'negative_obfuscation_boundary','note':'Benign parameter/path variant to check over-broad matching.'}],
      'bypass_variant_cases':[{'name':'safe_semantic_variant','note':'Replay a harmless event variant that changes path/tool/argument representation while preserving defensive semantics.'}],
      'field_chain_cases':[{'name':'collector_parser_normalizer_alert_chain','required_stages':['collector_emits','parser_preserves','normalizer_maps','condition_uses','alert_emits']}],
      'replay_input_schema':['timestamp','pid','ppid','uid','comm','cmdline','file_path','container_id','event_type'],
      'expected_artifacts':['raw event sample','normalized event sample','expected alert JSON','negative no-alert assertion','bypass variant assertion'],
      'missing_fixture':['real collector event sample','parser normalized sample','expected alert JSON','negative fixture','bypass fixture']
    }

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('path'); ap.add_argument('--json',action='store_true')
    args=ap.parse_args(); p=Path(args.path); files=[p] if p.is_file() else [x for x in p.rglob('*') if x.is_file()]
    for r in [plan(f) for f in files[:200]]: print(json.dumps(r, ensure_ascii=False))
if __name__ == '__main__': main()
