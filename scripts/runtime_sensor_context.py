#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, time
from pathlib import Path

DEFAULT_RUNTIME_KEYS = ['docker','containerd','cri-o','runc','kata','gvisor','firecracker','kubernetes']
DEFAULT_SENSOR_KEYS = ['lost_events','drop_rate','ring_buffer_overflow','audit_backlog','sampling_enabled','collector_restart','k8s_request_object','k8s_response_object']
DEFAULT_CAPABILITY_KEYS = ['process_events','file_events','network_events','container_events','k8s_audit_events','image_events','user_auth_events','kernel_syscalls']
NETWORK_DEVICE_CAPABILITY_KEYS = [
    'network_device_syslog',
    'network_device_aaa',
    'network_device_config_change',
    'netflow_or_ipfix',
    'snmp_traps',
    'routing_control_plane',
    'firmware_inventory',
]

CAP_EXPLANATIONS = {
    'runtime_inventory_missing': 'Runtime inventory is required to know which Linux/container/Kubernetes execution surfaces are observable.',
    'sensor_health_missing': 'Sensor health is required to distinguish true detection gaps from dropped or sampled telemetry.',
    'sensor_health_blockers_present': 'Loss, overflow, backlog, sampling, or restart evidence can create false negatives.',
    'kernel_version_unknown': 'Kernel-specific collectors and syscall semantics cannot be assumed without kernel context.',
    'cgroup_version_unknown': 'Container boundary claims require cgroup context.',
    'process_event_capability_unknown': 'Process claims need process event capability or a proven alternate field chain.',
    'file_event_capability_unknown': 'File claims need file event capability or a proven alternate field chain.',
    'network_event_capability_unknown': 'Network claims need network event capability or a proven alternate field chain.',
    'network_device_inventory_missing': 'Network-device claims need device inventory and management-plane telemetry context.',
    'network_device_sensor_context_incomplete': 'Network-device claims require syslog, AAA, config, flow, or SNMP proof depending on the behavior.',
}

def load_json(path: str|None, default=None):
    if not path:
        return default if default is not None else {}
    p = Path(path)
    if not p.exists() or not str(path):
        return default if default is not None else {}
    try:
        return json.load(open(p, encoding='utf-8'))
    except Exception as e:
        return {'_error': str(e), '_path': str(path)}

def boolish(v):
    if isinstance(v, bool): return v
    if isinstance(v, (int,float)): return bool(v)
    if v is None: return False
    return str(v).strip().lower() in ['1','true','yes','y','enabled','present','available']

def floatish(v, default=0.0):
    try: return float(v)
    except Exception: return default

def cap_key(cap: str) -> str:
    return str(cap).split(':', 1)[0]

def cap_explanation(cap: str) -> str:
    return CAP_EXPLANATIONS.get(cap_key(cap), 'This context gap caps confidence until the required telemetry proof is supplied.')

def context_score(missing_inputs: list[str], sensor_blockers: list[str], coverage_caps: list[str]) -> dict[str, object]:
    score = 100
    score -= min(40, 10 * len(set(missing_inputs)))
    score -= min(35, 7 * len(set(sensor_blockers)))
    score -= min(25, 5 * len(set(coverage_caps)))
    score = max(0, score)
    if score >= 85:
        band = 'high'
    elif score >= 60:
        band = 'medium'
    else:
        band = 'low'
    return {'score': score, 'band': band}

def main():
    ap = argparse.ArgumentParser(description='V10 runtime, sensor, kernel, and Kubernetes audit-policy context ingestion for ATT&CK coverage gates.')
    ap.add_argument('--runtime-inventory')
    ap.add_argument('--sensor-health')
    ap.add_argument('--kernel-context')
    ap.add_argument('--k8s-audit-policy')
    ap.add_argument('--network-device-inventory')
    ap.add_argument('--scenario', default='')
    ap.add_argument('--platform', default='Linux,Containers,Network Devices')
    ap.add_argument('--output-json', required=True)
    ap.add_argument('--output-md', required=True)
    args = ap.parse_args()

    runtime = load_json(args.runtime_inventory, {})
    sensor = load_json(args.sensor_health, {})
    kernel = load_json(args.kernel_context, {})
    k8s = load_json(args.k8s_audit_policy, {})
    network_device = load_json(args.network_device_inventory, {})
    missing_inputs = []
    if not runtime: missing_inputs.append('runtime_inventory')
    if not sensor: missing_inputs.append('sensor_health')
    if not kernel: missing_inputs.append('kernel_context')
    scenario_l = str(args.scenario or '').lower()
    k8s_required = 'kubernetes' in scenario_l or 'k8s' in scenario_l or 'kubernetes' in args.platform or 'k8s' in json.dumps(runtime).lower() or boolish(runtime.get('kubernetes'))
    if k8s_required:
        if not k8s: missing_inputs.append('k8s_audit_policy')
    network_device_required = scenario_l.startswith("network_") or boolish(runtime.get("network_devices")) or boolish(network_device.get("network_devices"))
    if network_device_required:
        if not network_device: missing_inputs.append('network_device_inventory')

    detected_runtimes = []
    for k in DEFAULT_RUNTIME_KEYS:
        aliases = [k, k.replace('-','_'), k.replace('-','')]
        if any(boolish(runtime.get(a)) for a in aliases):
            detected_runtimes.append(k)
    # Accept list-style inventory too
    for key in ['runtimes','container_runtimes','runtime_classes']:
        vals = runtime.get(key)
        if isinstance(vals, list):
            for v in vals:
                vv=str(v).lower()
                if vv not in detected_runtimes: detected_runtimes.append(vv)

    drop_rate = floatish(sensor.get('drop_rate', sensor.get('event_drop_rate', 0.0)))
    lost_events = floatish(sensor.get('lost_events', 0.0))
    ring_overflow = boolish(sensor.get('ring_buffer_overflow')) or boolish(sensor.get('perf_buffer_overflow'))
    audit_backlog = boolish(sensor.get('audit_backlog')) or floatish(sensor.get('audit_backlog_events',0)) > 0
    sampling = boolish(sensor.get('sampling_enabled'))
    collector_restart = boolish(sensor.get('collector_restart'))
    k8s_request = boolish(k8s.get('requestObject')) or boolish(k8s.get('request_object')) or str(k8s.get('level','')).lower() in ['request','requestresponse']
    k8s_response = boolish(k8s.get('responseObject')) or boolish(k8s.get('response_object')) or str(k8s.get('level','')).lower() == 'requestresponse'
    capabilities={}
    for key in DEFAULT_CAPABILITY_KEYS:
        capabilities[key]=boolish(sensor.get(key)) or boolish(runtime.get(key))
    network_device_capabilities={}
    for key in NETWORK_DEVICE_CAPABILITY_KEYS:
        network_device_capabilities[key] = boolish(sensor.get(key)) or boolish(network_device.get(key))

    sensor_blockers=[]
    if drop_rate > 0.01: sensor_blockers.append('drop_rate_above_1_percent')
    if lost_events > 0: sensor_blockers.append('lost_events_present')
    if ring_overflow: sensor_blockers.append('ring_buffer_overflow')
    if audit_backlog: sensor_blockers.append('audit_backlog_or_rate_limit')
    if sampling: sensor_blockers.append('sampling_enabled')
    if collector_restart: sensor_blockers.append('collector_restart_observed')
    if 'kubernetes' in [x.lower() for x in detected_runtimes] or k8s_required:
        if not k8s_request: sensor_blockers.append('k8s_requestObject_missing_or_unknown')
        if not k8s_response: sensor_blockers.append('k8s_responseObject_missing_or_unknown')
        if not capabilities.get('k8s_audit_events') and not k8s:
            sensor_blockers.append('k8s_audit_event_capability_unknown')
    if not any(capabilities.values()) and sensor:
        sensor_blockers.append('collector_capability_map_missing')
    if network_device_required:
        if not network_device:
            sensor_blockers.append('network_device_inventory_missing')
        for required in ['network_device_syslog', 'network_device_aaa', 'network_device_config_change']:
            if not network_device_capabilities.get(required):
                sensor_blockers.append(f'{required}_unknown')
        if not (network_device_capabilities.get('netflow_or_ipfix') or network_device_capabilities.get('snmp_traps')):
            sensor_blockers.append('network_device_flow_or_snmp_capability_unknown')

    cgroup_version = str(runtime.get('cgroup_version') or kernel.get('cgroup_version') or 'unknown')
    kernel_version = str(kernel.get('kernel_version') or kernel.get('release') or 'unknown')
    runtime_context_confidence = 'high' if runtime and detected_runtimes else 'low'
    sensor_context_confidence = 'high' if sensor and not sensor_blockers else 'medium' if sensor else 'low'
    k8s_policy_confidence = 'high' if k8s and k8s_request else 'medium' if k8s else 'unknown'

    # Gate caps are intentionally conservative.
    coverage_caps=[]
    if not runtime: coverage_caps.append('runtime_inventory_missing:scenario_comprehensive_not_allowed')
    if not sensor: coverage_caps.append('sensor_health_missing:resilience_confidence_cap_medium')
    if sensor_blockers: coverage_caps.append('sensor_health_blockers_present:telemetry_FN_risk')
    if kernel_version == 'unknown': coverage_caps.append('kernel_version_unknown:kernel_or_ebpf_applicability_uncertain')
    if cgroup_version == 'unknown': coverage_caps.append('cgroup_version_unknown:cgroup_claims_uncertain')
    if not capabilities.get('process_events') and sensor:
        coverage_caps.append('process_event_capability_unknown:process_claims_need_field_chain_proof')
    if not capabilities.get('file_events') and sensor:
        coverage_caps.append('file_event_capability_unknown:file_claims_need_field_chain_proof')
    if not capabilities.get('network_events') and sensor:
        coverage_caps.append('network_event_capability_unknown:network_claims_need_field_chain_proof')
    if network_device_required:
        if not network_device:
            coverage_caps.append('network_device_inventory_missing:network_device_claims_not_comprehensive')
        if sensor_blockers and any(str(x).startswith('network_device_') for x in sensor_blockers):
            coverage_caps.append('network_device_sensor_context_incomplete:device_claims_need_syslog_aaa_config_flow_or_snmp_proof')
    cap_explanations = [
        {
            'cap': cap,
            'cap_key': cap_key(cap),
            'explanation': cap_explanation(cap),
            'close_requirement': 'supply inventory, health, field-chain, or fixture evidence before upgrading the claim',
        }
        for cap in coverage_caps
    ]
    score = context_score(missing_inputs, sensor_blockers, coverage_caps)

    summary = {
        'coverage_model_version':'V10.5-wave4',
        'platform_scope': args.platform,
        'detected_runtimes': sorted(set(detected_runtimes)),
        'kernel_version': kernel_version,
        'cgroup_version': cgroup_version,
        'runtime_context_confidence': runtime_context_confidence,
        'sensor_context_confidence': sensor_context_confidence,
        'k8s_policy_confidence': k8s_policy_confidence,
        'network_device_context_required': network_device_required,
        'collector_capabilities': capabilities,
        'network_device_capabilities': network_device_capabilities,
        'missing_context_inputs': missing_inputs,
        'sensor_blockers': sorted(set(sensor_blockers)),
        'coverage_caps': coverage_caps,
        'coverage_cap_explanations': cap_explanations,
        'context_score': score,
        'theoretical_only': bool(missing_inputs),
        'runtime_inventory': runtime,
        'sensor_health': sensor,
        'kernel_context': kernel,
        'k8s_audit_policy': k8s,
        'network_device_inventory': network_device,
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    Path(args.output_json).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    md = [
        '# V10 Runtime / Sensor Context Review', '',
        f"- detected_runtimes: `{', '.join(summary['detected_runtimes']) or 'unknown'}`",
        f"- kernel_version: `{kernel_version}`",
        f"- cgroup_version: `{cgroup_version}`",
        f"- runtime_context_confidence: `{runtime_context_confidence}`",
        f"- sensor_context_confidence: `{sensor_context_confidence}`",
        f"- k8s_policy_confidence: `{k8s_policy_confidence}`",
        f"- context_score: `{score['score']}`",
        f"- context_score_band: `{score['band']}`",
        '', '## Coverage Caps',
    ]
    if coverage_caps:
        md += [f'- `{x}`' for x in coverage_caps]
    else:
        md.append('- None')
    md += ['', '## Sensor Blockers']
    md += [f'- `{x}`' for x in sensor_blockers] if sensor_blockers else ['- None']
    md += ['', '## Cap Explanations']
    if cap_explanations:
        md += [f"- `{x['cap']}`: {x['explanation']}" for x in cap_explanations]
    else:
        md.append('- None')
    Path(args.output_md).write_text('\n'.join(md)+'\n', encoding='utf-8')
if __name__ == '__main__': main()
