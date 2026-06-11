#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, subprocess, sys, time
from pathlib import Path
from audit_dag import write_dag
from common import now_id

DEFAULT_PLATFORM_SCOPE = 'Linux,Containers,Network Devices'
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[1] / 'attack_data' / 'config' / 'default_audit_config.json'


def load_config(path: str | Path | None = None):
    p = Path(path) if path else DEFAULT_CONFIG_PATH
    try:
        return json.load(open(p, encoding='utf-8'))
    except Exception:
        return {}


def run(cmd, cwd=None, timeout_seconds=120):
    # Keep phase execution cross-platform: Unix `timeout 120s` breaks on Windows.
    full = [sys.executable] + [str(x) for x in cmd]
    try:
        p = subprocess.run(full, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_seconds)
        return {
            'cmd': ' '.join(full),
            'returncode': p.returncode,
            'stdout': (p.stdout or '').strip(),
            'stderr': (p.stderr or '').strip(),
        }
    except subprocess.TimeoutExpired as e:
        return {
            'cmd': ' '.join(full),
            'returncode': 124,
            'stdout': (e.stdout or '').strip() if isinstance(e.stdout, str) else '',
            'stderr': f'phase_timeout_after_{timeout_seconds}s',
        }


def write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text, encoding='utf-8')


def append(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as f: f.write(text)


def load_json(path: Path, default=None):
    try: return json.load(open(path, encoding='utf-8'))
    except Exception: return default


def first_present(*values):
    for value in values:
        if value is not None:
            return value
    return None


def active_scope_file(index: str | Path, platform: str) -> Path:
    platform_l = str(platform or '').lower()
    index_path = Path(index)
    if 'network devices' in platform_l:
        return index_path / 'linux_container_network_scope.jsonl'
    return index_path / 'linux_container_scope.jsonl'


def main():
    pre=argparse.ArgumentParser(add_help=False)
    pre.add_argument('--config', default=str(DEFAULT_CONFIG_PATH))
    pre_args, _ = pre.parse_known_args()
    cfg = load_config(pre_args.config)
    scope_cfg = cfg.get('scope') or {}
    audit_cfg = cfg.get('audit') or {}
    default_platform = scope_cfg.get('platform') or DEFAULT_PLATFORM_SCOPE
    default_index = scope_cfg.get('attack_index') or 'attack_data/index'
    default_output_root = audit_cfg.get('output_root') or '.audit_runs'
    phase_timeout = int(audit_cfg.get('phase_timeout_seconds') or 120)

    ap=argparse.ArgumentParser(description='Orchestrate an ATT&CK coverage truth, cut-set, runtime/sensor, remediation, and blocker-first audit run.', parents=[pre])
    ap.add_argument('--input', required=True)
    ap.add_argument('--input-b')
    ap.add_argument('--mode', choices=['single_file','folder','compare_two'], default='folder')
    ap.add_argument('--platform', default=default_platform)
    ap.add_argument('--index', default=default_index)
    ap.add_argument('--scenario')
    ap.add_argument('--fixtures', help='Optional directory/file containing safe positive/negative/bypass/field-chain fixtures')
    ap.add_argument('--runtime-inventory', help='Optional JSON describing Docker/containerd/CRI-O/runc/Kata/gVisor/Kubernetes runtime inventory')
    ap.add_argument('--sensor-health', help='Optional JSON describing lost events, drop rate, audit backlog, sampling, collector restarts')
    ap.add_argument('--kernel-context', help='Optional JSON describing kernel version, cgroup version, BTF/CO-RE hints')
    ap.add_argument('--k8s-audit-policy', help='Optional JSON describing Kubernetes audit policy level/requestObject/responseObject fidelity')
    ap.add_argument('--network-device-inventory', help='Optional JSON describing Network Device syslog/AAA/config/NetFlow/SNMP/firmware telemetry context')
    ap.add_argument('--run-id')
    ap.add_argument('--output-root', default=default_output_root)
    ap.add_argument('--apply-retention', action='store_true', help='Archive older default audit runs according to audit config after this run')
    ap.add_argument('--resume', action='store_true')
    args=ap.parse_args()
    script_dir=Path(__file__).resolve().parent
    root=script_dir.parent
    scope_file=active_scope_file(args.index, args.platform)
    alias_pack=root/'attack_data'/'field_aliases'/'common_linux_container_k8s_network.json'
    if not alias_pack.exists():
        alias_pack=root/'attack_data'/'field_aliases'/'common_linux_container_k8s.json'
    run_id=args.run_id or now_id('audit')
    rd=Path(args.output_root)/run_id
    rd.mkdir(parents=True, exist_ok=True)
    state={'run_id':run_id,'mode':args.mode,'status':'running','input':args.input,'input_b':args.input_b,'platform':args.platform,'scenario':args.scenario,'config':str(pre_args.config),'phase_timeout_seconds':phase_timeout,'phases':{},'coverage_model_version':'V10.5-wave4','created_at':time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    write(rd/'state.json', json.dumps(state, ensure_ascii=False, indent=2))
    write_dag(rd/'audit_phase_dag.json')
    write(rd/'00_scope_and_assumptions.md', f"# Scope and Assumptions\n\n- mode: `{args.mode}`\n- input: `{args.input}`\n- input_b: `{args.input_b or 'N/A'}`\n- platform: `{args.platform}`\n- scenario override: `{args.scenario or 'auto'}`\n- index: `{args.index}`\n- scope_file: `{scope_file}`\n\nThis audit is limited to Linux, Containers, Kubernetes scenarios, and Network Devices. It does not claim full Enterprise ATT&CK coverage. Bypass findings are defensive resilience proof gaps only: missing telemetry, brittle predicates, field-chain loss, unchecked variants, missing fixtures, or runtime/sensor blockers. Validated coverage still requires evidence from the user's rules, parser/normalizer chain, fixtures, runtime context, and telemetry health.\n\n")
    def phase(name, cmd):
        res=run(cmd, cwd=root, timeout_seconds=phase_timeout)
        state['phases'][name]=res
        write(rd/'state.json', json.dumps(state, ensure_ascii=False, indent=2))
        append(rd/'run.log', json.dumps({name:res}, ensure_ascii=False)+'\n')
        if res['returncode']!=0:
            append(rd/'review_queue.md', f"\n## Phase failure: {name}\n\n```text\n{res['stderr']}\n```\n")
        return res

    phase('inventory', [str(script_dir/'inventory_scan.py'), args.input, '--output', str(rd/'input_manifest.jsonl')])
    phase('evidence', [str(script_dir/'extract_evidence.py'), args.input, '--output', str(rd/'evidence.jsonl')])
    phase('parse_rules', [str(script_dir/'parse_rules.py'), args.input, '--output', str(rd/'parsed_rules.jsonl')])
    phase('condition_ast', [str(script_dir/'condition_ast_parser.py'), '--parsed-rules', str(rd/'parsed_rules.jsonl'), '--output-jsonl', str(rd/'condition_ast.jsonl'), '--output-summary', str(rd/'condition_ast_summary.json')])
    phase('condition_ast_enrichment_v8_1', [str(script_dir/'condition_ast_enricher.py'), '--condition-ast', str(rd/'condition_ast.jsonl'), '--output-jsonl', str(rd/'condition_ast_enriched.jsonl'), '--output-summary', str(rd/'condition_ast_enriched_summary.json')])
    phase('scope_lock', [
        str(script_dir/'build_scope_lock.py'), '--scope', str(scope_file),
        '--lookup', str(Path(args.index)/'lookup_by_id.json'),
        '--metadata', str(Path(args.index)/'metadata.json'),
        '--scenario-model', str(root/'attack_data'/'models'/'scenario_attack_model.json'),
        '--output-json', str(rd/'scope_lock.json'),
        '--output-md', str(rd/'scope_lock.md')
    ])
    phase('data_component_alias', [str(script_dir/'data_component_alias.py'), '--parsed-rules', str(rd/'parsed_rules.jsonl'), '--alias-pack', str(alias_pack), '--output-jsonl', str(rd/'data_component_alias_findings.jsonl'), '--output-summary', str(rd/'data_component_alias_summary.json')])
    phase('infer_intent', [str(script_dir/'infer_intent.py'), args.input, '--output', str(rd/'intent_hints.jsonl')])
    phase('scenario_model_lint', [str(script_dir/'scenario_model_lint.py'), '--scenario-model', str(root/'attack_data'/'models'/'scenario_attack_model.json'), '--index', args.index, '--platform', args.platform, '--output-jsonl', str(rd/'scenario_model_lint.jsonl'), '--output-summary', str(rd/'scenario_model_lint_summary.json')])
    phase('scenario_attack_id_health', [str(script_dir/'scenario_attack_id_health.py'), '--scenario-model', str(root/'attack_data'/'models'/'scenario_attack_model.json'), '--index', args.index, '--platform', args.platform, '--output-jsonl', str(rd/'scenario_attack_id_health.jsonl'), '--output-summary', str(rd/'scenario_attack_id_health_summary.json')])
    phase('model_depth_gap_backlog_v10_5', [
        str(script_dir/'build_depth_gap_backlog.py'),
        '--scope', str(scope_file),
        '--lookup', str(Path(args.index)/'lookup_by_id.json'),
        '--scenario-model', str(root/'attack_data'/'models'/'scenario_attack_model.json'),
        '--output-dir', str(rd/'model_depth_gap')
    ])
    fl=phase('format_lint', [str(script_dir/'format_lint.py'), args.input, '--json'])
    write(rd/'format_lint.jsonl', (fl['stdout']+'\n') if fl['stdout'] else '')
    tv=phase('tag_validation', [str(script_dir/'validate_declared_tags.py'), args.input, '--index', args.index, '--expand-subtechs', '--json'])
    write(rd/'tag_validation.jsonl', (tv['stdout']+'\n') if tv['stdout'] else '')
    fc=phase('field_chain', [str(script_dir/'field_chain_analyzer.py'), args.input, '--json'])
    write(rd/'field_chain.jsonl', (fc['stdout']+'\n') if fc['stdout'] else '')
    phase('coverage', [
        str(script_dir/'compute_coverage.py'), '--index', args.index,
        '--parsed-rules', str(rd/'parsed_rules.jsonl'),
        '--intent-hints', str(rd/'intent_hints.jsonl'),
        '--evidence', str(rd/'evidence.jsonl'),
        '--field-chain', str(rd/'field_chain.jsonl'),
        '--platform', args.platform,
        '--output', str(rd/'coverage.jsonl'),
        '--denominator-output', str(rd/'attack_denominator.jsonl'),
        '--negative-denominator-output', str(rd/'negative_denominator.jsonl'),
        '--optional-denominator-output', str(rd/'optional_denominator_candidates.jsonl'),
        '--denominator-markdown-output', str(rd/'denominator_explainer.md'),
        '--summary-output', str(rd/'coverage_summary.json'),
        '--strategy-output', str(rd/'strategy_alignment.jsonl'),
        '--data-component-output', str(rd/'data_component_coverage.jsonl'),
        '--claim-output', str(rd/'complete_coverage_assessment.json'),
        '--claim-markdown-output', str(rd/'complete_coverage_assessment.md')
    ] + (['--scenario', args.scenario] if args.scenario else []))
    phase('fixture_ingest', [str(script_dir/'fixture_ingest.py'), '--fixtures', args.fixtures or '', '--coverage', str(rd/'coverage.jsonl'), '--output-inventory', str(rd/'fixture_inventory.jsonl'), '--output-coverage', str(rd/'fixture_coverage.jsonl'), '--output-summary', str(rd/'fixture_summary.json')]) if args.fixtures else (write(rd/'fixture_inventory.jsonl',''), write(rd/'fixture_coverage.jsonl',''), write(rd/'fixture_summary.json', json.dumps({'coverage_model_version':'V10.5-wave4','fixture_count':0,'note':'no fixtures supplied'}, ensure_ascii=False, indent=2)))
    phase('fixture_chain_validation_v8_1', [str(script_dir/'fixture_chain_validator.py'), '--fixture-inventory', str(rd/'fixture_inventory.jsonl'), '--fixture-coverage', str(rd/'fixture_coverage.jsonl'), '--coverage', str(rd/'coverage.jsonl'), '--output-jsonl', str(rd/'fixture_chain_validation.jsonl'), '--output-summary', str(rd/'fixture_chain_validation_summary.json')])
    summary=load_json(rd/'coverage_summary.json', {}) or {}
    scenario=args.scenario or summary.get('scenario') or 'unknown'
    phase('denominator_guard_v8', [
        str(script_dir/'denominator_guard.py'), '--denominator', str(rd/'attack_denominator.jsonl'),
        '--negative-denominator', str(rd/'negative_denominator.jsonl'),
        '--scenario-model', str(root/'attack_data'/'models'/'scenario_attack_model.json'),
        '--output-summary', str(rd/'denominator_guard.json'),
        '--output-md', str(rd/'denominator_review.md')
    ])
    phase('bypass_analysis_v8', [
        str(script_dir/'bypass_analyzer.py'), '--coverage', str(rd/'coverage.jsonl'),
        '--parsed-rules', str(rd/'parsed_rules.jsonl'), '--evidence', str(rd/'evidence.jsonl'), '--condition-ast', str(rd/'condition_ast_enriched.jsonl'),
        '--scenario-model', str(root/'attack_data'/'models'/'scenario_attack_model.json'), '--scenario', scenario,
        '--output', str(rd/'bypass_matrix.jsonl'), '--summary-output', str(rd/'bypass_summary.json')
    ])
    phase('behavior_primitive_matrix_v8', [
        str(script_dir/'behavior_primitive_matrix.py'), '--scenario-model', str(root/'attack_data'/'models'/'scenario_attack_model.json'),
        '--scenario', scenario, '--coverage', str(rd/'coverage.jsonl'), '--bypass-matrix', str(rd/'bypass_matrix.jsonl'),
        '--output-jsonl', str(rd/'behavior_primitive_matrix.jsonl'), '--output-summary', str(rd/'behavior_primitive_summary.json')
    ])
    phase('subtechnique_gap', [
        str(script_dir/'subtechnique_gap.py'), '--index', args.index,
        '--coverage', str(rd/'coverage.jsonl'), '--denominator', str(rd/'attack_denominator.jsonl'),
        '--platform', args.platform, '--output-jsonl', str(rd/'subtechnique_gaps.jsonl'), '--output-md', str(rd/'missing_subtechniques.md')
    ])
    phase('strategy_alignment', [
        str(script_dir/'attack_strategy_alignment.py'), '--index', args.index,
        '--coverage', str(rd/'coverage.jsonl'), '--denominator', str(rd/'attack_denominator.jsonl'),
        '--output-jsonl', str(rd/'attack_strategy_alignment.jsonl'), '--output-summary', str(rd/'attack_strategy_alignment_summary.json')
    ])
    phase('test_gap_analysis_v8', [
        str(script_dir/'test_gap_analyzer.py'), '--coverage', str(rd/'coverage.jsonl'),
        '--behavior-primitives', str(rd/'behavior_primitive_matrix.jsonl'), '--bypass-matrix', str(rd/'bypass_matrix.jsonl'),
        '--scenario-model', str(root/'attack_data'/'models'/'scenario_attack_model.json'), '--scenario', scenario,
        '--output-jsonl', str(rd/'test_gap_analysis.jsonl'), '--output-summary', str(rd/'test_gap_summary.json')
    ])
    tvp=phase('test_vector_plan_v10_5', [str(script_dir/'test_vector_plan.py'), args.input, '--json'])
    write(rd/'test_vector_plan.jsonl', (tvp['stdout']+'\n') if tvp['stdout'] else '')
    # Keep V6 resilience gate for backward-compatible artifacts.
    phase('coverage_gate_v6_compat', [
        str(script_dir/'coverage_gate.py'), '--coverage', str(rd/'coverage.jsonl'), '--denominator', str(rd/'attack_denominator.jsonl'),
        '--bypass-matrix', str(rd/'bypass_matrix.jsonl'), '--output-claims', str(rd/'attack_coverage_claims.jsonl'),
        '--output-summary', str(rd/'resilient_coverage_summary.json'), '--output-blockers-md', str(rd/'attack_coverage_blockers.md'),
        '--output-falsifiability-md', str(rd/'coverage_falsifiability.md')
    ])
    phase('attack_path_matrix_v8', [
        str(script_dir/'attack_path_matrix.py'), '--scenario-model', str(root/'attack_data'/'models'/'scenario_attack_model.json'),
        '--scenario', scenario, '--coverage', str(rd/'coverage.jsonl'), '--bypass-matrix', str(rd/'bypass_matrix.jsonl'),
        '--behavior-matrix', str(rd/'behavior_primitive_matrix.jsonl'), '--output-jsonl', str(rd/'attack_path_matrix.jsonl'),
        '--output-summary', str(rd/'attack_path_summary.json')
    ])
    phase('bypass_fixture_binding_v8_1', [
        str(script_dir/'bypass_fixture_binder.py'), '--attack-paths', str(rd/'attack_path_matrix.jsonl'),
        '--fixture-coverage', str(rd/'fixture_coverage.jsonl'), '--output-jsonl', str(rd/'bypass_fixture_bindings.jsonl'),
        '--output-summary', str(rd/'bypass_fixture_binding_summary.json')
    ])
    phase('data_component_gate_v8', [
        str(script_dir/'data_component_gate.py'), '--coverage', str(rd/'coverage.jsonl'), '--parsed-rules', str(rd/'parsed_rules.jsonl'),
        '--behavior-matrix', str(rd/'behavior_primitive_matrix.jsonl'), '--alias-pack', str(alias_pack),
        '--data-component-coverage', str(rd/'data_component_coverage.jsonl'), '--output-jsonl', str(rd/'data_component_gate.jsonl'),
        '--output-summary', str(rd/'data_component_gate_summary.json')
    ])
    phase('denominator_diff_v8', [
        str(script_dir/'denominator_diff.py'), '--current', str(rd/'attack_denominator.jsonl'),
        '--output-json', str(rd/'scenario_denominator_diff.json'), '--output-md', str(rd/'scenario_denominator_diff.md')
    ])
    phase('coverage_truth_gate_v8_compat', [
        str(script_dir/'coverage_gate_v8.py'), '--coverage', str(rd/'coverage.jsonl'), '--denominator', str(rd/'attack_denominator.jsonl'),
        '--bypass-matrix', str(rd/'bypass_matrix.jsonl'), '--strategy-alignment', str(rd/'attack_strategy_alignment.jsonl'),
        '--test-gaps', str(rd/'test_gap_analysis.jsonl'), '--denominator-guard', str(rd/'denominator_guard.json'), '--fixture-coverage', str(rd/'fixture_coverage.jsonl'), '--alias-findings', str(rd/'data_component_alias_findings.jsonl'),
        '--output-claims', str(rd/'attack_coverage_truth.jsonl'), '--output-summary', str(rd/'attack_coverage_truth_summary.json'),
        '--output-report', str(rd/'coverage_truth_report.md')
    ])
    phase('attack_claim_falsification_v8', [
        str(script_dir/'attack_claim_falsifier.py'), '--coverage', str(rd/'coverage.jsonl'), '--denominator', str(rd/'attack_denominator.jsonl'),
        '--attack-paths', str(rd/'attack_path_matrix.jsonl'), '--data-component-gate', str(rd/'data_component_gate.jsonl'),
        '--condition-ast', str(rd/'condition_ast.jsonl'), '--fixture-coverage', str(rd/'fixture_coverage.jsonl'),
        '--strategy-alignment', str(rd/'attack_strategy_alignment.jsonl'), '--denominator-guard', str(rd/'denominator_guard.json'),
        '--output-claims', str(rd/'attack_claim_falsification.jsonl'), '--output-summary', str(rd/'attack_claim_falsification_summary.json'),
        '--output-md', str(rd/'attack_claim_falsification.md')
    ])
    phase('coverage_claim_upgrade_v8_1', [
        str(script_dir/'coverage_claim_upgrader.py'), '--claims', str(rd/'attack_claim_falsification.jsonl'),
        '--fixture-chain', str(rd/'fixture_chain_validation.jsonl'), '--bypass-fixture-bindings', str(rd/'bypass_fixture_bindings.jsonl'),
        '--data-component-gate', str(rd/'data_component_gate.jsonl'), '--output-claims', str(rd/'attack_claim_falsification_v8_1.jsonl'),
        '--output-summary', str(rd/'attack_claim_falsification_v8_1_summary.json'), '--output-md', str(rd/'attack_claim_falsification_v8_1.md')
    ])

    phase('denominator_proof_graph_v9', [
        str(script_dir/'denominator_proof_graph.py'), '--denominator', str(rd/'attack_denominator.jsonl'),
        '--negative-denominator', str(rd/'negative_denominator.jsonl'), '--scenario-model', str(root/'attack_data'/'models'/'scenario_attack_model.json'),
        '--scenario', scenario, '--alias-pack', str(alias_pack),
        '--attack-version', 'enterprise-attack-v19.1', '--output-jsonl', str(rd/'denominator_proof_graph.jsonl'),
        '--output-summary', str(rd/'denominator_proof_graph_summary.json'), '--output-lockfile', str(rd/'attack_denominator.lock.json'),
        '--output-md', str(rd/'denominator_proof_graph.md')
    ])
    phase('claim_failure_model_v9', [
        str(script_dir/'attack_claim_failure_model.py'), '--claims', str(rd/'attack_claim_falsification_v8_1.jsonl'),
        '--coverage', str(rd/'coverage.jsonl'), '--bypass-matrix', str(rd/'bypass_matrix.jsonl'),
        '--data-component-gate', str(rd/'data_component_gate.jsonl'), '--fixture-chain', str(rd/'fixture_chain_validation.jsonl'),
        '--output-jsonl', str(rd/'attack_claim_failure_model.jsonl'), '--output-summary', str(rd/'attack_claim_failure_model_summary.json'),
        '--output-md', str(rd/'attack_claim_failure_model.md')
    ])
    phase('bypass_cutset_analysis_v9', [
        str(script_dir/'bypass_cutset_analyzer.py'), '--bypass-matrix', str(rd/'bypass_matrix.jsonl'),
        '--claims', str(rd/'attack_claim_failure_model.jsonl'), '--output-jsonl', str(rd/'bypass_cutsets.jsonl'),
        '--output-summary', str(rd/'bypass_cutsets_summary.json'), '--output-md', str(rd/'bypass_cutsets.md')
    ])
    phase('data_component_minset_v9', [
        str(script_dir/'data_component_minset.py'), '--data-component-gate', str(rd/'data_component_gate.jsonl'),
        '--behavior-matrix', str(rd/'behavior_primitive_matrix.jsonl'), '--scenario-model', str(root/'attack_data'/'models'/'scenario_attack_model.json'),
        '--output-jsonl', str(rd/'data_component_minimum_sets.jsonl'), '--output-summary', str(rd/'data_component_minimum_sets_summary.json'),
        '--output-md', str(rd/'data_component_minimum_sets.md')
    ])
    phase('coverage_score_v9', [
        str(script_dir/'coverage_score_v9.py'), '--claim-failure', str(rd/'attack_claim_failure_model.jsonl'),
        '--denominator-proof-summary', str(rd/'denominator_proof_graph_summary.json'), '--bypass-cutset-summary', str(rd/'bypass_cutsets_summary.json'),
        '--data-component-minset-summary', str(rd/'data_component_minimum_sets_summary.json'), '--fixture-summary', str(rd/'fixture_chain_validation_summary.json'),
        '--output-json', str(rd/'coverage_truth_dashboard.json'), '--output-md', str(rd/'coverage_truth_dashboard.md')
    ])

    phase('runtime_sensor_context_v10', [
        str(script_dir/'runtime_sensor_context.py'), '--platform', args.platform,
        '--scenario', scenario,
        '--runtime-inventory', args.runtime_inventory or '', '--sensor-health', args.sensor_health or '',
        '--kernel-context', args.kernel_context or '', '--k8s-audit-policy', args.k8s_audit_policy or '',
        '--network-device-inventory', args.network_device_inventory or '',
        '--output-json', str(rd/'runtime_sensor_context.json'), '--output-md', str(rd/'runtime_sensor_context.md')
    ])
    phase('field_chain_proof_graph_v10', [
        str(script_dir/'field_chain_proof_graph.py'), '--field-chain', str(rd/'field_chain.jsonl'),
        '--data-component-gate', str(rd/'data_component_gate.jsonl'), '--condition-ast', str(rd/'condition_ast_enriched.jsonl'),
        '--alias-findings', str(rd/'data_component_alias_findings.jsonl'), '--output-json', str(rd/'field_chain_proof_graph_summary.json'),
        '--output-jsonl', str(rd/'field_chain_proof_graph.jsonl'), '--output-md', str(rd/'field_chain_proof_graph.md')
    ])
    phase('coverage_final_gate_v10', [
        str(script_dir/'coverage_final_gate_v10.py'), '--claim-failure', str(rd/'attack_claim_failure_model.jsonl'),
        '--denominator-proof-summary', str(rd/'denominator_proof_graph_summary.json'), '--field-chain-proof-summary', str(rd/'field_chain_proof_graph_summary.json'),
        '--data-component-minset-summary', str(rd/'data_component_minimum_sets_summary.json'), '--bypass-cutset-summary', str(rd/'bypass_cutsets_summary.json'),
        '--fixture-chain-summary', str(rd/'fixture_chain_validation_summary.json'), '--runtime-sensor-context', str(rd/'runtime_sensor_context.json'),
        '--coverage-score-v9', str(rd/'coverage_truth_dashboard.json'), '--model-depth-summary', str(rd/'model_depth_gap'/'depth_gap_summary.json'), '--output-claims-jsonl', str(rd/'v10_final_claims.jsonl'),
        '--output-dashboard-json', str(rd/'coverage_truth_dashboard_v10.json'), '--output-dashboard-md', str(rd/'coverage_truth_dashboard_v10.md'),
        '--output-blocker-report-md', str(rd/'v10_blocker_first_report.md')
    ])
    phase('remediation_advisor', [
        str(script_dir/'remediation_advisor.py'), '--final-claims', str(rd/'v10_final_claims.jsonl'),
        '--parsed-rules', str(rd/'parsed_rules.jsonl'), '--coverage', str(rd/'coverage.jsonl'),
        '--coverage-dashboard', str(rd/'coverage_truth_dashboard_v10.json'),
        '--data-component-gate', str(rd/'data_component_gate.jsonl'), '--field-chain-proof', str(rd/'field_chain_proof_graph_summary.json'),
        '--runtime-sensor-context', str(rd/'runtime_sensor_context.json'), '--output-jsonl', str(rd/'remediation_plan.jsonl'),
        '--output-md', str(rd/'remediation_plan.md'), '--include-code-patch-guidance'
    ])
    phase('patch_blueprint', [
        str(script_dir/'patch_blueprint.py'), '--remediation-plan', str(rd/'remediation_plan.jsonl'),
        '--output-jsonl', str(rd/'patch_blueprints.jsonl'), '--output-md', str(rd/'patch_blueprints.md')
    ])
    phase('field_preservation_tests', [
        str(script_dir/'field_preservation_test_generator.py'), '--remediation-plan', str(rd/'remediation_plan.jsonl'),
        '--output-jsonl', str(rd/'field_preservation_tests.jsonl'), '--output-md', str(rd/'field_preservation_tests.md')
    ])
    phase('minimal_fixture_suite', [
        str(script_dir/'minimal_fixture_suite.py'), '--scenario-model', str(root/'attack_data'/'models'/'scenario_attack_model.json'),
        '--scenario', scenario, '--output-jsonl', str(rd/'minimal_fixture_suite.jsonl'), '--output-md', str(rd/'minimal_fixture_suite.md')
    ])
    base=load_json(rd/'coverage_summary.json', {}) or {}
    truth=load_json(rd/'coverage_truth_dashboard_v10.json', {}) or load_json(rd/'coverage_truth_dashboard.json', {}) or load_json(rd/'attack_claim_failure_model_summary.json', {}) or load_json(rd/'attack_claim_falsification_v8_1_summary.json', {}) or load_json(rd/'attack_claim_falsification_summary.json', {}) or load_json(rd/'attack_coverage_truth_summary.json', {}) or {}
    bypass=load_json(rd/'bypass_summary.json', {}) or {}
    primitive=load_json(rd/'behavior_primitive_summary.json', {}) or {}
    denom=load_json(rd/'denominator_guard.json', {}) or {}
    strategy=load_json(rd/'attack_strategy_alignment_summary.json', {}) or {}
    depth=load_json(rd/'model_depth_gap'/'depth_gap_summary.json', {}) or {}
    report=f"""# Final Audit Report - Blocker-first ATT&CK Coverage Truth

## 0. Executive Summary

- run_id: `{run_id}`
- mode: `{args.mode}`
- platform_scope: `{args.platform}`
- scope_file: `{scope_file}`
- scenario: `{base.get('scenario','unknown')}`
- denominator_count: `{base.get('denominator_count')}`
- denominator_hash: `{denom.get('denominator_hash')}`
- denominator_confidence: `{denom.get('denominator_confidence')}`
- effective_attack_coverage: `{first_present(truth.get('effective_attack_coverage'), truth.get('effective_attack_coverage_rate'))}`
- resilience_validated_coverage: `{first_present(truth.get('resilience_validated_coverage'), truth.get('resilience_validated_rate'))}`
- critical_resilience_rate: `{truth.get('critical_resilience_rate')}`
- critical_bypass_cutset_count: `{first_present(truth.get('critical_bypass_cutset_count'), truth.get('critical_bypass_gap_count'))}`
- field_chain_proof_rate: `{truth.get('field_chain_proof_rate')}`
- data_component_minimum_set_rate: `{truth.get('data_component_minimum_set_rate')}`
- fixture_proof_rate: `{truth.get('fixture_proof_rate')}`
- resilient_score_v10: `{truth.get('resilient_score_v10')}`
- behavior_primitive_resilience_rate: `{primitive.get('resilience_validated_behavior_primitive_rate')}`
- detection_strategy_coverage_rate: `{strategy.get('strategy_coverage_rate')}`
- model_l4_deep_model_count: `{depth.get('l4_deep_model_count')}`
- model_non_l4_depth_gap_count: `{depth.get('non_l4_depth_gap_count')}`
- model_bypass_proof_gap_count: `{depth.get('bypass_proof_gap_count')}`
- model_bypass_enrichment_gap_count: `{depth.get('bypass_enrichment_gap_count')}`
- model_fixture_template_gap_count: `{depth.get('fixture_template_gap_count')}`
- model_depth_resilient_model_count: `{depth.get('depth_resilient_model_count')}`
- model_depth_gate_passed: `{depth.get('depth_gate_passed')}`
- complete_coverage_claim: `{truth.get('complete_coverage_claim')}`

## 1. Coverage Truth Interpretation

Raw ATT&CK tag coverage is audit metadata, not detection capability. Effective coverage requires scenario denominator proof, behavior primitive binding, condition AST evidence, Data Component minimum-set satisfaction, and a field-chain proof graph. Resilience coverage additionally requires runtime/sensor context, bypass cut-set closure, fixture proof bound to attack paths, and a passing model-depth gate; positive fixtures alone do not prove resilience.

## 2. Required Review Files

- `denominator_review.md`
- `scope_lock.json`
- `scope_lock.md`
- `optional_denominator_candidates.jsonl`
- `coverage_truth_report.md`
- `condition_ast.jsonl`
- `condition_ast_enriched.jsonl`
- `data_component_alias_findings.jsonl`
- `fixture_coverage.jsonl`
- `fixture_chain_validation.jsonl`
- `bypass_fixture_bindings.jsonl`
- `behavior_primitive_matrix.jsonl`
- `bypass_matrix.jsonl`
- `test_gap_analysis.jsonl`
- `test_vector_plan.jsonl`
- `attack_coverage_truth.jsonl`
- `attack_path_matrix.jsonl`
- `data_component_gate.jsonl`
- `attack_claim_falsification.jsonl`
- `attack_claim_falsification_v8_1.jsonl`
- `denominator_proof_graph.jsonl`
- `attack_denominator.lock.json`
- `attack_claim_failure_model.jsonl`
- `bypass_cutsets.jsonl`
- `data_component_minimum_sets.jsonl`
- `coverage_truth_dashboard.json`
- `runtime_sensor_context.json`
- `field_chain_proof_graph.jsonl`
- `field_chain_proof_graph_summary.json`
- `coverage_truth_dashboard_v10.json`
- `v10_final_claims.jsonl`
- `v10_blocker_first_report.md`
- `remediation_plan.jsonl`
- `remediation_plan.md`
- `patch_blueprints.jsonl`
- `patch_blueprints.md`
- `field_preservation_tests.jsonl`
- `field_preservation_tests.md`
- `minimal_fixture_suite.jsonl`
- `minimal_fixture_suite.md`
- `attack_coverage_blockers.md`
- `coverage_falsifiability.md`

## 3. Generated Artifacts

```json
{json.dumps(sorted([p.name for p in rd.iterdir() if p.is_file()]), ensure_ascii=False, indent=2)}
```
"""
    write(rd/'12_final_report.md', report)
    vr=run([str(script_dir/'validate_report.py'), str(rd)], cwd=root)
    state['validation']=vr
    failed_phases=[name for name,res in state.get('phases', {}).items() if res.get('returncode') != 0]
    state['status']='completed' if not failed_phases and vr.get('returncode') == 0 else 'failed'
    if failed_phases:
        state['failed_phases']=failed_phases
    if args.apply_retention:
        retention_root = audit_cfg.get('retention_archive_root') or 'laji/audit_runs'
        keep_latest = str(audit_cfg.get('retention_keep_latest') or 10)
        state['retention'] = run([
            str(script_dir/'retention_manager.py'), '--output-root', args.output_root,
            '--archive-root', retention_root, '--keep-latest', keep_latest
        ], cwd=root, timeout_seconds=phase_timeout)
    write(rd/'state.json', json.dumps(state, ensure_ascii=False, indent=2))
    print(json.dumps({'run_dir':str(rd),'validation':vr}, ensure_ascii=False, indent=2))
if __name__=='__main__': main()
