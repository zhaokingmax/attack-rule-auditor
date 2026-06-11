#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path

REQUIRED = [
    'state.json', 'input_manifest.jsonl', 'evidence.jsonl', 'parsed_rules.jsonl', 'condition_ast.jsonl', 'condition_ast_summary.json', 'condition_ast_enriched.jsonl', 'condition_ast_enriched_summary.json',
    'data_component_alias_findings.jsonl', 'data_component_alias_summary.json',
    'scenario_model_lint.jsonl', 'scenario_model_lint_summary.json',
    'scenario_attack_id_health.jsonl', 'scenario_attack_id_health_summary.json',
    'scope_lock.json', 'scope_lock.md',
    'intent_hints.jsonl', 'attack_denominator.jsonl', 'coverage.jsonl',
    'coverage_summary.json', 'bypass_matrix.jsonl', 'bypass_summary.json',
    'denominator_guard.json', 'denominator_review.md',
    'behavior_primitive_matrix.jsonl', 'behavior_primitive_summary.json',
    'fixture_summary.json', 'fixture_chain_validation.jsonl', 'fixture_chain_validation_summary.json', 'bypass_fixture_bindings.jsonl', 'bypass_fixture_binding_summary.json',
    'test_gap_analysis.jsonl', 'test_gap_summary.json', 'test_vector_plan.jsonl',
    'attack_coverage_truth.jsonl', 'attack_coverage_truth_summary.json',
    'coverage_truth_report.md', 'attack_path_matrix.jsonl', 'attack_path_summary.json', 'data_component_gate.jsonl', 'data_component_gate_summary.json', 'attack_claim_falsification.jsonl', 'attack_claim_falsification_summary.json', 'attack_claim_falsification.md', 'attack_claim_falsification_v8_1.jsonl', 'attack_claim_falsification_v8_1_summary.json', 'attack_claim_falsification_v8_1.md',
    'denominator_proof_graph.jsonl', 'denominator_proof_graph_summary.json', 'denominator_proof_graph.md', 'attack_denominator.lock.json',
    'attack_claim_failure_model.jsonl', 'attack_claim_failure_model_summary.json', 'attack_claim_failure_model.md',
    'bypass_cutsets.jsonl', 'bypass_cutsets_summary.json', 'bypass_cutsets.md',
    'data_component_minimum_sets.jsonl', 'data_component_minimum_sets_summary.json', 'data_component_minimum_sets.md',
    'coverage_truth_dashboard.json', 'coverage_truth_dashboard.md', 'runtime_sensor_context.json', 'runtime_sensor_context.md', 'field_chain_proof_graph.jsonl', 'field_chain_proof_graph_summary.json', 'field_chain_proof_graph.md', 'v10_final_claims.jsonl', 'coverage_truth_dashboard_v10.json', 'coverage_truth_dashboard_v10.md', 'v10_blocker_first_report.md', 'remediation_plan.jsonl', 'remediation_plan.md', '12_final_report.md'
]
MAY_BE_EMPTY_REQUIRED = {
    # Empty is valid when the user did not provide fixture inputs; summaries carry the explicit zero counts.
    'fixture_chain_validation.jsonl',
    'bypass_fixture_bindings.jsonl',
    'remediation_plan.jsonl',
}
RECOMMENDED = [
    'negative_denominator.jsonl', 'optional_denominator_candidates.jsonl', 'denominator_explainer.md', 'strategy_alignment.jsonl',
    'data_component_coverage.jsonl', 'field_chain.jsonl', 'tag_validation.jsonl',
    'subtechnique_gaps.jsonl', 'missing_subtechniques.md',
    'attack_strategy_alignment.jsonl', 'attack_strategy_alignment_summary.json',
    'attack_coverage_claims.jsonl', 'resilient_coverage_summary.json',
    'attack_coverage_blockers.md', 'coverage_falsifiability.md', 'fixture_inventory.jsonl', 'fixture_coverage.jsonl'
]

def load_json(p: Path):
    try: return json.load(open(p, encoding='utf-8'))
    except Exception as e: return {'_error': str(e)}

def load_jsonl(p: Path):
    rows=[]
    try:
        for line in p.read_text(encoding='utf-8', errors='ignore').splitlines():
            if line.strip():
                rows.append(json.loads(line))
    except Exception as e:
        return [{'_error': str(e)}]
    return rows

def validate_with_schema(rd: Path):
    warnings=[]; failures=[]
    try:
        import jsonschema  # type: ignore
    except Exception as e:
        return failures, [f'jsonschema_unavailable:{e}']
    schema_dir=Path(__file__).resolve().parents[1]/'schemas'
    checks=[
        ('jsonl','coverage.jsonl','coverage.schema.json'),
        ('jsonl','attack_denominator.jsonl','denominator.schema.json'),
        ('jsonl','bypass_matrix.jsonl','bypass_matrix.schema.json'),
        ('json','complete_coverage_assessment.json','complete_coverage_assessment.schema.json'),
    ]
    for kind, artifact, schema_name in checks:
        p=rd/artifact; sp=schema_dir/schema_name
        if not p.exists() or not sp.exists():
            warnings.append(f'schema_check_skipped_missing:{artifact}:{schema_name}')
            continue
        schema=load_json(sp)
        if schema.get('_error'):
            failures.append(f'invalid_schema:{schema_name}:{schema.get("_error")}')
            continue
        instances=load_jsonl(p) if kind == 'jsonl' else [load_json(p)]
        for i, instance in enumerate(instances[:5000]):
            if isinstance(instance, dict) and instance.get('_error'):
                failures.append(f'invalid_json:{artifact}:{instance.get("_error")}')
                break
            try:
                jsonschema.validate(instance=instance, schema=schema)
            except jsonschema.ValidationError as e:
                failures.append(f'schema_validation_failed:{artifact}:row_{i}:{e.message}')
                break
    return failures, warnings

def main():
    ap=argparse.ArgumentParser(description='Validate V10.0 blocker-first ATT&CK coverage-truth report completeness.')
    ap.add_argument('run_dir')
    args=ap.parse_args()
    rd=Path(args.run_dir)
    failures=[]; warnings=[]
    for name in REQUIRED:
        p=rd/name
        if not p.exists(): failures.append(f'missing_required:{name}')
        elif p.stat().st_size == 0 and name not in MAY_BE_EMPTY_REQUIRED: failures.append(f'empty_required:{name}')
    for name in RECOMMENDED:
        p=rd/name
        if not p.exists(): warnings.append(f'missing_recommended:{name}')
        elif p.stat().st_size == 0: warnings.append(f'empty_recommended:{name}')
    truth=load_json(rd/'coverage_truth_dashboard_v10.json')
    if truth.get('_error'): failures.append(f'invalid_attack_claim_falsification_summary:{truth.get("_error")}')
    elif truth.get('coverage_model_version') not in ['V8','V8.0','V8.1','V9.0','V10.0','V10.2','V10.3','V10.4-wave3','V10.5-wave4']: warnings.append('claim_falsification_model_version_not_V8_to_V10_family')
    denom=load_json(rd/'denominator_guard.json')
    if denom.get('_error'): failures.append(f'invalid_denominator_guard:{denom.get("_error")}')
    if 'resilience_validated_coverage' not in truth and 'resilience_validated_rate' not in truth: failures.append('truth_summary_missing_resilience_validated_coverage')
    if 'critical_bypass_cutset_count' not in truth and 'critical_bypass_gap_count' not in truth: failures.append('truth_summary_missing_critical_bypass_cutset_count')
    schema_failures, schema_warnings = validate_with_schema(rd)
    failures.extend(schema_failures)
    warnings.extend(schema_warnings)
    status='pass' if not failures else 'fail'
    print(json.dumps({'status':status,'coverage_model_expected':'V10.5-wave4','failures':failures,'warnings':warnings}, ensure_ascii=False, indent=2))
    raise SystemExit(0 if status=='pass' else 1)
if __name__=='__main__': main()
