#!/usr/bin/env python3
from __future__ import annotations
"""Declarative audit phase graph for the runtime orchestrator."""

import json
import argparse
from pathlib import Path
from typing import Any

PHASE_DAG: list[dict[str, Any]] = [
    {"name": "inventory", "script": "inventory_scan.py", "depends_on": []},
    {"name": "evidence", "script": "extract_evidence.py", "depends_on": ["inventory"]},
    {"name": "parse_rules", "script": "parse_rules.py", "depends_on": ["inventory"]},
    {"name": "condition_ast", "script": "condition_ast_parser.py", "depends_on": ["parse_rules"]},
    {"name": "condition_ast_enrichment", "script": "condition_ast_enricher.py", "depends_on": ["condition_ast"]},
    {"name": "scope_lock", "script": "build_scope_lock.py", "depends_on": []},
    {"name": "data_component_alias", "script": "data_component_alias.py", "depends_on": ["parse_rules"]},
    {"name": "infer_intent", "script": "infer_intent.py", "depends_on": ["evidence"]},
    {"name": "scenario_model_lint", "script": "scenario_model_lint.py", "depends_on": ["scope_lock"]},
    {"name": "scenario_attack_id_health", "script": "scenario_attack_id_health.py", "depends_on": ["scope_lock"]},
    {"name": "model_depth_gap_backlog", "script": "build_depth_gap_backlog.py", "depends_on": ["scope_lock"]},
    {"name": "format_lint", "script": "format_lint.py", "depends_on": ["inventory"]},
    {"name": "tag_validation", "script": "validate_declared_tags.py", "depends_on": ["parse_rules"]},
    {"name": "field_chain", "script": "field_chain_analyzer.py", "depends_on": ["inventory"]},
    {"name": "coverage", "script": "compute_coverage.py", "depends_on": ["parse_rules", "infer_intent", "evidence", "field_chain"]},
    {"name": "fixture_ingest", "script": "fixture_ingest.py", "depends_on": ["coverage"]},
    {"name": "fixture_chain_validation", "script": "fixture_chain_validator.py", "depends_on": ["fixture_ingest", "coverage"]},
    {"name": "denominator_guard", "script": "denominator_guard.py", "depends_on": ["coverage"]},
    {"name": "bypass_analysis", "script": "bypass_analyzer.py", "depends_on": ["coverage", "condition_ast_enrichment"]},
    {"name": "behavior_primitive_matrix", "script": "behavior_primitive_matrix.py", "depends_on": ["coverage", "bypass_analysis"]},
    {"name": "subtechnique_gap", "script": "subtechnique_gap.py", "depends_on": ["coverage"]},
    {"name": "strategy_alignment", "script": "attack_strategy_alignment.py", "depends_on": ["coverage"]},
    {"name": "test_gap_analysis", "script": "test_gap_analyzer.py", "depends_on": ["behavior_primitive_matrix", "bypass_analysis"]},
    {"name": "test_vector_plan", "script": "test_vector_plan.py", "depends_on": ["coverage"]},
    {"name": "coverage_gate", "script": "coverage_gate.py", "depends_on": ["coverage", "bypass_analysis"]},
    {"name": "attack_path_matrix", "script": "attack_path_matrix.py", "depends_on": ["behavior_primitive_matrix", "bypass_analysis"]},
    {"name": "bypass_fixture_binding", "script": "bypass_fixture_binder.py", "depends_on": ["attack_path_matrix", "fixture_chain_validation"]},
    {"name": "data_component_gate", "script": "data_component_gate.py", "depends_on": ["coverage", "behavior_primitive_matrix"]},
    {"name": "denominator_diff", "script": "denominator_diff.py", "depends_on": ["coverage"]},
    {"name": "coverage_truth_gate", "script": "coverage_gate_v8.py", "depends_on": ["coverage", "denominator_guard", "test_gap_analysis", "fixture_chain_validation"]},
    {"name": "attack_claim_falsification", "script": "attack_claim_falsifier.py", "depends_on": ["coverage_truth_gate", "attack_path_matrix", "data_component_gate"]},
    {"name": "coverage_claim_upgrade", "script": "coverage_claim_upgrader.py", "depends_on": ["attack_claim_falsification", "fixture_chain_validation"]},
    {"name": "denominator_proof_graph", "script": "denominator_proof_graph.py", "depends_on": ["coverage"]},
    {"name": "claim_failure_model", "script": "attack_claim_failure_model.py", "depends_on": ["coverage_claim_upgrade", "data_component_gate"]},
    {"name": "bypass_cutset_analysis", "script": "bypass_cutset_analyzer.py", "depends_on": ["bypass_analysis", "claim_failure_model"]},
    {"name": "data_component_minset", "script": "data_component_minset.py", "depends_on": ["data_component_gate", "behavior_primitive_matrix"]},
    {"name": "coverage_score", "script": "coverage_score_v9.py", "depends_on": ["claim_failure_model", "bypass_cutset_analysis", "data_component_minset"]},
    {"name": "runtime_sensor_context", "script": "runtime_sensor_context.py", "depends_on": []},
    {"name": "field_chain_proof_graph", "script": "field_chain_proof_graph.py", "depends_on": ["field_chain", "data_component_gate"]},
    {"name": "coverage_final_gate", "script": "coverage_final_gate_v10.py", "depends_on": ["claim_failure_model", "field_chain_proof_graph", "runtime_sensor_context"]},
    {"name": "remediation_advisor", "script": "remediation_advisor.py", "depends_on": ["coverage_final_gate", "parse_rules", "coverage"]},
    {"name": "patch_blueprint", "script": "patch_blueprint.py", "depends_on": ["remediation_advisor"]},
    {"name": "field_preservation_tests", "script": "field_preservation_test_generator.py", "depends_on": ["remediation_advisor"]},
    {"name": "minimal_fixture_suite", "script": "minimal_fixture_suite.py", "depends_on": ["coverage"]},
    {"name": "validate_report", "script": "validate_report.py", "depends_on": ["coverage_final_gate", "remediation_advisor"]},
]


def phase_names() -> set[str]:
    return {row["name"] for row in PHASE_DAG}


def validate_dag() -> list[str]:
    names = phase_names()
    issues: list[str] = []
    for row in PHASE_DAG:
        for dep in row.get("depends_on", []):
            if dep not in names:
                issues.append(f"{row['name']} depends on missing phase {dep}")
    return issues


def write_dag(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "scope": "Linux,Containers,Kubernetes scenarios,Network Devices",
        "phase_count": len(PHASE_DAG),
        "issues": validate_dag(),
        "phases": PHASE_DAG,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Print or validate the declarative audit phase DAG.")
    ap.add_argument("--output-json", help="Optional path to write the DAG JSON.")
    args = ap.parse_args()
    if args.output_json:
        write_dag(Path(args.output_json))
    print(json.dumps({"phase_count": len(PHASE_DAG), "issues": validate_dag()}, ensure_ascii=False))
