#!/usr/bin/env python3
from __future__ import annotations
"""Generate defensive remediation guidance and code-patch plans from audit artifacts."""

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from common import detect_language, jsonl_read, jsonl_write, read_text


BLOCKER_RECOMMENDATIONS = {
    "denominator_gate_failed": "Review scenario denominator and ensure each claimed ATT&CK ID is directly tied to a scenario behavior primitive.",
    "field_chain_proof_incomplete_global": "Prove collector-to-parser-to-normalizer-to-rule-to-alert preservation for the required normalized fields.",
    "field_chain_proof_partial_global": "Close partial field-chain gaps and add regression tests for raw and normalized field names.",
    "data_component_minimum_set_incomplete": "Add the missing ATT&CK Data Component fields to the rule condition or downgrade the claim.",
    "data_component_minimum_set_partial": "Require all fields in at least one Data Component minimum set before claiming strong coverage.",
    "critical_bypass_cutset_unchecked": "Add safe defensive variant fixtures and semantic conditions for critical variant classes; do not rely on tool names or tags.",
    "fixture_chain_missing": "Add safe positive, negative, variant, and field-chain fixtures tied to the same ATT&CK ID and behavior primitive.",
    "sensor_health_blockers_present": "Fix sensor loss/drop/restart/backlog conditions before claiming resilience.",
    "runtime_or_sensor_context_missing": "Provide runtime inventory, sensor health, kernel/cgroup, Kubernetes audit, and Network Device telemetry context.",
    "model_depth_resilience_gate_failed": "Refresh the scenario model depth artifacts before accepting resilience claims.",
    "no_rule": "Add a detection condition or explicitly mark the technique as out of scope for this scenario.",
    "missing_field_chain": "Preserve and normalize required fields through the parser and normalizer.",
    "tool_name_only": "Replace tool-name-only matching with behavior semantics and required fields.",
    "ioc_only": "Replace IOC-only matching with behavioral predicates and environment-specific allowlists.",
    "parent_only": "Bind the rule to a concrete sub-technique or document why parent-only coverage is intentionally weak.",
}

LANGUAGE_FIX_HINTS = {
    "python": [
        "Add typed extraction for required semantic fields before rule evaluation.",
        "Preserve raw field names and normalized aliases in the event object.",
        "Add unit tests for positive, negative, and variant events.",
    ],
    "go": [
        "Add explicit struct fields or map keys for required semantic fields.",
        "Validate missing fields before emitting detection verdicts.",
        "Add table-driven tests for positive, negative, and variant events.",
    ],
    "rust": [
        "Add typed event fields with serde aliases for raw and normalized names.",
        "Return an explicit incomplete-evidence state when required fields are absent.",
        "Add fixture-driven tests for benign and variant cases.",
    ],
    "java": [
        "Add schema-backed getters for required semantic fields.",
        "Fail closed to a weak claim when parser input lacks required fields.",
        "Add JUnit tests for positive, negative, and variant fixture records.",
    ],
    "c": [
        "Add event fields to the emitted struct and userspace serializer.",
        "Track loss counters and field-preservation errors.",
        "Add replay tests for positive, negative, and variant metadata.",
    ],
    "c_cpp": [
        "Add event fields to the emitted struct/class and serializer.",
        "Preserve raw and normalized field names at parser boundaries.",
        "Add replay tests for positive, negative, and variant metadata.",
    ],
    "yaml": [
        "Add multi-field detection conditions and explicit filters for benign administrative lookalikes.",
        "Require correlated identity, object, action, and runtime/device context fields.",
        "Add safe fixture metadata for positive, negative, and variant cases.",
    ],
    "sigma_yaml": [
        "Use selections that require behavior semantics, not only command or tool substrings.",
        "Add condition logic that combines identity, object, action, and context fields.",
        "Add false-positive filters for approved administration paths.",
    ],
    "falco_yaml": [
        "Require evt/proc/container/k8s fields that prove the behavior primitive.",
        "Avoid single macro/tool-name matches for resilience claims.",
        "Add exceptions for benign break-glass, debug, and maintenance workflows.",
    ],
    "auditd": [
        "Add syscall and path watches that preserve uid/auid/pid/exe/path/action evidence.",
        "Ensure audit backlog and lost-event counters are monitored.",
        "Add replay metadata proving the rule sees the required fields.",
    ],
}


def safe_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def load_json(path: str | Path | None, default: Any = None) -> Any:
    if not path:
        return default
    p = Path(path)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default


def nested_get(obj: dict[str, Any], keys: list[str], default: Any = None) -> Any:
    cur: Any = obj
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return default if cur is None else cur


def recursive_find(obj: Any, names: set[str], max_depth: int = 6) -> Any:
    if max_depth < 0:
        return None
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in names and value not in (None, ""):
                return value
        for value in obj.values():
            found = recursive_find(value, names, max_depth - 1)
            if found not in (None, ""):
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = recursive_find(value, names, max_depth - 1)
            if found not in (None, ""):
                return found
    return None


def merge_unique(*values: Any) -> list[str]:
    out: list[str] = []
    for value in values:
        for item in safe_list(value):
            if isinstance(item, dict):
                for nested in item.values():
                    for nested_item in merge_unique(nested):
                        if nested_item not in out:
                            out.append(nested_item)
                continue
            text = str(item or "").strip()
            if text and text not in out:
                out.append(text)
    return out


def rule_map(parsed_rules: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out = {}
    for row in parsed_rules:
        if row.get("rule_id"):
            out[str(row["rule_id"])] = row
        if row.get("file_path"):
            out[str(row["file_path"])] = row
    return out


def claim_file(claim: dict[str, Any]) -> str | None:
    value = recursive_find(claim, {"file_path", "source_file", "rule_file"})
    if value:
        return str(value)
    for path in [
        ["source_claim", "file_path"],
        ["source_claim", "source_claim", "file_path"],
        ["source_claim", "source_claim", "source_record", "file_path"],
    ]:
        value = nested_get(claim, path)
        if value:
            return str(value)
    source = claim.get("source_claim") or {}
    if isinstance(source, dict):
        return source.get("file_path")
    return None


def claim_rule_id(claim: dict[str, Any]) -> str | None:
    value = recursive_find(claim, {"rule_id", "detection_rule_id", "source_rule_id"})
    if value:
        return str(value)
    source = claim.get("source_claim") or {}
    if isinstance(source, dict):
        for key in ["rule_id", "detection_rule_id", "source_rule_id"]:
            if source.get(key):
                return str(source[key])
        inner = source.get("source_claim")
        if isinstance(inner, dict) and inner.get("rule_id"):
            return str(inner["rule_id"])
    return None


def claim_attack_id(claim: dict[str, Any]) -> str | None:
    value = claim.get("attack_id") or claim.get("technique_id") or recursive_find(claim, {"attack_id", "technique_id"})
    return str(value) if value else None


def claim_scenario(claim: dict[str, Any]) -> str | None:
    value = claim.get("scenario") or recursive_find(claim, {"scenario"})
    return str(value) if value else None


def coverage_attack_id(row: dict[str, Any]) -> str:
    return str(row.get("technique_id") or row.get("attack_id") or "")


def coverage_score(row: dict[str, Any], attack_id: str | None, scenario: str | None) -> tuple[int, float]:
    score = 0
    if attack_id and coverage_attack_id(row) == attack_id:
        score += 50
    if scenario and str(row.get("scenario") or "") == scenario:
        score += 20
    if row.get("file_path"):
        score += 10
    if row.get("rule_id"):
        score += 10
    if row.get("matched_fields"):
        score += 5
    try:
        numeric = float(row.get("coverage_score") or 0)
    except Exception:
        numeric = 0.0
    return score, numeric


def candidate_patch_files(
    scenario: str | None,
    coverage_rows: list[dict[str, Any]],
    parsed_rules: list[dict[str, Any]],
) -> list[str]:
    files: list[str] = []
    for row in coverage_rows:
        if scenario and str(row.get("scenario") or "") != scenario:
            continue
        file_path = str(row.get("file_path") or "").strip()
        if file_path and file_path not in files:
            files.append(file_path)
    if not files and len(parsed_rules) <= 3:
        for row in parsed_rules:
            file_path = str(row.get("file_path") or "").strip()
            if file_path and file_path not in files:
                files.append(file_path)
    return files


def resolve_context(
    claim: dict[str, Any],
    rules: dict[str, dict[str, Any]],
    coverage_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    attack_id = claim_attack_id(claim)
    scenario = claim_scenario(claim)
    file_path = claim_file(claim)
    rule_id = claim_rule_id(claim)
    rule = rules.get(rule_id or "") or rules.get(file_path or "")

    candidates: list[dict[str, Any]] = []
    for row in coverage_rows:
        if rule_id and str(row.get("rule_id") or "") == rule_id:
            candidates.append(row)
            continue
        if file_path and str(row.get("file_path") or "") == file_path:
            candidates.append(row)
            continue
        if attack_id and coverage_attack_id(row) == attack_id:
            candidates.append(row)
    coverage = None
    if candidates:
        coverage = sorted(candidates, key=lambda row: coverage_score(row, attack_id, scenario), reverse=True)[0]
        file_path = file_path or coverage.get("file_path")
        rule_id = rule_id or coverage.get("rule_id")
        rule = rule or rules.get(str(rule_id or "")) or rules.get(str(file_path or ""))

    return {
        "attack_id": attack_id,
        "scenario": scenario,
        "file_path": str(file_path) if file_path else None,
        "rule_id": str(rule_id) if rule_id else None,
        "rule": rule,
        "coverage": coverage,
    }


def required_fields(claim: dict[str, Any]) -> list[str]:
    fields: list[str] = []
    for path in [
        ["source_claim", "required_fields"],
        ["source_claim", "source_claim", "required_fields"],
        ["source_claim", "source_claim", "source_record", "required_fields"],
    ]:
        for field in safe_list(nested_get(claim, path, [])):
            if isinstance(field, str) and field not in fields:
                fields.append(field)
    return fields


def language_for(file_path: str | None, rule: dict[str, Any] | None) -> str:
    if rule and rule.get("rule_format"):
        return str(rule["rule_format"])
    if not file_path:
        return "unknown"
    path = Path(file_path)
    text = read_text(path, max_bytes=100_000) if path.exists() and path.is_file() else ""
    return detect_language(path, text)


def infer_severity(blockers: list[str], final_claim: str) -> str:
    blocker_set = set(blockers)
    if "critical_bypass_cutset_unchecked" in blocker_set or final_claim in {"not_covered", "declared_only"}:
        return "critical"
    if blocker_set & {"field_chain_proof_incomplete_global", "data_component_minimum_set_incomplete", "sensor_health_blockers_present"}:
        return "high"
    if blocker_set & {"fixture_chain_missing", "runtime_or_sensor_context_missing"}:
        return "medium"
    return "low"


def code_patch_strategy(
    language: str,
    fields: list[str],
    blockers: list[str],
    file_path: str | None = None,
    rule_id: str | None = None,
    candidate_files: list[str] | None = None,
) -> dict[str, Any]:
    hints = LANGUAGE_FIX_HINTS.get(language, LANGUAGE_FIX_HINTS.get("yaml", []))
    field_text = ", ".join(fields[:12]) if fields else "required semantic fields from the claim"
    blocker_text = ", ".join(blockers[:8]) if blockers else "evidence gaps"
    return {
        "language": language,
        "patch_intent": "defensive_detection_or_parser_hardening",
        "patch_targets": {
            "file_path": file_path,
            "rule_id": rule_id,
            "candidate_patch_files": candidate_files or [],
        },
        "safe_change_summary": f"Preserve and require {field_text}; close blockers: {blocker_text}.",
        "change_categories": [
            "parser_or_normalizer_field_preservation",
            "rule_condition_semantic_hardening",
            "benign_filter_and_context_binding",
            "fixture_and_field_chain_regression_tests",
        ],
        "implementation_hints": hints,
        "do_not_include": [
            "exploit payloads",
            "weaponized commands",
            "live bypass procedures",
            "instructions for evading a detector",
        ],
    }


def render_md(rows: list[dict[str, Any]], dashboard: dict[str, Any], output_patch_note: bool) -> str:
    severity_counts = Counter(row["severity"] for row in rows)
    blocker_counts = Counter(blocker for row in rows for blocker in row.get("blockers", []))
    language_counts = Counter(row["language"] for row in rows)
    lines = [
        "# Remediation And Patch Plan",
        "",
        "This plan describes defensive evidence gaps and code-hardening work. It does not provide attack execution or evasion procedures.",
        "",
        "## Summary",
        "",
        f"- finding_count: `{len(rows)}`",
        f"- complete_coverage_claim: `{dashboard.get('complete_coverage_claim')}`",
        f"- resilient_score: `{dashboard.get('resilient_score_v10')}`",
        "",
        "## Severity Counts",
        "",
    ]
    lines += [f"- `{k}`: {v}" for k, v in sorted(severity_counts.items())] or ["- None"]
    lines += ["", "## Language Counts", ""]
    lines += [f"- `{k}`: {v}" for k, v in sorted(language_counts.items())] or ["- None"]
    lines += ["", "## Top Defensive Blockers", ""]
    lines += [f"- `{k}`: {v}" for k, v in blocker_counts.most_common(20)] or ["- None"]
    lines += ["", "## Priority Findings", ""]
    for row in rows[:50]:
        lines += [
            f"### {row['finding_id']}",
            "",
            f"- severity: `{row['severity']}`",
            f"- attack_id: `{row.get('attack_id')}`",
            f"- rule_id: `{row.get('rule_id') or 'unknown'}`",
            f"- final_claim: `{row.get('final_claim')}`",
            f"- file: `{row.get('file_path') or 'unknown'}`",
            f"- candidate_patch_files: `{', '.join(row.get('candidate_patch_files') or []) or 'not available'}`",
            f"- language: `{row.get('language')}`",
            f"- defensive_gap: {row.get('defensive_gap_summary')}",
            f"- recommendation: {row.get('recommendation')}",
            f"- fields_to_preserve_or_require: `{', '.join(row.get('required_fields') or []) or 'not available'}`",
            "",
            "Patch guidance:",
        ]
        for hint in row.get("code_patch_strategy", {}).get("implementation_hints", []):
            lines.append(f"- {hint}")
        lines.append("")
    if output_patch_note:
        lines += [
            "## Applying Code Changes",
            "",
            "When the user explicitly asks for modified code, read the target file, preserve its language/style, and apply a defensive patch that implements the field, condition, parser, or fixture changes above. If exact semantics are ambiguous, provide a patch candidate and mark unresolved assumptions.",
        ]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate defensive remediation recommendations and code-patch plans.")
    ap.add_argument("--final-claims", required=True)
    ap.add_argument("--parsed-rules", required=True)
    ap.add_argument("--coverage", help="coverage.jsonl used to resolve rule id, source file, language, and matched fields")
    ap.add_argument("--coverage-dashboard", required=True)
    ap.add_argument("--data-component-gate")
    ap.add_argument("--field-chain-proof")
    ap.add_argument("--runtime-sensor-context")
    ap.add_argument("--output-jsonl", required=True)
    ap.add_argument("--output-md", required=True)
    ap.add_argument("--include-code-patch-guidance", action="store_true")
    args = ap.parse_args()

    claims = jsonl_read(Path(args.final_claims))
    parsed = jsonl_read(Path(args.parsed_rules))
    coverage_rows = jsonl_read(Path(args.coverage)) if args.coverage else []
    dashboard = load_json(args.coverage_dashboard, {})
    rules = rule_map(parsed)

    findings = []
    for idx, claim in enumerate(claims, 1):
        blockers = [str(x) for x in safe_list(claim.get("blockers")) if x]
        final_claim = str(claim.get("v10_final_claim") or claim.get("final_claim") or "unknown")
        if final_claim == "bypass_resilient" and not blockers:
            continue
        context = resolve_context(claim, rules, coverage_rows)
        attack_id = context.get("attack_id")
        scenario = context.get("scenario")
        file_path = context.get("file_path")
        rule_id = context.get("rule_id")
        rule = context.get("rule")
        coverage = context.get("coverage") or {}
        candidates = candidate_patch_files(str(scenario) if scenario else None, coverage_rows, parsed)
        if not rule and not file_path and candidates:
            rule = rules.get(candidates[0])
        language = language_for(file_path, rule)
        fields = merge_unique(
            required_fields(claim),
            rule.get("required_fields") if isinstance(rule, dict) else [],
            coverage.get("matched_fields") if isinstance(coverage, dict) else [],
        )
        recommendation = next((BLOCKER_RECOMMENDATIONS.get(b) for b in blockers if b in BLOCKER_RECOMMENDATIONS), None)
        if not recommendation:
            recommendation = "Close the listed evidence gates before upgrading this claim."
        finding_id = f"remediation_{idx:04d}"
        defensive_gap_summary = (
            "Coverage can be overclaimed because required defensive evidence is missing or only partially proven: "
            + (", ".join(blockers[:8]) if blockers else final_claim)
        )
        findings.append({
            "finding_id": finding_id,
            "severity": infer_severity(blockers, final_claim),
            "attack_id": attack_id,
            "scenario": scenario,
            "behavior_primitive": claim.get("behavior_primitive"),
            "final_claim": final_claim,
            "file_path": file_path,
            "rule_id": rule_id,
            "candidate_patch_files": candidates,
            "language": language,
            "blockers": blockers,
            "defensive_gap_summary": defensive_gap_summary,
            "recommendation": recommendation,
            "required_fields": fields,
            "code_patch_strategy": code_patch_strategy(language, fields, blockers, file_path, rule_id, candidates),
            "source_resolution": {
                "resolved_from_coverage": bool(coverage),
                "coverage_rule_id": coverage.get("rule_id") if isinstance(coverage, dict) else None,
                "coverage_file_path": coverage.get("file_path") if isinstance(coverage, dict) else None,
                "candidate_patch_files": candidates,
            },
            "validation_requirements": [
                "positive fixture metadata proves the intended behavior",
                "negative fixture metadata covers benign administrative lookalikes",
                "variant fixture metadata covers defensive resilience proof requirements",
                "field-chain test proves raw and normalized fields are preserved",
                "runtime/sensor context is supplied or the claim remains capped",
            ],
        })

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda row: (severity_rank.get(row["severity"], 9), str(row.get("attack_id") or ""), str(row.get("file_path") or "")))
    jsonl_write(Path(args.output_jsonl), findings)
    Path(args.output_md).write_text(render_md(findings, dashboard, args.include_code_patch_guidance), encoding="utf-8")
    summary = {
        "finding_count": len(findings),
        "severity_counts": dict(Counter(row["severity"] for row in findings)),
        "language_counts": dict(Counter(row["language"] for row in findings)),
    }
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
