#!/usr/bin/env python3
from __future__ import annotations
"""Generate defensive code-patch blueprints from remediation findings."""

import argparse
import json
from pathlib import Path
from typing import Any

from common import jsonl_read, jsonl_write


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "attack_data" / "remediation" / "code_patch_templates.json"


def load_templates() -> dict[str, Any]:
    try:
        return json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def q(value: str) -> str:
    return json.dumps(value)


def language_snippet(language: str, fields: list[str]) -> str:
    fields = fields[:12] or ["required.semantic.field"]
    quoted = ", ".join(q(f) for f in fields)
    if language == "python":
        return (
            "required_fields = [" + quoted + "]\n"
            "missing = [field for field in required_fields if not event.get(field)]\n"
            "if missing:\n"
            "    return {'verdict': 'incomplete_evidence', 'missing_fields': missing}\n"
            "return evaluate_defensive_semantics(event)\n"
        )
    if language == "go":
        return (
            "required := []string{" + quoted + "}\n"
            "missing := MissingFields(event, required)\n"
            "if len(missing) > 0 {\n"
            "    return VerdictIncompleteEvidence(missing)\n"
            "}\n"
            "return EvaluateDefensiveSemantics(event)\n"
        )
    if language == "rust":
        return (
            "let required = [" + quoted + "];\n"
            "let missing = event.missing_required_fields(&required);\n"
            "if !missing.is_empty() {\n"
            "    return Verdict::IncompleteEvidence { missing_fields: missing };\n"
            "}\n"
            "return evaluate_defensive_semantics(event);\n"
        )
    if language == "java":
        return (
            "List<String> required = List.of(" + quoted + ");\n"
            "List<String> missing = event.missingRequiredFields(required);\n"
            "if (!missing.isEmpty()) {\n"
            "    return Verdict.incompleteEvidence(missing);\n"
            "}\n"
            "return evaluateDefensiveSemantics(event);\n"
        )
    if language == "c":
        return (
            "/* Add required-field presence flags to the event struct and serializer. */\n"
            "if (!event_has_required_fields(evt, required_fields, required_count)) {\n"
            "    return DETECTION_INCOMPLETE_EVIDENCE;\n"
            "}\n"
            "return evaluate_defensive_semantics(evt);\n"
        )
    if language == "c_cpp":
        return (
            "// Preserve raw and normalized aliases at parser boundaries.\n"
            "auto missing = event.missingRequiredFields(requiredFields);\n"
            "if (!missing.empty()) {\n"
            "    return Verdict::IncompleteEvidence(missing);\n"
            "}\n"
            "return evaluateDefensiveSemantics(event);\n"
        )
    if language == "sigma_yaml":
        return (
            "detection:\n"
            "  selection_required_fields:\n"
            + "\n".join(f"    {field}|exists: true" for field in fields)
            + "\n  condition: selection_required_fields and selection_behavior and not filter_benign_admin\n"
        )
    if language == "falco_yaml":
        return (
            "condition: >\n"
            "  evt.type exists and proc.cmdline exists and container.id exists\n"
            "  and not approved_admin_exception\n"
        )
    if language == "auditd":
        return (
            "# Add watches/syscall rules that preserve uid, auid, pid, exe, path, action,\n"
            "# and monitor lost/backlog counters before claiming resilience.\n"
        )
    return "Require identity, object, action, time, and runtime/device context fields before emitting a strong claim.\n"


def build_blueprint(row: dict[str, Any], templates: dict[str, Any]) -> dict[str, Any]:
    language = str(row.get("language") or "yaml")
    fields = [str(x) for x in row.get("required_fields") or [] if x]
    template = templates.get(language) or templates.get("yaml") or {}
    return {
        "finding_id": row.get("finding_id"),
        "attack_id": row.get("attack_id"),
        "language": language,
        "patch_targets": (row.get("code_patch_strategy") or {}).get("patch_targets", {}),
        "defensive_patch_template": template,
        "safe_code_blueprint": language_snippet(language, fields),
        "validation_requirements": row.get("validation_requirements") or [],
        "safety_boundary": [
            "defensive detection, parser, normalizer, fixture, or alert correctness only",
            "no exploit payloads",
            "no live bypass procedure",
            "no instructions for evading a detector",
        ],
    }


def render_md(rows: list[dict[str, Any]]) -> str:
    lines = [
        "# Defensive Patch Blueprints",
        "",
        "These blueprints describe defensive code changes only. They are not attack or evasion procedures.",
        "",
    ]
    for row in rows[:50]:
        lines += [
            f"## {row.get('finding_id')} - {row.get('attack_id')}",
            "",
            f"- language: `{row.get('language')}`",
            f"- targets: `{json.dumps(row.get('patch_targets'), ensure_ascii=False)}`",
            "",
            "```text",
            str(row.get("safe_code_blueprint") or "").rstrip(),
            "```",
            "",
        ]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate defensive patch blueprints from remediation_plan.jsonl.")
    ap.add_argument("--remediation-plan", required=True)
    ap.add_argument("--output-jsonl", required=True)
    ap.add_argument("--output-md", required=True)
    args = ap.parse_args()

    templates = load_templates()
    rows = [build_blueprint(row, templates) for row in jsonl_read(Path(args.remediation_plan))]
    jsonl_write(Path(args.output_jsonl), rows)
    Path(args.output_md).write_text(render_md(rows), encoding="utf-8")
    print(json.dumps({"blueprint_count": len(rows), "output_jsonl": args.output_jsonl}, ensure_ascii=False))


if __name__ == "__main__":
    main()
