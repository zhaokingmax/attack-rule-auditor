#!/usr/bin/env python3
from __future__ import annotations
"""Add Network Devices L4 coverage to the defensive scenario model.

The skill scope is Linux, Containers, Kubernetes scenarios, and Network Devices.
This script refreshes the Network Devices denominator support by adding
defensive observability, proof, and safe fixture requirements for Network
Devices-only gaps. It does not encode payloads, exploit steps, or operational
evasion instructions.
"""

import argparse
import json
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "attack_data" / "models" / "scenario_attack_model.json"
SEED_MAP_PATH = ROOT / "attack_data" / "models" / "scenario_seed_map.json"
LOOKUP_PATH = ROOT / "attack_data" / "index" / "lookup_by_id.json"
DATA_COMPONENTS_PATH = ROOT / "attack_data" / "index" / "data_components.jsonl"
EXPANDED_SCOPE_PATH = ROOT / "attack_data" / "index" / "linux_container_network_scope.jsonl"
SUMMARY_PATH = ROOT / "laji" / "attack_data" / "reports" / "network_device_extension_summary.json"
DELTA_PATH = ROOT / "laji" / "attack_data" / "reports" / "network_device_extension_delta.jsonl"
FIXTURE_PATH = ROOT / "attack_data" / "fixtures" / "network_device_templates.jsonl"
SENSOR_PATH = ROOT / "attack_data" / "sensors" / "network_device_sensor_capabilities.json"

VERSION = "V10.6-network-device-extension"
SAFE_NOTE = "Defensive validation requirement only; no executable bypass instructions are encoded."

SCENARIO_GROUPS: dict[str, dict[str, Any]] = {
    "network_device_cli_execution": {
        "description": "Network-device CLI execution and administrative session evidence.",
        "techniques": ["T1059.008"],
        "components": ["Command Execution", "User Account Authentication", "Network Traffic Content", "Application Log Content"],
        "fields": ["network.device.name", "network.device.vendor", "network.device.os", "aaa.user", "auth.result", "session.id", "event.action", "command.normalized", "source.ip"],
        "sensors": ["network_device_syslog", "aaa_tacacs_radius", "management_plane_session_logs", "configuration_archive_diff"],
        "category": "network_device_cli_variant",
    },
    "network_config_collection": {
        "description": "Configuration repository, SNMP/MIB, and device configuration collection evidence.",
        "techniques": ["T1602", "T1602.001", "T1602.002"],
        "components": ["Network Connection Creation", "Network Traffic Content", "Command Execution", "User Account Authentication", "File Modification"],
        "fields": ["network.device.name", "management.protocol", "snmp.oid", "api.resource", "config.path", "config.object", "aaa.user", "source.ip", "event.action"],
        "sensors": ["network_device_syslog", "snmp_poll_or_trap", "netconf_restconf_audit", "configuration_archive_diff", "aaa_tacacs_radius"],
        "category": "network_config_repository_variant",
    },
    "network_device_authentication": {
        "description": "Network-device authentication process and wireless identity evidence.",
        "techniques": ["T1556.004", "T1557.004"],
        "components": ["User Account Authentication", "Application Log Content", "Network Traffic Content", "Network Traffic Flow", "File Modification"],
        "fields": ["network.device.name", "aaa.user", "auth.result", "auth.method", "firmware.version", "image.hash.sha256", "wireless.ssid", "wireless.bssid", "source.ip"],
        "sensors": ["aaa_tacacs_radius", "network_device_syslog", "wireless_controller_logs", "firmware_inventory", "image_integrity_monitor"],
        "category": "network_device_identity_variant",
    },
    "network_boundary_visibility": {
        "description": "Boundary bridging, NAT traversal, and traffic duplication evidence across control-plane and flow telemetry.",
        "techniques": ["T1599", "T1599.001", "T1020.001"],
        "components": ["Network Traffic Flow", "Network Traffic Content", "Network Connection Creation", "Firewall Rule Modification", "Command Execution"],
        "fields": ["network.device.name", "interface.name", "routing.zone.before", "routing.zone.after", "nat.rule.id", "mirror.session.id", "network.source.ip", "network.destination.ip", "network.bytes"],
        "sensors": ["netflow_or_ipfix", "packet_broker_or_span_inventory", "network_device_syslog", "firewall_policy_audit", "configuration_archive_diff"],
        "category": "network_boundary_variant",
    },
    "network_crypto_impairment": {
        "description": "Encryption, crypto hardware, and network-device firewall control impairment evidence.",
        "techniques": ["T1600", "T1600.001", "T1600.002", "T1686.002"],
        "components": ["Command Execution", "File Modification", "Network Traffic Content", "Firewall Rule Modification", "Firewall Disable", "Module Load"],
        "fields": ["network.device.name", "crypto.policy.name", "crypto.key.length", "crypto.hardware.state", "firewall.rule.id", "firewall.action", "config.hash.sha256", "aaa.user", "event.action"],
        "sensors": ["network_device_syslog", "firewall_policy_audit", "configuration_archive_diff", "crypto_policy_inventory", "aaa_tacacs_radius"],
        "category": "network_crypto_firewall_variant",
    },
    "network_system_image_integrity": {
        "description": "Network-device system image modification, patching, and downgrade evidence.",
        "techniques": ["T1601", "T1601.001", "T1601.002"],
        "components": ["Command Execution", "File Modification", "File Metadata", "Firmware Modification", "Image Modification"],
        "fields": ["network.device.name", "image.name", "image.version", "image.hash.sha256", "boot.image.name", "config.path", "aaa.user", "event.action"],
        "sensors": ["network_device_syslog", "image_integrity_monitor", "configuration_archive_diff", "firmware_inventory", "aaa_tacacs_radius"],
        "category": "network_system_image_variant",
    },
    "network_firmware_boot_integrity": {
        "description": "Firmware, ROMMON, and TFTP boot integrity evidence for network devices.",
        "techniques": ["T1542.001", "T1542.004", "T1542.005"],
        "components": ["Firmware Modification", "Command Execution", "Network Connection Creation", "OS API Execution", "File Creation"],
        "fields": ["network.device.name", "firmware.version", "firmware.hash.sha256", "boot.mode", "boot.source", "tftp.server.ip", "aaa.user", "event.action"],
        "sensors": ["firmware_inventory", "network_device_syslog", "boot_integrity_monitor", "configuration_archive_diff", "aaa_tacacs_radius"],
        "category": "network_firmware_boot_variant",
    },
    "network_direct_storage_access": {
        "description": "Raw storage or direct volume access evidence on network device storage surfaces.",
        "techniques": ["T1006"],
        "components": ["Command Execution", "File Access", "Process Access", "Process Creation", "File Metadata"],
        "fields": ["network.device.name", "storage.device", "storage.partition", "file.path", "process.executable", "aaa.user", "event.action"],
        "sensors": ["network_device_syslog", "embedded_os_audit", "storage_integrity_monitor", "configuration_archive_diff"],
        "category": "network_storage_access_variant",
    },
}
GENERATED_SCENARIOS = set(SCENARIO_GROUPS)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def stable_unique(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            out.append(text)
            seen.add(text)
    return out


def slug(value: str) -> str:
    text = str(value or "").lower().replace(".", "_")
    text = re.sub(r"[^a-z0-9_]+", "_", text)
    return re.sub(r"_+", "_", text).strip("_") or "unknown"


def valid_components() -> set[str]:
    return {row["name"] for row in read_jsonl(DATA_COMPONENTS_PATH) if row.get("name")}


def expanded_scope_rows(lookup: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [
        rec
        for tid, rec in lookup.items()
        if {"Linux", "Containers", "Network Devices"} & set(rec.get("platforms") or [])
    ]
    return sorted(rows, key=lambda r: str(r.get("technique_id")))


def components_for(rec: dict[str, Any], group: dict[str, Any], valid: set[str]) -> list[str]:
    preferred = stable_unique((rec.get("data_components") or []) + group["components"])
    cleaned = [component for component in preferred if component in valid]
    return cleaned[:7] or ["Command Execution", "Application Log Content"]


def fields_for(group: dict[str, Any], components: list[str]) -> list[str]:
    fields = list(group["fields"]) + ["event.action", "event.category", "event.outcome", "observer.name"]
    for component in components:
        lc = component.lower()
        if "network" in lc:
            fields += ["network.source.ip", "network.destination.ip", "network.protocol", "network.bytes"]
        if "firewall" in lc:
            fields += ["firewall.rule.id", "firewall.action", "firewall.policy.name"]
        if "firmware" in lc:
            fields += ["firmware.version", "firmware.hash.sha256"]
        if "image" in lc:
            fields += ["image.name", "image.version", "image.hash.sha256"]
        if "user account" in lc or "logon" in lc:
            fields += ["aaa.user", "auth.result", "auth.method", "source.ip"]
        if "command" in lc:
            fields += ["command.normalized", "command.object", "aaa.user", "session.id"]
        if "file" in lc:
            fields += ["file.path", "file.hash.sha256", "file.operation"]
    return stable_unique(fields)[:18]


def minimum_sets(components: list[str]) -> list[list[str]]:
    if len(components) <= 2:
        return [components]
    control_plane = [c for c in components if c in {"Command Execution", "Application Log Content", "User Account Authentication", "Firewall Rule Modification", "Firewall Disable"}]
    data_plane = [c for c in components if c in {"Network Traffic Flow", "Network Traffic Content", "Network Connection Creation"}]
    integrity = [c for c in components if c in {"Firmware Modification", "Image Modification", "File Modification", "File Metadata"}]
    out = [x[:3] for x in [control_plane, data_plane, integrity] if x]
    return out or [components[:3]]


def semantic_axes(rec: dict[str, Any], group_name: str) -> list[str]:
    axes = {
        "network_device_cli_execution": ["management session context", "command semantics", "AAA identity correlation", "configuration diff linkage"],
        "network_config_collection": ["repository object access", "management protocol context", "identity and source correlation", "read versus write separation"],
        "network_device_authentication": ["authentication path integrity", "image or firmware baseline correlation", "wireless identity context", "normal enrollment separation"],
        "network_boundary_visibility": ["policy boundary state", "flow-path change correlation", "mirror or NAT object lifecycle", "data-plane and control-plane agreement"],
        "network_crypto_impairment": ["crypto policy state", "firewall policy state", "hardware capability state", "post-change traffic consistency"],
        "network_system_image_integrity": ["image inventory baseline", "boot configuration linkage", "hash and version consistency", "reload or boot event correlation"],
        "network_firmware_boot_integrity": ["firmware baseline", "boot source integrity", "management-plane actor context", "network boot telemetry correlation"],
        "network_direct_storage_access": ["storage object access", "embedded OS process context", "raw versus file-level access separation", "integrity baseline correlation"],
    }
    return axes.get(group_name, ["network device state change", "identity correlation", "control-plane evidence", "negative fixture separation"])


def negative_fixture(group_name: str) -> list[str]:
    return [
        "approved administrative maintenance with a valid change ticket does not satisfy the primitive by itself",
        "single-field, tag-only, technique-name-only, or device-name-only matches remain blocked",
        "collector-only visibility without parser and normalizer field-chain proof remains non-validated",
        f"benign {group_name.replace('_', ' ')} lookalike activity is represented as safe metadata and must not validate coverage",
    ]


def build_behavior(tid: str, rec: dict[str, Any], group_name: str, group: dict[str, Any], valid: set[str]) -> dict[str, Any]:
    components = components_for(rec, group, valid)
    fields = fields_for(group, components)
    return {
        "id": f"network_device_{slug(tid)}_l4_model",
        "keywords": stable_unique([tid, rec.get("name", ""), rec.get("parent_name", ""), *rec.get("tactics", [])]),
        "attack_ids": [tid],
        "required_data_components": components,
        "required_fields": fields,
        "critical": True,
        "description": f"Network Devices L4 defensive model for ATT&CK {tid} ({rec.get('name')}); validates control-plane, identity, integrity, and telemetry evidence before coverage is claimed.",
        "data_component_minimum_sets": minimum_sets(components),
        "coverage_maturity": "L4_deep_model",
        "sensor_requirements": stable_unique(group["sensors"]),
        "proof_requirements": [
            "condition_ast_evidence",
            "field_chain_evidence",
            "data_component_minimum_set",
            "safe_positive_fixture_metadata",
            "safe_negative_fixture_metadata",
            "bypass_resilience_review",
            "network_device_sensor_context_review",
        ],
        "attack_semantics": {
            "technique_id": tid,
            "technique_name": rec.get("name"),
            "tactics": rec.get("tactics", []),
            "semantic_axes": semantic_axes(rec, group_name),
            "observable_state_changes": components,
            "correlation_requirements": fields[:10],
            "syscalls": [],
            "tools": [],
            "file_paths": [],
            "network_indicators": [
                "management-plane session metadata",
                "configuration or firmware baseline delta",
                "control-plane event correlated with data-plane flow change",
            ],
        },
        "telemetry_feasibility": {
            "observable": True,
            "primary_sensors": stable_unique(group["sensors"]),
            "minimum_fields": fields[:10],
            "blind_spots": [
                "local console access without AAA or command accounting can cap confidence",
                "encrypted management channels require endpoint, syslog, or configuration-diff correlation",
                "missing config archive or baseline hash prevents integrity-level validation",
            ],
        },
        "negative_fixture_requirements": negative_fixture(group_name),
        "network_device_extension": {
            "extension_version": VERSION,
            "source_attack_id": tid,
            "scenario": group_name,
            "safe_use_note": "Defensive model extension only; no executable attack steps are encoded.",
        },
    }


def build_bypass(tid: str, behavior: dict[str, Any], group: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"network_device_{slug(tid)}_bypass_resilience_proof",
        "description": f"Network Devices defensive bypass-resilience proof requirement for ATT&CK {tid}; validates that coverage depends on correlated device, identity, state-change, and telemetry evidence.",
        "keywords": stable_unique(behavior["keywords"] + ["network-device", "field-chain", "negative-fixture", "control-plane"]),
        "attack_ids": [tid],
        "critical": True,
        "category": group["category"],
        "required_fields": behavior["required_fields"],
        "required_data_components": behavior["required_data_components"],
        "check_requirement": "Require safe synthetic or replay metadata proving behavior semantics, Data Component minimum sets, raw and normalized field-chain preservation, and benign administrative negative fixtures; ATT&CK tags, device names, single command strings, or one data source alone must not validate resilient coverage.",
        "behavior_primitive": behavior["id"],
        "safe_use_note": SAFE_NOTE,
        "network_device_extension": {
            "extension_version": VERSION,
            "safe_use_note": "Proof requirement only; do not execute attack behavior.",
        },
    }


def build_fixture(tid: str, behavior: dict[str, Any], group_name: str) -> dict[str, Any]:
    return {
        "coverage_model_version": VERSION,
        "fixture_template_id": f"network_device_fixture_{slug(tid)}",
        "technique_id": tid,
        "scenario": group_name,
        "behavior_primitive": behavior["id"],
        "required_fields": behavior["required_fields"],
        "required_data_components": behavior["required_data_components"],
        "positive_fixture_requirements": [
            "safe synthetic event or replay metadata contains all required fields",
            "event binds to device state, identity, and behavior semantics rather than ATT&CK tag mention",
            "field-chain evidence proves collector, parser, normalizer, rule condition, and alert output preserve the required fields",
        ],
        "variant_fixture_requirements": [
            "raw syslog, parsed ECS-like fields, and normalized SIEM fields are represented as benign metadata",
            "control-plane and data-plane records can be correlated without executing attack behavior",
            "vendor-specific field aliases are covered by explicit mapping metadata",
        ],
        "negative_fixture_requirements": negative_fixture(group_name),
        "safe_use_note": "Fixture template describes defensive evidence shape only and must not execute attack behavior.",
    }


def strip_existing(model: dict[str, Any]) -> dict[str, Any]:
    meta = model.get("_meta", {}) if isinstance(model.get("_meta"), dict) else {}
    cleaned = {
        key: value
        for key, value in model.items()
        if key.startswith("_") or key not in GENERATED_SCENARIOS
    }
    meta.pop("network_device_extension", None)
    cleaned["_meta"] = meta
    return cleaned


def build_scenarios(lookup: dict[str, Any], valid: set[str]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    scenarios: dict[str, Any] = {}
    delta_rows: list[dict[str, Any]] = []
    fixture_rows: list[dict[str, Any]] = []
    for group_name, group in SCENARIO_GROUPS.items():
        behaviors: list[dict[str, Any]] = []
        bypasses: list[dict[str, Any]] = []
        for tid in group["techniques"]:
            rec = lookup[tid]
            behavior = build_behavior(tid, rec, group_name, group, valid)
            bypass = build_bypass(tid, behavior, group)
            behaviors.append(behavior)
            bypasses.append(bypass)
            fixture_rows.append(build_fixture(tid, behavior, group_name))
            delta_rows.append({
                "coverage_model_version": VERSION,
                "technique_id": tid,
                "name": rec.get("name"),
                "scenario": group_name,
                "tactics": rec.get("tactics", []),
                "platforms": rec.get("platforms", []),
                "behavior_primitive": behavior["id"],
                "bypass_primitive": bypass["id"],
                "required_data_components": behavior["required_data_components"],
                "required_fields": behavior["required_fields"],
                "sensor_requirements": behavior["sensor_requirements"],
                "safe_use_note": "Defensive Network Devices model extension only; no payloads, exploit steps, or operational bypass instructions.",
            })
        scenarios[group_name] = {
            "description": group["description"],
            "platform_scope": ["Network Devices"],
            "must_cover_attack_ids": stable_unique(group["techniques"]),
            "should_cover_attack_ids": [],
            "behavior_primitives": behaviors,
            "bypass_primitives": bypasses,
            "critical_behavior_primitives": [behavior["id"] for behavior in behaviors],
            "complete_gate": {
                "requires_denominator_confidence": "high",
                "requires_subtechnique_review": True,
                "requires_data_component_gate": True,
                "requires_strategy_gate": True,
                "requires_field_chain_gate": True,
                "requires_test_gate": True,
                "requires_bypass_gate": True,
                "requires_network_device_sensor_context": True,
            },
            "phase_coverage": "network_device_extension",
            "safe_use_note": "Bypass primitives are defensive proof requirements only and do not contain executable attack steps.",
        }
    return scenarios, delta_rows, fixture_rows


def update_seed_map(seed_path: Path, scenarios: dict[str, Any]) -> None:
    seed = read_json(seed_path) if seed_path.exists() else {}
    seed = {key: value for key, value in seed.items() if key not in GENERATED_SCENARIOS}
    meta = seed.pop("_meta", {}) if isinstance(seed.get("_meta"), dict) else {}
    for name, scenario in scenarios.items():
        behavior = scenario.get("behavior_primitives", []) or []
        seed[name] = {
            "description": scenario.get("description", ""),
            "platform_scope": ["Network Devices"],
            "tactic_scope": stable_unique([
                tactic
                for bp in behavior
                for tactic in (bp.get("attack_semantics", {}) or {}).get("tactics", [])
            ]),
            "keywords": stable_unique([kw for bp in behavior for kw in (bp.get("keywords") or [])]),
            "seed_attack_ids": scenario.get("must_cover_attack_ids", []),
            "must_cover_attack_ids": scenario.get("must_cover_attack_ids", []),
            "critical_attack_ids": scenario.get("must_cover_attack_ids", []),
            "behavior_primitives": [bp.get("id") for bp in behavior if bp.get("id")],
            "source": "scenario_attack_model_v10_6_network_device_extension",
        }
    meta.update({
        "network_device_extension": "Network Devices scenario packs synchronized.",
        "safe_use_note": "Network Devices bypass entries are proof requirements only.",
    })
    seed["_meta"] = meta
    write_json(seed_path, seed)


def collect_ids(model: dict[str, Any]) -> tuple[set[str], set[str]]:
    behavior: set[str] = set()
    bypass: set[str] = set()
    for scenario_name, scenario in model.items():
        if scenario_name.startswith("_") or not isinstance(scenario, dict):
            continue
        for primitive in scenario.get("behavior_primitives", []) or []:
            behavior.update(str(tid).upper() for tid in primitive.get("attack_ids", []) or [])
        for primitive in scenario.get("bypass_primitives", []) or []:
            bypass.update(str(tid).upper() for tid in primitive.get("attack_ids", []) or [])
    return behavior, bypass


def build_sensor_matrix(delta_rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_sensor: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "technique_ids": [],
        "required_fields": [],
        "required_data_components": [],
    })
    for row in delta_rows:
        for sensor in row.get("sensor_requirements", []) or []:
            entry = by_sensor[sensor]
            entry["technique_ids"].append(row["technique_id"])
            entry["required_fields"].extend(row.get("required_fields", []))
            entry["required_data_components"].extend(row.get("required_data_components", []))
    sensors = []
    for sensor, entry in by_sensor.items():
        sensors.append({
            "sensor": sensor,
            "technique_count": len(set(entry["technique_ids"])),
            "technique_ids": stable_unique(entry["technique_ids"]),
            "required_fields": stable_unique(entry["required_fields"])[:40],
            "required_data_components": stable_unique(entry["required_data_components"]),
        })
    return {
        "coverage_model_version": VERSION,
        "scope": "Network Devices",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sensor_count": len(sensors),
        "sensors": sorted(sensors, key=lambda row: (-row["technique_count"], row["sensor"])),
        "safe_use_note": "Capability matrix records defensive telemetry requirements only.",
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Refresh Network Devices support for the Linux/Containers/Kubernetes/Network Devices scope.")
    ap.add_argument("--dry-run", action="store_true", help="Print planned source and output files without modifying model data.")
    args = ap.parse_args()
    if args.dry_run:
        print(json.dumps({
            "status": "dry_run",
            "model_path": str(MODEL_PATH),
            "seed_map_path": str(SEED_MAP_PATH),
            "expanded_scope_path": str(EXPANDED_SCOPE_PATH),
            "summary_path": str(SUMMARY_PATH),
            "delta_path": str(DELTA_PATH),
            "fixture_path": str(FIXTURE_PATH),
            "sensor_path": str(SENSOR_PATH),
        }, ensure_ascii=False))
        return

    lookup = read_json(LOOKUP_PATH)
    valid = valid_components()
    model = strip_existing(read_json(MODEL_PATH))
    scenarios, delta_rows, fixture_rows = build_scenarios(lookup, valid)
    model.update(scenarios)
    meta = model.setdefault("_meta", {})
    meta["network_device_extension"] = VERSION
    meta["network_device_extension_generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    meta["network_device_safe_use_note"] = "Network Devices extension adds defensive observability and proof requirements only."

    write_json(MODEL_PATH, model)
    update_seed_map(SEED_MAP_PATH, scenarios)
    expanded_rows = expanded_scope_rows(lookup)
    write_jsonl(EXPANDED_SCOPE_PATH, expanded_rows)
    write_jsonl(DELTA_PATH, delta_rows)
    write_jsonl(FIXTURE_PATH, fixture_rows)
    write_json(SENSOR_PATH, build_sensor_matrix(delta_rows))

    behavior, bypass = collect_ids(model)
    scope_ids = {str(row.get("technique_id")).upper() for row in expanded_rows}
    network_ids = {tid for tid, rec in lookup.items() if "Network Devices" in (rec.get("platforms") or [])}
    expanded_gaps = sorted(scope_ids - behavior)
    bypass_gaps = sorted(scope_ids - bypass)
    by_tactic = Counter(tactic for tid in expanded_gaps for tactic in lookup[tid].get("tactics", []) or ["unknown"])
    summary = {
        "coverage_model_version": (model.get("_meta") or {}).get("coverage_model_version"),
        "network_device_extension_version": VERSION,
        "status": "applied",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generated_scenario_count": len(scenarios),
        "generated_behavior_primitive_count": sum(len(sc.get("behavior_primitives", []) or []) for sc in scenarios.values()),
        "generated_bypass_primitive_count": sum(len(sc.get("bypass_primitives", []) or []) for sc in scenarios.values()),
        "generated_fixture_template_count": len(fixture_rows),
        "network_device_scope_count": len(network_ids),
        "expanded_scope_count": len(scope_ids),
        "expanded_direct_model_count": len(scope_ids & behavior),
        "expanded_bypass_proof_count": len(scope_ids & bypass),
        "expanded_direct_gap_count": len(expanded_gaps),
        "expanded_bypass_gap_count": len(bypass_gaps),
        "expanded_direct_gap_by_tactic": sorted(by_tactic.items(), key=lambda x: (-x[1], x[0])),
        "scenario_pack_counts": {name: len(sc.get("behavior_primitives", []) or []) for name, sc in scenarios.items()},
        "safe_use_note": "Network Devices extension is defensive coverage modeling only; no executable attack behavior is encoded.",
    }
    write_json(SUMMARY_PATH, summary)
    print(json.dumps({
        "network_device_extension_version": VERSION,
        "generated_behavior_primitive_count": summary["generated_behavior_primitive_count"],
        "expanded_direct_model": f"{summary['expanded_direct_model_count']}/{summary['expanded_scope_count']}",
        "expanded_direct_gap_count": summary["expanded_direct_gap_count"],
        "expanded_bypass_gap_count": summary["expanded_bypass_gap_count"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
