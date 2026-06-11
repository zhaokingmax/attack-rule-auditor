#!/usr/bin/env python3
from __future__ import annotations
"""Build the active Linux/Containers/K8S/Network Devices field alias pack."""

import argparse
import json
from pathlib import Path
from typing import Any


NETWORK_SEMANTIC_FIELDS = {
    "device.id": ["device.id", "device_id", "host.id", "node.id", "chassis_id", "serial_number"],
    "device.name": ["device.name", "device_name", "host.name", "hostname", "node.name", "sysName"],
    "device.vendor": ["device.vendor", "vendor", "manufacturer", "platform.vendor"],
    "device.os": ["device.os", "network.os", "platform.os", "os.version", "software.version"],
    "network_device.interface.name": ["interface.name", "interface_name", "ifname", "if_name", "port.name"],
    "network_device.interface.state": ["interface.state", "if_state", "oper_status", "admin_status", "link_state"],
    "network_device.config.action": ["config.action", "change.action", "event.action", "cli.action", "command.action"],
    "network_device.config.command": ["config.command", "cli.command", "command", "cmd", "message.command"],
    "network_device.config.path": ["config.path", "config.file", "running_config", "startup_config"],
    "network_device.config.hash": ["config.hash", "config_hash", "running_config_hash", "startup_config_hash"],
    "network_device.aaa.user": ["aaa.user", "aaa_user", "auth.user", "user.name", "tacacs_user", "radius_user"],
    "network_device.aaa.result": ["aaa.result", "auth.result", "authentication.result", "login.result"],
    "network_device.aaa.source": ["aaa.source", "auth.source", "source.ip", "client.ip", "management.source.ip"],
    "network_device.syslog.facility": ["syslog.facility", "facility", "log.facility"],
    "network_device.syslog.severity": ["syslog.severity", "severity", "log.level", "priority"],
    "network_device.snmp.oid": ["snmp.oid", "snmp_oid", "oid", "object_id"],
    "network_device.snmp.trap": ["snmp.trap", "trap.oid", "trap_name", "notification.type"],
    "network_device.flow.bytes": ["netflow.bytes", "ipfix.bytes", "network.bytes", "bytes", "octets"],
    "network_device.flow.packets": ["netflow.packets", "ipfix.packets", "network.packets", "packets"],
    "network_device.flow.protocol": ["netflow.protocol", "ipfix.protocol", "network.protocol", "protocol", "proto"],
    "network_device.route.prefix": ["route.prefix", "route_prefix", "network.prefix", "destination.prefix"],
    "network_device.route.next_hop": ["route.next_hop", "next_hop", "nexthop", "gateway"],
    "network_device.route.protocol": ["route.protocol", "routing.protocol", "bgp", "ospf", "isis", "eigrp"],
    "network_device.acl.name": ["acl.name", "acl_name", "access_list", "access-list", "policy.name"],
    "network_device.acl.action": ["acl.action", "acl_action", "policy.action", "permit_deny"],
    "network_device.firmware.version": ["firmware.version", "image.version", "software.image", "boot.image"],
    "network_device.firmware.hash": ["firmware.hash", "image.hash", "boot.image.hash", "software.hash"],
}

NETWORK_COMPONENT_HINTS = {
    "Application Log Content": [
        "device.id",
        "device.name",
        "network_device.syslog.facility",
        "network_device.syslog.severity",
        "network_device.config.command",
        "network_device.config.action",
    ],
    "Network Traffic Flow": [
        "device.id",
        "device.name",
        "network_device.flow.bytes",
        "network_device.flow.packets",
        "network_device.flow.protocol",
    ],
    "Network Traffic Content": [
        "device.id",
        "device.name",
        "network_device.config.command",
        "network_device.aaa.source",
    ],
    "User Account Authentication": [
        "device.id",
        "device.name",
        "network_device.aaa.user",
        "network_device.aaa.result",
        "network_device.aaa.source",
    ],
    "File Metadata": [
        "device.id",
        "device.name",
        "network_device.config.hash",
        "network_device.firmware.hash",
        "network_device.firmware.version",
    ],
    "Cloud Service Modification": [
        "device.id",
        "device.name",
        "network_device.config.action",
        "network_device.config.command",
        "network_device.interface.name",
        "network_device.route.prefix",
        "network_device.acl.name",
    ],
}


def merge_unique(existing: list[Any], additions: list[Any]) -> list[Any]:
    out = list(existing or [])
    seen = {str(x) for x in out}
    for item in additions:
        if str(item) not in seen:
            out.append(item)
            seen.add(str(item))
    return out


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description="Build active Linux/Containers/K8S/Network Devices alias pack.")
    ap.add_argument("--source", default=str(root / "attack_data" / "field_aliases" / "common_linux_container_k8s.json"))
    ap.add_argument("--output", default=str(root / "attack_data" / "field_aliases" / "common_linux_container_k8s_network.json"))
    args = ap.parse_args()

    source = Path(args.source)
    output = Path(args.output)
    pack = json.loads(source.read_text(encoding="utf-8"))
    pack["description"] = (
        "Common field alias pack for Linux, Containers, Kubernetes, Network Devices, ECS, OCSF, "
        "Falco, auditd, eBPF, syslog, NetFlow/IPFIX, SNMP, and AAA-style schemas."
    )
    pack["active_scope"] = ["Linux", "Containers", "Kubernetes scenarios", "Network Devices"]

    semantic = pack.setdefault("semantic_fields", {})
    for field, aliases in NETWORK_SEMANTIC_FIELDS.items():
        semantic[field] = merge_unique(semantic.get(field, []), aliases)
        pack[field] = merge_unique(pack.get(field, []), aliases)

    hints = pack.setdefault("attack_data_component_hints", {})
    for component, fields in NETWORK_COMPONENT_HINTS.items():
        hints[component] = merge_unique(hints.get(component, []), fields)

    metadata = pack.setdefault("_metadata", {})
    metadata["active_scope"] = "Linux, Containers, Kubernetes scenarios, Network Devices"
    metadata["safe_use_note"] = "Defensive field normalization only; no attack behavior is encoded."
    pack["_network_device_note"] = (
        "Network Devices aliases cover defensive syslog, AAA, SNMP, NetFlow/IPFIX, routing, ACL, "
        "interface, configuration, and firmware evidence chains."
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(pack, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "semantic_field_count": len(semantic), "component_hint_count": len(hints)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
