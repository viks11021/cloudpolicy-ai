"""
firewall.py — VPC firewall rule compliance checks.
"""

from __future__ import annotations

from cloudpolicy_ai.parser import TerraformResource
from cloudpolicy_ai.rules.base import Finding, Severity

SENSITIVE_PORTS = {"22": "SSH", "3389": "RDP", "3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis"}
OPEN_CIDR = "0.0.0.0/0"


def _allow_blocks(attrs: dict) -> list[dict]:
    allow = attrs.get("allow", [])
    if isinstance(allow, dict):
        return [allow]
    if isinstance(allow, list):
        return [a for a in allow if isinstance(a, dict)]
    return []


def _source_ranges(attrs: dict) -> list[str]:
    ranges = attrs.get("source_ranges", [])
    if isinstance(ranges, str):
        return [ranges]
    return ranges if isinstance(ranges, list) else []


class OpenSensitivePortRule:
    rule_id = "FW-001"
    title = "Firewall rule must not expose sensitive ports to 0.0.0.0/0"
    severity = Severity.CRITICAL
    applies_to = ("google_compute_firewall",)

    def check(self, resource: TerraformResource) -> Finding | None:
        if resource.resource_type != "google_compute_firewall":
            return None
        if OPEN_CIDR not in _source_ranges(resource.attributes):
            return None

        for allow in _allow_blocks(resource.attributes):
            ports = allow.get("ports", [])
            if isinstance(ports, str):
                ports = [ports]
            for port in ports:
                port_str = str(port)
                if port_str in SENSITIVE_PORTS:
                    name = SENSITIVE_PORTS[port_str]
                    return Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        resource_address=resource.address,
                        file_path=resource.file_path,
                        message=(
                            f"{resource.address} allows inbound traffic on port {port_str} "
                            f"({name}) from {OPEN_CIDR} (the entire internet)."
                        ),
                        remediation=(
                            f"Restrict source_ranges for port {port_str} to trusted CIDR "
                            "ranges, or use Identity-Aware Proxy (IAP) for admin access "
                            "instead of exposing the port directly."
                        ),
                    )
        return None


class AllowAllProtocolsRule:
    rule_id = "FW-002"
    title = "Firewall rule should not allow all protocols from 0.0.0.0/0"
    severity = Severity.HIGH
    applies_to = ("google_compute_firewall",)

    def check(self, resource: TerraformResource) -> Finding | None:
        if resource.resource_type != "google_compute_firewall":
            return None
        if OPEN_CIDR not in _source_ranges(resource.attributes):
            return None

        for allow in _allow_blocks(resource.attributes):
            protocol = allow.get("protocol")
            if protocol == "all":
                return Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    resource_address=resource.address,
                    file_path=resource.file_path,
                    message=(
                        f"{resource.address} allows protocol \"all\" from {OPEN_CIDR}, "
                        "exposing every port and protocol to the internet."
                    ),
                    remediation="Scope the allow block to specific protocols and ports the workload needs.",
                )
        return None


ALL_RULES = [OpenSensitivePortRule(), AllowAllProtocolsRule()]
