"""
scanner.py — The rule engine. Loads all rule modules, runs them against
parsed Terraform resources, and collects findings.
"""

from __future__ import annotations

from cloudpolicy_ai.parser import TerraformResource, parse_directory
from cloudpolicy_ai.rules import cloud_sql, firewall, iam, labels, storage
from cloudpolicy_ai.rules.base import Finding

RULE_MODULES = [storage, firewall, iam, cloud_sql, labels]


def _all_rules():
    rules = []
    for module in RULE_MODULES:
        rules.extend(module.ALL_RULES)
    return rules


def scan_resources(resources: list[TerraformResource]) -> list[Finding]:
    findings: list[Finding] = []
    rules = _all_rules()
    for resource in resources:
        for rule in rules:
            finding = rule.check(resource)
            if finding is not None:
                findings.append(finding)
    return findings


def scan_directory(directory: str) -> tuple[list[TerraformResource], list[Finding]]:
    resources = parse_directory(directory)
    findings = scan_resources(resources)
    return resources, findings


def rule_count() -> int:
    return len(_all_rules())
