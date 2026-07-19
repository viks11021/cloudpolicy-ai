"""
base.py

Defines the Rule protocol every policy rule implements, and the Finding
dataclass produced when a rule is violated.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from gcp_compliance_scanner.parser import TerraformResource


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    resource_address: str
    file_path: str
    message: str
    remediation: str


class Rule(Protocol):
    rule_id: str
    title: str
    severity: Severity
    applies_to: tuple[str, ...]

    def check(self, resource: TerraformResource) -> Finding | None:
        ...
