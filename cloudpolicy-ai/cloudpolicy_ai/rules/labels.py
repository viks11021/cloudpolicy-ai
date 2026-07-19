"""
labels.py — Resource labelling / general hygiene rules.

GCP's equivalent of AWS tags is "labels" — lowercase keys, used the same
way for cost allocation and ownership tracking.
"""

from __future__ import annotations

from cloudpolicy_ai.parser import TerraformResource
from cloudpolicy_ai.rules.base import Finding, Severity

REQUIRED_LABELS = {"environment", "owner"}
LABELABLE_TYPES = (
    "google_storage_bucket",
    "google_sql_database_instance",
    "google_compute_instance",
    "google_compute_firewall",
)


class RequiredLabelsRule:
    rule_id = "LABEL-001"
    title = "Resource should have required labels (environment, owner)"
    severity = Severity.LOW
    applies_to = LABELABLE_TYPES

    def check(self, resource: TerraformResource) -> Finding | None:
        if resource.resource_type not in LABELABLE_TYPES:
            return None

        labels = resource.attributes.get("labels", {})
        if not isinstance(labels, dict):
            labels = {}

        missing = REQUIRED_LABELS - set(labels.keys())
        if missing:
            return Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                resource_address=resource.address,
                file_path=resource.file_path,
                message=f"{resource.address} is missing required label(s): {', '.join(sorted(missing))}.",
                remediation=(
                    "Add the missing labels, e.g. "
                    'labels = { environment = "prod", owner = "platform-team" }.'
                ),
            )
        return None


ALL_RULES = [RequiredLabelsRule()]
