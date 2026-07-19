"""
iam.py — Project/resource-level IAM compliance rules.
"""

from __future__ import annotations

from gcp_compliance_scanner.parser import TerraformResource
from gcp_compliance_scanner.rules.base import Finding, Severity

PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
IAM_RESOURCE_TYPES = ("google_project_iam_member", "google_project_iam_binding")


def _members(attrs: dict) -> list[str]:
    if "member" in attrs:
        return [attrs["member"]]
    if "members" in attrs:
        m = attrs["members"]
        return m if isinstance(m, list) else [m]
    return []


class PrimitiveRoleRule:
    rule_id = "IAM-001"
    title = "IAM binding should not grant primitive roles (Owner/Editor)"
    severity = Severity.HIGH
    applies_to = IAM_RESOURCE_TYPES

    def check(self, resource: TerraformResource) -> Finding | None:
        if resource.resource_type not in IAM_RESOURCE_TYPES:
            return None
        role = resource.attributes.get("role")
        if role in PRIMITIVE_ROLES:
            return Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                resource_address=resource.address,
                file_path=resource.file_path,
                message=f"{resource.address} grants the primitive role \"{role}\", which is broader than most workloads need.",
                remediation=(
                    "Use a predefined role scoped to the actual task (e.g. "
                    "roles/storage.objectAdmin) or a custom role, instead of "
                    "Owner/Editor."
                ),
            )
        return None


class PublicProjectAccessRule:
    rule_id = "IAM-002"
    title = "IAM binding must not grant project-level access to allUsers/allAuthenticatedUsers"
    severity = Severity.CRITICAL
    applies_to = IAM_RESOURCE_TYPES

    def check(self, resource: TerraformResource) -> Finding | None:
        if resource.resource_type not in IAM_RESOURCE_TYPES:
            return None
        for member in _members(resource.attributes):
            if member in PUBLIC_MEMBERS:
                return Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    resource_address=resource.address,
                    file_path=resource.file_path,
                    message=(
                        f"{resource.address} grants \"{resource.attributes.get('role')}\" "
                        f"to {member} at the project level."
                    ),
                    remediation=f"Remove {member} and grant access to specific principals instead.",
                )
        return None


ALL_RULES = [PrimitiveRoleRule(), PublicProjectAccessRule()]
