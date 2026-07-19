"""
storage.py — Google Cloud Storage bucket compliance rules.
"""

from __future__ import annotations

from gcp_compliance_scanner.parser import TerraformResource
from gcp_compliance_scanner.rules.base import Finding, Severity

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


class UniformBucketAccessRule:
    rule_id = "GCS-001"
    title = "Storage bucket should have uniform bucket-level access enabled"
    severity = Severity.MEDIUM
    applies_to = ("google_storage_bucket",)

    def check(self, resource: TerraformResource) -> Finding | None:
        if resource.resource_type != "google_storage_bucket":
            return None
        if not resource.attributes.get("uniform_bucket_level_access"):
            return Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                resource_address=resource.address,
                file_path=resource.file_path,
                message=(
                    f"{resource.address} does not set uniform_bucket_level_access = true, "
                    "so access is governed by legacy per-object ACLs rather than IAM."
                ),
                remediation="Set uniform_bucket_level_access = true to enforce IAM-only access control.",
            )
        return None


class PublicIAMMemberRule:
    rule_id = "GCS-002"
    title = "Storage bucket must not grant access to allUsers or allAuthenticatedUsers"
    severity = Severity.CRITICAL
    applies_to = ("google_storage_bucket_iam_member", "google_storage_bucket_iam_binding")

    def check(self, resource: TerraformResource) -> Finding | None:
        if resource.resource_type not in self.applies_to:
            return None

        attrs = resource.attributes
        members = []
        if "member" in attrs:
            members = [attrs["member"]]
        elif "members" in attrs:
            m = attrs["members"]
            members = m if isinstance(m, list) else [m]

        for member in members:
            if member in PUBLIC_MEMBERS:
                return Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    resource_address=resource.address,
                    file_path=resource.file_path,
                    message=(
                        f"{resource.address} grants \"{attrs.get('role', 'a role')}\" to "
                        f"{member}, making the bucket accessible to {'anyone on the internet' if member == 'allUsers' else 'any authenticated Google account'}."
                    ),
                    remediation=(
                        f"Remove the {member} member and grant access to specific "
                        "principals (users, service accounts, or groups) instead."
                    ),
                )
        return None


class VersioningRule:
    rule_id = "GCS-003"
    title = "Storage bucket should have versioning enabled"
    severity = Severity.LOW
    applies_to = ("google_storage_bucket",)

    def check(self, resource: TerraformResource) -> Finding | None:
        if resource.resource_type != "google_storage_bucket":
            return None
        versioning = resource.attributes.get("versioning")
        enabled = isinstance(versioning, dict) and bool(versioning.get("enabled"))
        if not enabled:
            return Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                resource_address=resource.address,
                file_path=resource.file_path,
                message=f"{resource.address} does not have versioning enabled.",
                remediation="Add a versioning { enabled = true } block to the bucket.",
            )
        return None


ALL_RULES = [UniformBucketAccessRule(), PublicIAMMemberRule(), VersioningRule()]
