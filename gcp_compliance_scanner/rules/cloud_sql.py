"""
cloud_sql.py — Cloud SQL instance compliance rules.
"""

from __future__ import annotations

from gcp_compliance_scanner.parser import TerraformResource
from gcp_compliance_scanner.rules.base import Finding, Severity


class PublicIPRule:
    rule_id = "SQL-001"
    title = "Cloud SQL instance should not have a public IP enabled"
    severity = Severity.CRITICAL
    applies_to = ("google_sql_database_instance",)

    def check(self, resource: TerraformResource) -> Finding | None:
        if resource.resource_type != "google_sql_database_instance":
            return None
        settings = resource.attributes.get("settings", {})
        ip_config = settings.get("ip_configuration", {}) if isinstance(settings, dict) else {}
        if isinstance(ip_config, dict) and ip_config.get("ipv4_enabled"):
            return Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                resource_address=resource.address,
                file_path=resource.file_path,
                message=f"{resource.address} has ipv4_enabled = true, assigning a public IP address.",
                remediation=(
                    "Set ipv4_enabled = false and use private services access "
                    "or Cloud SQL Auth Proxy to connect from within the VPC instead."
                ),
            )
        return None


class BackupConfigRule:
    rule_id = "SQL-002"
    title = "Cloud SQL instance should have automated backups enabled"
    severity = Severity.MEDIUM
    applies_to = ("google_sql_database_instance",)

    def check(self, resource: TerraformResource) -> Finding | None:
        if resource.resource_type != "google_sql_database_instance":
            return None
        settings = resource.attributes.get("settings", {})
        backup_config = settings.get("backup_configuration", {}) if isinstance(settings, dict) else {}
        enabled = isinstance(backup_config, dict) and backup_config.get("enabled")
        if not enabled:
            return Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                resource_address=resource.address,
                file_path=resource.file_path,
                message=f"{resource.address} does not have backup_configuration.enabled = true.",
                remediation="Add a backup_configuration { enabled = true } block inside settings.",
            )
        return None


ALL_RULES = [PublicIPRule(), BackupConfigRule()]
