from gcp_compliance_scanner.parser import TerraformResource
from gcp_compliance_scanner.rules.cloud_sql import BackupConfigRule, PublicIPRule
from gcp_compliance_scanner.rules.firewall import AllowAllProtocolsRule, OpenSensitivePortRule
from gcp_compliance_scanner.rules.iam import PrimitiveRoleRule, PublicProjectAccessRule
from gcp_compliance_scanner.rules.labels import RequiredLabelsRule
from gcp_compliance_scanner.rules.storage import (
    PublicIAMMemberRule,
    UniformBucketAccessRule,
    VersioningRule,
)


def make_resource(resource_type, name="test", attributes=None, file_path="test.tf"):
    return TerraformResource(
        resource_type=resource_type, resource_name=name, attributes=attributes or {}, file_path=file_path
    )


class TestStorageRules:
    def test_uniform_access_flagged_when_missing(self):
        resource = make_resource("google_storage_bucket", attributes={"name": "x"})
        assert UniformBucketAccessRule().check(resource) is not None

    def test_uniform_access_passes_when_enabled(self):
        resource = make_resource(
            "google_storage_bucket", attributes={"uniform_bucket_level_access": True}
        )
        assert UniformBucketAccessRule().check(resource) is None

    def test_public_member_all_users_flagged(self):
        resource = make_resource(
            "google_storage_bucket_iam_member",
            attributes={"member": "allUsers", "role": "roles/storage.objectViewer"},
        )
        finding = PublicIAMMemberRule().check(resource)
        assert finding is not None
        assert finding.severity.value == "CRITICAL"

    def test_specific_member_not_flagged(self):
        resource = make_resource(
            "google_storage_bucket_iam_member",
            attributes={"member": "user:someone@example.com", "role": "roles/storage.objectViewer"},
        )
        assert PublicIAMMemberRule().check(resource) is None

    def test_versioning_flagged_when_missing(self):
        resource = make_resource("google_storage_bucket", attributes={})
        assert VersioningRule().check(resource) is not None


class TestFirewallRules:
    def test_open_ssh_flagged(self):
        resource = make_resource(
            "google_compute_firewall",
            attributes={
                "allow": [{"protocol": "tcp", "ports": ["22"]}],
                "source_ranges": ["0.0.0.0/0"],
            },
        )
        finding = OpenSensitivePortRule().check(resource)
        assert finding is not None
        assert finding.rule_id == "FW-001"

    def test_restricted_ssh_not_flagged(self):
        resource = make_resource(
            "google_compute_firewall",
            attributes={
                "allow": [{"protocol": "tcp", "ports": ["22"]}],
                "source_ranges": ["10.0.0.0/16"],
            },
        )
        assert OpenSensitivePortRule().check(resource) is None

    def test_allow_all_protocol_flagged(self):
        resource = make_resource(
            "google_compute_firewall",
            attributes={"allow": [{"protocol": "all"}], "source_ranges": ["0.0.0.0/0"]},
        )
        assert AllowAllProtocolsRule().check(resource) is not None


class TestIAMRules:
    def test_primitive_role_owner_flagged(self):
        resource = make_resource(
            "google_project_iam_member",
            attributes={"role": "roles/owner", "member": "user:x@example.com"},
        )
        assert PrimitiveRoleRule().check(resource) is not None

    def test_scoped_role_not_flagged(self):
        resource = make_resource(
            "google_project_iam_member",
            attributes={"role": "roles/storage.objectViewer", "member": "user:x@example.com"},
        )
        assert PrimitiveRoleRule().check(resource) is None

    def test_public_member_flagged(self):
        resource = make_resource(
            "google_project_iam_member",
            attributes={"role": "roles/viewer", "member": "allAuthenticatedUsers"},
        )
        finding = PublicProjectAccessRule().check(resource)
        assert finding is not None
        assert finding.severity.value == "CRITICAL"


class TestCloudSQLRules:
    def test_public_ip_flagged(self):
        resource = make_resource(
            "google_sql_database_instance",
            attributes={"settings": {"ip_configuration": {"ipv4_enabled": True}}},
        )
        assert PublicIPRule().check(resource) is not None

    def test_private_ip_not_flagged(self):
        resource = make_resource(
            "google_sql_database_instance",
            attributes={"settings": {"ip_configuration": {"ipv4_enabled": False}}},
        )
        assert PublicIPRule().check(resource) is None

    def test_missing_backup_config_flagged(self):
        resource = make_resource("google_sql_database_instance", attributes={"settings": {}})
        assert BackupConfigRule().check(resource) is not None

    def test_backup_enabled_not_flagged(self):
        resource = make_resource(
            "google_sql_database_instance",
            attributes={"settings": {"backup_configuration": {"enabled": True}}},
        )
        assert BackupConfigRule().check(resource) is None


class TestLabelsRule:
    def test_missing_labels_flagged(self):
        resource = make_resource("google_storage_bucket", attributes={"labels": {"environment": "prod"}})
        finding = RequiredLabelsRule().check(resource)
        assert finding is not None
        assert "owner" in finding.message

    def test_all_labels_present_not_flagged(self):
        resource = make_resource(
            "google_storage_bucket",
            attributes={"labels": {"environment": "prod", "owner": "platform-team"}},
        )
        assert RequiredLabelsRule().check(resource) is None
