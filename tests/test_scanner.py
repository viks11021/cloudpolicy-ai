import os

from gcp_compliance_scanner.scanner import rule_count, scan_directory

EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "examples", "vulnerable-gcp-infra")


def test_scan_directory_finds_known_issues():
    resources, findings = scan_directory(EXAMPLES_DIR)
    assert len(resources) == 7

    rule_ids = {f.rule_id for f in findings}
    expected = {
        "GCS-001", "GCS-002", "GCS-003",
        "FW-001", "FW-002",
        "IAM-001", "IAM-002",
        "SQL-001", "SQL-002",
    }
    assert expected.issubset(rule_ids), f"Missing expected findings: {expected - rule_ids}"


def test_rule_count_matches_registered_rules():
    assert rule_count() >= 9


def test_clean_config_produces_no_findings(tmp_path):
    clean_tf = tmp_path / "main.tf"
    clean_tf.write_text(
        """
        resource "google_storage_bucket" "clean" {
          name                        = "clean-bucket"
          location                    = "US"
          uniform_bucket_level_access = true
          versioning {
            enabled = true
          }
          labels = {
            environment = "prod"
            owner       = "platform-team"
          }
        }
        """
    )
    resources, findings = scan_directory(str(tmp_path))
    assert len(resources) == 1
    assert findings == []
