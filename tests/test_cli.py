import json
import os

from click.testing import CliRunner

from gcp_compliance_scanner.cli import cli

EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "examples", "vulnerable-gcp-infra")


def test_scan_console_output_exits_zero_by_default():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", EXAMPLES_DIR])
    assert result.exit_code == 0
    assert "GCP compliance findings" in result.output


def test_scan_json_output_is_valid_json():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", EXAMPLES_DIR, "--format", "json"])
    assert result.exit_code == 0
    findings = json.loads(result.output)
    assert len(findings) == 13
    assert findings[0]["severity"] == "CRITICAL"


def test_scan_markdown_output():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", EXAMPLES_DIR, "--format", "markdown"])
    assert result.exit_code == 0
    assert "## GCP Compliance Scan Report" in result.output


def test_fail_on_critical_exits_nonzero():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", EXAMPLES_DIR, "--fail-on", "CRITICAL"])
    assert result.exit_code == 1


def test_scan_nonexistent_directory_errors():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "/nonexistent/path/xyz"])
    assert result.exit_code != 0


def test_explain_without_project_does_not_crash(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", EXAMPLES_DIR, "--explain"])
    assert result.exit_code == 0
    assert "explain skipped" in result.output.lower() or "GOOGLE_CLOUD_PROJECT" in result.output


def test_scan_output_to_file(tmp_path):
    output_file = tmp_path / "report.json"
    runner = CliRunner()
    result = runner.invoke(
        cli, ["scan", EXAMPLES_DIR, "--format", "json", "--output", str(output_file)]
    )
    assert result.exit_code == 0
    assert output_file.exists()
    data = json.loads(output_file.read_text())
    assert len(data) == 13
