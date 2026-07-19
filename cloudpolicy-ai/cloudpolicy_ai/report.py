"""
report.py — Formats findings for console (rich table), JSON, or Markdown.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from cloudpolicy_ai.rules.base import Finding, Severity

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

SEVERITY_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id))


def to_json(findings: list[Finding]) -> str:
    payload = [{**asdict(f), "severity": f.severity.value} for f in sort_findings(findings)]
    return json.dumps(payload, indent=2)


def to_markdown(findings: list[Finding]) -> str:
    if not findings:
        return "## GCP Compliance Scan Report\n\nNo findings. All checks passed.\n"

    lines = ["## GCP Compliance Scan Report", ""]
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    lines.append(
        f"**{len(findings)} finding(s):** "
        f"{counts[Severity.CRITICAL]} critical, {counts[Severity.HIGH]} high, "
        f"{counts[Severity.MEDIUM]} medium, {counts[Severity.LOW]} low"
    )
    lines.append("")
    lines.append("| Severity | Rule | Resource | Issue |")
    lines.append("|---|---|---|---|")
    for f in sort_findings(findings):
        lines.append(f"| {f.severity.value} | {f.rule_id} | `{f.resource_address}` | {f.message} |")

    lines.append("")
    lines.append("### Remediation")
    for f in sort_findings(findings):
        lines.append(f"- **{f.resource_address}** ({f.rule_id}): {f.remediation}")

    return "\n".join(lines) + "\n"


def print_console(findings: list[Finding], resource_count: int, rules_run: int) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()

    if not findings:
        console.print(
            f"\n[bold green]✓ No findings.[/bold green] "
            f"Scanned {resource_count} resource(s) against {rules_run} rule(s).\n"
        )
        return

    table = Table(title=f"GCP compliance findings ({len(findings)})")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Resource")
    table.add_column("Issue")

    for f in sort_findings(findings):
        table.add_row(
            f"[{SEVERITY_COLOR[f.severity]}]{f.severity.value}[/{SEVERITY_COLOR[f.severity]}]",
            f.rule_id,
            f.resource_address,
            f.message,
        )

    console.print()
    console.print(table)
    console.print(
        f"\nScanned {resource_count} resource(s) against {rules_run} rule(s). "
        f"Run with --explain for a Vertex AI-generated summary.\n"
    )
