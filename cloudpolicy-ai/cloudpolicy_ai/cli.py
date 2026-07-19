"""
cli.py — Command-line entry point.

Usage:
    cloudpolicy-ai scan <directory> [--format console|json|markdown] [--explain] [--fail-on SEVERITY]
"""

from __future__ import annotations

import sys

import click

from cloudpolicy_ai import report
from cloudpolicy_ai.rules.base import Severity
from cloudpolicy_ai.scanner import rule_count, scan_directory
from cloudpolicy_ai.vertex_explainer import AIExplainerError, explain_findings

SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


@click.group()
@click.version_option()
def cli():
    """A GCP Terraform compliance scanner with an optional Vertex AI explanation layer."""


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--format", "output_format",
    type=click.Choice(["console", "json", "markdown"]),
    default="console",
    help="Output format.",
)
@click.option("--explain", is_flag=True, help="Generate a Vertex AI (Gemini)-powered plain-English summary.")
@click.option(
    "--project", default=None, help="GCP project ID for Vertex AI (defaults to GOOGLE_CLOUD_PROJECT env var)."
)
@click.option("--location", default="us-central1", help="Vertex AI region.")
@click.option(
    "--fail-on",
    type=click.Choice([s.value for s in Severity]),
    default=None,
    help="Exit with a non-zero status if any finding at or above this severity is present.",
)
@click.option("--output", type=click.Path(), default=None, help="Write output to a file instead of stdout.")
def scan(directory, output_format, explain, project, location, fail_on, output):
    """Scan DIRECTORY for GCP Terraform compliance issues."""
    try:
        resources, findings = scan_directory(directory)
    except FileNotFoundError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)

    if output_format == "json":
        text = report.to_json(findings)
    elif output_format == "markdown":
        text = report.to_markdown(findings)
    else:
        report.print_console(findings, resource_count=len(resources), rules_run=rule_count())
        text = None

    if explain:
        try:
            summary = explain_findings(findings, project=project, location=location)
            click.echo("\n" + "=" * 60)
            click.echo("VERTEX AI SUMMARY")
            click.echo("=" * 60)
            click.echo(summary)
        except AIExplainerError as exc:
            click.echo(f"\n[--explain skipped] {exc}", err=True)

    if text is not None:
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(text)
            click.echo(f"Report written to {output}")
        else:
            click.echo(text)

    if fail_on:
        threshold = SEVERITY_RANK[Severity(fail_on)]
        blocking = [f for f in findings if SEVERITY_RANK[f.severity] >= threshold]
        if blocking:
            click.echo(f"\n{len(blocking)} finding(s) at or above {fail_on} severity. Failing build.", err=True)
            sys.exit(1)


if __name__ == "__main__":
    cli()
