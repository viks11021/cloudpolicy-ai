"""
vertex_explainer.py — Optional AI explanation layer using Google's Gen AI
SDK against Vertex AI (branded, as of May 2026, under the "Gemini Enterprise
Agent Platform" console — the API endpoint and auth model are unchanged).

Uses `google-genai`, the current unified SDK. The older
`vertexai.generative_models` module (from `google-cloud-aiplatform`) was
deprecated June 24, 2025 and removed June 24, 2026 — do not use it; this
module was migrated off it deliberately, not left on it by accident.

Authenticated via a GCP project + Application Default Credentials — the
same enterprise auth model as before, not a simple API key. This is the
same code path Google now documents as the standard way to call Gemini
through a GCP project rather than the consumer AI Studio API.

Requires:
    - A GCP project with the Vertex AI / Gemini Enterprise Agent Platform
      API enabled (endpoint: aiplatform.googleapis.com — same endpoint,
      new console name)
    - Application Default Credentials configured (`gcloud auth application-default login`,
      or a service account key / workload identity in CI)
    - GOOGLE_CLOUD_PROJECT environment variable set
"""

from __future__ import annotations

import os
import textwrap

from cloudpolicy_ai.rules.base import Finding

SYSTEM_PROMPT = textwrap.dedent(
    """\
    You are a cloud security reviewer summarising a GCP Terraform compliance
    scan for a platform engineering team ahead of a project design review.
    You will be given a list of structured findings (rule id, severity,
    resource, message, suggested remediation).

    Write a short, prioritised report in plain English:
    1. One-paragraph overall risk summary (should this project design be
       approved, or blocked pending fixes?).
    2. Findings grouped by severity, CRITICAL first, each as a short bullet
       with resource, plain-English risk, and the fix.
    3. If there are more than 5 findings, call out the 2-3 that matter most
       and note the rest are lower priority rather than listing everything
       with equal weight.

    Be direct and concrete. Do not repeat the raw rule IDs as if they mean
    something to the reader; explain the actual risk instead.
    """
)


class AIExplainerError(RuntimeError):
    """Raised when the AI explanation layer can't run (e.g. no project configured)."""


def _findings_to_prompt(findings: list[Finding]) -> str:
    lines = []
    for f in findings:
        lines.append(
            f"- [{f.severity.value}] {f.rule_id} — {f.resource_address}\n"
            f"  Issue: {f.message}\n"
            f"  Suggested fix: {f.remediation}"
        )
    return "\n".join(lines)


def explain_findings(
    findings: list[Finding],
    project: str | None = None,
    location: str = "us-central1",
    model_name: str = "gemini-2.5-flash",
) -> str:
    """
    Send findings to Gemini (via Vertex AI / Gemini Enterprise Agent
    Platform) using the google-genai SDK, and return a human-readable
    report.

    Requires GOOGLE_CLOUD_PROJECT (or the `project` argument) and valid
    Application Default Credentials for that project. Raises
    AIExplainerError with a clear message rather than a raw SDK traceback
    if either is missing, or if the request itself fails.
    """
    if not findings:
        return "No findings — nothing to explain. This configuration passed all checks."

    project = project or os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project:
        raise AIExplainerError(
            "GOOGLE_CLOUD_PROJECT is not set. Export it to use --explain, "
            "e.g.: export GOOGLE_CLOUD_PROJECT=my-gcp-project-id\n"
            "Also ensure Application Default Credentials are configured: "
            "gcloud auth application-default login"
        )

    try:
        from google import genai
    except ImportError as exc:
        raise AIExplainerError(
            "The 'google-genai' package is required for --explain. "
            "Install it with: pip install google-genai"
        ) from exc

    try:
        client = genai.Client(vertexai=True, project=project, location=location)
        prompt = f"{SYSTEM_PROMPT}\n\nFindings from this scan:\n\n{_findings_to_prompt(findings)}"
        response = client.models.generate_content(model=model_name, contents=prompt)
    except Exception as exc:
        raise AIExplainerError(
            f"Gen AI / Vertex AI request failed: {exc}\n"
            "Check that the Vertex AI API is enabled on this project "
            "(shown as 'Gemini Enterprise Agent Platform' / "
            "aiplatform.googleapis.com in the console), your ADC identity "
            "has appropriate access, and the region "
            f"'{location}' supports {model_name}."
        ) from exc

    return response.text.strip()
