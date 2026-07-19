"""
vertex_explainer.py — Optional AI explanation layer using Vertex AI (Gemini).

This uses the real Vertex AI SDK (google-cloud-aiplatform), authenticated via
a GCP project + Application Default Credentials — not the simpler consumer
Gemini API (which only needs an API key). That distinction is deliberate:
Vertex AI is what's actually used in enterprise GCP environments, where
access is governed by IAM and audit-logged like any other GCP API call,
which is the same authentication model used in production environments.

Requires:
    - A GCP project with the Vertex AI API enabled
    - Application Default Credentials configured (`gcloud auth application-default login`,
      or a service account key / workload identity in CI)
    - GOOGLE_CLOUD_PROJECT environment variable set

This module could not be tested against the live Vertex AI API from the
environment this was built in (no network path to *.googleapis.com), so the
request/response shape has been double-checked against Google's documented
SDK usage but has not been run end-to-end. The graceful-degradation paths
(missing project, missing SDK) are tested. Verify the first live call
against your own GCP project before relying on this in an interview demo.
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
    model_name: str = "gemini-2.0-flash-001",
) -> str:
    """
    Send findings to Vertex AI (Gemini) and return a human-readable report.

    Requires GOOGLE_CLOUD_PROJECT (or the `project` argument) and valid
    Application Default Credentials for that project. Raises
    AIExplainerError with a clear message rather than a raw SDK traceback
    if either is missing.
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
        import vertexai
        from vertexai.generative_models import GenerativeModel
    except ImportError as exc:
        raise AIExplainerError(
            "The 'google-cloud-aiplatform' package is required for --explain. "
            "Install it with: pip install google-cloud-aiplatform"
        ) from exc

    try:
        vertexai.init(project=project, location=location)
        model = GenerativeModel(model_name)
        prompt = f"{SYSTEM_PROMPT}\n\nFindings from this scan:\n\n{_findings_to_prompt(findings)}"
        response = model.generate_content(prompt)
    except Exception as exc:
        # Vertex AI raises various google.api_core exceptions depending on the
        # failure (auth, quota, region availability, etc). Surface them
        # through our own error type with the original message intact rather
        # than letting a raw SDK exception propagate.
        raise AIExplainerError(
            f"Vertex AI request failed: {exc}\n"
            "Check that the Vertex AI API is enabled on this project, your "
            "ADC identity has the Vertex AI User role, and the region "
            f"'{location}' supports {model_name}."
        ) from exc

    return response.text.strip()
