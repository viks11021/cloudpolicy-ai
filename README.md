# gcp-compliance-scanner

A Terraform GCP infrastructure compliance scanner with an optional
**Vertex AI (Gemini)** explanation layer.

Companion project to [compliance-scanner](https://github.com/<your-username>/compliance-scanner)
(AWS + Anthropic). This one targets GCP resource types and uses real
Vertex AI — GCP project + Application Default Credentials, not just an API
key — the same authentication model used for production GCP workloads.

This directly mirrors work automating GCP project design compliance reviews
in production — a manual review process that used to take 2-3 days brought
down to about 20 minutes with an AI-assisted checklist. This is a
from-scratch, open-source reimplementation of that idea, built to be
inspectable and extensible.

## Quick start

```bash
git clone https://github.com/<your-username>/gcp-compliance-scanner.git
cd gcp-compliance-scanner
pip install -e .

# Scan the intentionally-vulnerable example
gcp-compliance-scanner scan examples/vulnerable-gcp-infra
```

### Vertex AI explanation layer

```bash
pip install -e ".[ai]"

# Requires a GCP project with the Vertex AI API enabled, and
# Application Default Credentials configured:
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=your-gcp-project-id

gcp-compliance-scanner scan examples/vulnerable-gcp-infra --explain
```

`--explain` is entirely optional — the scanner works fully without it, no
GCP project or credentials required for a plain scan.

### CI usage

```bash
gcp-compliance-scanner scan ./terraform --fail-on CRITICAL --format json --output report.json
```

## What it checks

| Area | Rules |
|---|---|
| Cloud Storage | Uniform bucket-level access, public IAM members (allUsers/allAuthenticatedUsers), versioning |
| VPC Firewall | Sensitive ports (SSH/RDP/DB) open to 0.0.0.0/0, allow-all protocol rules |
| IAM | Primitive roles (Owner/Editor), public project-level access |
| Cloud SQL | Public IP exposure, automated backups |
| Labels | Required labels present (environment, owner) |

## Architecture

```
.tf files → parser.py → TerraformResource[] → scanner.py → rules/*.py → Finding[]
                                                                              │
                                              ┌───────────────────────────────┤
                                              ▼                               ▼
                                        report.py                  vertex_explainer.py
                                   (console/JSON/Markdown)      (optional, needs GCP project
                                                                  + Application Default Credentials)
```

Same pipeline shape as the AWS/Anthropic sibling project — parser and rule
engine are the reusable core, only the rule set and the AI backend differ.

## Vertex AI vs. the simpler Gemini API — why this matters

This project deliberately uses the **Vertex AI SDK**
(`google-cloud-aiplatform`), not the simpler consumer Gemini API. They are
different products:

| | Vertex AI | Gemini API (AI Studio) |
|---|---|---|
| Auth | GCP project + Application Default Credentials | API key |
| Access control | IAM roles, audit-logged like any GCP API call | Key-based only |
| Typical use | Enterprise / production GCP environments | Prototyping, personal projects |

Using Vertex AI here means the auth flow, error handling, and permissions
model match what you'd actually deal with running this against a real
company GCP project — not a simplified stand-in.

## Known limitations

- **`jsonencode(...)` and other Terraform functions are not evaluated** —
  this is a static parser, not a Terraform interpreter.
- **No cross-resource / `for_each` evaluation** — each resource block is
  checked independently.
- **The Vertex AI integration has not been run against a live GCP project**
  from the environment this was built in (no network path to
  `*.googleapis.com` available). The request/response shape matches
  Google's documented SDK usage, and the graceful-degradation paths
  (missing project, missing SDK) are tested — but verify the first live
  `--explain` call against your own GCP project before relying on it in a
  demo or interview.

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

31 tests, 91% coverage.

## License

MIT — see [LICENSE](LICENSE).
