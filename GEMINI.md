# AWS Discovery Tool

Using AWS CLI, assume environmnet variables
- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY
- AWS_SESSION_TOKEN

# Types of Operations
- ALWAYS ask for confirmation for any DELETION operations

# Script Generation

- **Bash First:** Use for simple one-liners or basic resource listing. Use `jq` for filtering.
- **Python for Logic:** Fall back to Python for complex data transformation or cross-service analysis.
- **Portability:** Use `uv` for Python scripts. Always include inline dependency metadata.
- **CLI Structure:**
    - Support `--region` and `--profile` flags.
    - Default to `STDOUT` for reports.
    - Implement a `--json` flag for machine-readable output.

# Account Review Patterns

- **Read-Only:** Ensure scripts only use `get-*`, `list-*`, and `describe-*` operations.
- **Summary First:** Always provide a high-level summary (counts, status) before listing raw resource details.
- **Categorization:** Group findings by risk level (High/Med/Low) or service.
- **Parallelization:** Use `boto3` with concurrent futures for multi-region or multi-account checks.

# NEVER EVER DO THIS
- hardcode secrets in scripts
- Include `Delete*` or `Terminate*` calls in "Review" tools.

## Python Guidance

Use `uv run` with script headers for zero-install execution:

```python
# /// script
# dependencies = ["boto3", "click"]
# ///
import boto3
import click

@click.command()
@click.option("--region", default="us-east-1")
def review(region):
    session = boto3.Session(region_name=region)
    # ... review logic
```

# Outputs

## Work log

Maintain a timestamped work log in the top level directory - `discovery-YY-MM-DD.md`

## JSON
Store data as JSON in a heirarchal folder structure that takes into `account/region/resource/` where artifacts are put


## Diagraming

Use `diagrams` which may be installed by `uv pip install diagrams`
