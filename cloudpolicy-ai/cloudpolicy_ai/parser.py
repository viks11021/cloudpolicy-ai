"""
parser.py

Parses Terraform (.tf) files into a normalised list of resource dicts that
the rule engine can evaluate. Provider-agnostic — works for any resource
type, GCP included.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field
from typing import Any


def _strip_quotes(value: str) -> str:
    """hcl2 v8+ leaves literal double-quote characters around string leaves
    and dict/block keys (e.g. the key '"google_storage_bucket"' instead of
    'google_storage_bucket'). Strip them so rule code can compare against
    plain strings."""
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


@dataclass
class TerraformResource:
    """A single parsed Terraform resource, normalised for rule evaluation."""

    resource_type: str          # e.g. "google_storage_bucket"
    resource_name: str          # e.g. "data_lake"
    attributes: dict[str, Any] = field(default_factory=dict)
    file_path: str = ""

    @property
    def address(self) -> str:
        """Terraform-style resource address, e.g. google_storage_bucket.data_lake"""
        return f"{self.resource_type}.{self.resource_name}"


def _flatten_attr_value(value: Any) -> Any:
    """
    python-hcl2 wraps many attribute values in single-item lists because HCL
    blocks can technically repeat, and (as of v8) leaves literal quotes on
    string leaves/keys and injects '__is_block__' markers into block dicts.
    Normalise all of that away so rule-writing can assume plain Python
    types: unwrapped scalars, clean dict keys, no marker keys.
    """
    if isinstance(value, list) and len(value) == 1:
        return _flatten_attr_value(value[0])
    if isinstance(value, dict):
        return {
            _strip_quotes(k): _flatten_attr_value(v)
            for k, v in value.items()
            if k not in ("__is_block__", "__comments__", "__start_line__", "__end_line__")
        }
    if isinstance(value, str):
        return _strip_quotes(value)
    return value


def parse_file(path: str) -> list[TerraformResource]:
    """Parse a single .tf file into a list of TerraformResource objects."""
    import hcl2

    resources: list[TerraformResource] = []

    with open(path, "r", encoding="utf-8") as f:
        try:
            data = hcl2.load(f)
        except Exception as exc:  # pragma: no cover - surfaced to caller
            raise ValueError(f"Failed to parse {path}: {exc}") from exc

    for resource_block in data.get("resource", []):
        for resource_type, named_resources in resource_block.items():
            resource_type = _strip_quotes(resource_type)
            for resource_name, attrs in named_resources.items():
                resource_name = _strip_quotes(resource_name)
                flat_attrs = _flatten_attr_value(attrs)
                resources.append(
                    TerraformResource(
                        resource_type=resource_type,
                        resource_name=resource_name,
                        attributes=flat_attrs if isinstance(flat_attrs, dict) else {},
                        file_path=path,
                    )
                )

    return resources


def parse_directory(directory: str) -> list[TerraformResource]:
    """Parse every .tf file in a directory (non-recursive by default)."""
    tf_files = sorted(glob.glob(os.path.join(directory, "*.tf")))
    if not tf_files:
        raise FileNotFoundError(f"No .tf files found in {directory}")

    all_resources: list[TerraformResource] = []
    for tf_file in tf_files:
        all_resources.extend(parse_file(tf_file))
    return all_resources
