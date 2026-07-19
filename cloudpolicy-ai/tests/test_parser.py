import os

import pytest

from cloudpolicy_ai.parser import parse_directory, parse_file

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def test_parse_file_extracts_resources():
    resources = parse_file(os.path.join(FIXTURE_DIR, "simple.tf"))
    assert len(resources) == 2
    types = {r.resource_type for r in resources}
    assert "google_storage_bucket" in types
    assert "google_compute_firewall" in types


def test_resource_address_format():
    resources = parse_file(os.path.join(FIXTURE_DIR, "simple.tf"))
    addresses = {r.address for r in resources}
    assert "google_storage_bucket.example" in addresses


def test_parse_directory_raises_on_empty_dir(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse_directory(str(tmp_path))


def test_parse_directory_reads_all_tf_files():
    resources = parse_directory(
        os.path.join(os.path.dirname(__file__), "..", "examples", "vulnerable-gcp-infra")
    )
    assert len(resources) == 7
