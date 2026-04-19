"""Tests for the seed forms loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.seed_forms import SeedFormsError, load_seed_forms


def test_load_returns_empty_when_path_is_none() -> None:
    assert load_seed_forms(None) == []


def test_load_returns_empty_when_file_missing(tmp_path: Path) -> None:
    assert load_seed_forms(tmp_path / "does-not-exist.yml") == []


def test_load_parses_minimal_form(tmp_path: Path) -> None:
    yaml_path = tmp_path / "seed.yml"
    yaml_path.write_text(
        """
forms:
  - action: http://target.test/login
    method: POST
    inputs:
      - name: email
        type: email
      - name: password
        type: password
"""
    )
    forms = load_seed_forms(yaml_path)
    assert len(forms) == 1
    assert forms[0].action == "http://target.test/login"
    assert forms[0].method == "POST"
    assert [i.name for i in forms[0].inputs] == ["email", "password"]


def test_load_raises_on_malformed_yaml(tmp_path: Path) -> None:
    yaml_path = tmp_path / "bad.yml"
    yaml_path.write_text("forms: [not a dict")
    with pytest.raises(SeedFormsError):
        load_seed_forms(yaml_path)


def test_load_raises_when_form_missing_required_key(tmp_path: Path) -> None:
    yaml_path = tmp_path / "bad.yml"
    yaml_path.write_text(
        """
forms:
  - method: POST
    inputs: []
"""
    )
    with pytest.raises(SeedFormsError):
        load_seed_forms(yaml_path)
