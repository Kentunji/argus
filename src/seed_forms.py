"""Load user-declared forms from a YAML file.

The static crawler can't see SPA-rendered forms or REST endpoints not
linked from HTML. Seed forms let the user declare these manually so
detectors get coverage of the real attack surface.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from src.crawler import Form, FormInput
from src.logger import get_logger

log = get_logger(__name__)


class SeedFormsError(Exception):
    """Raised when seed_forms.yml is malformed."""


def load_seed_forms(path: Path | None) -> list[Form]:
    """Load forms from `path`. Returns [] if path is None or doesn't exist."""
    if path is None:
        return []
    if not path.exists():
        log.info("Seed forms file not found at %s — skipping", path)
        return []

    try:
        with path.open() as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as exc:
        raise SeedFormsError(f"Failed to parse {path}: {exc}") from exc

    raw_forms = data.get("forms", [])
    if not isinstance(raw_forms, list):
        raise SeedFormsError(f"'forms' must be a list in {path}")

    forms: list[Form] = []
    for idx, raw in enumerate(raw_forms):
        try:
            action = raw["action"]
            method = raw.get("method", "GET").upper()
            raw_inputs = raw.get("inputs", [])
            inputs = tuple(
                FormInput(
                    name=i["name"],
                    type=i.get("type", "text"),
                    value=i.get("value", ""),
                )
                for i in raw_inputs
            )
        except (KeyError, TypeError) as exc:
            raise SeedFormsError(
                f"Form #{idx} in {path} is malformed: {exc}"
            ) from exc

        forms.append(
            Form(
                action=action,
                method=method if method in ("GET", "POST") else "GET",
                inputs=inputs,
                source_page=f"seed_forms.yml#{idx}",
            )
        )

    log.info("Loaded %d seed form(s) from %s", len(forms), path)
    return forms
