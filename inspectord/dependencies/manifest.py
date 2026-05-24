"""Manifest YAML loader.

Each manifest file lives under `inspectord/dependencies/manifest_files/<name>.yaml`
and is loaded via `importlib.resources`. External (test) manifests are loaded
from a path.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import yaml
from pydantic import ValidationError

from inspectord.dependencies.schemas import DependencyManifest


class ManifestLoadError(RuntimeError):
    """Raised when a manifest YAML is missing, malformed, or schema-invalid."""


def _load(text: str, source: str) -> DependencyManifest:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ManifestLoadError(f"{source}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestLoadError(f"{source}: top-level YAML must be a mapping")
    try:
        return DependencyManifest.model_validate(data)
    except ValidationError as exc:
        raise ManifestLoadError(f"{source}: schema validation failed:\n{exc}") from exc


def load_manifest_from_path(path: Path) -> DependencyManifest:
    """Load a manifest from a filesystem path. Used by tests."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ManifestLoadError(f"manifest not found: {path}") from exc
    return _load(text, str(path))


def load_packaged_manifests() -> dict[str, DependencyManifest]:
    """Load every YAML manifest shipped under inspectord/dependencies/manifest_files/."""
    result: dict[str, DependencyManifest] = {}
    pkg = files("inspectord.dependencies.manifest_files")
    for entry in pkg.iterdir():
        if not entry.name.endswith(".yaml"):
            continue
        text = entry.read_text(encoding="utf-8")
        m = _load(text, entry.name)
        result[m.name] = m
    return result
