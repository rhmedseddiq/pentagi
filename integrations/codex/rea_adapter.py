"""Optional boundary for future REA compiled-Windows analysis integrations.

PentAGI and the Codex flow runner do not import REA. An adapter is loaded only
when an operator explicitly supplies a Python ``module:factory`` specification.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any, Mapping, Protocol, runtime_checkable


@runtime_checkable
class REAAdapter(Protocol):
    def analyze_windows_binary(
        self, artifact: Path, manifest: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Return structured static/dynamic analysis results for an approved artifact."""


def load_adapter(specification: str) -> REAAdapter:
    """Load a user-supplied ``module:factory`` without making REA a dependency."""
    module_name, separator, factory_name = specification.partition(":")
    if not separator or not module_name or not factory_name:
        raise ValueError("REA adapter must use the module:factory form")
    factory = getattr(importlib.import_module(module_name), factory_name)
    adapter = factory()
    if not isinstance(adapter, REAAdapter):
        raise TypeError("REA adapter factory does not implement analyze_windows_binary")
    return adapter


def analyze_artifact(
    specification: str, artifact: str | Path, manifest: Mapping[str, Any]
) -> Mapping[str, Any]:
    path = Path(artifact).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError("Windows analysis artifact must be a file")
    return load_adapter(specification).analyze_windows_binary(path, manifest)
