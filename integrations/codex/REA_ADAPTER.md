# Optional REA adapter contract

The initial integration targets PentAGI's existing REST/GraphQL flow API. REA is optional and not imported at startup.

Implement a Python factory that returns an object with this method:

```python
def analyze_windows_binary(self, artifact: Path, manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    ...
```

Then load it explicitly:

```python
from integrations.codex.rea_adapter import analyze_artifact

result = analyze_artifact(
    "my_rea_plugin:build_adapter",
    "artifacts/GamingArenaClient.exe",
    {"profile": "gaming-windows-client", "build_id": "test-build-123"},
)
```

The plugin owns REA-specific authentication, file transfer, analysis, and result decoding. The PentAGI flow runner remains usable when the adapter is absent. Implementations should analyze only an operator-provided test build and return structured evidence that can be reviewed and sanitized before joining a PentAGI flow report.
