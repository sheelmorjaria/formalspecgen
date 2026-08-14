"""Optional MCP façade for FormalSpecGen's structured verification workflows.

Install the optional SDK with ``pip install 'formalspecgen[mcp]'``.  The core functions in this
module remain importable without the SDK, which keeps the CLI and test environments lightweight.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - exercised by environments without the optional SDK
    FastMCP = None

from pipeline import config
from pipeline.java_inspection import inspect_java_file
from pipeline.orchestrator import run_implementation_loop
from pipeline.verify import verify


def _workspace_path(value: str, *, must_exist: bool = True) -> Path:
    root = Path.cwd().resolve()
    path = Path(value).expanduser()
    path = (root / path).resolve() if not path.is_absolute() else path.resolve()
    if root != path and root not in path.parents:
        raise ValueError("path must remain inside the current workspace")
    if must_exist and not path.exists():
        raise FileNotFoundError(str(path))
    return path


def verify_code(file_path: str, mode: str = "esc") -> dict[str, Any]:
    """Verify Java, Rust, or C source and return a structured verdict."""
    path = _workspace_path(file_path)
    suffix = path.suffix.lower()
    if suffix in {".java", ".jml"}:
        exit_code, output = verify(path, mode=mode)
        return {"status": "VERIFIED" if exit_code == 0 else "VERIFY_FAILED",
                "claim": "DEDUCTIVE_PROOF" if exit_code == 0 and mode == "esc" else "NO_PROOF",
                "exit_code": exit_code, "mode": mode, "file": str(path), "output": output}
    if suffix == ".rs":
        from pipeline.verify_rust import verify_rust
        result = verify_rust(path.read_text(encoding="utf-8"), mode=mode, backend="prusti")
    elif suffix == ".c":
        from pipeline.verify_c import verify_c as verify_c_source
        result = verify_c_source(path.read_text(encoding="utf-8"), mode=mode)
    else:
        return {"status": "UNSUPPORTED_LANGUAGE", "claim": "NO_PROOF", "file": str(path)}
    return {"file": str(path), **result}


def validate_architecture(artifact_path: str, timeout: int = 120) -> dict[str, Any]:
    """Validate a unified architecture through its typed model and TLC gate."""
    from pipeline.architecture_tla_renderer import render_unified_architecture
    from pipeline.staged_architecture import UnifiedArchitecture
    from pipeline.architecture_tlc_gate import validate_architecture_with_tlc
    path = _workspace_path(artifact_path)
    try:
        architecture = UnifiedArchitecture.model_validate(json.loads(path.read_text(encoding="utf-8")))
        tla, cfg = render_unified_architecture(architecture)
        with tempfile.TemporaryDirectory(prefix="formalspecgen-mcp-") as directory:
            root = Path(directory)
            tla_path, cfg_path = root / "architecture.tla", root / "architecture.cfg"
            tla_path.write_text(tla, encoding="utf-8"); cfg_path.write_text(cfg, encoding="utf-8")
            result = validate_architecture_with_tlc(tla_path, cfg_path, config.TLC_JAR,
                                                    config.JAVA_BIN, timeout)
        return {"artifact": str(path), **result}
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return {"status": "ARCHITECTURE_INVALID", "claim": "NO_PROOF", "message": str(exc)}


def implement_code(spec_path: str, provider: str = "ollama",
                   assurance_level: str = "critical") -> dict[str, Any]:
    """Run the native implementation loop for a workspace source/spec scaffold."""
    path = _workspace_path(spec_path)
    return run_implementation_loop(path, provider=provider, assurance_level=assurance_level)


def inspect_code(file_path: str) -> dict[str, Any]:
    """Run deterministic Java modernization inspection."""
    return inspect_java_file(_workspace_path(file_path))


def create_server():
    if FastMCP is None:
        raise RuntimeError("MCP SDK is not installed; install with: pip install 'formalspecgen[mcp]'")
    server = FastMCP("FormalSpecGen")
    server.tool()(verify_code)
    server.tool()(validate_architecture)
    server.tool()(implement_code)
    server.tool()(inspect_code)
    return server


if __name__ == "__main__":
    create_server().run()
