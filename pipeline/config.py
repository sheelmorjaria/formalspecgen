# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Runtime config. Reads a gitignored .env at the project root for secrets.

Ported from formalspecDD (unchanged in shape); OPENJML points at the symlinked
dist under tools/openjml-dist.
"""
import os
import sys
from pathlib import Path

# Frozen application data is read-only and may be extracted to a temporary directory.
# Keep generated run evidence in the explicit per-user application directory.
BUNDLE_ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
ROOT = Path(os.environ.get("FORMALSPECGEN_HOME", str(BUNDLE_ROOT))).resolve()


def resource_path(*parts: str) -> Path:
    """Resolve immutable application data in source, target, or venv installs."""
    relative = Path(*parts)
    candidates = (ROOT / relative, Path(sys.prefix).resolve() / relative)
    return next((path for path in candidates if path.exists()), candidates[0])


def load_env(path=None):
    p = Path(path) if path else ROOT / ".env"
    if not p.exists():
        return
    for ln in p.read_text().splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#") and "=" in ln:
            k, v = ln.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


load_env()

# OpenJML (repository-local distribution by default; runs with no environment overrides)
OPENJML = os.environ.get("OPENJML_BIN", str(ROOT / "tools/openjml-dist/openjml"))
CHECK_TIMEOUT = int(os.environ.get("CHECK_TIMEOUT", "60"))   # -parse/-check wall clock
ESC_TIMEOUT = int(os.environ.get("ESC_TIMEOUT", "180"))      # -esc wall clock (deep check)
LLM_TIMEOUT = int(os.environ.get("LLM_TIMEOUT", "240"))      # reasoning models can be slow
LLM_MAX_TOKENS = int(os.environ.get("LLM_MAX_TOKENS", "8192"))  # structured output ceiling

# Dafny boundary backend. The user-space tool needs its colocated .NET runtime exposed.
DAFNY_BIN = os.environ.get("DAFNY_BIN", str(Path.home() / ".dotnet" / "tools" / "dafny"))
DOTNET_ROOT = os.environ.get("DOTNET_ROOT", str(Path.home() / ".dotnet"))
DAFNY_TIMEOUT = int(os.environ.get("DAFNY_TIMEOUT", "180"))

# Runtime Assertion Checking / generated JUnit evidence.
OPENJML_HOME = os.environ.get("OPENJML_HOME", str(Path(OPENJML).resolve().parent))
# Passing this explicitly avoids relying on the platform launcher to infer its
# installation root.  That inference is particularly fragile when a .bat file is
# launched by a frozen Python process hosted by VS Code on Windows.
OPENJML_SPECS = os.environ.get("OPENJML_SPECS", str(Path(OPENJML_HOME) / "specs"))
OPENJML_JAVA = os.environ.get("OPENJML_JAVA", f"{OPENJML_HOME}/jdk/bin/java")
JMLRUNTIME = os.environ.get("JMLRUNTIME", f"{OPENJML_HOME}/jmlruntime.jar")
JAVAC = os.environ.get("JAVAC", "javac")
JUNIT_JAR = os.environ.get(
    "JUNIT_JAR", str(ROOT / "tools" / "lib" /
                     "junit-platform-console-standalone-1.9.3.jar"))
RAC_TIMEOUT = int(os.environ.get("RAC_TIMEOUT", "180"))

# TLA+/TLC targeted concurrency backend.
TLC_JAR = os.environ.get("TLC_JAR", str(ROOT / "tools" / "tla2tools.jar"))
TLC_TIMEOUT = int(os.environ.get("TLC_TIMEOUT", "60"))
JAVA_BIN = os.environ.get("JAVA_BIN", "java")
# TLAPS is installed as a repository-local, self-contained distribution so its
# Isabelle and backend dependencies do not alter the host environment.
TLAPM_BIN = os.environ.get("TLAPM_BIN", str(ROOT / ".tools" / "bin" / "tlapm"))

# Experimental Prusti lane. The extension installs the verifier and its pinned rustup
# toolchain into global storage; CLI users may point at an existing prusti-rustc.
PRUSTI_BIN = os.environ.get("PRUSTI_BIN", str(ROOT / "tools" / "prusti" / "prusti-rustc"))
RUSTC_BIN = os.environ.get("RUSTC_BIN", "rustc")
PRUSTI_TIMEOUT = int(os.environ.get("PRUSTI_TIMEOUT", "180"))
# The generic Kani lane appends the `kani` subcommand when using Cargo.
# `cargo-kani` is the installed plugin binary, not the invocation contract.
KANI_BIN = os.environ.get("KANI_BIN", "cargo")
KANI_TIMEOUT = int(os.environ.get("KANI_TIMEOUT", "180"))
FRAMAC_BIN = os.environ.get(
    "FRAMAC_BIN", str(ROOT / "tools" / "frama-c-33.0" / "bin" / "frama-c"))
FRAMAC_TIMEOUT = int(os.environ.get("FRAMAC_TIMEOUT", "180"))
FRAMAC_PROVERS = os.environ.get("FRAMAC_PROVERS", "z3")
CC_BIN = os.environ.get("CC_BIN", "gcc")

# Foundational Rust judges. RefinedRust is intentionally invoked through an
# isolated opam switch so its Rocq/Iris dependencies cannot contaminate the
# application's Python or system-Rocq environments.
OPAM_BIN = os.environ.get("OPAM_BIN", "opam")
REFINEDRUST_SWITCH = os.environ.get("REFINEDRUST_SWITCH", "refinedrust")
REFINEDRUST_BOUNDARY_LEDGER = os.environ.get(
    "REFINEDRUST_BOUNDARY_LEDGER",
    str(ROOT / "examples" / "formalkernel" / "kernel" / "refinement" /
        "refinedrust_boundary_ledger.json"))
VERUS_BIN = os.environ.get(
    "VERUS_BIN", str(ROOT / ".tools" / "verus-download" /
                     "verus-x86-linux" / "verus"))
VERUS_BOUNDARY_LEDGER = os.environ.get(
    "VERUS_BOUNDARY_LEDGER",
    str(ROOT / "examples" / "formalkernel" / "kernel" / "verus_allocator" /
        "bridges" / "evidence.json"))

# GLM / Zhipu BigModel (OpenAI-compatible v4 API)
GLM_API_KEY = os.environ.get("GLM_API_KEY", "")
GLM_BASE_URL = os.environ.get("GLM_BASE_URL", "https://api.z.ai/api/paas/v4").rstrip("/")
GLM_MODEL = os.environ.get("GLM_MODEL", "glm-4.5-flash")
# z.ai reasoning models do deep thinking by default, which burns tokens (truncating the
# answer at low max_tokens) and time (gateway 524 at high max_tokens). We validate
# externally with OpenJML, so disable it by default. Set GLM_THINKING=enabled to restore.
GLM_THINKING = os.environ.get("GLM_THINKING", "disabled")   # "disabled" | "enabled"

# OpenAI (provider-swappable + fallback — ported from formalspecDD)
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")

# Ollama (local, free, unlimited — OpenAI-compatible API)
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1").rstrip("/")
OLLAMA_API_KEY = os.environ.get("OLLAMA_API_KEY", "ollama")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3-coder:30b")
OLLAMA_STRUCTURED_THINKING = os.environ.get(
    "OLLAMA_STRUCTURED_THINKING", "disabled").strip().lower()
OLLAMA_NUM_PREDICT = int(os.environ.get("OLLAMA_NUM_PREDICT", "8192"))
OLLAMA_NUM_CTX = int(os.environ.get("OLLAMA_NUM_CTX", "16384"))
