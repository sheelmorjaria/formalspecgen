import os
import shutil
from pathlib import Path

import pytest

from pipeline import config


def pytest_addoption(parser):
    parser.addoption("--live-llm", action="store_true", default=False,
                     help="run non-deterministic Ollama E2E tests")


@pytest.fixture
def require_live_llm(request):
    if not request.config.getoption("--live-llm"):
        pytest.skip("pass --live-llm to exercise the configured Ollama service")


def require_tool(executable: str, label: str) -> str:
    path = Path(executable)
    resolved = str(path.resolve()) if path.exists() else shutil.which(executable)
    if not resolved:
        pytest.skip(f"{label} is unavailable: {executable}")
    return resolved


@pytest.fixture
def openjml_tool():
    return require_tool(config.OPENJML, "OpenJML")


@pytest.fixture
def dafny_tool():
    return require_tool(config.DAFNY_BIN, "Dafny")


@pytest.fixture
def framac_tools():
    return (require_tool(config.FRAMAC_BIN, "Frama-C"),
            require_tool(config.CC_BIN, "C compiler"))


@pytest.fixture
def tlc_tool():
    path = Path(config.TLC_JAR)
    if not path.exists():
        pytest.skip(f"TLC is unavailable: {config.TLC_JAR}")
    return str(path.resolve())
