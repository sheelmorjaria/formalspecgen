try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 compatibility
    import tomli as tomllib
from pathlib import Path

import pytest

from pipeline import __version__
from pipeline.cli import build_parser


def test_cli_and_distribution_versions_share_package_source(capsys):
    assert __version__ == "1.2.1"
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["dynamic"] == ["version"]
    assert project["tool"]["setuptools"]["dynamic"]["version"] == {
        "attr": "pipeline.__version__"}
    with pytest.raises(SystemExit) as stopped:
        build_parser().parse_args(["--version"])
    assert stopped.value.code == 0
    assert capsys.readouterr().out.strip() == f"formalspecgen {__version__}"
