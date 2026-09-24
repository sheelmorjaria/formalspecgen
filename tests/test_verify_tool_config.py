import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline import config, verify
from pipeline.execution import ExecutionObservation


class FakeExecutor:
    def __init__(self, exit_code=0, output=""):
        self.exit_code = exit_code
        self.output = output
        self.request = None

    def execute(self, request):
        self.request = request
        return ExecutionObservation(
            status="COMPLETED" if self.exit_code == 0 else "TOOL_FAILED",
            exit_code=self.exit_code, output=self.output, requested_policy={},
            enforced_policy={}, policy_compliance="ENFORCED",
            snapshot_manifest_sha256=request.snapshot.manifest_sha256)


class VerifyToolConfigurationTests(unittest.TestCase):
    def test_missing_env_file_is_ignored(self):
        config.load_env(Path(tempfile.gettempdir()) / "formalspecgen-no-such-env")

    def test_explicit_specs_path_is_passed_to_openjml(self):
        with self.subTest():
            from tempfile import TemporaryDirectory
            with TemporaryDirectory() as root:
                root_path = Path(root)
                specs = root_path / "specs"; specs.mkdir()
                tool = root_path / "openjml"; tool.write_text("tool", encoding="utf-8")
                source = root_path / "Example.java"; source.write_text("class Example {}", encoding="utf-8")
                executor = FakeExecutor()
                with patch.object(verify.config, "OPENJML", str(tool)), \
                     patch.object(verify.config, "OPENJML_SPECS", str(specs)):
                    exit_code, _ = verify.verify(source, executor=executor)
                self.assertEqual(exit_code, 0)
                self.assertEqual(
                    list(executor.request.command),
                    [str(tool), "-check", "--specs-path", str(specs.resolve()),
                     "/input/Example.java"],
                )

    def test_missing_internal_specs_is_a_tool_error(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as root:
            root_path = Path(root)
            tool = root_path / "openjml"; tool.write_text("tool", encoding="utf-8")
            source = root_path / "Example.java"; source.write_text("class Example {}", encoding="utf-8")
            executor = FakeExecutor(
                exit_code=1,
                output="error: Could not find the internal system specifications: null/specs")
            with patch.object(verify.config, "OPENJML", str(tool)), \
                 patch.object(verify.config, "OPENJML_SPECS", ""):
                exit_code, _ = verify.verify(source, executor=executor)
            self.assertEqual(exit_code, verify.TOOL_ERROR_EXIT)
            self.assertEqual(verify.classify(exit_code), "TOOL_ERROR")


if __name__ == "__main__":
    unittest.main()
