import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline import config, verify


class VerifyToolConfigurationTests(unittest.TestCase):
    def test_missing_env_file_is_ignored(self):
        config.load_env(Path(tempfile.gettempdir()) / "formalspecgen-no-such-env")

    def test_explicit_specs_path_is_passed_to_openjml(self):
        with tempfile.TemporaryDirectory() as root:
            specs = Path(root) / "specs"
            specs.mkdir()
            completed = type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            with patch.object(verify.config, "OPENJML", "openjml"), \
                 patch.object(verify.config, "OPENJML_SPECS", str(specs)), \
                 patch.object(verify.subprocess, "run", return_value=completed) as run:
                exit_code, _ = verify.verify(Path(root) / "Example.java")
            self.assertEqual(exit_code, 0)
            self.assertEqual(
                run.call_args.args[0],
                ["openjml", "-check", "--specs-path", str(specs),
                 str(Path(root) / "Example.java")],
            )

    def test_missing_internal_specs_is_a_tool_error(self):
        completed = type(
            "Completed", (),
            {"returncode": 1, "stdout": "", "stderr":
             "error: Could not find the internal system specifications: null/specs"},
        )()
        with patch.object(verify.config, "OPENJML", "openjml"), \
             patch.object(verify.config, "OPENJML_SPECS", ""), \
             patch.object(verify.subprocess, "run", return_value=completed):
            exit_code, _ = verify.verify("Example.java")
        self.assertEqual(exit_code, verify.TOOL_ERROR_EXIT)
        self.assertEqual(verify.classify(exit_code), "TOOL_ERROR")


if __name__ == "__main__":
    unittest.main()
