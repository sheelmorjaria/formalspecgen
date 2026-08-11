import unittest
from unittest.mock import patch

from pipeline import handoff


class HandoffRuntimeTests(unittest.TestCase):
    def test_configured_dd_python_is_authoritative(self):
        with patch.dict("os.environ", {"FORMALSPEC_DD_PYTHON": r"C:\Python311\python.exe"}):
            self.assertEqual(handoff._dd_python(), r"C:\Python311\python.exe")

    def test_source_runtime_uses_current_interpreter(self):
        with patch.dict("os.environ", {}, clear=True), patch.object(handoff.sys, "frozen", False,
                                                                    create=True):
            self.assertEqual(handoff._dd_python(), handoff.sys.executable)

    def test_frozen_runtime_uses_platform_python_launcher(self):
        with patch.dict("os.environ", {}, clear=True), patch.object(
                handoff.sys, "frozen", True, create=True):
            with patch.object(handoff.os, "name", "posix"):
                self.assertEqual(handoff._dd_python(), "python3")
            with patch.object(handoff.os, "name", "nt"):
                self.assertEqual(handoff._dd_python(), "python")


if __name__ == "__main__":
    unittest.main()
