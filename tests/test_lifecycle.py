import json
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

from pipeline.lifecycle import (
    EvidenceClaim, PipelineState, RunLedger, failure_fingerprint,
    normalize_diagnostic, sha256_text,
    command_version,
)


class LifecycleTests(unittest.TestCase):
    def test_transition_writes_structured_evidence_and_event(self):
        events = []
        with tempfile.TemporaryDirectory() as directory:
            ledger = RunLedger(Path(directory), events.append)
            transition = ledger.record(PipelineState.CANDIDATE, "PROPOSED",
                claim=EvidenceClaim.TRANSFORMATION,
                details={"candidate_hash": sha256_text("code")},
                evidence={"source": "code"})
            payload = json.loads(Path(transition.evidence_path).read_text())
        self.assertEqual(payload["state"], "CANDIDATE")
        self.assertEqual(payload["claim"], "TRANSFORMATION")
        self.assertEqual(events[0]["type"], "pipeline_transition")

    def test_failure_fingerprint_is_backend_and_context_aware(self):
        first = failure_fingerprint("openjml", "Postcondition", "withdraw", 12,
                                    "/tmp/a.java: error   cannot prove")
        same = failure_fingerprint("openjml", "Postcondition", "withdraw", 12,
                                   "C:\\work\\a.java: error cannot prove")
        other = failure_fingerprint("prusti", "Postcondition", "withdraw", 12,
                                    "/tmp/a.java: error cannot prove")
        self.assertEqual(first, same)
        self.assertNotEqual(first, other)

    def test_diagnostic_normalization_removes_noise(self):
        self.assertEqual(normalize_diagnostic("  ERROR   at line 42 "),
                         "error at line <n>")

    def test_command_version_normalizes_empty_and_unavailable_tools(self):
        with patch("pipeline.lifecycle.subprocess.run", return_value=SimpleNamespace(
                stdout="", stderr="", returncode=7)):
            self.assertEqual(command_version(["tool", "--version"]), "exit 7")
        with patch("pipeline.lifecycle.subprocess.run", side_effect=OSError("missing")):
            self.assertEqual(command_version(["missing"]), "unavailable: missing")


if __name__ == "__main__":
    unittest.main()
