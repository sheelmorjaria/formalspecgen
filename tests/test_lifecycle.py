import hashlib
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

    def test_ledger_commits_once_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = RunLedger(root)
            transition = ledger.record(
                PipelineState.PROOF, "VERIFIED", claim=EvidenceClaim.DEDUCTIVE_PROOF,
                evidence={"source_sha256": sha256_text("source")})
            self.assertEqual(RunLedger.validate(root)["status"], "INCOMPLETE")
            manifest = ledger.commit({"final_status": "VERIFIED", "claim": "DEDUCTIVE_PROOF"})
            self.assertTrue(manifest.is_file())
            self.assertEqual(RunLedger.validate(root)["status"], "VALID")
            with self.assertRaises(RuntimeError):
                ledger.record(PipelineState.PROOF, "AGAIN", claim=EvidenceClaim.NO_PROOF)
            with self.assertRaises(RuntimeError):
                ledger.commit({"final_status": "AGAIN"})

            artifact = Path(transition.evidence_path)
            artifact.chmod(0o644)
            artifact.write_text("{}", encoding="utf-8")
            self.assertEqual(RunLedger.validate(root)["status"], "INVALID")

    def test_ledger_refuses_commit_after_prepublication_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = RunLedger(root)
            transition = ledger.record(
                PipelineState.PROOF, "VERIFIED", claim=EvidenceClaim.DEDUCTIVE_PROOF)
            Path(transition.evidence_path).unlink()
            with self.assertRaises(RuntimeError, msg="unavailable"):
                ledger.commit({"final_status": "VERIFIED"})

    def test_ledger_validation_rejects_malformed_manifest_and_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = RunLedger(root)
            manifest_path = ledger.commit({"final_status": "DONE"})
            manifest_path.write_text("not-json", encoding="utf-8")
            self.assertEqual(RunLedger.validate(root)["status"], "INVALID")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = RunLedger(root)
            manifest_path = ledger.commit({"final_status": "DONE"})
            manifest_path.write_text("{}", encoding="utf-8")
            self.assertIn("schema", RunLedger.validate(root)["message"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = RunLedger(root)
            manifest_path = ledger.commit({"final_status": "DONE"})
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            payload["artifacts"] = [{"path": "../outside", "size": 0, "sha256": ""}]
            manifest_path.write_text(json.dumps(payload), encoding="utf-8")
            result = RunLedger.validate(root)
            self.assertEqual(result["status"], "INVALID")
            self.assertIn("invalid evidence artifact path", result["message"])

    def test_ledger_validation_binds_artifacts_to_run_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = RunLedger(root)
            manifest_path = ledger.commit({"final_status": "DONE"})
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            run_path = root / "evidence" / "run.json"
            run_payload = json.loads(run_path.read_text(encoding="utf-8"))
            run_payload["run_id"] = "different-run"
            encoded = json.dumps(
                run_payload, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8")
            run_path.write_bytes(encoded)
            manifest["artifacts"][0]["size"] = len(encoded)
            manifest["artifacts"][0]["sha256"] = hashlib.sha256(encoded).hexdigest()
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            result = RunLedger.validate(root)
            self.assertEqual(result["status"], "INVALID")
            self.assertIn("identity mismatch", result["message"])

    def test_artifact_inventory_validation_rejects_empty_malformed_and_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertIn("no artifact", RunLedger._validate_artifacts(root, []))
            self.assertIn("malformed", RunLedger._validate_artifacts(root, [{}]))
            content = b"{}"
            (root / "a.json").write_bytes(content)
            record = {"path": "a.json", "size": len(content),
                      "sha256": hashlib.sha256(content).hexdigest()}
            self.assertIn(
                "duplicate", RunLedger._validate_artifacts(root, [record, record]))

    def test_ledger_validation_rejects_invalid_payloads_and_hash_chain(self):
        cases = [
            ("transition", b"not-json", "Expecting value"),
            ("transition", b"[]", "not an object"),
            ("run", None, "run identity artifact"),
            ("chain", None, "hash chain"),
        ]
        for mode, replacement, expected in cases:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                ledger = RunLedger(root)
                ledger.record(
                    PipelineState.PROOF, "VERIFIED",
                    claim=EvidenceClaim.DEDUCTIVE_PROOF)
                manifest_path = ledger.commit({"final_status": "DONE"})
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                index = 0 if mode == "run" else 1
                artifact_path = root / "evidence" / manifest["artifacts"][index]["path"]
                if mode == "run":
                    payload = json.loads(artifact_path.read_text(encoding="utf-8"))
                    payload["schema"] = "wrong-schema"
                    replacement = json.dumps(
                        payload, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8")
                elif mode == "chain":
                    payload = json.loads(artifact_path.read_text(encoding="utf-8"))
                    payload["previous_artifact_sha256"] = "0" * 64
                    replacement = json.dumps(
                        payload, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8")
                artifact_path.write_bytes(replacement)
                manifest["artifacts"][index]["size"] = len(replacement)
                manifest["artifacts"][index]["sha256"] = hashlib.sha256(
                    replacement).hexdigest()
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                result = RunLedger.validate(root)
                self.assertEqual(result["status"], "INVALID")
                self.assertIn(expected, result["message"])

    def test_ledger_run_identity_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            RunLedger(root)
            with self.assertRaises(FileExistsError):
                RunLedger(root)

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
