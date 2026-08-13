import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from pipeline import kani


CODE = """fn add(a: u8, b: u8) -> u8 { a.wrapping_add(b) }
#[cfg(kani)]
#[kani::proof]
fn addition_is_commutative() {
    let a: u8 = kani::any();
    let b: u8 = kani::any();
    assert_eq!(add(a, b), add(b, a));
}
"""

KANI_OK_OUTPUT = ("Check 1: addition_is_commutative.assert1.1 - Status: SUCCESS\n"
                  "Successfully verified 1 of 1 properties (1 VC, 0 unreachable)")


def test_harness_and_diagnostic_parsing():
    assert kani.kani_harnesses(CODE) == ["addition_is_commutative"]
    assert kani.kani_harnesses("fn plain() {}") == []
    findings = kani.parse_kani_diagnostics("FAILED: assertion failed\n Location: src/lib.rs:8:4")
    assert findings[0]["category"] == "KaniProperty"
    assert findings[1]["line"] == 8


def test_kani_fails_closed_without_harness_or_tool():
    assert kani.verify_kani("fn plain() {}") ["status"] == "HARNESS_REQUIRED"
    with patch.object(kani.shutil, "which", return_value=None):
        result = kani.verify_kani(CODE)
    assert result["status"] == "TOOL_MISSING" and result["claim"] == "NO_PROOF"


def test_kani_success_failure_timeout_and_os_error():
    for returncode, status, claim, stdout in (
            (0, "VERIFIED", "BOUNDED_RUST_EVIDENCE", KANI_OK_OUTPUT),
            (1, "VERIFY_FAILED", "NO_PROOF", "FAILED: assertion failed")):
        completed = SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")
        with patch.object(kani.shutil, "which", return_value="/bin/cargo"), \
             patch.object(kani.subprocess, "run", return_value=completed):
            result = kani.verify_kani("use prusti_contracts::*;\n#[pure]\n" + CODE)
        assert result["status"] == status and result["claim"] == claim
        assert result["bounded"] and result["command"][-2:] == ["kani", "--tests"]
        if status == "VERIFIED":
            assert result["verified_properties"] == 1
    with patch.object(kani.shutil, "which", return_value="/bin/cargo"), \
         patch.object(kani.subprocess, "run", side_effect=subprocess.TimeoutExpired("kani", 1)):
        assert kani.verify_kani(CODE)["status"] == "TIMEOUT"
    with patch.object(kani.shutil, "which", return_value="/bin/cargo"), \
         patch.object(kani.subprocess, "run", side_effect=OSError("broken")):
        assert kani.verify_kani(CODE)["status"] == "TOOL_ERROR"


def test_kani_exit_zero_without_checked_property_is_vacuous():
    completed = SimpleNamespace(returncode=0, stdout="ok", stderr="")
    with patch.object(kani.shutil, "which", return_value="/bin/cargo"), \
         patch.object(kani.subprocess, "run", return_value=completed):
        result = kani.verify_kani(CODE)
    assert result["status"] == "VACUOUS_VERIFIED" and result["claim"] == "NO_PROOF"
    assert result["verified_properties"] is None and "vacuity_note" in result


def test_kani_managed_release_invokes_driver_directly():
    completed = SimpleNamespace(returncode=0, stdout=KANI_OK_OUTPUT, stderr="")
    with patch.object(kani.shutil, "which", return_value="/managed/bin/kani-driver"), \
         patch.object(kani.subprocess, "run", return_value=completed):
        result = kani.verify_kani(CODE)
    assert result["status"] == "VERIFIED"
    assert result["command"] == ["/managed/bin/kani-driver", "--tests"]
