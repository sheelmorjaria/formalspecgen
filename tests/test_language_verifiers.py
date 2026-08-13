# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
from unittest.mock import patch

from pipeline import verify_c as c_adapter
from pipeline import verify_rust as rust_adapter
from pipeline import verify_cpp as cpp_adapter


def test_rust_adapter_lint_compile_prusti_and_kani_routes():
    with patch.object(rust_adapter, "lint_rust", return_value=[{"severity": "error"}]):
        assert rust_adapter.verify_rust("unsafe fn f() {}")["status"] == "RUST_LINT_FAILED"
    with patch.object(rust_adapter, "lint_rust", return_value=[]), \
         patch.object(rust_adapter, "check_rust_syntax",
                      return_value={"status": "RUST_CHECKED", "exit_code": 0}):
        assert rust_adapter.verify_rust("fn f() {}", mode="check")["claim"] == "STATIC_CHECK"
    with patch.object(rust_adapter, "lint_rust", return_value=[]), \
         patch.object(rust_adapter, "verify_prusti",
                      return_value={"status": "VERIFIED", "exit_code": 0}):
        assert rust_adapter.verify_rust("fn f() {}", mode="esc")["claim"] == "DEDUCTIVE_PROOF"
    with patch.object(rust_adapter, "lint_rust", return_value=[]), \
         patch.object(rust_adapter, "verify_kani",
                      return_value={"status": "VERIFIED", "exit_code": 0}):
        assert rust_adapter.verify_rust("fn f() {}", backend="kani")["claim"] == "BOUNDED_EVIDENCE"
    with patch.object(rust_adapter, "lint_rust", return_value=[]), \
         patch.object(rust_adapter, "verify_prusti",
                      return_value={"status": "VERIFY_FAILED", "exit_code": 1}):
        assert rust_adapter.verify_rust("fn f() {}")["claim"] == "NO_PROOF"


def test_c_adapter_routes_proof_and_compile():
    with patch.object(c_adapter, "verify_framac", return_value={"status": "VERIFIED"}) as proof:
        assert c_adapter.verify_c("int f(void){}", "esc")["language"] == "c"
        proof.assert_called_once()
    with patch.object(c_adapter, "check_c_syntax", return_value={"status": "C_CHECKED"}) as check:
        assert c_adapter.verify_c("int f(void){}", "check")["status"] == "C_CHECKED"
        check.assert_called_once()


def test_cpp_adapter_routes_bounded_esbmc():
    with patch.object(cpp_adapter, "subprocess") as process:
        process.run.return_value = type("Result", (), {
            "returncode": 0, "stdout": "Verification successful", "stderr": ""})()
        result = cpp_adapter.verify_cpp("Safe.cpp")
    assert result["claim"] == "BOUNDED_CPP_PROOF"
