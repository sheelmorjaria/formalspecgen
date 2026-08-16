"""Tests for the ESBMC diagnostic parser (shared VC schema)."""
from pipeline.parse_esbmc import parse_esbmc_vcs

COUNTEREXAMPLE = """State 1 file counter.cpp line 10 function main
----------------------------------------------------
Violated property:
  file counter.cpp line 10 function main
  dereference failure: pointer NULL

VERIFICATION FAILED
"""

BOUNDS = "Verification failed: array bounds violated (line 10)\n"

OVERFLOW = """Violated property:
  file calc.cpp line 22 function add
  arithmetic overflow on +


VERIFICATION FAILED
"""


def test_esbmc_dereference_failure_maps_to_possibly_null():
    vcs = parse_esbmc_vcs(COUNTEREXAMPLE)
    assert len(vcs) == 1
    vc = vcs[0]
    assert vc.category == "PossiblyNull"
    assert vc.file == "counter.cpp"
    assert vc.line == 10
    assert vc.method == "main"
    assert "pointer NULL" in vc.detail


def test_esbmc_bounds_violation_maps_to_undefined_negative_index():
    vcs = parse_esbmc_vcs(BOUNDS)
    assert len(vcs) == 1
    assert vcs[0].category == "UndefinedNegativeIndex"
    assert vcs[0].line == 10
    assert vcs[0].file == "candidate.cpp"


def test_esbmc_overflow_maps_to_arithmetic_range():
    vcs = parse_esbmc_vcs(OVERFLOW)
    assert vcs[0].category == "ArithmeticOperationRange"
    assert vcs[0].file == "calc.cpp"
    assert vcs[0].line == 22
    assert vcs[0].method == "add"


def test_esbmc_success_output_has_no_vcs():
    assert parse_esbmc_vcs("Verifying harness\nVERIFICATION SUCCESSFUL\n") == []
    assert parse_esbmc_vcs("") == []


def test_esbmc_unknown_shapes_get_fallback_category_and_dedupe():
    text = ("Violated property:\n  file a.cpp line 3\n  some custom check\n"
            "Violated property:\n  file a.cpp line 3\n  some custom check\n")
    vcs = parse_esbmc_vcs(text)
    assert len(vcs) == 1
    assert vcs[0].category == "EsbmcVerification"
    assert vcs[0].line == 3


def test_esbmc_missing_location_falls_back_to_line_zero():
    vcs = parse_esbmc_vcs("Verification failed: array bounds violated\n")
    assert vcs[0].line == 0
    assert vcs[0].file == "candidate.cpp"
