"""M16: real-OpenJML evidence for the hardening strategies.

Same shape as test_capacity_bounding_e2e.py: a static fixture stands in for
the provider rewrite and real OpenJML ESC must discharge the strengthened
contract. The deterministic residual check fires BEFORE the prover in the
negative cases.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline.behavior_correction import correct_behavior


def _openjml_available() -> bool:
    from pipeline import config
    return bool(config.OPENJML) and Path(config.OPENJML).exists()


OVERFLOW = """public class Meter {
    public int total;

    public void add(int n) { total = total * 3 + n; }
}
"""

CHECKED_MATH = """public class Meter {
    public int total;

    //@ requires n >= 0 && total >= 0 && total <= 2147483647 - n;
    //@ ensures total == \\old(total) + n;
    //@ assignable total;
    public void add(int n) {
        if (total <= Integer.MAX_VALUE - n) { total = total + n; }
    }
}
"""


def test_checked_math_proves_with_real_openjml(tmp_path):
    if not _openjml_available():
        pytest.skip("OpenJML unavailable")
    source = tmp_path / "Meter.java"
    source.write_text(OVERFLOW, encoding="utf-8")
    with patch("pipeline.behavior_correction._chat_fn") as chat:
        chat.return_value.return_value = (CHECKED_MATH, "fixture", {})
        result = correct_behavior(source, "CWE-190", tmp_path / "out",
                                  strategy="checked-math")
    assert result["status"] == "BEHAVIOR_CORRECTION_VERIFIED", result
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert result["mitigated_cwe"] == "CWE-190"
    assert result["formal_proof"] == "DEDUCTIVE_PROOF"


def test_unchecked_arithmetic_never_reaches_the_prover(tmp_path):
    if not _openjml_available():
        pytest.skip("OpenJML unavailable")
    source = tmp_path / "Meter.java"
    source.write_text(OVERFLOW, encoding="utf-8")
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify") as verify:
        chat.return_value.return_value = (OVERFLOW, "fixture", {})
        result = correct_behavior(source, "CWE-190", tmp_path / "out",
                                  strategy="checked-math")
    assert result["code"] == "strategy_not_satisfied"
    verify.assert_not_called()


ASSERTING = """public class Validator {
    public int check(int value) {
        assert value > 0;
        return value;
    }
}
"""

FAIL_SAFE = """public class Validator {
    //@ requires true;
    //@ ensures (value > 0) ==> (\\result == value);
    //@ ensures !(value > 0) ==> (\\result == -1);
    public int check(int value) {
        if (value > 0) { return value; }
        return -1;
    }
}
"""


def test_fail_safe_proves_with_real_openjml(tmp_path):
    if not _openjml_available():
        pytest.skip("OpenJML unavailable")
    source = tmp_path / "Validator.java"
    source.write_text(ASSERTING, encoding="utf-8")
    with patch("pipeline.behavior_correction._chat_fn") as chat:
        chat.return_value.return_value = (FAIL_SAFE, "fixture", {})
        result = correct_behavior(source, "CWE-617", tmp_path / "out",
                                  strategy="fail-safe")
    assert result["status"] == "BEHAVIOR_CORRECTION_VERIFIED", result
    assert result["mitigated_cwe"] == "CWE-617"


RACY = """import java.util.ArrayList;
import java.util.List;

public class Registry {
    public List<String> names = new ArrayList<>();
}
"""

IMMUTABLE_SNAPSHOT = """import java.util.Arrays;

public class Registry {
    public final String[] names;

    //@ requires initial != null;
    //@ ensures names.length == initial.length;
    public Registry(String[] initial) {
        this.names = Arrays.copyOf(initial, initial.length);
    }

    //@ ensures \\result.length == names.length;
    public String[] view() {
        return Arrays.copyOf(names, names.length);
    }
}
"""


def test_immutable_snapshot_proves_with_real_openjml(tmp_path):
    if not _openjml_available():
        pytest.skip("OpenJML unavailable")
    source = tmp_path / "Registry.java"
    source.write_text(RACY, encoding="utf-8")
    with patch("pipeline.behavior_correction._chat_fn") as chat:
        chat.return_value.return_value = (IMMUTABLE_SNAPSHOT, "fixture", {})
        result = correct_behavior(source, "CWE-362", tmp_path / "out",
                                  strategy="immutable-snapshot")
    assert result["status"] == "BEHAVIOR_CORRECTION_VERIFIED", result
    assert result["mitigated_cwe"] == "CWE-362"
