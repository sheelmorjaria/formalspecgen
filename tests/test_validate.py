from unittest.mock import patch

from pipeline import validate
from pipeline.schemas import VC


SOURCE = "public class Validatable {}"


def test_check_stub_rejects_empty_and_unparseable_sources_without_tooling():
    with patch.object(validate, "verify") as verify:
        assert validate.check_stub("") == (False, ["no parseable Java class in stub"])
        assert validate.check_stub("interface OnlyInterface {}") == (
            False, ["no parseable Java class in stub"])
    verify.assert_not_called()


def test_check_stub_accepts_only_verified_exit_and_writes_named_utf8_source():
    observed = {}

    def fake_verify(path, mode):
        observed["name"] = path.name
        observed["source"] = path.read_text(encoding="utf-8")
        observed["mode"] = mode
        return 0, "clean"

    with (patch.object(validate, "verify", side_effect=fake_verify),
          patch.object(validate, "classify", return_value="VERIFIED"),
          patch.object(validate, "parse_check") as parse):
        result = validate.check_stub(SOURCE)
    assert result == (True, [])
    assert observed == {"name": "Validatable.java", "source": SOURCE, "mode": "check"}
    parse.assert_not_called()


def test_check_stub_returns_structured_diagnostic_details_on_failure():
    diagnostics = [
        VC("Bad.java", 4, "error", detail="unknown symbol", raw="raw-one"),
        VC("Bad.java", 5, "warning", detail="", raw="raw-two"),
    ]
    with (patch.object(validate, "verify", return_value=(1, "tool output")),
          patch.object(validate, "classify", return_value="COMPILE_FAILED"),
          patch.object(validate, "parse_check", return_value=diagnostics)):
        ok, errors = validate.check_stub(SOURCE)
    assert ok is False
    assert errors == ["unknown symbol", "raw-two"]


def test_zero_exit_with_nonverified_classification_fails_closed():
    with (patch.object(validate, "verify", return_value=(0, "warning")),
          patch.object(validate, "classify", return_value="UNKNOWN"),
          patch.object(validate, "parse_check", return_value=[])):
        assert validate.check_stub(SOURCE) == (False, [])
