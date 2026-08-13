from pathlib import Path
from unittest.mock import patch

from pipeline.dependency_injection import inject_dependency
from pipeline.llm import LLMError


ADAPTER = """// UNVERIFIED EXTERNAL BOUNDARY: generated integration stub.
public class StripePaymentGateway implements PaymentGateway {
    //@ requires amount > 0;
    //@ ensures \\result ==> amount > 0;
    public boolean charge(int amount) {
        return false;
    }
}
"""


def test_stripe_injection_preserves_surface_and_marks_io_unverified(tmp_path):
    path = tmp_path / "StripePaymentGateway.java"
    path.write_text(ADAPTER, encoding="utf-8")
    candidate = ADAPTER.replace("return false;", "return com.stripe.model.Charge.create(null) != null;")
    with patch("pipeline.dependency_injection._chat_fn") as chat:
        chat.return_value.return_value = ("```java\n" + candidate + "\n```", "ollama", {})
        result = inject_dependency(path, "stripe")
    assert result["status"] == "INJECTED"
    assert result["claim"] == "UNVERIFIED_EXTERNAL_ADAPTER"
    assert not result["external_io_safety_proved"]
    assert "Charge.create" in path.read_text()


def test_stripe_injection_fails_closed_on_marker_or_surface_changes(tmp_path):
    path = tmp_path / "StripePaymentGateway.java"
    path.write_text(ADAPTER, encoding="utf-8")
    with patch("pipeline.dependency_injection._chat_fn") as chat:
        chat.return_value.return_value = ("```java\npublic class Other {}\n```", "ollama", {})
        result = inject_dependency(path, "stripe")
    assert result["code"] == "boundary_marker_removed"
    changed = ADAPTER.replace("StripePaymentGateway", "OtherPaymentGateway")
    with patch("pipeline.dependency_injection._chat_fn") as chat:
        chat.return_value.return_value = ("```java\n" + changed + "\n```", "ollama", {})
        assert inject_dependency(path, "stripe")["code"] == "adapter_surface_changed"
    assert path.read_text() == ADAPTER
    assert inject_dependency(path, "paypal")["code"] == "unsupported_dependency"
    plain = tmp_path / "Plain.java"; plain.write_text("public class Plain {}")
    assert inject_dependency(plain, "stripe")["code"] == "not_external_adapter"
    malformed = tmp_path / "Malformed.java"
    malformed.write_text("// UNVERIFIED EXTERNAL BOUNDARY", encoding="utf-8")
    assert inject_dependency(malformed, "stripe")["code"] == "adapter_surface_unrecognized"
    with patch("pipeline.dependency_injection._chat_fn", side_effect=LLMError("timeout", "slow")):
        assert inject_dependency(path, "stripe")["code"] == "provider_error"
