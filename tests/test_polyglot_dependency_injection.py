"""M5: polyglot SDK injection for Rust and C++ external adapters."""
from __future__ import annotations

from unittest.mock import patch

from pipeline.dependency_injection import inject_dependency

RUST_ADAPTER = """// UNVERIFIED EXTERNAL BOUNDARY: generated integration stub.
pub struct AwsUploader;

impl PaymentGateway for AwsUploader {
    #[requires(amount > 0)]
    fn charge(&self, amount: i32) -> bool {
        // TODO: Implement external API call; this body is not proof evidence.
        unreachable!("external boundary")
    }
}
"""

RUST_INJECTED = RUST_ADAPTER.replace(
    "        // TODO: Implement external API call; this body is not proof evidence.\n"
    "        unreachable!(\"external boundary\")",
    "        // aws-sdk-s3 client call; network behavior remains unverified.\n"
    "        upload_via_aws_sdk_s3(amount)")

CPP_ADAPTER = """// UNVERIFIED EXTERNAL BOUNDARY: generated integration stub.
class HttpClient : public PaymentGateway {
public:
    bool charge(int amount) override {
        // TODO: real external call via the SDK; not proof evidence.
        return false;
    }
};
"""

CPP_INJECTED = CPP_ADAPTER.replace(
    "        // TODO: real external call via the SDK; not proof evidence.\n"
    "        return false;",
    "        // libcurl transfer; network behavior remains unverified.\n"
    "        return curl_perform(amount);")


def _chat_returning(text):
    return lambda provider: lambda messages, model, temperature: (
        "```" + text + "```", "fixture", {})


def test_rust_aws_injection_preserves_contracts_and_marker(tmp_path):
    adapter = tmp_path / "AwsUploader.rs"
    adapter.write_text(RUST_ADAPTER, encoding="utf-8")
    with patch("pipeline.dependency_injection._chat_fn",
               side_effect=_chat_returning(RUST_INJECTED)):
        result = inject_dependency(adapter, "aws", provider="ollama")
    assert result["status"] == "INJECTED"
    assert result["claim"] == "UNVERIFIED_EXTERNAL_ADAPTER"
    assert result["language"] == "rust"
    assert result["external_io_safety_proved"] is False
    candidate = adapter.read_text(encoding="utf-8")
    assert "aws-sdk-s3" in candidate
    assert "UNVERIFIED EXTERNAL BOUNDARY" in candidate
    assert "#[requires(amount > 0)]" in candidate  # Prusti contract preserved


def test_cpp_curl_injection_preserves_marker_and_signatures(tmp_path):
    adapter = tmp_path / "HttpClient.cpp"
    adapter.write_text(CPP_ADAPTER, encoding="utf-8")
    with patch("pipeline.dependency_injection._chat_fn",
               side_effect=_chat_returning(CPP_INJECTED)):
        result = inject_dependency(adapter, "curl", provider="ollama")
    assert result["status"] == "INJECTED"
    assert result["language"] == "cpp"
    candidate = adapter.read_text(encoding="utf-8")
    assert "libcurl" in candidate or "curl_perform" in candidate
    assert "UNVERIFIED EXTERNAL BOUNDARY" in candidate


def test_rust_surface_change_and_marker_removal_fail_closed(tmp_path):
    adapter = tmp_path / "AwsUploader.rs"
    adapter.write_text(RUST_ADAPTER, encoding="utf-8")
    renamed = RUST_INJECTED.replace("fn charge(&self, amount: i32)",
                                    "fn charge_with(&self, amount: i32)")
    with patch("pipeline.dependency_injection._chat_fn",
               side_effect=_chat_returning(renamed)):
        result = inject_dependency(adapter, "aws")
    assert result["code"] == "adapter_surface_changed"

    adapter.write_text(RUST_ADAPTER, encoding="utf-8")
    markerless = RUST_INJECTED.replace(
        "// UNVERIFIED EXTERNAL BOUNDARY: generated integration stub.", "")
    with patch("pipeline.dependency_injection._chat_fn",
               side_effect=_chat_returning(markerless)):
        result = inject_dependency(adapter, "aws")
    assert result["code"] == "boundary_marker_removed"


def test_unsupported_dependencies_and_non_adapter_shapes_fail_closed(tmp_path):
    c_source = tmp_path / "adapter.c"
    c_source.write_text("// UNVERIFIED EXTERNAL BOUNDARY\nint x;\n", encoding="utf-8")
    assert inject_dependency(c_source, "aws")["code"] == "unsupported_dependency"

    rust_file = tmp_path / "plain.rs"
    rust_file.write_text("pub fn no_marker() {}\n", encoding="utf-8")
    assert inject_dependency(rust_file, "aws")["code"] == "not_external_adapter"
    assert inject_dependency(rust_file, "stripe")["code"] == "unsupported_dependency"

    adapter = tmp_path / "NotAnImpl.rs"
    adapter.write_text("// UNVERIFIED EXTERNAL BOUNDARY\npub fn loose() {}\n",
                       encoding="utf-8")
    assert inject_dependency(adapter, "aws")["code"] == "adapter_surface_unrecognized"

    java = tmp_path / "Stripe.java"
    java.write_text("// UNVERIFIED EXTERNAL BOUNDARY\nclass X {}\n", encoding="utf-8")
    assert inject_dependency(java, "stripe")["code"] == "adapter_surface_unrecognized"


def test_java_stripe_lane_unchanged(tmp_path):
    from tests.test_dependency_injection import ADAPTER  # reuse the shipped fixture

    adapter = tmp_path / "StripePaymentGateway.java"
    adapter.write_text(ADAPTER, encoding="utf-8")
    with patch("pipeline.dependency_injection._chat_fn",
               return_value=lambda *_a: ("```java\n" + ADAPTER + "\n```", "m", {})):
        result = inject_dependency(adapter, "stripe", provider="ollama")
    assert result["status"] == "INJECTED"
    assert "language" not in result or result.get("language") == "java"
