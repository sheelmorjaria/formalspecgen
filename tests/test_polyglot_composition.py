"""M4: polyglot composition rendering and native verification (unit, mocked provers)."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from pipeline.polyglot_composition import (
    build_polyglot_composition_sources,
    verify_polyglot_composition,
)


def _artifact():
    return {
        "system_name": "Checkout",
        "architecture": {"components": [
            {"id": "payments", "name": "PaymentGateway", "type": "interface",
             "external": True, "adapter": "StripePaymentGateway",
             "operations": [{"name": "charge",
                             "parameters": [{"name": "amount", "type": "int"}],
                             "returns": "boolean",
                             "requires": ["amount > 0"],
                             "ensures": ["\\result ==> amount > 0"],
                             "assignable": []}]},
        ]},
        "bindings": [{"component": "payments", "module_name": "smart_lock"}],
        "use_cases": [{"name": "charge order",
                       "steps": [{"component": "payments", "operation": "charge",
                                  "arguments": {"amount": "amount"}}]}],
    }


def _resolved_fake():
    return {"payments": SimpleNamespace(
        domain_name="SmartLock", module_name="smart_lock", operations=[],
        state_variables=[], tlc_invariants=[])}


_VERIFIED = {"status": "VERIFIED", "claim": "whatever", "output": "proved", "vcs": []}


def test_rust_port_is_a_contracted_trait(tmp_path):  # user Test 4.1
    from pipeline.composition import parse_composition
    spec = parse_composition(_artifact())
    sources = build_polyglot_composition_sources(spec, _resolved_fake(), "rust")
    unit = sources["Checkout.rs"]
    assert "pub trait PaymentGateway" in unit
    assert "fn charge(&self, amount: i32) -> bool;" in unit
    assert "#[requires(amount > 0)]" in unit
    # single compilation unit + scaffolding adapter with the boundary marker
    assert "use prusti_contracts::*;" in unit
    adapter = sources["StripePaymentGateway.rs"]
    assert "UNVERIFIED EXTERNAL BOUNDARY" in adapter
    assert "impl PaymentGateway for StripePaymentGateway" in adapter


def test_rust_orchestrator_injects_boxed_port(tmp_path):  # user Test 4.2
    from pipeline.composition import parse_composition
    spec = parse_composition(_artifact())
    sources = build_polyglot_composition_sources(spec, _resolved_fake(), "rust")
    unit = sources["Checkout.rs"]
    assert "payments: P0" in unit  # Prusti 0.2.2: generic param, not Box<dyn>
    assert "impl<P0: PaymentGateway> ChargeOrderOrchestrator<P0> {" in unit
    assert "pub struct ChargeOrderOrchestrator" in unit
    assert "#[requires(amount > 0)]" in unit
    assert "self.payments.charge(amount);" in unit


def test_c_port_is_a_function_pointer_struct():  # user Test 4.3
    from pipeline.composition import parse_composition
    spec = parse_composition(_artifact())
    sources = build_polyglot_composition_sources(spec, _resolved_fake(), "c")
    unit = sources["checkout.c"]
    assert "struct PaymentGateway {" in unit
    assert "bool (*charge)(int);" in unit
    assert "requires amount > 0;" in unit
    # contracted reference implementation the proof binds to
    assert "paymentgateway_charge_reference" in unit
    assert "stripe_payment_gateway.c" in sources
    assert "UNVERIFIED EXTERNAL BOUNDARY" in sources["stripe_payment_gateway.c"]


def test_c_orchestrator_calls_through_the_port_pointer():  # user Test 4.4
    from pipeline.composition import parse_composition
    spec = parse_composition(_artifact())
    sources = build_polyglot_composition_sources(spec, _resolved_fake(), "c")
    unit = sources["checkout.c"]
    assert "gateway->charge(amount);" in unit
    assert "void charge_order_orchestrate(PaymentGateway *gateway, int amount)" in unit
    assert "requires gateway->charge == paymentgateway_charge_reference;" in unit


def test_cpp_virtual_port_and_bounded_claim_ceiling():
    from pipeline.composition import parse_composition
    spec = parse_composition(_artifact())
    sources = build_polyglot_composition_sources(spec, _resolved_fake(), "cpp")
    unit = sources["Checkout.cpp"]
    assert "class PaymentGateway" in unit
    assert "virtual bool charge(int amount) = 0;" in unit
    assert "payments_->charge(amount);" in unit
    assert "assert(amount > 0);" in unit  # bounded obligation
    assert "StripePaymentGateway.cpp" in sources


def test_verify_rust_and_c_mint_system_composition_proof():
    with patch("pipeline.verify_rust.verify_rust", return_value=dict(_VERIFIED)):
        result = verify_polyglot_composition(_artifact(), language="rust")
    assert result["status"] == "COMPOSITION_VERIFIED"
    assert result["claim"] == "SYSTEM_COMPOSITION_PROOF"
    assert result["single_compilation_unit"] is True
    assert result["unverified_boundaries"] == ["StripePaymentGateway"]
    assert result["external_io_safety_proved"] is False
    assert result["concurrent_linearizability_proved"] is False

    with patch("pipeline.verify_c.verify_c", return_value=dict(_VERIFIED)):
        result = verify_polyglot_composition(_artifact(), language="c")
    assert result["claim"] == "SYSTEM_COMPOSITION_PROOF"


def test_verify_cpp_mints_bounded_ceiling():  # user Test 4.7
    with patch("pipeline.verify_cpp.verify_cpp",
               return_value={"status": "VERIFIED", "claim": "BOUNDED_CPP_PROOF",
                             "output": "VERIFICATION SUCCESSFUL", "vcs": []}):
        result = verify_polyglot_composition(_artifact(), language="cpp")
    assert result["status"] == "COMPOSITION_VERIFIED"
    assert result["claim"] == "BOUNDED_SYSTEM_COMPOSITION_PROOF"
    assert result["bounded_only"] is True


def test_adapter_excluded_from_prover_input():  # user Test 5.3 (boundary isolation)
    calls = {}

    def spying_verify(code, **kwargs):
        calls["code"] = code
        return dict(_VERIFIED)

    with patch("pipeline.verify_rust.verify_rust", side_effect=spying_verify):
        result = verify_polyglot_composition(_artifact(), language="rust")
    assert result["status"] == "COMPOSITION_VERIFIED"
    prover_input = calls["code"]
    assert "pub trait PaymentGateway" in prover_input
    assert "impl PaymentGateway for StripePaymentGateway" not in prover_input
    assert result["verification_skips"] == {
        "StripePaymentGateway": "Unverified external boundary"}


def test_failed_prover_and_vacuity_fail_closed():
    with patch("pipeline.verify_rust.verify_rust",
               return_value={"status": "VERIFY_FAILED", "output": "postcondition failed"}):
        result = verify_polyglot_composition(_artifact(), language="rust")
    assert result["status"] == "COMPOSITION_VERIFY_FAILED"
    assert result["claim"] == "NO_PROOF"

    vacuous = {"status": "VERIFIED", "output": "ok", "vcs": []}
    with patch("pipeline.verify_rust.verify_rust", return_value=vacuous), \
         patch("pipeline.polyglot_composition.build_polyglot_composition_sources",
               return_value={"Checkout.rs": "pub fn empty() {}\n"}):
        result = verify_polyglot_composition(_artifact(), language="rust")
    assert result["status"] == "VACUOUS_COMPOSITION"
    assert result["claim"] == "NO_PROOF"


def test_no_esc_flag_and_unsupported_language():
    with patch("pipeline.verify_rust.verify_rust", return_value=dict(_VERIFIED)):
        result = verify_polyglot_composition(_artifact(), language="rust", run_esc=False)
    assert result["status"] == "COMPOSITION_CHECKED"
    assert result["claim"] == "STATIC_CHECK"

    assert verify_polyglot_composition(
        _artifact(), language="python")["status"] == "UNSUPPORTED_BOUNDARY"


def test_resolution_lint_and_coupling_failures_fail_closed(tmp_path):
    (tmp_path / "empty").mkdir()
    result = verify_polyglot_composition(
        _artifact(), v2_dir=str(tmp_path / "empty"), language="rust")
    assert result["status"] == "RESOLUTION_FAILED"
    assert "not found" in result["message"]

    unsatisfiable = _artifact()
    unsatisfiable["use_cases"][0]["steps"][0]["arguments"] = {"amount": "-5"}
    result = verify_polyglot_composition(unsatisfiable, language="rust")
    assert result["status"] == "UNSATISFIABLE_BINDING"

    unknown_op = _artifact()
    unknown_op["use_cases"][0]["steps"][0]["operation"] = "refund"
    result = verify_polyglot_composition(unknown_op, language="rust")
    assert result["status"] == "COMPOSITION_LINT_FAILED"
    assert any(item["code"] == "composition-unknown-port-operation"
               for item in result["findings"])


def test_unsafe_adapter_identifier_and_builder_language_gate():
    from pipeline.composition import parse_composition
    from pipeline.polyglot_composition import (
        UnsupportedPolyglotComposition, build_polyglot_composition_sources,
    )

    unsafe = _artifact()
    unsafe["architecture"]["components"][0]["adapter"] = "Not A Name!"
    assert verify_polyglot_composition(
        unsafe, language="rust")["status"] == "UNSUPPORTED_BOUNDARY"

    spec = parse_composition(_artifact())
    try:
        build_polyglot_composition_sources(spec, _resolved_fake(), "python")
    except UnsupportedPolyglotComposition:
        pass
    else:
        raise AssertionError("unsupported language must fail closed")


def test_void_port_operations_render_in_all_three_lanes():
    from pipeline.composition import parse_composition
    value = _artifact()
    value["architecture"]["components"][0]["operations"][0].update(
        {"returns": "void", "ensures": ["true"]})
    spec = parse_composition(value)
    rust = build_polyglot_composition_sources(spec, _resolved_fake(), "rust")
    assert "fn charge(&self, amount: i32);" in rust["Checkout.rs"]  # no return arrow
    assert "excluded from verification" in rust["StripePaymentGateway.rs"]
    c_unit = build_polyglot_composition_sources(spec, _resolved_fake(), "c")
    assert "void (*charge)(int);" in c_unit["checkout.c"]
    assert "(void)0;" in c_unit["checkout.c"]
    cpp_unit = build_polyglot_composition_sources(spec, _resolved_fake(), "cpp")
    assert "virtual void charge(int amount) = 0;" in cpp_unit["Checkout.cpp"]


def _mixed_artifact():
    value = _artifact()
    value["architecture"]["components"].append(
        {"id": "locks", "name": "Locks", "layer": "entities", "kind": "class",
         "operations": [], "dependencies": []})
    value["bindings"].append({"component": "locks", "module_name": "smart_lock"})
    value["use_cases"][0]["steps"].append({"component": "locks", "operation": "lock"})
    return value


def _mixed_resolved():
    from types import SimpleNamespace as NS
    payments = NS(domain_name="SmartLock", module_name="smart_lock",
                  operations=[], state_variables=[], tlc_invariants=[])
    locks = NS(domain_name="SmartLock", module_name="smart_lock",
               execution_model="atomic_operations", concurrency=None, invariants=[],
               operations=[NS(name="lock", return_type="void", guards=[])],
               state_variables=[], tlc_invariants=[])
    return {"payments": payments, "locks": locks}


def test_c_and_cpp_lanes_reject_mixed_core_steps_but_rust_renders_both():
    for language in ("c", "cpp"):
        with patch("pipeline.polyglot_composition.resolve_bindings",
                   return_value=_mixed_resolved()):
            result = verify_polyglot_composition(
                _mixed_artifact(), language=language, run_esc=False)
        assert result["status"] == "UNSUPPORTED_BOUNDARY"
        assert "external Port steps only" in result["message"]

    from pipeline.composition import parse_composition
    spec = parse_composition(_mixed_artifact())
    with patch("pipeline.v2_prusti_serializer.render_struct",
               return_value="// reviewed struct"):
        sources = build_polyglot_composition_sources(spec, _mixed_resolved(), "rust")
    unit = sources["Checkout.rs"]
    assert "pub struct ChargeOrderOrchestrator<P0, P1>" not in unit  # locks is concrete
    assert "impl<P0: PaymentGateway> ChargeOrderOrchestrator<P0> {" in unit
    assert "locks: SmartLock," in unit  # concrete reviewed core, not a generic port
    assert "self.locks.lock();" in unit


def test_rust_unit_embeds_reviewed_domain_struct():
    from pipeline.composition import parse_composition
    spec = parse_composition(_mixed_artifact())
    with patch("pipeline.v2_prusti_serializer.render_struct",
               return_value="// reviewed struct") as spy:
        sources = build_polyglot_composition_sources(spec, _mixed_resolved(), "rust")
    assert "// reviewed struct" in sources["Checkout.rs"]
    assert spy.call_count == 1  # only the bound non-external component


def test_cpp_vacuity_fails_closed():
    vacuous = {"status": "VERIFIED", "output": "ok", "vcs": []}
    with patch("pipeline.verify_cpp.verify_cpp", return_value=vacuous), \
         patch("pipeline.polyglot_composition.build_polyglot_composition_sources",
               return_value={"Checkout.cpp": "int untouched;\n"}):
        result = verify_polyglot_composition(_artifact(), language="cpp")
    assert result["status"] == "VACUOUS_COMPOSITION"
    assert result["claim"] == "NO_PROOF"
