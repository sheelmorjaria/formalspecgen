from pipeline.domain_v2 import DomainSpecV2
from pipeline.domain_v2_model import UnsupportedV2Boundary
from pipeline.domain_v2_tla import render_v2_tla
import pytest


def spec_with(operation, *, actors=1, variables=None):
    variables = variables or [
        {"kind":"int","name":"x","bound":[0,2],"initial":1},
        {"kind":"int","name":"y","bound":[0,2],"initial":2}]
    invariant={"id":"NonNegative","expression":{"kind":"gte",
        "left":{"kind":"field","name":variables[0]["name"]},
        "right":{"kind":"integer","value":0}}}
    return DomainSpecV2.model_validate({"schema_version":2,"domain_name":"TestDomain",
        "module_name":"test_domain","actors":actors,"state_variables":variables,
        "operations":[operation],"tlc_invariants":[invariant]})


def test_boolean_result_and_failure_are_rendered_as_explicit_actor_actions():
    op={"name":"StartMoveUp","return_type":"boolean","failure_semantics":"false_and_stutter",
      "guards":[{"id":"stopped","expression":{"kind":"eq","left":{"kind":"field","name":"motion"},"right":{"kind":"integer","value":0}}}],
      "effects":[{"id":"start","target":"motion","value":{"kind":"integer","value":1}}],"frame":["motion"]}
    variables=[{"kind":"int","name":"floor","bound":[0,4],"initial":0},
      {"kind":"int","name":"motion","bound":[0,2],"initial":0}]
    tla,cfg=render_v2_tla(spec_with(op,actors=2,variables=variables))
    assert 'callResult = [a \\in Actors |-> "none"]' in tla
    assert 'callResult \\in [Actors -> {"none", "true", "false"}]' in tla
    assert "StartMoveUpFailure(actor) ==" in tla
    assert 'callResult\' = [callResult EXCEPT ![actor] = "false"]' in tla
    assert "UNCHANGED <<floor, motion>>" in tla
    assert "vars == <<floor, motion, callResult>>" in tla
    assert "Actors = {a1, a2}" in cfg


def test_void_action_and_typed_invariant_render_without_actor_state():
    op={"name":"Increment","return_type":"void","failure_semantics":"unavailable",
      "guards":[],"effects":[{"id":"inc","target":"x","value":{"kind":"add","left":{"kind":"old","expression":{"kind":"field","name":"x"}},"right":{"kind":"integer","value":1}}}],"frame":["x"]}
    tla,cfg=render_v2_tla(spec_with(op))
    assert "EXTENDS Naturals" in tla
    assert "CONSTANTS Actors" not in tla and "callResult" not in tla
    assert "Increment ==\n    /\\ TRUE" in tla
    assert "x' = (x + 1)" in tla
    assert "INVARIANT\nNonNegative" in cfg


def test_void_action_preserves_call_result_when_domain_mixes_api_return_types():
    void={"name":"Tick","return_type":"void","failure_semantics":"unavailable",
      "guards":[],"effects":[{"id":"inc","target":"x","value":{"kind":"add",
      "left":{"kind":"field","name":"x"},"right":{"kind":"integer","value":1}}}],
      "frame":["x"]}
    boolean={"name":"Try","return_type":"boolean","failure_semantics":"false_and_stutter",
      "guards":[],"effects":[],"frame":[]}
    base=spec_with(void).model_dump(mode="json"); base["operations"].append(boolean)
    tla,_=render_v2_tla(DomainSpecV2.model_validate(base))
    tick=tla.split("Tick ==",1)[1].split("\n\n",1)[0]
    assert "UNCHANGED <<y, callResult>>" in tick


def test_renderer_rejects_incomplete_frames_and_exception_results():
    op={"name":"Bad","return_type":"void","failure_semantics":"unavailable",
      "guards":[],"effects":[],"frame":["x"]}
    from pydantic import ValidationError
    with pytest.raises(ValidationError,match="framed field"):
        render_v2_tla(spec_with(op))
    op={"name":"Bad","return_type":"boolean","failure_semantics":"exception",
      "exception_type":"E","exception_trigger":{"kind":"boolean","value":True},
      "guards":[],"effects":[],"frame":[]}
    with pytest.raises(UnsupportedV2Boundary,match="exception-result"):
        render_v2_tla(spec_with(op))


def test_expression_renderer_rejects_objects_outside_typed_union():
    from pipeline.domain_v2_tla import render_expression
    with pytest.raises(UnsupportedV2Boundary, match="unsupported expression"):
        render_expression(object())


def test_expression_renderer_emits_tla_negation():
    from pipeline.domain_v2 import BooleanExpr, NotExpr
    from pipeline.domain_v2_tla import render_expression
    assert render_expression(NotExpr(expression=BooleanExpr(value=False))) == "~(FALSE)"


def test_renderer_extends_integers_for_negative_bounded_sentinels():
    op={"name":"Clear","return_type":"void","failure_semantics":"unavailable",
        "guards":[],"effects":[{"id":"clear","target":"channel",
        "value":{"kind":"integer","value":-1}}],"frame":["channel"]}
    variables=[{"kind":"int","name":"channel","bound":[-1,1],"initial":-1}]
    tla,_=render_v2_tla(spec_with(op,variables=variables))
    assert "EXTENDS Integers" in tla
    assert "channel \\in -1..1" in tla
    assert "channel' = -1" in tla

    from pipeline.domain_v2_tla import _contains_negative_integer
    assert _contains_negative_integer({"nested": [{"kind": "integer", "value": -2}]})
