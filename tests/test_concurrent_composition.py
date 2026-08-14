from pipeline.concurrent_composition import render_actor_model


def test_actor_model_tracks_interleavings_and_call_results():
    result = render_actor_model(["OrderA", "OrderB"])
    assert result["status"] == "CONCURRENT_MODEL_READY"
    assert result["concurrent_linearizability_proved"] is False
    assert "Actors == {OrderA, OrderB}" in result["tla"]
    assert "callResult" in result["tla"]


def test_actor_model_rejects_duplicate_or_invalid_names():
    assert render_actor_model(["A", "A"])["status"] == "CONCURRENT_MODEL_INVALID"
    assert render_actor_model(["A-B"])["status"] == "CONCURRENT_MODEL_INVALID"
