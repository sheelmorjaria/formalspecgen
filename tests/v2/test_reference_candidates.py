# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path

import pytest

from pipeline.domain_v2_model import validate_transitions_and_invariants
from pipeline.domain_v2_promotion import load_candidate
from pipeline.domain_v2_tla import render_v2_tla


@pytest.mark.parametrize("name", ["rest_api_resource", "iot_sensor"])
def test_reference_candidate_is_typed_bounded_and_renderable(name):
    path = Path("domains/examples/v2") / f"{name}.v2.yaml"
    candidate = load_candidate(path)
    states, transitions = validate_transitions_and_invariants(candidate)
    tla, cfg = render_v2_tla(candidate)
    assert candidate.review_status == "unreviewed"
    assert states >= 1 and transitions >= 1
    assert f"---- MODULE {candidate.domain_name} ----" in tla
    assert "SPECIFICATION\nSpec" in cfg
