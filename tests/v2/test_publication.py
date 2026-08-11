import json
import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from pipeline.domain_v2_publication import (
    EvidenceEnvelope, PendingEvidence, ValidatedEvidence, publish_validation_failure,
    publish_validation_success, validated_envelope, write_json_atomic,
)

H="a"*64

def base():
    return {"schema_version":2,"candidate_sha256":H,
      "execution_assumption":"atomic_last_result_abstraction",
      "bounds":{"floor":[0,4],"actors":2},"state_space_upper_bound":270}


def validated():
    return ValidatedEvidence.model_validate({**base(),"validation_status":"VALIDATED",
      "generated_tla_sha256":"b"*64,"abstraction_mode":"atomic_operations",
      "reachable_state_count":42,"reachable_transition_count":115,
      "tools":{"tlc":{"version":"2.19","command":["java","-jar","tlc.jar"],"status":"OK"}},
      "tlc_exit_status":0})


def test_pending_counts_and_exit_status_are_null():
    value=PendingEvidence.model_validate({**base(),"validation_status":"PENDING",
      "reachable_state_count":None,"reachable_transition_count":None,"tlc_exit_status":None})
    assert value.reachable_state_count is None


@pytest.mark.parametrize("field,value", [("reachable_state_count",None),
  ("reachable_state_count",0),("reachable_transition_count",None),("tlc_exit_status",1)])
def test_validated_evidence_requires_completed_measurements(field,value):
    data=validated().model_dump(mode="json"); data[field]=value
    with pytest.raises(ValidationError): ValidatedEvidence.model_validate(data)


def test_validated_envelope_detects_digest_tampering():
    envelope=validated_envelope(validated())
    assert len(envelope.evidence_sha256)==64
    data=envelope.model_dump(mode="json"); data["evidence"]["reachable_state_count"]=43
    with pytest.raises(ValidationError,match="digest mismatch"):
        EvidenceEnvelope.model_validate(data)


def test_atomic_write_fsyncs_before_replace_and_publishes_complete_json(tmp_path):
    destination=tmp_path/"evidence.json"; events=[]
    real_fsync,real_replace=os.fsync,os.replace
    def fsync(fd): events.append("fsync"); return real_fsync(fd)
    def replace(src,dst):
        events.append("replace"); assert Path(src).parent==destination.parent
        return real_replace(src,dst)
    from pathlib import Path
    with patch("pipeline.domain_v2_publication.os.fsync",side_effect=fsync), \
         patch("pipeline.domain_v2_publication.os.replace",side_effect=replace):
        write_json_atomic(destination,{"complete":True})
    assert events.index("fsync") < events.index("replace")
    assert json.loads(destination.read_text())=={"complete":True}
    assert not list(tmp_path.glob("*.tmp"))


def test_failure_artifact_is_separate_scrubbed_and_preserves_success(tmp_path):
    success=tmp_path/"domain.validation.json"
    failure=tmp_path/"domain.validation_failed.json"
    publish_validation_success(success,validated()); original=success.read_bytes()
    publish_validation_failure(failure,candidate_sha256=H,failed_gate="tlc",
      diagnostic="token=supersecret model failed",tool_provenance={"status":"TLC_FAILED"})
    assert success.read_bytes()==original
    failed=json.loads(failure.read_text())
    assert failed["validation_status"]=="VALIDATION_FAILED"
    assert "supersecret" not in failed["diagnostic"]


def test_atomic_write_cleans_temporary_file_when_replace_fails(tmp_path):
    destination=tmp_path/"never-published.json"
    with patch("pipeline.domain_v2_publication.os.replace",
               side_effect=OSError("simulated crash")):
        with pytest.raises(OSError,match="simulated crash"):
            write_json_atomic(destination,{"status":"VALIDATED"})
    assert not destination.exists()
    assert not list(tmp_path.glob("*.tmp"))
