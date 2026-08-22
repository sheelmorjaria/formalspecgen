import json
from pathlib import Path
from pipeline.network_scale import verify_network_scale
ARTIFACT = Path("examples/formalkernel/kernel/network_scale.json")
def test_network_routing_and_partitions():
    verdict = verify_network_scale(ARTIFACT)
    assert verdict["status"] == "NETWORK_RESOURCE_PARTITION_PROVED"
    assert verdict["distinct_states"] == 49 and verdict["queue_count"] == 4
    assert verdict["physical_packet_delivery_proved"] is False
def test_partition_drift_fails(tmp_path):
    artifact=json.loads(ARTIFACT.read_text()); artifact["queue_partitions"]["tenant"]=[0,2]
    artifact["validation"]=str((ARTIFACT.parent/artifact["validation"]).resolve())
    path=tmp_path/"net.json"; path.write_text(json.dumps(artifact))
    assert verify_network_scale(path)["code"] == "NETWORK_PARTITION_POLICY_INVALID"
