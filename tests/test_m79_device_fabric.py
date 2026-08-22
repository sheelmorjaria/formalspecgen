import json
import shutil
from pathlib import Path
import pytest
from pipeline.device_fabric import verify_device_fabric

ARTIFACT = Path("examples/formalkernel/kernel/device_fabric.json")

@pytest.mark.skipif(shutil.which("z3") is None, reason="real Z3 not installed")
def test_device_domains_and_multiqueue_budgets():
    verdict = verify_device_fabric(ARTIFACT)
    assert verdict["status"] == "DEVICE_DMA_DOMAIN_ISOLATION_PROVED"
    assert verdict["device_count"] == 2 and verdict["queue_count"] == 6
    assert verdict["physical_iommu_enforcement_proved"] is False

def test_overlap_and_physical_overclaim_fail_closed(tmp_path):
    artifact = json.loads(ARTIFACT.read_text())
    artifact["devices"]["net0"]["dma_window"] = artifact["devices"]["nvme0"]["dma_window"]
    path = tmp_path / "fabric.json"; path.write_text(json.dumps(artifact))
    assert verify_device_fabric(path)["code"] == "DEVICE_DMA_DOMAIN_OVERLAP"
    artifact = json.loads(ARTIFACT.read_text()); artifact["msix_delivery_proved"] = True
    path.write_text(json.dumps(artifact))
    assert verify_device_fabric(path)["code"] == "DEVICE_FABRIC_EPISTEMIC_BOUNDARY_INVALID"
