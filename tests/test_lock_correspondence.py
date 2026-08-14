from pipeline.lock_correspondence import check_lock_correspondence


def test_lock_correspondence_preflight_requires_java_and_protocol_model():
    result = check_lock_correspondence(
        {"Inventory.java": "class Inventory { synchronized void reserve() {} }"},
        "CONSTANT Lock\nAcquire == TRUE\nRelease == TRUE")
    assert result["status"] == "LOCK_CORRESPONDENCE_READY"
    assert result["concurrent_linearizability_proved"] is False


def test_lock_correspondence_fails_closed_without_lock_evidence():
    assert check_lock_correspondence({"Inventory.java": "class Inventory {}"}, "Lock == TRUE")["status"] == \
        "LOCK_CORRESPONDENCE_MISSING"
