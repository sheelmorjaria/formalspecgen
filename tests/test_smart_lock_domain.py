import unittest
from pipeline.domains.smart_lock_extract import (
    UnsupportedJmlSemantics, extract_smart_lock_model, recognizes_smart_lock)
from pipeline.domains.smart_lock_render import render_smart_lock

class SmartLockDomainTests(unittest.TestCase):
    def test_complete_api_is_recognized(self):
        self.assertTrue(recognizes_smart_lock("class X { void CloseDoor() {} void OpenDoor() {} void LockDoor() {} void UnlockDoor() {} }"))
        self.assertFalse(recognizes_smart_lock("class X {}"))

    def test_unreviewed_adapter_fails_closed(self):
        with self.assertRaises(UnsupportedJmlSemantics):
            extract_smart_lock_model("class X {}", "", None)
        with self.assertRaises(UnsupportedJmlSemantics):
            render_smart_lock(None)

if __name__ == "__main__":
    unittest.main()
