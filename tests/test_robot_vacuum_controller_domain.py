import unittest
from pipeline.domains.robot_vacuum_controller_extract import (
    UnsupportedJmlSemantics, extract_robot_vacuum_controller_model, recognizes_robot_vacuum_controller)

class RobotVacuumControllerDomainTests(unittest.TestCase):
    def test_complete_api_is_recognized(self):
        self.assertTrue(recognizes_robot_vacuum_controller("class X { void startCleaning() {} void stopCleaning() {} void dock() {} }"))
        self.assertFalse(recognizes_robot_vacuum_controller("class X {}"))

    def test_unreviewed_adapter_fails_closed(self):
        with self.assertRaises(UnsupportedJmlSemantics):
            extract_robot_vacuum_controller_model("class X {}", "", None)

if __name__ == "__main__":
    unittest.main()
