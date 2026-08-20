import unittest

from pipeline.domains.router import (
    AmbiguousDomain, DomainMaturity, DomainPlugin, UnsupportedDomain,
    maturity_report, select_domain,
)


class DomainRouterTests(unittest.TestCase):
    def plugin(self, name, result):
        return DomainPlugin(name, lambda _code: result, lambda *_: ({}, []), lambda _: ("", ""))

    def test_no_match_fails_closed(self):
        with self.assertRaises(UnsupportedDomain):
            select_domain("code", [self.plugin("none", False)])

    def test_ambiguous_match_fails_closed(self):
        with self.assertRaisesRegex(AmbiguousDomain, "one, two"):
            select_domain("code", [self.plugin("one", True), self.plugin("two", True)])

    def test_maturity_ceiling_fails_closed_before_adapter_execution(self):
        scaffold = self.plugin("vfs", True)
        with self.assertRaisesRegex(UnsupportedDomain, "maturity 'scaffold'.*NO_PROOF"):
            select_domain("code", [scaffold],
                          minimum_maturity=DomainMaturity.BOUNDED_EVIDENCE)

    def test_maturity_report_names_allowed_operations(self):
        bounded = DomainPlugin(
            "scheduler", lambda _code: True, lambda *_: ({}, []), lambda _: ("", ""),
            maturity=DomainMaturity.BOUNDED_EVIDENCE,
            evidence_ceiling="BOUNDED_ARCHITECTURE_EVIDENCE")
        report = maturity_report([bounded])[0]
        self.assertEqual(report["maturity"], "bounded-evidence")
        self.assertIn("bounded_architecture", report["available_operations"])
        self.assertFalse(report["critical_implementation_available"])


if __name__ == "__main__":
    unittest.main()
