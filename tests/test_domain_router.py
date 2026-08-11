import unittest

from pipeline.domains.router import (
    AmbiguousDomain, DomainPlugin, UnsupportedDomain, select_domain,
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


if __name__ == "__main__":
    unittest.main()
