import unittest

from pipeline.tla_backend import lint_tla_model, normalize_cfg, normalize_tla_syntax, parse_output


TLA = """---- MODULE Banking ----
VARIABLE balance
Init == balance = 0
Next == balance' = balance
Spec == Init /\\ [][Next]_<<balance>>
Safety == balance >= 0
===="""
CFG = "SPECIFICATION Spec\nINVARIANT Safety"


class TlaOutputParsingTests(unittest.TestCase):
    def test_documented_markers(self):
        tla, cfg = parse_output(f"=== TLA ===\n{TLA}\n=== CFG ===\n{CFG}\n=== END ===")
        self.assertEqual(tla, TLA)
        self.assertEqual(cfg, CFG)

    def test_markers_with_inner_fences(self):
        tla, cfg = parse_output(
            f"=== TLA ===\n```tla\n{TLA}\n```\n=== CFG ===\n```cfg\n{CFG}\n```\n=== END ===")
        self.assertEqual(tla, TLA)
        self.assertEqual(cfg, CFG)

    def test_separate_fenced_blocks(self):
        tla, cfg = parse_output(f"```tlaplus\n{TLA}\n```\n```config\n{CFG}\n```")
        self.assertEqual(tla, TLA)
        self.assertEqual(cfg, CFG)

    def test_incomplete_output_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "complete TLA"):
            parse_output("Here is a description but no model")

    def test_missing_module_terminator_is_restored(self):
        unterminated = TLA.rsplit("\n====", 1)[0]
        tla, cfg = parse_output(
            f"=== TLA ===\n{unterminated}\n=== CFG ===\n{CFG}\n=== END ===")
        self.assertTrue(tla.endswith("\n===="))
        self.assertEqual(cfg, CFG)

    def test_invariant_lists_are_expanded_to_explicit_entries(self):
        cfg = normalize_cfg("""SPECIFICATION Spec
INVARIANTS
    TypeOK
    NoDoubleSpending
PROPERTY EventuallyCompletes
""")
        self.assertEqual(cfg, "SPECIFICATION Spec\nINVARIANT TypeOK\n"
                              "INVARIANT NoDoubleSpending\nPROPERTY EventuallyCompletes")

    def test_constant_assignments_are_preserved(self):
        cfg = "SPECIFICATION Spec\nCONSTANTS\nAccounts = {a1, a2}\nMaxBalance = 10"
        self.assertEqual(normalize_cfg(cfg), cfg)

    def test_model_cfg_aliases_and_redundant_mode_are_canonicalized(self):
        cfg = normalize_cfg("INIT Init\nNEXT Next\nINV Inv\nSPEC Spec")
        self.assertEqual(cfg, "INVARIANT Inv\nSPECIFICATION Spec")

    def test_java_long_suffix_is_removed_from_tla_integer(self):
        self.assertEqual(normalize_tla_syntax("Init == x = 0L\nBound == 9000L"),
                         "Init == x = 0\nBound == 9000")

    def test_int_import_is_normalized_to_standard_integers_module(self):
        source = "---- MODULE A ----\nEXTENDS Naturals, Int\nIntValue == Int\n===="
        self.assertEqual(normalize_tla_syntax(source),
                         "---- MODULE A ----\nEXTENDS Naturals, Integers\nIntValue == Int\n====")

    def test_top_level_single_equals_is_normalized_to_definition(self):
        source = "AccountID = 1 .. 3\nInit == x = 0"
        self.assertEqual(normalize_tla_syntax(source), "AccountID == 1 .. 3\nInit == x = 0")

    def test_next_branch_cannot_assign_an_unchanged_variable(self):
        source = r"""Next ==
    \/ /\\ UNCHANGED <<x, y>>
       /\\ x' = x + 1
Spec == Init /\\ [][Next]_<<x, y>>
===="""
        self.assertEqual(lint_tla_model(source),
                         ["Next branch 2 both assigns and declares UNCHANGED: x"])

    def test_consistent_next_branch_passes_model_lint(self):
        source = r"""Next ==
    \/ /\\ UNCHANGED <<y>>
       /\\ x' = x + 1
Spec == Init /\\ [][Next]_<<x, y>>
===="""
        self.assertEqual(lint_tla_model(source), [])


if __name__ == "__main__":
    unittest.main()
