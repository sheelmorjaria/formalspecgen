import unittest

from pipeline.jml_ast import BinaryExpr, JmlExpressionSyntaxError, OldValue, parse_jml_expression
from pipeline.transition_ir import TLARenderer, UnsupportedBoundaryError


class TypedJmlAstTests(unittest.TestCase):
    def test_parser_respects_arithmetic_precedence(self):
        ast = parse_jml_expression("balance == \\old(balance) + amount - 1",
                                   fields={"balance"}, parameters={"amount"})
        self.assertIsInstance(ast, BinaryExpr)
        self.assertEqual(ast.kind, "eq")
        self.assertEqual(ast.right.kind, "sub")
        self.assertEqual(ast.right.left.kind, "add")
        self.assertIsInstance(ast.right.left.left, OldValue)

    def test_parser_rejects_quantifier_and_method_call(self):
        with self.assertRaises(JmlExpressionSyntaxError):
            parse_jml_expression(r"\forall int i; i >= 0", parameters={"i"})
        with self.assertRaises(JmlExpressionSyntaxError):
            parse_jml_expression("helper(amount)", parameters={"amount"})

    def test_unknown_identifier_is_not_assumed_to_be_a_parameter(self):
        with self.assertRaisesRegex(JmlExpressionSyntaxError, "unknown identifier"):
            parse_jml_expression("balance == mystery", fields={"balance"})

    def test_renderer_maps_old_field_without_a_prime(self):
        ast = parse_jml_expression(r"\old(balance) + amount",
                                   fields={"balance"}, parameters={"amount"})
        self.assertEqual(TLARenderer().render_expression(ast), "(balances[self] + amount)")

    def test_renderer_rejects_nonlinear_arithmetic(self):
        ast = parse_jml_expression("balance * amount",
                                   fields={"balance"}, parameters={"amount"})
        with self.assertRaisesRegex(UnsupportedBoundaryError, "nonlinear arithmetic"):
            TLARenderer().render_expression(ast)

    def test_result_must_be_lowered_before_rendering(self):
        ast = parse_jml_expression(r"\result")
        with self.assertRaisesRegex(UnsupportedBoundaryError, "success/failure"):
            TLARenderer().render_expression(ast)


if __name__ == "__main__":
    unittest.main()
