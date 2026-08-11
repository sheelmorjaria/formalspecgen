import unittest

from pipeline.jml_to_dafny import UnsupportedBoundary, translate_jml_to_dafny


class RecursivePureHelperTranslationTests(unittest.TestCase):
    def test_general_recursive_helper_is_rendered_as_dafny_function(self):
        source = r"""
public class Arithmetic {
  //@ requires n >= 0;
  public static /*@ pure @*/ int triangular(int n) {
    return n == 0 ? 0 : triangular(n - 1) + n;
  }
}
"""
        translation = translate_jml_to_dafny(source)
        self.assertEqual(translation.boundary, "recursive_helper")
        self.assertIn("function triangular(n: int): int", translation.dafny_code)
        self.assertIn("requires n >= 0", translation.dafny_code)
        self.assertIn(
            "if n == 0 then 0 else triangular(n - 1) + n",
            translation.dafny_code,
        )

    def test_nonrecursive_pure_method_fails_closed(self):
        source = """
public class Arithmetic {
  public static /*@ pure @*/ int twice(int n) { return n + n; }
}
"""
        with self.assertRaisesRegex(UnsupportedBoundary, "recursive return expression"):
            translate_jml_to_dafny(source)

    def test_statement_body_fails_closed(self):
        source = """
public class Arithmetic {
  public static /*@ pure @*/ int count(int n) {
    int next = n - 1;
    return n == 0 ? 0 : count(next) + 1;
  }
}
"""
        with self.assertRaisesRegex(UnsupportedBoundary, "recursive return expression"):
            translate_jml_to_dafny(source)

    def test_unsupported_parameter_type_fails_closed(self):
        source = """
public class Arithmetic {
  public static /*@ pure @*/ int sum(int[] values, int n) {
    return n == 0 ? 0 : sum(values, n - 1) + values[n - 1];
  }
}
"""
        with self.assertRaisesRegex(UnsupportedBoundary, "unsupported pure-helper parameter"):
            translate_jml_to_dafny(source)


if __name__ == "__main__":
    unittest.main()
