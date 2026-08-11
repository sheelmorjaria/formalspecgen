import pytest

from pipeline.jml_to_dafny import UnsupportedBoundary, detect_boundary, translate_jml_to_dafny


LINKED = r"""
public class Node {
  public int value;
  public Node next;

  //@ requires start != null;
  //@ requires target != null;
  //@ requires acyclic(start);
  //@ assignable \nothing;
  public static /*@ pure @*/ boolean reachable(Node start, Node target) {
    return start == target || (start.next != null && reachable(start.next, target));
  }
}
"""


def test_linked_reachability_preserves_identity_and_dynamic_frames():
    assert detect_boundary(LINKED) == "linked_reachability"
    translated = translate_jml_to_dafny(LINKED)
    assert translated.boundary == "linked_reachability"
    assert "class Node" in translated.dafny_code
    assert "ghost var Repr: set<Node>" in translated.dafny_code
    assert "next.Repr < Repr" in translated.dafny_code
    assert "ghost predicate reachable(start: Node, target: Node)" in translated.dafny_code
    assert "decreases start.Repr" in translated.dafny_code


@pytest.mark.parametrize("source, message", [
    (LINKED.replace("//@ requires acyclic(start);\n", ""), "acyclic"),
    (LINKED.replace(r"//@ assignable \nothing;", "//@ assignable next;"), "assignable"),
    (LINKED.replace("public Node next;", "public Node next; public Node other;"), "exactly one"),
    (LINKED.replace("return start == target || (start.next != null && reachable(start.next, target));",
                    "return target.next == start;"), "outside the reviewed"),
    (LINKED.replace("public int value;", "public int value; void mutate(Node n) { n.next = this; }"),
     "does not permit link mutation"),
])
def test_linked_boundary_rejects_unreviewed_heap_semantics(source, message):
    with pytest.raises(UnsupportedBoundary, match=message):
        translate_jml_to_dafny(source)


def test_linked_boundary_requires_pure_two_node_helper():
    malformed = LINKED.replace("boolean reachable(Node start, Node target)",
                               "boolean reachable(Node start)")
    with pytest.raises(UnsupportedBoundary, match="two nodes"):
        translate_jml_to_dafny(malformed)
