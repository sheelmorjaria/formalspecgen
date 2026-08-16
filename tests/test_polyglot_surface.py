"""Tests for Tree-sitter public-API and contract surfaces (polyglot gate inputs)."""
from __future__ import annotations

from pipeline.polyglot_surface import contract_clauses, public_api_surface

RUST = """pub fn process(value: i32) -> i32 {
    value + 1
}

fn helper(value: i32) -> i32 { value }

pub trait Gateway {
    fn charge(&self, amount: i32) -> bool;
}
"""

C = """/*@ requires 0 <= index < 10; */
int get(int *arr, int index) {
    return arr[index];
}

static int internal(int x) { return x; }

/* loop invariant ... inside body, not a contract block at top level */
"""

CPP = """class Counter {
public:
    void increment();
    int value() const;
private:
    int count_;
};

void Counter::increment() {
    if (count_ < 5) { count_ = count_ + 1; }
    assert(count_ >= 0 && count_ <= 5);
}
"""


def test_rust_public_api_surface_separates_pub_from_private():
    surface = public_api_surface(RUST, "rust")
    assert any(s.startswith("pub fn process") for s in surface)
    assert not any(s.startswith("fn helper") for s in surface)
    assert any(s.startswith("pub trait Gateway") for s in surface)


def test_user_test_3_3_pub_to_private_changes_surface():
    demoted = RUST.replace("pub fn process", "fn process")
    assert public_api_surface(RUST, "rust") != public_api_surface(demoted, "rust")
    assert not any("process" in s for s in public_api_surface(demoted, "rust"))


def test_c_surface_includes_functions():
    surface = public_api_surface(C, "c")
    assert any("int get" in s for s in surface)
    assert any("internal" in s for s in surface)


def test_cpp_surface_includes_classes_and_methods():
    surface = public_api_surface(CPP, "cpp")
    assert any("class Counter" in s for s in surface)
    assert any("increment" in s for s in surface)


def test_contract_clauses_per_language():
    rust = contract_clauses(
        "#[requires(value >= 0)]\n#[ensures(result >= 0)]\npub fn f(value: i32) -> i32",
        "rust")
    assert any("requires" in clause for clause in rust)
    assert any("ensures" in clause for clause in rust)

    c = contract_clauses(C, "c")
    assert any("requires" in clause for clause in c)

    cpp = contract_clauses(CPP, "cpp")
    assert any("assert" in clause for clause in cpp)


def test_regex_fallback_when_tree_sitter_absent(monkeypatch):
    import pipeline.polyglot_surface as surface_module
    monkeypatch.setattr(surface_module, "Parser", None, raising=False)
    surface = surface_module.public_api_surface(RUST, "rust")
    assert surface  # fallback still extracts signatures
    assert any("fn" in s for s in surface)


def test_unparseable_source_and_unknown_suffix_fall_back(tmp_path):
    import pipeline.polyglot_surface as surface
    # A has_error Tree-sitter parse falls back to regex extraction, which finds
    # no COMPLETE signature in malformed code — the surface is empty, so any
    # gate over it fails closed rather than inventing a surface.
    broken = "pub fn broken( {"
    assert surface.public_api_surface(broken, "rust") == []
    # Unknown suffix (no grammar, no fallback entry) yields None nodes -> regex path.
    assert surface._ts_nodes("int main(){}", ".txt") is None
    # Rust with functions but no traits takes the signature list (not the trait fallback).
    assert any("fn" in s for s in surface.public_api_surface("pub fn only() {}", "rust"))
