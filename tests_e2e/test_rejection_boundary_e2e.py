"""M18: the proven rejection boundary in every native idiom.

M17 (Java/JML `signals`) defined the mathematical template — work beyond the
capacity is rejected, exactly at the boundary, and the count advances
otherwise. These tests prove the SAME template with each lane's native
mechanism: Rust's Result under Prusti, C's errno-style return under Frama-C
WP, and C++'s throw under ESBMC's bounded check.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pipeline.verify_c import verify_c
from pipeline.verify_cpp import verify_cpp
from pipeline.verify_rust import verify_rust


RUST_BOUNDARY = """use prusti_contracts::*;

pub struct BoundedPool {
    pub acquired: i32,
    pub capacity: i32,
}

impl BoundedPool {
    #[requires(self.capacity >= 0 && self.capacity < 2147483647
               && self.acquired >= 0 && self.acquired <= self.capacity)]
    #[ensures(old(self.acquired) == self.capacity ==> result.is_err())]
    #[ensures(old(self.acquired) < self.capacity
              ==> result.is_ok() && self.acquired == old(self.acquired) + 1)]
    pub fn acquire(&mut self) -> Result<(), i32> {
        if self.acquired == self.capacity {
            return Err(self.capacity);
        }
        self.acquired += 1;
        Ok(())
    }
}
"""


def _prusti_available() -> bool:
    try:
        from pipeline.config import PRUSTI_BIN
        return Path(PRUSTI_BIN).exists()
    except Exception:
        return False


def test_rust_result_rejection_boundary_proves_with_prusti():
    """Result::is_err fires exactly at acquired == capacity; the count
    advances otherwise (the Rust spelling of the M17 signals template)."""
    if not _prusti_available():
        pytest.skip("Prusti unavailable")
    result = verify_rust(RUST_BOUNDARY, mode="esc")
    assert result.get("claim") == "DEDUCTIVE_PROOF", result


C_BOUNDARY = r"""struct pool {
    int acquired;
    int capacity;
};

/*@
    requires \valid(pool);
    requires pool->capacity >= 0 && pool->capacity <= 2147483646;
    requires pool->acquired >= 0 && pool->acquired <= pool->capacity;
    assigns pool->acquired;
    behavior full:
        assumes pool->acquired == pool->capacity;
        ensures \result == -1;
    behavior not_full:
        assumes pool->acquired < pool->capacity;
        ensures \result == 0;
        ensures pool->acquired == \old(pool->acquired) + 1;
    complete behaviors;
    disjoint behaviors;
*/
int pool_acquire(struct pool *pool) {
    if (pool->acquired == pool->capacity) {
        return -1;
    }
    pool->acquired = pool->acquired + 1;
    return 0;
}
"""


def _framac_available() -> bool:
    try:
        from pipeline.config import FRAMAC_BIN
        return Path(FRAMAC_BIN).exists()
    except Exception:
        return False


def test_c_errno_rejection_boundary_proves_with_frama_c():
    """The errno-style -1 return fires exactly at the boundary, and the two
    ACSL behaviors are proven complete and disjoint."""
    if not _framac_available():
        pytest.skip("Frama-C unavailable")
    result = verify_c(C_BOUNDARY, mode="esc")
    assert result.get("claim") in {"DEDUCTIVE_PROOF"}, result


CPP_BOUNDARY = """#include <cassert>
#include <exception>

// A string-free rejection exception: std::string message construction is a
// libc loop that exceeds ESBMC's default unwind budget and would mask the
// boundary obligation we actually care about.
class CapacityReached : public std::exception {
public:
    const char* what() const noexcept override { return "pool at capacity"; }
};

class BoundedPool {
public:
    int acquired;
    int capacity;

    BoundedPool() : acquired(0), capacity(2) {}

    void acquire(int item) {
        (void)item;
        if (acquired == capacity) {
            throw CapacityReached();
        }
        acquired = acquired + 1;
    }

    // The adapter's generated harness calls this no-argument entry point;
    // the boundary contract lives in the assertions it checks.
    void check_boundary() {
        acquire(1);
        acquire(2);
        assert(acquired == 2);
        bool threw = false;
        try {
            acquire(3);          // the boundary: exactly at capacity
        } catch (const CapacityReached&) {
            threw = true;
        }
        assert(threw);           // the throw path is reachable at the boundary
        assert(acquired == 2);   // and the count never advances past it
    }
};
"""


def test_cpp_throw_rejection_boundary_checks_with_esbmc(tmp_path):
    """Bounded evidence: ESBMC explores the harness and confirms the throw
    path fires at the boundary without advancing the count."""
    if shutil.which("esbmc") is None:
        pytest.skip("ESBMC unavailable")
    source = tmp_path / "pool.cpp"
    source.write_text(CPP_BOUNDARY, encoding="utf-8")
    result = verify_cpp(source)
    assert result.get("status") == "VERIFIED", result
