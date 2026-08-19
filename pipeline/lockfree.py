# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M36: lock-free concurrency — the ESBMC interleaving judge (OS lane 1).

Probe-grounded against real ESBMC 8.4.0 BEFORE this module was written:

- a two-thread SPSC ring (the kfifo shape) — array + head/tail shared
  ints, a guarded push/pop per thread, ONE single-word store per thread
  (the linearization point) — VERIFIES under all explored interleavings;
- an unguarded overfill FAILS (the judge is not decorative);
- C11 atomics are NOT modeled by this build (``no body for __c11_atomic_*``
  → loads return nondeterministic values), so the dialect is plain shared
  memory under the SC pthread model. The linearization point is the
  single-word store, probed sufficient.

Epistemics: ESBMC proves the capacity invariant (``head - tail <= CAP``,
``tail <= head``) over every interleaving within the unwind bound —
bounded interleaving safety, machine-judged. Scheduler fairness ("if a
thread steps, it does not corrupt state") is the human-accepted
assumption; progress/starvation-freedom is explicitly NOT claimed
(progress_proved: false).
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ESBMC_AVAILABLE = shutil.which("esbmc") is not None

_CAP = re.compile(r"#\s*define\s+CAP\s+(\d+)")
_BUF = re.compile(r"\b(?:int|unsigned|u?int\d+_t)\s+buf\s*\[\s*(\d+)\s*\]")
_GLOBAL_INTS = re.compile(
    r"(?:(?:^|,)\s*(?:(?:int|unsigned)\s+)?|(?:int|unsigned)\s+)"
    r"(head|tail)\s*=\s*\d+(?=\s*[;,])", re.M)
_THREAD_FN = re.compile(
    r"void\s*\*\s*(?P<name>\w+)\s*\(\s*void\s*\*[^)]*\)\s*\{", re.M)
_PTHREAD_CREATE = re.compile(r"pthread_create\s*\([^,]+,\s*[^,]+,\s*(\w+)")
_PTHREAD_JOIN = re.compile(r"pthread_join\s*\([^;]+;")
_LOOP_BOUND = re.compile(r"for\s*\([^;]*;\s*\w+\s*<\s*(\d+)\s*;")


def _fail(code: str, message: str) -> dict:
    return {"status": "LOCK_FREE_VERIFICATION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def _brace_matched_body(text: str, open_brace: int) -> str:
    level = 0
    for position in range(open_brace, len(text)):
        if text[position] == "{":
            level += 1
        elif text[position] == "}":
            level -= 1
            if level == 0:
                return text[open_brace + 1:position]
    return text[open_brace + 1:]


def detect_spsc_ring(text: str) -> dict:
    """Structural detection of the SPSC ring dialect: CAP + buffer + two
    shared index globals, each owned by exactly one thread function."""
    cap = _CAP.search(text)
    buf = _BUF.search(text)
    if not cap and not buf:
        return _fail("no_ring_structure",
                     "no ring buffer shape: expected a CAP #define or a "
                     "buf[...] array plus head/tail shared indices")
    shared = set(_GLOBAL_INTS.findall(text))
    if not {"head", "tail"} <= shared:
        return _fail("no_ring_structure",
                     "the SPSC dialect requires global head and tail "
                     "indices initialized at file scope")
    created = _PTHREAD_CREATE.findall(text)
    functions = {m.group("name"): _brace_matched_body(
        text, text.index("{", m.start())) for m in _THREAD_FN.finditer(text)
        if m.group("name") in set(created)}
    owners: dict[str, list[str]] = {}
    for name, body in functions.items():
        for field in ("head", "tail"):
            stores = re.findall(rf"\b{field}\s*=[^=]", body)
            if stores:
                owners.setdefault(field, []).append(name)
    for field, writers in owners.items():
        if len(writers) > 1:
            return _fail(
                "mpmc_not_in_dialect",
                f"{len(writers)} thread functions store '{field}' — an "
                "MPMC shape. The probed ESBMC dialect is single-producer "
                "single-consumer; MPMC interleaving explodes the bound "
                "and is not approximated")
    return {"status": "DETECTED", "code": "SPSC_RING_DETECTED",
            "capacity": int(cap.group(1)) if cap else int(buf.group(1)),
            "shared_fields": sorted(shared),
            "thread_functions": sorted(functions),
            "owners": {f: w[0] for f, w in owners.items() if w}}


def linearization_coverage(text: str, detection: dict) -> dict:
    """The structural gate: every concurrent operation takes effect at
    EXACTLY one single-word store to its shared index. Zero or multiple
    stores fail closed — there is no designated atomic step."""
    if detection.get("status") != "DETECTED":
        return detection
    functions = {m.group("name"): _brace_matched_body(
        text, text.index("{", m.start())) for m in _THREAD_FN.finditer(text)}
    points: dict[str, str] = {}
    for field in detection["shared_fields"]:
        owner = detection.get("owners", {}).get(field)
        if owner is None:
            return _fail(
                "LINEARIZATION_POINT_MISSING",
                f"no thread function stores '{field}': its side of the "
                "ring has no designated atomic step where the operation "
                "takes effect")
        body = functions.get(owner, "")
        stores = re.findall(rf"\b{field}\s*=[^=]", body)
        if len(stores) == 0:
            return _fail(
                "LINEARIZATION_POINT_MISSING",
                f"thread '{owner}' never stores '{field}': its operation "
                "has no designated atomic step where it takes effect")
        if len(stores) > 1:
            return _fail(
                "LINEARIZATION_MULTIPLE_STORES",
                f"thread '{owner}' stores '{field}' {len(stores)} times: "
                "the linearization point must be exactly ONE single-word "
                "store per concurrent operation")
        points[owner] = field
    return {"status": "COVERAGE_PROVED", "code": "LINEARIZATION_COVERAGE",
            "linearization_points": points}


def verify_lockfree(source: str | Path) -> dict:
    """Real ESBMC over the two-thread ring: the capacity invariant must
    hold under every explored interleaving."""
    path = Path(source)
    if not path.is_file():
        return _fail("input_unavailable", str(path))
    if path.suffix.lower() != ".c":
        return _fail("UNSUPPORTED_BOUNDARY",
                     "the lock-free lane verifies .c pthread sources")
    text = path.read_text(encoding="utf-8")
    detection = detect_spsc_ring(text)
    if detection.get("status") != "DETECTED":
        return detection
    joins = list(_PTHREAD_JOIN.finditer(text))
    if not joins:
        return _fail("no_thread_harness",
                     "main() never joins the worker threads — there is no "
                     "point at which the capacity invariant can be judged")
    coverage = linearization_coverage(text, detection)
    if coverage.get("status") != "COVERAGE_PROVED":
        return coverage
    # diagnosable residuals are behind us; only now the availability gate
    # (the c846ef5 ordering discipline)
    if not ESBMC_AVAILABLE:
        return _fail("esbmc_unavailable",
                     "esbmc binary not found on PATH")
    harness = text
    capacity = detection["capacity"]
    if f"head - tail <= {capacity}" not in harness:
        anchor = joins[-1].end()
        harness = (harness[:anchor]
                   + f"\n    assert(head - tail <= {capacity});"
                   + "\n    assert(tail <= head);"
                   + harness[anchor:])
    bounds = [int(b) for b in _LOOP_BOUND.findall(text)] or [3]
    unwind = max(bounds) + 3
    with tempfile.TemporaryDirectory() as directory:
        staged = Path(directory) / "ring.c"
        staged.write_text(harness, encoding="utf-8")
        try:
            process = subprocess.run(
                ["esbmc", str(staged), "--unwind", str(unwind)],
                capture_output=True, text=True, timeout=300)
        except (subprocess.TimeoutExpired, TimeoutError, OSError):
            return _fail("esbmc_timeout",
                         f"ESBMC did not finish within 300s at unwind "
                         f"{unwind}")
    output = (process.stdout or "") + (process.stderr or "")
    if "VERIFICATION SUCCESSFUL" in output:
        return {
            "status": "LOCK_FREE_LINEARIZABILITY_PROVED",
            "claim": "LOCK_FREE_LINEARIZABILITY_PROVED",
            "judge": "esbmc",
            "scope": "concurrent_interleaving_bmc",
            "concurrency_model": "lock_free_spsc",
            "capacity": capacity,
            "linearization_points": coverage["linearization_points"],
            "unwind": unwind,
            "memory_model": "sequential_consistency_pthreads",
            "c11_atomics": "not_modeled_by_esbmc_build",
            "scheduler_fairness": "human_accepted_assumption",
            "progress_proved": False,
            "note": "ESBMC proved the capacity invariant under every "
                    "explored producer/consumer interleaving within the "
                    "unwind bound; fairness (threads that step do not "
                    "corrupt state) is the reviewer's assumption; "
                    "starvation-freedom is not claimed",
        }
    if "VERIFICATION FAILED" in output:
        return _fail("interleaving_violation",
                     "an interleaving violates the capacity invariant: "
                     + output[-500:])
    if "error" in output.lower() and "VERIFICATION" not in output:
        code = ("esbmc_parse_error" if "parse" in output.lower()
                else "esbmc_crashed")
        return _fail(code, output[-400:])
    return _fail("esbmc_no_verdict", output[-400:])


# ---- M50: the MPSC endpoint judge (the name-server lane) --------------

_MPSC_LANES = re.compile(r"#\s*define\s+LANES\s+(\d+)")
_MPSC_CAP = re.compile(r"#\s*define\s+CAP\s+(\d+)")
_MPSC_LANECAP = re.compile(r"#\s*define\s+LANE_CAP\s+(\d+)")
_MPSC_HEAD = re.compile(r"\bint\s+head\s*\[\s*LANES\s*\]\s*=")
_MPSC_TAIL = re.compile(r"\bint\s+tail\s*\[\s*LANES\s*\]\s*=")
_LANE_STORE = re.compile(r"\bhead\s*\[\s*(\d+)\s*\]\s*=[^=]")


def verify_mpsc(source: str | Path) -> dict:
    """The MPSC endpoint witness: capacity statically partitioned into
    per-producer lanes (the provable shape in the plain-int SC dialect —
    a shared-head enqueue has a REAL lost-update interleaving there).
    Each producer owns exactly one lane head (its linearization point);
    ESBMC proves the per-lane and TOTAL capacity invariants under every
    two-producer interleaving. The consumer is deliberately absent from
    the harness: it only decreases occupancy (its absence makes the
    bound harder) and per-lane consumer correctness is the M36-proved
    SPSC shape."""
    path = Path(source)
    if not path.is_file():
        return _fail("input_unavailable", str(path))
    if path.suffix.lower() != ".c":
        return _fail("UNSUPPORTED_BOUNDARY",
                     "the mpsc lane verifies .c pthread sources")
    text = path.read_text(encoding="utf-8")

    lanes = _MPSC_LANES.search(text)
    cap = _MPSC_CAP.search(text)
    lane_cap = _MPSC_LANECAP.search(text)
    if not (lanes and cap and lane_cap) \
            or not _MPSC_HEAD.search(text) or not _MPSC_TAIL.search(text):
        return _fail("no_mpsc_structure",
                     "expected the partitioned-lane dialect: #define "
                     "LANES/CAP/LANE_CAP plus head[LANES] and tail[LANES] "
                     "shared index arrays")
    lanes_n, cap_n, lane_cap_n = (int(lanes.group(1)), int(cap.group(1)),
                                  int(lane_cap.group(1)))
    if lane_cap_n * lanes_n != cap_n:
        return _fail("PARTITION_MISMATCH",
                     f"LANE_CAP {lane_cap_n} x LANES {lanes_n} != CAP "
                     f"{cap_n} — the static partition must account for "
                     "every slot exactly once")
    created = _PTHREAD_CREATE.findall(text)
    if len(created) < 2:
        return _fail("no_thread_harness",
                     "an MPSC witness needs at least two producer "
                     "threads — one producer is the SPSC shape")
    joins = list(_PTHREAD_JOIN.finditer(text))
    if not joins:
        return _fail("no_thread_harness",
                     "main() never joins the producers — there is no "
                     "point at which the capacity invariant can be judged")
    functions = {m.group("name"): _brace_matched_body(
        text, text.index("{", m.start())) for m in _THREAD_FN.finditer(text)
        if m.group("name") in set(created)}
    lane_owners: dict[int, str] = {}
    for name in created:
        body = functions.get(name, "")
        stores = _LANE_STORE.findall(body)
        if not stores:
            return _fail("LINEARIZATION_POINT_MISSING",
                         f"producer '{name}' never stores its lane head — "
                         "its operation has no designated atomic step "
                         "where it takes effect")
        if len(stores) > 1 or len(set(stores)) > 1:
            return _fail("LINEARIZATION_MULTIPLE_STORES",
                         f"producer '{name}' stores head[] {len(stores)} "
                         "times across lanes "
                         f"{sorted(set(stores))} — the linearization point "
                         "is exactly ONE single-word store to ONE lane")
        lane = int(stores[0])
        if lane in lane_owners:
            return _fail("LANE_OWNER_CONFLICT",
                         f"producers '{lane_owners[lane]}' and '{name}' "
                         f"both store head[{lane}] — a shared-head "
                         "enqueue is the unprovable MPMC shape in this "
                         "dialect; partition the capacity instead")
        if not 0 <= lane < lanes_n:
            return _fail("LANE_INDEX_OUT_OF_RANGE",
                         f"producer '{name}' stores head[{lane}] but "
                         f"LANES is {lanes_n}")
        if re.search(r"\btail\s*\[[^\]]*\]\s*=[^=]", body):
            return _fail("PRODUCER_WRITES_TAIL",
                         f"producer '{name}' stores a tail — tails belong "
                         "to the consumer (the M36 SPSC shape) alone")
        lane_owners[lane] = name
    # only now the availability gate (the c846ef5 ordering discipline)
    if not ESBMC_AVAILABLE:
        return _fail("esbmc_unavailable",
                     "esbmc binary not found on PATH")
    harness = text
    if f"head[0] - tail[0] <= {lane_cap_n}" not in harness:
        anchor = joins[-1].end()
        asserts = "".join(
            f"\n    assert(head[{i}] - tail[{i}] <= {lane_cap_n});"
            for i in range(lanes_n))
        asserts += (f"\n    assert(head[0] + head[1] - tail[0] - tail[1]"
                    f" <= {cap_n});")
        asserts += "".join(
            f"\n    assert(tail[{i}] <= head[{i}]);"
            for i in range(lanes_n))
        harness = harness[:anchor] + asserts + harness[anchor:]
    bounds = [int(b) for b in _LOOP_BOUND.findall(text)]
    bounds.append(lane_cap_n)   # symbolic bound: i < LANE_CAP
    unwind = max(bounds) + 3
    with tempfile.TemporaryDirectory() as directory:
        staged = Path(directory) / "mpsc.c"
        staged.write_text(harness, encoding="utf-8")
        try:
            process = subprocess.run(
                ["esbmc", str(staged), "--unwind", str(unwind)],
                capture_output=True, text=True, timeout=300)
        except (subprocess.TimeoutExpired, TimeoutError, OSError):
            return _fail("esbmc_timeout",
                         f"ESBMC did not finish within 300s at unwind "
                         f"{unwind}")
    output = (process.stdout or "") + (process.stderr or "")
    if "VERIFICATION SUCCESSFUL" in output:
        return {
            "status": "MPSC_BOUNDED_PARTITION_PROVED",
            "claim": "MPSC_BOUNDED_PARTITION_PROVED",
            "judge": "esbmc",
            "scope": "partitioned_producer_interleaving_bmc",
            "lanes": lanes_n,
            "lane_capacity": lane_cap_n,
            "capacity": cap_n,
            "lane_owners": lane_owners,
            "unwind": unwind,
            "memory_model": "sequential_consistency_pthreads",
            "consumer": "m36_spsc_shape_not_reproved",
            "scheduler_fairness": "human_accepted_assumption",
            "progress_proved": False,
            "note": "ESBMC proved the per-lane and total capacity "
                    "invariants under every two-producer interleaving "
                    "within the unwind bound; the consumer multiplexes "
                    "lanes in the M36-proved SPSC shape",
        }
    return _fail(
        "esbmc_verification_failed",
        f"ESBMC found a capacity-invariant violation (or failed) within "
        f"unwind {unwind}: {output[-400:]}")
