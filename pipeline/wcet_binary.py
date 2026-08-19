# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M44: binary-level WCET — real rustc + objdump, longest CFG path.

The M38 bound reads SOURCE loop trips; this lane reads the EMITTED
OBJECT: ``rustc --emit=obj`` (default opt-level, where the CFG stays
faithful to source loops — the probe showed -O constant-folds an
8-trip loop into ``lea``+``ret``, which is a *correct* tiny bound for
that binary but a different dialect) → ``objdump -d`` → blocks, back
edges, and a sound longest-path bound under the human cost model.

Epistemics, probed on this host:
- Back edges the profile does not bound → ``UNBOUNDED_LOOP_DETECTED``
  (never guessed).
- Indirect control flow (``call *``/``jmp *`` — e.g. the O0 overflow
  panic path) is statically unresolvable in a .o → refused as
  ``WCET_UNBOUNDED_INDIRECT`` unless the human declares
  ``panic_paths: bounded_abort`` with a ``panic_cost_cycles`` budget
  (a trusted assumption, recorded as such).
- The per-iteration loop cost sums the whole loop region — an
  over-approximation, which is sound for an upper bound; the verdict
  records ``loop_cost_overapprox``.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

DEFAULT_COST_MODEL = {"instruction": 1, "memory": 2, "branch": 3}

_BRANCHES = {"jmp", "ret", "call", "loop"} | {
    f"j{suffix}" for suffix in (
        "g", "ge", "l", "le", "e", "ne", "a", "ae", "b", "be", "s", "ns",
        "o", "no", "p", "np", "cxz", "ecxz", "rcxz")}
_CONDITIONAL = {name for name in _BRANCHES
                if name != "jmp" and name != "ret"}

_INSTR_RE = re.compile(
    r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )*[0-9a-f]{2}\s+(\S+)\s*(.*)$")
_FUNC_RE = re.compile(r"^([0-9a-f]+) <([^>]+)>:$")
_TARGET_RE = re.compile(r"\b([0-9a-f]+) <")
_MEM_RE = re.compile(r"\(%r|\(%e|\(%[a-z]")

RUSTC_BIN = shutil.which("rustc")
OBJDUMP_BIN = shutil.which("objdump")


def _fail(code: str, message: str, **extra) -> dict:
    return {"status": "WCET_VERIFICATION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message, **extra}


def _classify(mnemonic: str, operands: str) -> str:
    if mnemonic in _BRANCHES:
        return "branch"
    if mnemonic == "lea":  # address arithmetic, no memory access
        return "instruction"
    if _MEM_RE.search(operands) or mnemonic in {"push", "pop"}:
        return "memory"
    return "instruction"


def parse_functions(disassembly: str) -> dict[str, list[tuple]]:
    """objdump text → {function: [(addr, mnemonic, operands)]}."""
    functions: dict[str, list[tuple]] = {}
    current = None
    for line in disassembly.splitlines():
        header = _FUNC_RE.match(line)
        if header:
            current = header.group(2)
            functions[current] = []
            continue
        match = _INSTR_RE.match(line)
        if match and current is not None:
            functions[current].append((int(match.group(1), 16),
                                       match.group(2),
                                       match.group(3) or ""))
    return {name: instrs for name, instrs in functions.items() if instrs}


def _build_cfg(instructions: list[tuple]) -> dict:
    """Instructions → {blocks, edges, back_edges, indirect}."""
    addr_to_index = {addr: i for i, (addr, _, _) in enumerate(instructions)}
    leaders = {instructions[0][0]}
    branch_at: dict[int, tuple[str, int | None]] = {}
    indirect: list[int] = []
    for addr, mnemonic, operands in instructions:
        if mnemonic in _BRANCHES:
            target = None
            if "*" in operands:
                # jmp */call * — the target is a runtime value (or a
                # relocation the .o cannot show); never resolve the
                # trailing "# addr <name>" comment as a target
                indirect.append(addr)
            elif mnemonic != "ret":
                found = _TARGET_RE.search(operands)
                if found:
                    target = int(found.group(1), 16)
            branch_at[addr] = (mnemonic, target)
            if target is not None:
                leaders.add(target)
            nxt_index = addr_to_index[addr] + 1
            if (mnemonic in _CONDITIONAL or mnemonic == "call") \
                    and nxt_index < len(instructions):
                leaders.add(instructions[nxt_index][0])
    blocks: dict[int, int] = {}       # leader → end addr (inclusive)
    order = sorted(leaders)
    for i, leader in enumerate(order):
        end = (order[i + 1] - 1) if i + 1 < len(order) \
            else instructions[-1][0]
        blocks[leader] = end
    edges: list[tuple[int, int]] = []
    for leader in order:
        i = addr_to_index[leader]
        while i < len(instructions):
            addr = instructions[i][0]
            if addr in branch_at:
                mnemonic, target = branch_at[addr]
                if target is not None and target in blocks:
                    edges.append((leader, target))
                if (mnemonic in _CONDITIONAL or mnemonic == "call") \
                        and i + 1 < len(instructions):
                    nxt = instructions[i + 1][0]
                    if nxt in blocks:
                        edges.append((leader, nxt))
                break
            if addr == blocks[leader]:
                if i + 1 < len(instructions):
                    nxt = instructions[i + 1][0]
                    if nxt in blocks:
                        edges.append((leader, nxt))
                break
            i += 1
    back = [(src, dst) for src, dst in edges if dst <= src]
    return {"blocks": blocks, "edges": edges, "back_edges": back,
            "indirect": indirect}


def _block_costs(instructions: list[tuple], blocks: dict[int, int],
                 cost_model: dict) -> dict[int, int]:
    index = {addr: (mn, ops) for addr, mn, ops in instructions}
    costs = {}
    for leader, end in blocks.items():
        total, addr = 0, leader
        while addr <= end:
            mnemonic, operands = index[addr]
            total += cost_model[_classify(mnemonic, operands)]
            if addr == end:
                break
            addr = next(a for a in index if a > addr)
        costs[leader] = total
    return costs


def wcet_bound_binary(source: str | Path, timing: dict) -> dict:
    """Bound the emitted object's longest CFG path under the human cost
    model. Fail-closed mirrors realtime.wcet_bound's codes."""
    path = Path(source)
    if not path.is_file():
        return _fail("input_unavailable", str(path))
    if path.suffix.lower() != ".rs":
        return _fail("UNSUPPORTED_BOUNDARY",
                     "the binary WCET lane verifies Rust .rs sources")
    if "max_cycles" not in timing:
        return _fail("timing_constraints_missing",
                     "the timing profile requires max_cycles")
    if not RUSTC_BIN or not OBJDUMP_BIN:
        return _fail("toolchain_unavailable",
                     "binary WCET needs rustc and objdump on PATH — the "
                     "source-level M38 bound remains available")

    cost = dict(DEFAULT_COST_MODEL)
    cost.update(timing.get("cost_model", {}))
    with tempfile.TemporaryDirectory() as work:
        obj = Path(work) / (path.stem + ".o")
        try:
            compile_run = subprocess.run(
                [RUSTC_BIN, "--emit=obj", "--crate-type=lib",
                 str(path), "-o", str(obj)],
                capture_output=True, text=True, timeout=120)
        except (subprocess.TimeoutExpired, TimeoutError, OSError):
            return _fail("rustc_timeout", "rustc did not finish")
        if compile_run.returncode != 0:
            return _fail("rustc_failed",
                         compile_run.stderr[-300:] or "rustc error")
        try:
            disasm = subprocess.run(
                [OBJDUMP_BIN, "-d", str(obj)],
                capture_output=True, text=True, timeout=60)
        except (subprocess.TimeoutExpired, TimeoutError, OSError):
            return _fail("objdump_timeout", "objdump did not finish")
        if disasm.returncode != 0:
            return _fail("objdump_failed", disasm.stderr[-300:])
        functions = parse_functions(disasm.stdout)
    if not functions:
        return _fail("no_functions_found",
                     "the object emitted no disassemblable functions")

    bounds = timing.get("loop_bounds", {})
    per_function: dict[str, int] = {}
    for name, instructions in functions.items():
        cfg = _build_cfg(instructions)
        if cfg["indirect"]:
            if timing.get("panic_paths") != "bounded_abort":
                return _fail(
                    "WCET_UNBOUNDED_INDIRECT",
                    f"{name} has unresolvable indirect control flow at "
                    f"{', '.join(hex(a) for a in cfg['indirect'])} — "
                    "declare panic_paths=bounded_abort with a "
                    "panic_cost_cycles budget, or remove the path")
            if "panic_cost_cycles" not in timing:
                return _fail("timing_constraints_missing",
                             "panic_paths=bounded_abort requires "
                             "panic_cost_cycles")
        for src, dst in cfg["back_edges"]:
            trips = bounds.get(name)
            if trips is None:
                return _fail(
                    "UNBOUNDED_LOOP_DETECTED",
                    f"{name} has a loop (back edge {hex(src)} -> "
                    f"{hex(dst)}) with no declared trip count — the "
                    "binary lane never guesses loop bounds")
        costs = _block_costs(instructions, cfg["blocks"], cost)
        # longest acyclic path: forward edges only go low -> high, so a
        # descending-address sweep is a valid topological order
        forward = [(s, d) for s, d in cfg["edges"] if d > s]
        succs: dict[int, list[int]] = {}
        for s, d in forward:
            succs.setdefault(s, []).append(d)
        longest: dict[int, int] = {}
        for leader in sorted(cfg["blocks"], reverse=True):
            downstream = [longest[d] for d in succs.get(leader, [])
                          if d in longest]
            base = costs[leader]
            if cfg["indirect"] and timing.get(
                    "panic_paths") == "bounded_abort":
                base += int(timing["panic_cost_cycles"])
            longest[leader] = base + (max(downstream) if downstream else 0)
        total = longest[min(cfg["blocks"])]
        for src, _dst in cfg["back_edges"]:
            trips = int(bounds[name])
            region = sum(cost for leader, cost in costs.items()
                         if min(cfg["blocks"]) <= leader <= src)
            total += region * (trips - 1)
        per_function[name] = total

    wcet = max(per_function.values())
    if wcet > timing["max_cycles"]:
        return _fail("DEADLINE_MISSED",
                     f"binary longest path {wcet} cycles exceeds the "
                     f"deadline {timing['max_cycles']}",
                     per_function=per_function)
    return {"status": "WCET_BOUND_PROVEN", "claim": "WCET_BOUND_PROVEN",
            "judge": "objdump_static_analysis", "scope": "binary_cfg",
            "wcet_cycles": wcet,
            "headroom_cycles": timing["max_cycles"] - wcet,
            "per_function_cycles": per_function,
            "cost_model": cost,
            "cost_model_ownership": "human_declared_hardware_profile",
            "loop_cost_overapprox": True,
            "wcet_method": "rustc --emit=obj + objdump -d CFG longest "
                           "path (loop region over-approximation); aiT "
                           "judge_pending"}
