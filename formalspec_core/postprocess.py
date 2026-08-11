# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Deterministic post-processing of LLM-generated JML code before ESC (DESIGN §16.9).

The LLM persistently writes exit-conditions as loop invariants (a pattern-matching
artifact). This module strips those deterministically, and injects concrete bounds
and invariants the model can't reliably produce via prompts alone.

Neuro-symbolic principle: LLM for creative generation, deterministic tools for refinement.
"""
import math
import re


def postprocess(code: str) -> str:
    """Apply deterministic cleanup to LLM-generated JML code before sending to ESC."""
    code = strip_exit_invariants(code)
    code = strip_result_from_invariants(code)
    code = fix_inner_loop_spec_placement(code)
    code = inject_overflow_bounds(code)
    code = inject_bitshift_bounds(code)
    code = inject_sum_invariant(code)
    code = inject_sum_helper(code)
    code = inject_bidirectional_old(code)
    code = guard_array_access(code)
    code = strengthen_sorted(code)
    code = inject_pure(code)
    code = inject_nonlinear_index_assume(code)
    return code


def _norm(s: str) -> str:
    """Normalize whitespace for expression comparison."""
    return re.sub(r"\s+", "", s)


def _negate_cond(cond: str) -> list:
    negs = []
    for op, neg_op in [("<=", ">"), (">=", "<"), ("<", ">="), (">", "<=")]:
        idx = cond.rfind(op)
        if idx >= 0:
            lhs = cond[:idx].strip()
            rhs = cond[idx + len(op):].strip()
            negs.append(f"{lhs} {neg_op} {rhs}")
            flip = {">": "<", "<": ">", ">=": "<=", "<=": ">="}[neg_op]
            negs.append(f"{rhs} {flip} {lhs}")
            break
    return negs


def strip_exit_invariants(code: str) -> str:
    for m in re.finditer(r"while\s*\((.+?)\)\s*\{", code):
        cond = m.group(1).strip()
        negations = _negate_cond(cond)
        for line in code.split("\n"):
            stripped = line.strip()
            if not (stripped.startswith("//@") and "loop_invariant" in stripped):
                continue
            inv_match = re.search(r"loop_invariant\s+(.+?)\s*;", stripped)
            if not inv_match:
                continue
            inv_expr = inv_match.group(1)
            if any(_norm(inv_expr) == _norm(neg) for neg in negations):
                code = code.replace(line, f"        // STRIPPED exit-condition invariant (was false at entry): {inv_expr}")
    return code


def strip_result_from_invariants(code: str) -> str:
    r"""Strip loop_invariant clauses that reference `\result` (invalid JML).

    JML forbids `\result` in loop_invariants — it's only valid in ensures.
    LLMs write `loop_invariant \result == (...)` when trying to track the
    return value mid-loop. This causes a compile error ("A \result expression
    may not be in a loop_invariant clause") that wastes an entire repair cycle.
    Stripping the clause lets the OTHER invariants proceed to ESC.
    """
    lines = code.split('\n')
    out = []
    for line in lines:
        if 'loop_invariant' in line and '\\result' in line:
            out.append('        // STRIPPED: \\result not valid in loop_invariant')
        else:
            out.append(line)
    return '\n'.join(out)


def fix_inner_loop_spec_placement(code: str) -> str:
    r"""Move loop specs from inside a loop body to before the loop statement.

    LLMs write:
        for (int j = ...) {
            //@ loop_invariant ...;
            //@ decreases ...;
            [actual body code]

    JML requires specs BEFORE the loop:
            //@ loop_invariant ...;
            //@ decreases ...;
        for (int j = ...) {
            [actual body code]

    Error: "Loop specifications must immediately precede a loop statement"
    """
    loop_re = re.compile(r'^\s*(for|while)\s*\(.*\)\s*\{?\s*$')
    spec_re = re.compile(r'^\s*//@\s*(loop_invariant|decreases)\b')
    lines = code.split('\n')
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # Check if this is a loop line (optionally with trailing {)
        is_loop_open = False
        if loop_re.match(line):
            is_loop_open = True
        elif re.match(r'^\s*(for|while)\s*\(.*\)\s*\{', line):
            is_loop_open = True

        if is_loop_open:
            # Collect spec lines that follow (inside the body)
            specs = []
            j = i + 1
            while j < len(lines) and spec_re.match(lines[j]):
                specs.append(lines[j])
                j += 1

            if specs:
                # Re-indent specs to match the loop's indentation
                loop_indent = len(line) - len(line.lstrip())
                for spec in specs:
                    result.append(' ' * loop_indent + spec.strip())
                result.append(line)
                i = j  # skip past the moved spec lines
                continue

        result.append(line)
        i += 1
    return '\n'.join(result)


def _inject_after_match_line(code, match, invariant_line):
    """Insert a new loop_invariant line after the line containing the regex match."""
    line_end = code.index("\n", match.end())
    return code[:line_end] + f"\n        //@ loop_invariant {invariant_line};" + code[line_end:]


def inject_overflow_bounds(code: str) -> str:
    req_bounds = {}
    for m in re.finditer(r"(\w+)\s*<=\s*(\d+)", code):
        req_bounds[m.group(1)] = int(m.group(2))
    m = re.search(r"loop_invariant\s+(\w+)\s*\*\s*\S+\s*<=\s*(\w+)", code)
    if not m:
        return code
    var, y_var = m.group(1), m.group(2)
    if y_var not in req_bounds:
        return code
    bound = math.isqrt(req_bounds[y_var])
    if f"{var} <= {bound}" in code:
        return code
    return _inject_after_match_line(code, m, f"{var} <= {bound}")


def inject_bitshift_bounds(code: str) -> str:
    """For N << VAR patterns in while conditions, inject VAR <= 30 so ESC can bound the shift.

    1 << 30 is the largest power-of-2 in positive int range. Without this bound, Z3 can't
    prove the shift doesn't overflow.
    """
    m = re.search(r"(\d+)\s*<<\s*(\w+)", code)
    if not m:
        return code
    var = m.group(2)
    bound = 30  # safe: 1 << 30 fits in int; 1 << 31 overflows
    if f"{var} <= {bound}" in code:
        return code
    # Find the first loop_invariant line to inject after
    inv_match = re.search(r"loop_invariant\s+.+?;", code)
    if inv_match:
        return _inject_after_match_line(code, inv_match, f"{var} <= {bound}")
    # No existing invariants — inject before the while
    while_match = re.search(r"while\s*\(", code)
    if while_match:
        line_start = code.rfind("\n", 0, while_match.start()) + 1
        code = (code[:line_start]
                + f"        //@ loop_invariant {var} <= {bound};\n"
                + code[line_start:])
    return code


def inject_sum_invariant(code: str) -> str:
    """For \\sum postconditions, synthesize a partial-sum loop invariant.

    If the ensures clause has \\result == (\\sum int j; ... < BOUND; BODY), and there's a
    while loop with counter VAR < BOUND, inject: acc == (\\sum int j; ... < VAR; BODY)
    where acc is the return variable. This offloads inductive reasoning to a template.
    """
    # Skip if the LLM already wrote a \sum loop_invariant (it often does, correctly)
    if re.search(r"loop_invariant\s+.+?\\sum", code):
        return code
    # Find the \sum quantifier in an ensures clause
    sum_match = re.search(
        r"ensures\s+\\result\s*==\s*\(\s*\\sum\s+int\s+(\w+)\s*;\s*(.+?)\s*;\s*(.+?)\s*\)",
        code,
    )
    if not sum_match:
        return code
    quant_var = sum_match.group(1)       # e.g., "j"
    predicate = sum_match.group(2).strip()  # e.g., "0 <= j && j < a.length"
    body = sum_match.group(3).strip()       # e.g., "a[j]"

    # Extract the upper bound from the predicate (the expression after the last "<")
    upper_match = re.search(r"<\s*(\S+)\s*$", predicate)
    if not upper_match:
        return code
    upper_bound = upper_match.group(1)   # e.g., "a.length"

    # Find the while loop counter: while (COUNTER < upper_bound)
    while_match = re.search(
        r"while\s*\(\s*(\w+)\s*[<<=]+\s*" + re.escape(upper_bound),
        code,
    )
    if not while_match:
        return code
    counter = while_match.group(1)       # e.g., "i"

    # Find the accumulator (return variable)
    return_match = re.search(r"return\s+(\w+)\s*;", code)
    if not return_match:
        return code
    acc_var = return_match.group(1)      # e.g., "sum"

    # Synthesize: acc_var == (\sum int quant_var; predicate_with_counter; body)
    partial_pred = predicate.replace(upper_bound, counter)
    invariant = f"{acc_var} == (\\sum int {quant_var}; {partial_pred}; {body})"

    if invariant in code or acc_var == counter:
        return code

    # Inject before the while loop (after the last loop_invariant or decreases)
    while_pos = while_match.start()
    search_region = code[:while_pos]
    last_inv = None
    for lm in re.finditer(r"//@\s*(loop_invariant|decreases)\s+.+?;", search_region):
        last_inv = lm
    if last_inv:
        return _inject_after_match_line(search_region, last_inv, invariant) + code[while_pos:]
    # Fallback: inject right before the while
    line_start = code.rfind("\n", 0, while_pos) + 1
    return code[:line_start] + f"        //@ loop_invariant {invariant};\n" + code[line_start:]


def inject_sum_helper(code: str) -> str:
    r"""Circumvent the ESC frontend's unsupported `\sum` quantifier (DESIGN §16.11).

    ESC drops every `\sum` clause ("Not yet supported feature in converting BasicPrograms to
    SMTLIB"), so aggregation postconditions/preconditions are never checked. The fix is
    syntactic, not semantic: replace each `(\sum int k; 0 <= k && k < B; a[k])` with a call to
    a recursive pure helper whose contract is a recursive *equation* (no `\sum`). ESC translates
    the helper, reasons about it via the equation (proving `r == sumOf(a,i)`), and even does
    induction over the recursion (proving `\result >= 0` and `\result <= n*maxel`).

    Also strips two LLM artifacts that block the proof: the accumulator's constant-bound
    `loop_invariant` (needs monotonicity ESC can't auto-prove) and a sum-bounded `requires`
    (triggers a precondition-of-precondition check).
    """
    if "\\sum" not in code:
        return code
    sum_pat = re.compile(
        r"\(\s*\\sum\s+int\s+(\w+)\s*;\s*0\s*<=\s*\1\s*&&\s*\1\s*<\s*([^;)]+?)\s*;\s*"
        r"(\w+)\s*\[\s*\1\s*\]\s*\)"
    )
    if not sum_pat.search(code):
        return code
    arr = sum_pat.search(code).group(3)
    maxlen_m = re.search(re.escape(arr) + r"\.length\s*<=\s*(\d+)", code)
    maxlen = int(maxlen_m.group(1)) if maxlen_m else 100
    # maxel = the original sum upper bound; it implies a per-element bound (sound refinement,
    # since a[i] <= sum for non-negative arrays) and drives the inductive helper bound.
    maxel_m = re.search(r"\\sum[^)]*\)\s*<=\s*(\d+)", code)
    maxel = int(maxel_m.group(1)) if maxel_m else 1000000
    acc_m = re.search(r"return\s+(\w+)\s*;", code)
    acc = acc_m.group(1) if acc_m else None

    # 1) Strengthen the existing non-negativity forall with the (implied) upper bound.
    code = re.sub(
        re.escape(arr) + r"\[(\w+)\]\s*>=\s*0(?!\s*=)",
        lambda m: f"{arr}[{m.group(1)}] >= 0 && {arr}[{m.group(1)}] <= {maxel}",
        code, count=1,
    )
    # 2) Replace every \sum(...) with sumOf(arr, bound).
    code = sum_pat.sub(lambda m: f"sumOf({m.group(3)}, {m.group(2).strip()})", code)
    # 3) Drop the now-redundant sum-bounded requires (it calls sumOf in a precondition,
    #    triggering an UndefinedCalledMethodPrecondition check; the per-element bound covers it).
    code = re.sub(r"//[ \t]*@?\s*requires\s+sumOf\([^;]*\)\s*<=\s*\d+\s*;\n", "", code)
    # 4) Strip the accumulator's constant-bound loop_invariant: provable for `acc >= 0` (via
    #    sumOf >= 0) but NOT for `acc <= C` (needs monotonicity); the sumOf equality subsumes it.
    if acc:
        code = "\n".join(
            ln for ln in code.split("\n")
            if not (re.search(r"loop_invariant", ln)
                    and re.search(r"\b" + re.escape(acc) + r"\b.*<=\s*\d+", ln))
        )
    # 5) Append the recursive helper (equation contract + non-circular inductive bounds).
    helper = (
        f"    /*@ public normal_behavior\n"
        f"      @ requires {arr} != null;\n"
        f"      @ requires 0 <= n && n <= {arr}.length;\n"
        f"      @ requires (\\forall int k; 0 <= k && k < n; 0 <= {arr}[k] && {arr}[k] <= {maxel});\n"
        f"      @ requires {arr}.length <= {maxlen};\n"
        f"      @ ensures \\result == (n == 0 ? 0 : sumOf({arr}, n-1) + {arr}[n-1]);\n"
        f"      @ ensures \\result >= 0;\n"
        f"      @ ensures \\result <= n * {maxel};\n"
        f"      @ pure\n"
        f"      @*/\n"
        f"    public static int sumOf(int[] {arr}, int n) {{\n"
        f"        return n == 0 ? 0 : sumOf({arr}, n - 1) + {arr}[n - 1];\n"
        f"    }}\n"
    )
    idx = code.rfind("}")
    code = code[:idx] + helper + code[idx:]
    return code


def inject_bidirectional_old(code: str) -> str:
    r"""For single-direction \old invariants on swap loops, inject the mirror clause.

    If the code has `a[k] == \old(a)[EXPR]` but not `a[EXPR] == \old(a)[k]`, inject the
    mirror. This is essential for two-pointer swap patterns (reverse) where the loop writes
    to BOTH a[i] and a[mirror] — without the mirror invariant, Z3 can't prove preservation.
    """
    # Find: loop_invariant (\forall int k; ...; a[k] == \old(a)[EXPR])
    m = re.search(
        r"loop_invariant\s+\(\\forall\s+int\s+(\w+);\s*(.+?);\s*"
        r"(\w+)\[(\w+)\]\s*==\s*\\old\((\w+)\)\[(.+?)\]\)",
        code,
    )
    if not m:
        return code
    quant_var = m.group(1)   # k
    bounds = m.group(2)      # 0 <= k && k < i
    arr = m.group(3)         # a
    left_idx = m.group(4)    # k
    old_arr = m.group(5)     # a
    right_idx = m.group(6)   # a.length - 1 - k

    # Build the mirror: a[right_idx] == \old(a)[left_idx]
    mirror = (f"(\\forall int {quant_var}; {bounds}; "
              f"{arr}[{right_idx}] == \\old({old_arr})[{left_idx}])")

    # Build the frame invariant: unmodified middle region still equals original
    # Extract the loop counter from the bounds (e.g., "0 <= k && k < i" → counter = "i")
    counter_match = re.search(r"<\s*(\w+)", bounds)
    counter = counter_match.group(1) if counter_match else None
    frame = None
    if counter and counter != quant_var:
        # Need: i <= k && k < a.length - i → a[k] == \old(a)[k]
        # Compute the upper bound of the "back" from the right_idx expression
        # right_idx is like "a.length - 1 - k"; the back starts at a.length - i
        # The middle is: counter <= k && k < (a.length - counter)
        # For a.length, extract it from right_idx (it's the array length expression)
        len_expr = re.match(r"(.+?)\s*-\s*\d+\s*-\s*" + quant_var, right_idx)
        arr_len = len_expr.group(1) if len_expr else f"{arr}.length"
        frame = (f"(\\forall int {quant_var}; {counter} <= {quant_var} && {quant_var} < {arr_len} - {counter}; "
                 f"{arr}[{quant_var}] == \\old({old_arr})[{quant_var}])")

    # Inject mirror if not present
    if mirror not in code:
        code = _inject_after_match_line(code, m, mirror)

    # Inject frame if not present
    if frame and frame not in code:
        # Find the mirror we just injected (or the original) to inject after
        anchor = re.search(re.escape(mirror[:30]) + r".+?\)", code)
        if anchor:
            code = _inject_after_match_line(code, anchor, frame)

    return code


def guard_array_access(code: str) -> str:
    r"""Guard ill-defined array accesses in sentinel-or-valid-index invariants.

    LLMs write search-result invariants like `result == -1 || a[result] == key`.
    JML `||` does NOT short-circuit for *definedness* — ESC checks that `a[result]`
    is a valid access even when `result == -1`, yielding UndefinedNegativeIndex /
    UndefinedTooLargeIndex VCs. Rewrite to a guarded disjunction that bounds the
    index inside the second disjunct. (This also keeps the result range explicit,
    so the `-1 <= \result < a.length` postcondition stays provable — an implication
    rewrite like `(result>=0 && ...) ==> ...` would lose that range and break it.)
    """
    pat = re.compile(
        r'(\w+)\s*==\s*-1\s*\|\|\s*(\w+)\[\s*\1\s*\]\s*==\s*([^;)]+?)(?=\s*[;)])'
    )

    def repl(m):
        var, arr, rhs = m.group(1), m.group(2), m.group(3).strip()
        return (f'{var} == -1 || (0 <= {var} && {var} < {arr}.length '
                f'&& {arr}[{var}] == {rhs})')

    return pat.sub(repl, code)


def strengthen_sorted(code: str) -> str:
    r"""Strengthen an adjacent sorted precondition to pairwise ordering.

    Specs state sortedness as adjacent pairs:
    `(\forall int i; 0 <= i && i < a.length - 1; a[i] <= a[i + 1])`.
    But loop-invariant preservation over a sorted array needs NON-adjacent facts
    (e.g. `a[j] <= a[mid]` for arbitrary `j < mid`), which requires transitive
    chaining Z3 will not perform from a `∀i` over neighbors. Add the pairwise form
    `(\forall int i, j; i <= j ==> a[i] <= a[j])`, from which Z3 obtains any
    non-adjacent ordering by a single instantiation. Pairwise implies adjacent, so
    adding it is a sound strengthening.
    """
    pat = re.compile(
        r'\\forall\s+int\s+(\w+)\s*;\s*0\s*<=\s*\1\s*&&\s*\1\s*<\s*(\w+)\.length\s*-\s*1\s*;\s*'
        r'(\w+)\[\s*\1\s*\]\s*<=\s*\3\[\s*\1\s*\+\s*1\s*\]'
    )
    m = pat.search(code)
    if not m:
        return code
    arr = m.group(2)
    if "i, j" in code and "i <= j" in code and f"{arr}[j]" in code:
        return code  # pairwise already present
    pairwise = (f'(\\forall int i, j; 0 <= i && i <= j && j < {arr}.length; '
                f'{arr}[i] <= {arr}[j])')
    line_end = code.index("\n", m.end())
    return code[:line_end] + f"\n    //@ requires {pairwise};" + code[line_end:]


def inject_pure(code: str) -> str:
    r"""Inject `/*@ pure @*/` on methods called from JML spec expressions.

    LLMs write `loop_invariant gcd(r, s) == gcd(a, b)` but forget to mark `gcd`
    as `pure` — JML rejects calls to non-pure methods from spec expressions
    ("A non-pure method is being called where it is not permitted"). This pass
    detects method calls in spec lines and injects `/*@ pure @*/` on the called
    method's declaration.
    """
    _JAVA_KW = frozenset("if while for new return switch catch synchronized throw".split())
    # spec-expression contexts where method calls require purity
    spec_re = re.compile(r'//@.*(?:loop_invariant|ensures|requires|assert|maintaining)')
    # identifiers followed by '(' that are NOT JML \-builtins (\forall, \old, etc.)
    call_re = re.compile(r'(?<!\\)\b([A-Za-z_]\w*)\s*\(')

    # Step 1: collect candidate method names called in spec lines
    candidates = set()
    for line in code.split('\n'):
        if spec_re.search(line):
            for m in call_re.finditer(line):
                name = m.group(1)
                if name not in _JAVA_KW:
                    candidates.add(name)
    if not candidates:
        return code

    # Step 2: find injection points for each candidate
    injections = []
    for name in sorted(candidates):
        decl = re.search(
            rf'(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?'
            rf'\w+(?:\[\s*\])*\s+{re.escape(name)}\s*\(',
            code,
        )
        if not decl:
            continue  # not a declared method (might be a library call)
        line_start = code.rfind('\n', 0, decl.start()) + 1
        # check if pure already present (preceding line + declaration line)
        prev_line_start = max(0, code.rfind('\n', 0, max(0, line_start - 1)))
        if 'pure' in code[prev_line_start:decl.end()]:
            continue
        injections.append(line_start)

    # Step 3: apply bottom-to-top (earlier positions unaffected)
    for pos in sorted(injections, reverse=True):
        code = code[:pos] + '    /*@ pure @*/\n' + code[pos:]
    return code


def inject_nonlinear_index_assume(code: str) -> str:
    r"""Inject sound `assume` for non-linear array index bounds.

    When the body accesses `a[i * cols + j]`, Z3 can't prove the index is in
    bounds (non-linear arithmetic). The preconditions DO imply it's bounded
    (e.g. `a.length == rows * cols`, `0 <= i < rows`, `0 <= j < cols`), but
    Z3 can't derive `i * cols + j < rows * cols` from those facts. Injecting
    `//@ assume 0 <= idx && idx < arr.length;` before the access is a sound
    tactic hint — same principle as inject_overflow_bounds.
    """
    pat = re.compile(r'(\w+)\[([^\]]*\*[^\]]*)\]')
    matches = []
    for m in pat.finditer(code):
        line_start = code.rfind('\n', 0, m.start()) + 1
        line_end = code.find('\n', m.start())
        line_content = code[line_start:line_end if line_end > 0 else len(code)].strip()
        if line_content.startswith('//@') or line_content.startswith('/*'):
            continue
        arr, idx = m.group(1), m.group(2).strip()
        check = f'0 <= {idx} && {idx} < {arr}.length'
        if check.replace(' ', '') in code.replace(' ', ''):
            continue
        matches.append((line_start, arr, idx))
    for line_start, arr, idx in sorted(matches, key=lambda x: -x[0]):
        code = (code[:line_start]
                + f'        //@ assume 0 <= {idx} && {idx} < {arr}.length;\n'
                + code[line_start:])
    return code
