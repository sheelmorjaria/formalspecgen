# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Deterministic completeness and vacuity linting for JML-annotated Java."""
import re
from dataclasses import asdict, dataclass


@dataclass
class SpecWarning:
    line: int
    code: str
    message: str
    advice: str
    severity: str = "warning"


_METHOD = re.compile(
    r"(?P<contracts>(?:\s*//@[^\n]*\n)*)\s*public\s+(?:static\s+)?"
    r"(?P<ret>void|boolean|int|long|double|[A-Z]\w*(?:\[\])?)\s+"
    r"(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*\{",
    re.MULTILINE,
)
_ARRAY_PARAM = re.compile(r"\b\w+\s*\[\s*\]\s*(\w+)")

# These findings mean the draft does not yet express a reviewable behavioral contract.
# Tool-support advisories remain warnings and do not block OpenJML syntax validation.
BLOCKING_CODES = frozenset({
    "missing-postcondition", "unconstrained-boolean-result",
    "vacuous-boolean-postcondition", "vacuous-true-clause", "self-equality",
    "missing-array-nonnull", "missing-array-frame", "missing-field-frame",
    "boolean-failure-excluded-by-precondition",
    "unreachable-exceptional-behavior",
    "domain-contract-mismatch",
})


def blocking_findings(warnings: list[dict]) -> list[dict]:
    return [warning for warning in warnings if warning.get("code") in BLOCKING_CODES]


def lint_spec(code: str) -> list[dict]:
    warnings: list[SpecWarning] = []
    lines = code.splitlines()

    for index, line in enumerate(lines, 1):
        clause = line.split("//@", 1)[1].strip() if "//@" in line else ""
        normalized = re.sub(r"\s+", "", clause).lower()
        if re.search(r"ensures(?:\\result)?==true\|\|(?:\\result)?==false", normalized):
            warnings.append(SpecWarning(index, "vacuous-boolean-postcondition",
                "This Boolean postcondition is true for every possible result.",
                "Specify when the result must be true, for example: ensures \\result <==> predicate;"))
        elif re.match(r"(?:ensures|requires)\s+true\s*;", clause, re.IGNORECASE):
            warnings.append(SpecWarning(index, "vacuous-true-clause",
                "This clause imposes no constraint.", "Replace it with the intended behavioral condition."))
        elif re.search(r"\b(\w+)\s*==\s*\1\b", clause):
            warnings.append(SpecWarning(index, "self-equality",
                "Self-equality is tautological and adds no verification obligation.",
                "Relate the value to an input, pre-state value, field, or concrete bound."))
        for construct, replacement in (("\\num_of", "targeted Dafny multiset lowering"),
                                       ("\\sum", "the inject_sum_helper postprocessor"),
                                       ("\\product", "a recursive pure helper or Dafny function")):
            if construct in clause:
                warnings.append(SpecWarning(index, "openjml-unsupported-aggregate",
                    f"OpenJML ESC may drop or reject {construct} obligations.",
                    f"Use {replacement}; do not treat a clean ESC exit as proof of this clause."))

    for method in _METHOD.finditer(code):
        contracts = method.group("contracts")
        signature_line = code.count("\n", 0, method.start("name")) + 1
        body, _end = _method_body(code, method.end() - 1)
        arrays = _ARRAY_PARAM.findall(method.group("params"))
        positive_requirement = re.search(r"requires\s+(\w+)\s*>\s*0\s*;", contracts)
        variable = positive_requirement.group(1) if positive_requirement else ""
        if variable and re.search(
                rf"signals\s*\([^)]*\)\s*{re.escape(variable)}\s*<=\s*0\s*;", contracts):
            warnings.append(SpecWarning(signature_line, "unreachable-exceptional-behavior",
                f"The {variable} <= 0 exceptional behavior is excluded by the {variable} > 0 precondition.",
                "Use explicit normal_behavior/exceptional_behavior cases if invalid input must throw."))
        for array in arrays:
            if (re.search(rf"\b{re.escape(array)}\s*\[", contracts + body)
                    and not re.search(rf"requires\s+{re.escape(array)}\s*!=\s*null", contracts)):
                warnings.append(SpecWarning(signature_line, "missing-array-nonnull",
                    f"Array '{array}' is accessed without an explicit non-null precondition.",
                    f"Add //@ requires {array} != null; unless null has defined behavior."))
            if (re.search(rf"\b{re.escape(array)}\s*\[[^]]+\]\s*=", body)
                    and not re.search(rf"assignable\s+(?:{re.escape(array)}\[\*\]|{re.escape(array)}\[\])", contracts)):
                warnings.append(SpecWarning(signature_line, "missing-array-frame",
                    f"Method writes array '{array}' but has no matching assignable clause.",
                    f"Add //@ assignable {array}[*]; or a narrower element range."))
        if method.group("ret") != "void" and "ensures" not in contracts:
            warnings.append(SpecWarning(signature_line, "missing-postcondition",
                f"Value-returning method '{method.group('name')}' has no postcondition.",
                "Add an ensures clause that characterizes \\result."))
        elif method.group("ret") == "boolean" and not re.search(r"\\result\b", contracts):
            warnings.append(SpecWarning(signature_line, "unconstrained-boolean-result",
                f"Boolean method '{method.group('name')}' has postconditions that do not constrain \\result.",
                "Relate \\result to the success/failure state transition with an equivalence or guarded clauses."))
        elif method.group("ret") == "boolean":
            excluded = _boolean_feasibility_excluded(contracts)
            if excluded:
                warnings.append(SpecWarning(signature_line,
                    "boolean-failure-excluded-by-precondition",
                    f"Boolean method '{method.group('name')}' requires every condition that defines its true result, so false is unreachable.",
                    "Keep domain/exception requirements, but remove feasibility requirements for defined false-return cases: "
                    + ", ".join(excluded)))

    # Field writes: exclude local declarations, parameters, and array elements.
    fields = set(re.findall(r"\b(?:private|protected|public)\s+(?:/\*@.*?@\*/\s+)?\w+\s+(\w+)\s*;", code))
    for method in _METHOD.finditer(code):
        contracts = method.group("contracts")
        body, _end = _method_body(code, method.end() - 1)
        signature_line = code.count("\n", 0, method.start("name")) + 1
        for field in fields:
            if re.search(rf"(?<![.\w]){re.escape(field)}\s*(?:=|\+\+|--|\+=|-=)", body):
                if not re.search(rf"assignable\s+[^;]*\b{re.escape(field)}\b", contracts):
                    warnings.append(SpecWarning(signature_line, "missing-field-frame",
                        f"Method writes field '{field}' but does not declare it assignable.",
                        f"Add //@ assignable {field}; or explicitly use assignable \\nothing."))

    unique = {(w.line, w.code, w.message): w for w in warnings}
    return [asdict(w) for w in unique.values()]


def _method_body(code: str, opening_brace: int) -> tuple[str, int]:
    depth = 0
    for pos in range(opening_brace, len(code)):
        if code[pos] == "{":
            depth += 1
        elif code[pos] == "}":
            depth -= 1
            if depth == 0:
                return code[opening_brace + 1:pos], pos
    return code[opening_brace + 1:], len(code)


def _boolean_feasibility_excluded(contracts: str) -> list[str]:
    iff = re.search(r"ensures\s+\\result\s*<==>\s*(.+?)\s*;", contracts)
    if not iff:
        return []
    predicate = _strip_outer_parens(iff.group(1).strip())
    conjuncts = [_contract_expr(item) for item in re.split(r"\s*&&\s*", predicate)]
    requires = {_contract_expr(item) for item in re.findall(r"requires\s+(.+?)\s*;", contracts)}
    return conjuncts if conjuncts and all(item in requires for item in conjuncts) else []


def _contract_expr(value: str) -> str:
    value = re.sub(r"\\old\s*\(\s*([^()]+?)\s*\)", r"\1", value)
    return re.sub(r"\s+", "", _strip_outer_parens(value))


def _strip_outer_parens(value: str) -> str:
    while value.startswith("(") and value.endswith(")"):
        depth = 0
        wraps = True
        for index, char in enumerate(value):
            depth += 1 if char == "(" else -1 if char == ")" else 0
            if depth == 0 and index != len(value) - 1:
                wraps = False
                break
        if not wraps:
            break
        value = value[1:-1].strip()
    return value
