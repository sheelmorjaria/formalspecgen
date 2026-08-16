# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic, read-only Java modernization inspection."""
from __future__ import annotations

import hashlib
import math
from pathlib import Path

import javalang


GOD_FIELD_THRESHOLD = 10
GOD_METHOD_THRESHOLD = 15
LONG_METHOD_LINES = 60
CONSTRUCTOR_DEPENDENCY_THRESHOLD = 5
BUILDER_ARGUMENT_THRESHOLD = 6
PROXY_MIN_PUBLIC_METHODS = 2
PROXY_GUARDED_DELEGATION_RATIO = 0.5
COMMAND_BRANCH_THRESHOLD = 3

def inspect_java_file(path: str | Path) -> dict:
    # Local import: pattern_registry imports the detector classes defined below,
    # so importing it at module scope would create an import cycle.
    from .pattern_registry import PATTERN_REGISTRY
    source_path = Path(path)
    if source_path.suffix.lower() not in {".java", ".jml"}:
        return _fail("unsupported_language", "Java/JML source is required")
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as exc:
        return _fail("source_unavailable", str(exc))
    try:
        tree = javalang.parse.parse(source)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError,
            TypeError) as exc:
        return _fail("unsupported_java_syntax", str(exc))
    classes = [declaration for declaration in tree.types
               if isinstance(declaration, javalang.tree.ClassDeclaration)]
    if len(tree.types) != 1 or len(classes) != 1:
        return _fail("unsupported_class_shape", "Exactly one concrete class is required")
    declaration = classes[0]
    class_name = declaration.name
    methods = list(declaration.constructors) + list(declaration.methods)
    fields = list(declaration.fields)
    findings = []
    for plugin in PATTERN_REGISTRY:
        findings.extend(plugin.detector(source, declaration).detect())

    return {"status": "INSPECTED", "claim": "STATIC_INSPECTION",
            "scope": "deterministic_token_aware_java_structure_heuristics",
            "parser_mode": "javalang_ast_0.13.0", "source": str(source_path.resolve()),
            "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "class": class_name, "metrics": {"fields": len(fields), "methods": len(methods)},
            "findings": findings, "automated_refactor_applied": False,
            "formal_defect_proved": False, "behavior_equivalence_proved": False}


def _mask_non_code(source: str) -> str:
    output = list(source); index = 0; state = "code"
    while index < len(source):
        pair = source[index:index + 2]
        char = source[index]
        if state == "code" and pair in {"//", "/*"}:
            state = "line" if pair == "//" else "block"
            output[index] = output[index + 1] = " "; index += 2; continue
        if state == "code" and char in {'"', "'"}:
            state = "string" if char == '"' else "char"; output[index] = " "
        elif state == "line":
            if char == "\n": state = "code"
            else: output[index] = " "
        elif state == "block":
            if pair == "*/":
                output[index] = output[index + 1] = " "; index += 2; state = "code"; continue
            if char != "\n": output[index] = " "
        elif state in {"string", "char"}:
            quote = '"' if state == "string" else "'"
            if char == "\\" and index + 1 < len(source):
                output[index] = output[index + 1] = " "; index += 2; continue
            output[index] = " " if char != "\n" else "\n"
            if char == quote: state = "code"
            elif char == "\n": raise ValueError("unterminated string or character literal")
        index += 1
    if state in {"block", "string", "char"}:
        raise ValueError("unterminated comment or literal")
    return "".join(output)


def _matching_brace(source: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(source)):
        depth += 1 if source[index] == "{" else -1 if source[index] == "}" else 0
        if depth == 0: return index
    return opening


def _runtime_type_condition(condition) -> bool:
    nodes = [condition]
    if isinstance(condition, javalang.ast.Node):
        nodes.extend(node for _, node in condition)
    has_type_member = any(isinstance(node, javalang.tree.MemberReference) and
                          node.member == "type" for node in nodes)
    return any(
        isinstance(node, javalang.tree.BinaryOperation) and
        (node.operator == "instanceof" or (node.operator in {"==", "!="} and has_type_member))
        or isinstance(node, javalang.tree.MethodInvocation) and node.member == "getClass"
        for node in nodes)


class PatternDetector:
    """Small deterministic detector registered in ``DETECTOR_REGISTRY``."""
    def __init__(self, source: str, declaration) -> None:
        self.source, self.declaration = source, declaration

    def detect(self) -> list[dict]:
        raise NotImplementedError


class CoreStructureDetector(PatternDetector):
    def detect(self) -> list[dict]:
        findings = []
        methods = list(self.declaration.constructors) + list(self.declaration.methods)
        switches = [node for _, node in self.declaration.filter(javalang.tree.IfStatement)
                    if _runtime_type_condition(node.condition)]
        if len(switches) >= 2:
            implicated = [method.name for method in methods
                          if any(candidate is node for node in switches
                                 for _, candidate in method.filter(javalang.tree.IfStatement))]
            findings.append(_finding(_line(switches[0]), "type-switch", "warning",
                f"Found {len(switches)} runtime type-dispatch branches.", "Strategy",
                "Move variant behavior behind a polymorphic strategy interface."))
            if implicated:
                findings[-1]["methods"] = sorted(set(implicated))
        if (len(self.declaration.fields) >= GOD_FIELD_THRESHOLD and
                len(methods) >= GOD_METHOD_THRESHOLD):
            finding = _finding(_line(self.declaration), "god-class", "warning",
                f"Class has {len(self.declaration.fields)} fields and {len(methods)} methods.",
                "Facade", "Split cohesive responsibilities, retaining a small façade at the existing boundary.")
            finding.update({"class": self.declaration.name,
                            "field_count": len(self.declaration.fields),
                            "callable_count": len(methods),
                            "fields": sorted({declarator.name for field in self.declaration.fields
                                               for declarator in field.declarators}),
                            "methods": sorted(method.name for method in methods)})
            findings.append(finding)
        for method in methods:
            lines = _callable_lines(self.source, method)
            if lines > LONG_METHOD_LINES:
                findings.append(_finding(_line(method), "long-method", "warning",
                    f"Method {method.name} spans {lines} lines.", "Extract Method",
                    "Extract cohesive steps while preserving the existing JML method contract."))
            if (isinstance(method, javalang.tree.ConstructorDeclaration) and
                    len(method.parameters) >= CONSTRUCTOR_DEPENDENCY_THRESHOLD):
                findings.append(_finding(_line(method), "constructor-overinjection", "warning",
                    f"Constructor accepts {len(method.parameters)} dependencies/parameters.",
                    "Facade", "Group cohesive collaborators behind narrower role interfaces; review lifetime ownership."))
        return findings


class SingletonDetector(PatternDetector):
    def detect(self) -> list[dict]:
        private_constructor = any("private" in node.modifiers
                                  for node in self.declaration.constructors)
        accessor = next((node for node in self.declaration.methods
                         if {"public", "static"}.issubset(node.modifiers) and
                         _type_name(node.return_type) == self.declaration.name), None)
        if not private_constructor or accessor is None:
            return []
        return [_finding(_line(accessor), "singleton-global-access", "warning",
            "Private construction plus a public static self-typed accessor forms a Singleton.",
            "Dependency Injection", "Review global lifetime/state and prefer an explicitly owned dependency where possible.")]


class ObserverDetector(PatternDetector):
    def detect(self) -> list[dict]:
        listener_list = any(_type_name(field.type) in {"List", "Collection", "Set"} and
                            "Listener" in str(field.type.arguments)
                            for field in self.declaration.fields)
        names = [method.name for method in self.declaration.methods]
        adds = any(name.startswith("add") and name.endswith("Listener") for name in names)
        removes = any(name.startswith("remove") and name.endswith("Listener") for name in names)
        if not (listener_list and adds and removes):
            return []
        return [_finding(_line(self.declaration), "listener-registry", "info",
            "Listener collection has paired add/remove listener operations.", "Observer",
            "Make event ordering, subscription lifetime, and callback failure semantics explicit.")]


class BuilderOpportunityDetector(PatternDetector):
    def detect(self) -> list[dict]:
        findings = []
        for _, node in self.declaration.filter(javalang.tree.ClassCreator):
            arguments = list(node.arguments or [])
            literal_count = sum(isinstance(argument, javalang.tree.Literal)
                                for argument in arguments)
            if (len(arguments) >= BUILDER_ARGUMENT_THRESHOLD and
                    literal_count >= math.ceil(len(arguments) * 0.6)):
                findings.append(_finding(_line(node), "large-literal-construction", "warning",
                    f"Constructor call has {len(arguments)} arguments, mostly literals.", "Builder",
                    "Use named construction steps and validate required values before build()."))
        return findings


class RepositoryDetector(PatternDetector):
    _DATABASE_MEMBERS = {"executeQuery", "executeUpdate", "persist", "merge",
                         "remove", "getConnection", "prepareStatement"}

    def detect(self) -> list[dict]:
        calls = [node for _, node in self.declaration.filter(javalang.tree.MethodInvocation)
                 if node.member in self._DATABASE_MEMBERS]
        business_branches = list(self.declaration.filter(javalang.tree.IfStatement))
        calculations = [node for _, node in self.declaration.filter(javalang.tree.BinaryOperation)
                        if node.operator in {"+", "-", "*", "/", "%"}]
        if not calls or not (business_branches or calculations):
            return []
        return [_finding(_line(calls[0]), "mixed-persistence-logic", "warning",
            "Database API calls are mixed with branching or calculation logic.", "Repository",
            "Extract persistence behind an interface and keep transaction assumptions explicit.")]


class AdapterDetector(PatternDetector):
    def detect(self) -> list[dict]:
        if len(self.declaration.fields) != 1 or not self.declaration.constructors:
            return []
        field_names = {declarator.name for declarator in self.declaration.fields[0].declarators}
        if not any(_assigns_field(constructor, field_names)
                   for constructor in self.declaration.constructors):
            return []
        public_methods = [method for method in self.declaration.methods
                          if "public" in method.modifiers and method.body]
        if len(public_methods) < 2:
            return []
        delegated = sum(_delegates_to(method, field_names) for method in public_methods)
        if delegated / len(public_methods) < 0.8:
            return []
        return [_finding(_line(self.declaration), "delegation-wrapper", "info",
            f"{delegated}/{len(public_methods)} public methods delegate directly to one field.",
            "Adapter", "Document the target contract and verify argument/result translation explicitly.")]


class FactoryMethodDetector(PatternDetector):
    def detect(self) -> list[dict]:
        findings = []
        for method in self.declaration.methods:
            returned = _type_name(method.return_type)
            if not returned or returned in {"void", "boolean", "byte", "short", "int",
                                            "long", "float", "double", "char"}:
                continue
            decisions = ([node for _, node in method.filter(javalang.tree.IfStatement)] +
                         [node for _, node in method.filter(javalang.tree.SwitchStatement)])
            if not decisions:
                continue
            concrete = {_type_name(node.type) for decision in decisions
                        for _, node in decision.filter(javalang.tree.ClassCreator)
                        if _type_name(node.type) and _type_name(node.type) != returned}
            if len(concrete) < 2:
                continue
            findings.append(_finding(_line(method), "conditional-object-creation", "warning",
                f"Method {method.name} conditionally creates concrete types: " +
                ", ".join(sorted(concrete)) + ".", "Factory Method",
                "Move creation policy behind a factory contract; preserve failure and constructor side effects."))
            findings[-1]["method"] = method.name
        return findings


class StatePatternDetector(PatternDetector):
    _STATE_NAMES = {"state", "status", "mode"}

    def detect(self) -> list[dict]:
        candidates = {declarator.name for field in self.declaration.fields
                      if _type_name(field.type) in {"int", "Integer", "String"}
                      for declarator in field.declarators
                      if declarator.name.lower() in self._STATE_NAMES}
        for field_name in sorted(candidates):
            affected = [method for method in self.declaration.methods
                        if _method_branches_on(method, field_name)]
            if len(affected) >= 2:
                finding = _finding(_line(affected[0]), "repeated-state-dispatch", "warning",
                    f"Field {field_name} controls branching in {len(affected)} methods.",
                    "State", "Model legal transitions first, then isolate state-dependent behavior behind explicit state contracts.")
                finding.update({"field": field_name,
                                "methods": sorted(method.name for method in affected)})
                return [finding]
        return []


class DecoratorDetector(PatternDetector):
    _CROSS_CUTTING = {"log", "info", "debug", "warn", "error", "trace", "increment",
                      "record", "timer", "count", "metric"}

    def detect(self) -> list[dict]:
        interfaces = {_type_name(item) for item in self.declaration.implements or []}
        if not interfaces:
            return []
        fields = {declarator.name: _type_name(field.type) for field in self.declaration.fields
                  for declarator in field.declarators}
        wrapped = {name for name, type_name in fields.items() if type_name in interfaces}
        if not wrapped or not any(_constructor_accepts_and_assigns(
                constructor, interfaces, wrapped) for constructor in self.declaration.constructors):
            return []
        public_methods = [method for method in self.declaration.methods
                          if "public" in method.modifiers and method.body]
        decorated = [method for method in public_methods
                     if _contains_delegation(method, wrapped) and _has_cross_cutting_call(
                         method, wrapped, self._CROSS_CUTTING)]
        if not decorated or len(decorated) * 2 < len(public_methods):
            return []
        finding = _finding(_line(decorated[0]), "cross-cutting-delegation", "warning",
            f"{len(decorated)}/{len(public_methods)} public methods combine cross-cutting calls with wrapped-interface delegation.",
            "Decorator", "Move logging/metrics to a decorator while preserving callback order and exception behavior.")
        finding["methods"] = sorted(method.name for method in decorated)
        finding["interfaces"] = sorted(interfaces)
        finding["wrapped_fields"] = sorted(wrapped)
        return [finding]


class NullObjectDetector(PatternDetector):
    """Detect repeated nullable collaborator checks suitable for Null Object."""
    def detect(self) -> list[dict]:
        checks = []
        for _, node in self.declaration.filter(javalang.tree.IfStatement):
            condition = node.condition
            if isinstance(condition, javalang.tree.BinaryOperation) and condition.operator in {"==", "!="}:
                text = str(condition.operandl) + str(condition.operandr)
                if "null" in text.lower():
                    checks.append(node)
        if len(checks) < 2:
            return []
        return [_finding(_line(checks[0]), "repeated-null-check", "info",
                         f"Found {len(checks)} nullable branches.", "Null Object",
                         "Provide a safe no-op implementation to eliminate repeated null checks and preserve CWE-476 safety.")]


class ProxyDetector(PatternDetector):
    """Detect guarded delegation to a wrapped interface (Proxy vs plain Adapter)."""
    def detect(self) -> list[dict]:
        interfaces = {_type_name(item) for item in self.declaration.implements or []}
        if not interfaces:
            return []
        wrapped = {declarator.name for field in self.declaration.fields
                   if _type_name(field.type) in interfaces
                   for declarator in field.declarators}
        if not wrapped:
            return []
        public_methods = [method for method in self.declaration.methods
                          if "public" in method.modifiers and method.body]
        if len(public_methods) < PROXY_MIN_PUBLIC_METHODS:
            return []
        guarded = [method for method in public_methods
                   if _has_guard(method) and _contains_delegation(method, wrapped)]
        if not guarded or len(guarded) / len(public_methods) < PROXY_GUARDED_DELEGATION_RATIO:
            return []
        finding = _finding(_line(guarded[0]), "guard-delegation", "info",
            f"{len(guarded)}/{len(public_methods)} public methods guard access before "
            "delegating to the wrapped interface.", "Proxy",
            "Make the guard (access control, caching, or lazy acquisition) explicit and "
            "verify it preserves the wrapped contract.")
        finding["methods"] = sorted(method.name for method in guarded)
        finding["wrapped_fields"] = sorted(wrapped)
        return [finding]


class CommandDetector(PatternDetector):
    """Detect string-keyed command dispatch suitable for Command objects."""
    def detect(self) -> list[dict]:
        findings = []
        for method in self.declaration.methods:
            string_params = {parameter.name for parameter in method.parameters
                             if _type_name(parameter.type) == "String"}
            if not string_params:
                continue
            for _, switch in method.filter(javalang.tree.SwitchStatement):
                if (len(_switch_cases_with_work(switch)) >= COMMAND_BRANCH_THRESHOLD and
                        _references_name(switch.expression, string_params)):
                    finding = _finding(_line(switch), "string-command-dispatch", "warning",
                        f"Method {method.name} dispatches commands through a switch on a "
                        "String parameter.", "Command",
                        "Replace string-keyed dispatch with command objects and keep "
                        "unknown-command behavior explicit.")
                    finding["method"] = method.name
                    findings.append(finding)
                    break
            branch_counts: dict[str, int] = {}
            for _, branch in method.filter(javalang.tree.IfStatement):
                parameter = _string_equality_parameter(branch.condition, string_params)
                if parameter and _branch_performs_work(branch.then_statement):
                    branch_counts[parameter] = branch_counts.get(parameter, 0) + 1
            for parameter in sorted(branch_counts):
                if branch_counts[parameter] < COMMAND_BRANCH_THRESHOLD:
                    continue
                finding = _finding(_line(method), "string-command-dispatch", "warning",
                    f"Method {method.name} dispatches {branch_counts[parameter]} branches "
                    f"on String parameter {parameter}.", "Command",
                    "Replace string-keyed dispatch with command objects and keep "
                    "unknown-command behavior explicit.")
                finding["method"] = method.name
                findings.append(finding)
        return findings


class ProducerConsumerDetector(PatternDetector):
    """Detect bounded-buffer storage needing overflow/underflow review."""
    _PUT_PREFIXES = ("put", "produce")
    _GET_PREFIXES = ("get", "consume", "take")
    _MONITOR_MEMBERS = {"wait", "notifyAll"}

    def detect(self) -> list[dict]:
        if not any(_is_array_field(field) for field in self.declaration.fields):
            return []
        put_methods = [method for method in self.declaration.methods
                       if method.name.startswith(self._PUT_PREFIXES)]
        get_methods = [method for method in self.declaration.methods
                       if method.name.startswith(self._GET_PREFIXES)]
        if not put_methods or not get_methods:
            return []
        occupancy_fields = {declarator.name for field in self.declaration.fields
                            if _type_name(field.type) in {"int", "Integer"}
                            for declarator in field.declarators
                            if _is_occupancy_name(declarator.name)}
        tracked_occupancy = (any(_assigns_field(method, occupancy_fields)
                                 for method in put_methods) and
                             any(_assigns_field(method, occupancy_fields)
                                 for method in get_methods))
        uses_monitor = any(node.member in self._MONITOR_MEMBERS
                           for _, node in self.declaration.filter(
                               javalang.tree.MethodInvocation))
        if not (tracked_occupancy or uses_monitor):
            return []
        finding = _finding(_line(self.declaration), "bounded-buffer", "info",
            f"Array storage with paired {put_methods[0].name}/{get_methods[0].name} "
            "operations forms a bounded buffer.", "Producer-Consumer",
            "Model the buffer as a bounded TLC specification and check overflow/underflow "
            "(put on full, get on empty) before refactoring.")
        finding.update({"put_methods": sorted(method.name for method in put_methods),
                        "get_methods": sorted(method.name for method in get_methods)})
        return [finding]


# Kept as the explicit detector order for direct imports; pipeline.pattern_registry
# derives its registry copy from PATTERN_REGISTRY and tests pin both together.
DETECTOR_REGISTRY = (CoreStructureDetector, SingletonDetector, ObserverDetector,
                     BuilderOpportunityDetector, RepositoryDetector, AdapterDetector,
                     FactoryMethodDetector, StatePatternDetector, DecoratorDetector,
                     NullObjectDetector, ProxyDetector, CommandDetector,
                     ProducerConsumerDetector)


def _type_name(node) -> str:
    return getattr(node, "name", "") if node is not None else ""


def _delegates_to(method, field_names: set[str]) -> bool:
    if len(method.body) != 1:
        return False
    statement = method.body[0]
    expression = (statement.expression if isinstance(
        statement, javalang.tree.StatementExpression) else
        statement.expression if isinstance(statement, javalang.tree.ReturnStatement) else None)
    return (isinstance(expression, javalang.tree.MethodInvocation) and
            expression.qualifier in field_names)


def _contains_delegation(method, field_names: set[str]) -> bool:
    return any(node.qualifier in field_names for _, node in method.filter(
        javalang.tree.MethodInvocation))


def _has_guard(method) -> bool:
    return next(method.filter(javalang.tree.IfStatement), None) is not None


def _walk_nodes(node):
    # Iterates Node.__iter__ directly would re-yield each node as its own first
    # item and recurse forever, so descend through the raw children property.
    if isinstance(node, (list, tuple)):
        for item in node:
            yield from _walk_nodes(item)
    elif isinstance(node, javalang.ast.Node):
        yield node
        for child in node.children:
            yield from _walk_nodes(child)


def _references_name(node, names: set[str]) -> bool:
    for walked in _walk_nodes(node):
        if isinstance(walked, javalang.tree.MemberReference) and walked.member in names:
            return True
        if (isinstance(walked, javalang.tree.MethodInvocation) and
                walked.qualifier in names):
            return True
    return False


def _is_null_literal(node) -> bool:
    return isinstance(node, javalang.tree.Literal) and str(node.value).lower() == "null"


def _string_equality_parameter(condition, string_params: set[str]) -> str | None:
    for node in _walk_nodes(condition):
        if (isinstance(node, javalang.tree.BinaryOperation) and node.operator == "=="
                and not _is_null_literal(node.operandl)
                and not _is_null_literal(node.operandr)):
            for operand in (node.operandl, node.operandr):
                if (isinstance(operand, javalang.tree.MemberReference) and
                        operand.member in string_params):
                    return operand.member
        elif (isinstance(node, javalang.tree.MethodInvocation) and
                node.member == "equals"):
            qualifier = node.qualifier
            if isinstance(qualifier, str) and qualifier in string_params:
                return qualifier
            if (isinstance(qualifier, javalang.tree.MemberReference) and
                    qualifier.member in string_params):
                return qualifier.member
            for argument in node.arguments or []:
                if (isinstance(argument, javalang.tree.MemberReference) and
                        argument.member in string_params):
                    return argument.member
    return None


def _branch_performs_work(then_statement) -> bool:
    if isinstance(then_statement, javalang.tree.BlockStatement):
        return bool(getattr(then_statement, "statements", None))
    return then_statement is not None


def _switch_cases_with_work(switch) -> list:
    return [case for case in switch.cases
            if any(not isinstance(statement, javalang.tree.BreakStatement)
                   for statement in (case.statements or []))]


def _is_array_field(field) -> bool:
    return bool(getattr(field.type, "dimensions", None))


def _is_occupancy_name(name: str) -> bool:
    lowered = name.lower()
    return "count" in lowered or lowered in {"size", "occupancy"}


def _assigns_field(constructor, field_names: set[str]) -> bool:
    for _, assignment in constructor.filter(javalang.tree.Assignment):
        target = assignment.expressionl
        if isinstance(target, javalang.tree.MemberReference) and target.member in field_names:
            return True
        if (isinstance(target, javalang.tree.This) and
                any(isinstance(selector, javalang.tree.MemberReference) and
                    selector.member in field_names for selector in target.selectors or [])):
            return True
    return False


def _method_branches_on(method, field_name: str) -> bool:
    decisions = ([node for _, node in method.filter(javalang.tree.IfStatement)] +
                 [node for _, node in method.filter(javalang.tree.SwitchStatement)])
    for decision in decisions:
        expression = decision.condition if isinstance(
            decision, javalang.tree.IfStatement) else decision.expression
        nodes = [expression] + ([node for _, node in expression]
                                if isinstance(expression, javalang.ast.Node) else [])
        if any(isinstance(node, javalang.tree.MemberReference) and
               node.member == field_name for node in nodes):
            return True
    return False


def _constructor_accepts_and_assigns(constructor, interfaces: set[str],
                                     wrapped_fields: set[str]) -> bool:
    accepts = any(_type_name(parameter.type) in interfaces for parameter in constructor.parameters)
    return accepts and _assigns_field(constructor, wrapped_fields)


def _has_cross_cutting_call(method, wrapped: set[str], names: set[str]) -> bool:
    return any(node.qualifier not in wrapped and node.member.lower() in names
               for _, node in method.filter(javalang.tree.MethodInvocation))


def _callable_lines(source: str, method) -> int:
    if method.body is None or method.position is None:
        return 0
    masked = _mask_non_code(source)
    lines = source.splitlines(keepends=True)
    start = sum(len(line) for line in lines[:method.position.line - 1])
    opening = masked.find("{", start)
    if opening < 0:
        return 0
    end = _matching_brace(masked, opening)
    return source.count("\n", start, end) + 1


def _line(node) -> int:
    return node.position.line if node.position is not None else 1


def _finding(line: int, code: str, severity: str, message: str,
             pattern: str, recommendation: str) -> dict:
    return {"line": line, "code": code,
            "severity": severity, "message": message, "suggested_pattern": pattern,
            "recommendation": recommendation}


def _fail(code: str, message: str) -> dict:
    return {"status": "FAIL", "claim": "NO_PROOF", "code": code, "message": message,
            "automated_refactor_applied": False, "formal_defect_proved": False,
            "behavior_equivalence_proved": False}
