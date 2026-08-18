"""Conservative bottom-up extraction of architecture and unreviewed domain candidates."""
from __future__ import annotations

import json
from pathlib import Path
import re
import yaml
from .jml_ast import parse_jml_expression

try:  # Optional at import time for minimal installations.
    from tree_sitter import Language, Parser
    import tree_sitter_java, tree_sitter_rust, tree_sitter_c, tree_sitter_cpp
except ImportError:  # pragma: no cover - exercised only in minimal environments
    Language = Parser = None


_TS_LANGUAGES = {
    ".java": tree_sitter_java.language() if Parser else None,
    ".rs": tree_sitter_rust.language() if Parser else None,
    ".c": tree_sitter_c.language() if Parser else None,
    ".h": tree_sitter_c.language() if Parser else None,
    ".cpp": tree_sitter_cpp.language() if Parser else None,
}


def _tree_sitter_declarations(source: Path, text: str) -> tuple[list[dict] | None, bool]:
    """(declarations, had_parse_errors); None only without a grammar."""
    language = _TS_LANGUAGES.get(source.suffix.lower())
    if language is None:
        return None, False
    parser = Parser(); parser.language = Language(language)
    tree = parser.parse(text.encode("utf-8"))
    # Error-tolerant: production sources routinely contain one or two
    # constructs the grammar flags, but the well-formed struct/class nodes
    # elsewhere in the tree are still sound extraction targets. The error
    # flag is still reported so reviewers see the parse was not clean.
    types = {".java": {"class_declaration": False, "interface_declaration": True},
             ".rs": {"struct_item": False},
             ".c": {"struct_specifier": False},
             ".h": {"struct_specifier": False},
             ".cpp": {"class_specifier": False, "struct_specifier": False}}[source.suffix.lower()]
    declarations = []

    def collect_fields(node):
        fields = []
        for child in node.children:
            if child.type in {"class_body", "field_declaration_list", "declaration_list"}:
                stack = [child]
                while stack:
                    current = stack.pop()
                    if current.type in {"field_declaration", "field_declaration_list"}:
                        names = []
                        pending = list(current.children)
                        while pending:
                            item = pending.pop()
                            if item.type == "field_identifier":
                                names.append(item)
                            elif item.type == "variable_declarator":
                                names.extend(n for n in item.children if n.type in {"identifier", "field_identifier"})
                            pending.extend(item.children)
                        type_text = current.text.decode("utf-8")
                        if "*" not in type_text:  # pointers are not scalar state
                            for n in names:
                                fields.append((n.text.decode(), "boolean" if "bool" in type_text else "int"))
                    stack.extend(current.children)
        return fields

    def walk(node):
        if node.type in types:
            name_node = next((child for child in node.children if child.type in {"identifier", "type_identifier"}), None)
            if name_node:
                unique_fields = list(dict.fromkeys(collect_fields(node)))
                declarations.append({"name": name_node.text.decode(), "interface": types[node.type], "fields": unique_fields})
        if node.type == "type_definition" and "struct_specifier" in types:
            # Anonymous typedef structs (``typedef struct { ... } dev_t;``) name
            # their type on the typedef declarator, not on the struct itself —
            # the dominant shape in embedded stacks (TinyUSB, mbedTLS). Tagged
            # typedefs keep registering under the struct tag only, so lwIP's
            # ``typedef struct tcp_pcb {...} tcp_pcb_t;`` still yields exactly
            # one component.
            struct = next((child for child in node.children if child.type == "struct_specifier"), None)
            if struct is not None and not any(child.type == "type_identifier" for child in struct.children):
                name_node = next((child for child in node.children if child.type == "type_identifier"), None)
                if name_node:
                    unique_fields = list(dict.fromkeys(collect_fields(struct)))
                    declarations.append({"name": name_node.text.decode(), "interface": False, "fields": unique_fields})
        for child in node.children:
            walk(child)
    walk(tree.root_node)
    return declarations, tree.root_node.has_error


def _polyglot_declarations(source: Path, text: str) -> list[dict]:
    """Extract a structural shell for non-Java sources.

    Tree-sitter grammars can be installed by downstream users; the fallback keeps
    extraction deterministic in minimal/offline environments.
    """
    suffix = source.suffix.lower()
    result = []
    if suffix == ".java":
        for match in re.finditer(r"\b(class|interface)\s+(\w+)[^{]*\{(?P<body>.*?)\}", text, re.S):
            fields = [(name, "boolean" if typ == "boolean" else "int")
                      for typ, name in re.findall(r"\b(int|boolean|bool)\s+(\w+)\s*;", match.group("body"))]
            result.append({"name": match.group(2), "interface": match.group(1) == "interface", "fields": fields})
    elif suffix == ".rs":
        for match in re.finditer(r"\bstruct\s+(\w+)\s*\{(?P<body>.*?)\}", text, re.S):
            fields = re.findall(r"\b(\w+)\s*:\s*(i\d+|u\d+|bool)\s*,?", match.group("body"))
            result.append({"name": match.group(1), "interface": False,
                           "fields": [(name, "int" if typ != "bool" else "boolean") for name, typ in fields]})
    elif suffix in {".c", ".cpp", ".cc", ".cxx"}:
        for match in re.finditer(r"\b(struct|class)\s+(\w+)\s*\{(?P<body>.*?)\}\s*;", text, re.S):
            fields = re.findall(r"\b(int|bool|boolean)\s+(\w+)\s*;", match.group("body"))
            result.append({"name": match.group(2), "interface": False,
                           "fields": [(name, "boolean" if typ == "bool" else "int") for typ, name in fields]})
    return result


def extract_components_ts(file_path: str | Path) -> list[dict] | None:
    """Public Tree-sitter extraction entry point."""
    path = Path(file_path)
    try:
        return _tree_sitter_declarations(path, path.read_text(encoding="utf-8"))[0]
    except (OSError, UnicodeError):
        return None


def _snake_name(value: str) -> str:
    return re.sub(r"(?<!^)([A-Z])", r"_\1", value).lower()


# Lifecycle functions are bare (`recycle()`) or prefixed (`connection_recycle`,
# `tcp_reset`) — both spellings mark a reset/recycle routine.
_LIFECYCLE_NAMES = re.compile(r"^(?:\w+_)?(?:recycle|reset|clear|init)$", re.I)
_NESTED_BLOCK = re.compile(r"\{[^{}]*\}")


def _unguarded_writes(body: str, fields: set[str],
                      access: str = r"(?:this\.)?") -> set[str]:
    """State fields assigned OUTSIDE any nested block of the body.

    Stripping nested ``{...}`` regions leaves exactly the statements that
    run unconditionally — the shape of a recycle()/reset() that always
    writes its fields. Guarded dialects never extract these, so they are
    the classic source of a missing lifecycle transition.
    """
    stripped = body
    while _NESTED_BLOCK.search(stripped):
        stripped = _NESTED_BLOCK.sub("", stripped)
    found: set[str] = set()
    for field in fields:
        if re.search(rf"\b{access}{re.escape(field)}\s*=\s*-?\w+\s*;", stripped):
            found.add(field)
    return found


def _lifecycle_notes(functions: list[tuple[str, str]], fields: set[str],
                     access: str = r"(?:this\.)?", notes: list[str] | None = None) -> None:
    """POTENTIAL_LIFECYCLE_RESET for recycle/reset/clear/init functions
    whose unguarded state writes the guarded dialects cannot extract."""
    if notes is None:
        return
    for name, body in functions:
        if not _LIFECYCLE_NAMES.match(name.split("::")[-1]):
            continue
        touched = _unguarded_writes(body, fields, access)
        if touched:
            notes.append(
                f"POTENTIAL_LIFECYCLE_RESET: {name}() unconditionally writes "
                f"{', '.join(sorted(touched))} but was not auto-extracted "
                "(unguarded writes are outside the guarded-transition "
                "dialect); verify whether it is a missing reset/recycle "
                "transition")


def _pascal_name(value: str) -> str:
    return "".join(part[:1].upper() + part[1:] for part in value.split("_") if part)


def _infer_java_transitions(text: str, fields: list[tuple[str, str]],
                            notes: list[str] | None = None) -> list[dict]:
    """Guarded scalar assignments inside Java methods, over this.field / field.

    Parser methods usually return a status (Tomcat's parseRequestLine is
    boolean — the classic incremental-parser shape), so the scanner accepts
    any scalar return next to void; reference returns stay outside. Multiple
    guarded writes per method each mint a transition (a phase counter's
    if (phase == N) { phase = N+1; } chain is one machine, one method).
    """
    notes = [] if notes is None else notes
    names = {name for name, _ in fields}
    transitions: list[dict] = []
    used: set[str] = set()
    method_head = re.compile(
        r"(?:public|protected|private|static|\s)*?(?:void|boolean|int|long|short|byte)\s+"
        r"(\w+)\s*\([^)]*\)(?:\s*throws\s+[\w.,\s]+)?\s*\{")
    # The effect must live inside the guard's own brace block (nested
    # braces refused, exactly like the C boolean-guard rule). Method
    # bodies are brace-matched, not line-matched: a non-greedy body
    # pattern would truncate at the first nested closing brace.
    guard_head = re.compile(
        r"if\s*\(\s*(?:this\.)?(?P<field>\w+)\s*(?P<op>==|!=|<=|>=|<|>)\s*"
        r"(?P<limit>-?\d+)\s*\)\s*\{")
    functions: list[tuple[str, str]] = []
    for match in method_head.finditer(text):
        name = match.group(1)
        if name in {"<init>"}:
            continue
        body = _brace_matched(text, match.end())
        functions.append((name, body))
        for hit in guard_head.finditer(body):
            if hit["field"] not in names:
                continue
            field_name = hit["field"]
            # Brace-matched guard region; nested control flow (Tomcat's
            # try/switch inside a phase arm) refuses auto-extraction but
            # is reported so the reviewer knows exactly which phases to
            # complete by hand.
            region = _brace_matched(body, hit.end())
            if "{" in region or "}" in region:
                if re.search(rf"\b(?:this\.)?{re.escape(field_name)}\s*=\s*-?\d+\s*;", region):
                    notes.append(f"{name} guard {field_name} {hit['op']} "
                                 f"{hit['limit']}: nested control flow around "
                                 "the state write skipped")
                continue
            bump = re.search(
                rf"\b(?:this\.)?{re.escape(field_name)}\s*=\s*(?:this\.)?"
                rf"{re.escape(field_name)}\s*(?P<arith>[+-])\s*(?P<amount>\d+)\s*;",
                region)
            assignment = re.search(
                rf"\b(?:this\.)?{re.escape(field_name)}\s*=\s*"
                rf"(?P<value>-?\d+)\s*;", region)
            guard = f"{field_name} {hit['op']} {hit['limit']}"
            value = (f"{field_name} {bump['arith']} {bump['amount']}"
                     if bump else (assignment["value"] if assignment else None))
            if value is None:
                continue
            try:
                guard_ast = parse_jml_expression(guard, fields=names)
                value_ast = parse_jml_expression(value, fields=names)
            except Exception:
                continue
            label, counter = name, 2
            while label in used:
                label, counter = f"{name}_{counter}", counter + 1
            used.add(label)
            transitions.append({"name": label, "guard": guard_ast,
                               "target": field_name, "value": value_ast})
    _lifecycle_notes(functions, names, notes=notes)
    return transitions


_C_ACCESS = r"\w+\s*(?:->|\.)\s*"


def _resolve_c_constant(token: str, enums: dict[str, int]) -> str | None:
    """Integer literal or enum identifier -> canonical integer string."""
    token = token.strip()
    try:
        return str(int(token, 0))
    except ValueError:
        return str(enums[token]) if token in enums else None


def _brace_matched(text: str, start: int) -> str:
    """Body text between the brace at ``start`` and its match."""
    depth, index = 1, start
    while index < len(text) and depth:
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
        index += 1
    return text[start:index - 1]


_C_FUNCTION = re.compile(
    r"(?m)^[ \t]*(?:static\s+|const\s+|inline\s+)*"
    r"(?P<ret>\w+)\s+(?P<name>\w+(?:::\w+)*)\s*\([^;{}]*\)\s*\{")


def _c_void_functions(text: str) -> list[tuple[str, str]]:
    """(name, brace-matched body) for every scalar-returning function definition.

    Production state mutators usually return a status code (lwIP's
    ``tcp_process`` is ``static err_t``); the return value is orthogonal to
    the state write, so scalar-status returns are accepted alongside void.
    Pointer-returning functions stay outside the boundary.
    """
    functions = []
    for header in _C_FUNCTION.finditer(text):
        # C++ out-of-line methods qualify the name (Reader::ReadPhysicalRecord);
        # op names use the unqualified method tail.
        functions.append((header.group("name").split("::")[-1],
                          _brace_matched(text, header.end())))
    return functions


_SWITCH = re.compile(r"switch\s*\(\s*\w+\s*(?:->|\.)\s*(?P<field>\w+)\s*\)\s*\{")
_CASE_LABEL = re.compile(r"(?:case\s+(?P<const>\w+)|default)\s*:")


def _switch_case_transitions(body: str, function_name: str, names: set[str],
                             enums: dict[str, int], notes: list[str]) -> list[dict]:
    """Translate ``switch (x->state)`` dispatch into one transition per case.

    Fail-closed per case: fall-through (no ``break``), unknown case constants,
    unknown effect constants, and case bodies without a single state write are
    skipped with a note for the human reviewer.
    """
    transitions = []
    for switch in _SWITCH.finditer(body):
        field = switch.group("field")
        if field not in names:
            continue
        switch_body = _brace_matched(body, switch.end())
        labels = list(_CASE_LABEL.finditer(switch_body))
        for index, label in enumerate(labels):
            constant = label.group("const")
            if constant is None:  # default:
                continue
            end = labels[index + 1].start() if index + 1 < len(labels) else len(switch_body)
            segment = switch_body[label.end():end]
            if re.search(r"\bbreak\b", segment) is None:
                notes.append(f"{function_name} case {constant}: "
                             "fall-through case skipped")
                continue
            case_value = _resolve_c_constant(constant, enums)
            if case_value is None:
                notes.append(f"{function_name} case {constant}: "
                             "unknown case constant skipped")
                continue
            assignment = None
            for candidate_assignment in re.finditer(
                    rf"{_C_ACCESS}(?P<target>\w+)\s*=\s*(?P<value>\w+)\s*;", segment):
                # Real case bodies assign other fields first; take the write
                # that targets the state field itself.
                if candidate_assignment.group("target") == field:
                    assignment = candidate_assignment
                    break
            if assignment is None:
                continue
            effect_value = _resolve_c_constant(assignment.group("value"), enums)
            if effect_value is None:
                notes.append(f"{function_name} case {constant}: "
                             "unknown effect constant skipped")
                continue
            guard_text = f"{field} == {case_value}"
            inner = re.search(r"if\s*\((?P<cond>[^)]+)\)\s*\{", segment)
            if inner is not None and assignment.start() > inner.start():
                condition = re.sub(
                    rf"\w+\s*(?:->|\.)\s*{re.escape(field)}\b", field,
                    inner.group("cond").strip())
                try:
                    parse_jml_expression(condition, fields={field})
                except Exception:
                    # The condition references a parameter or unknown name:
                    # TLA has no parameters, so the input condition is dropped
                    # and the over-approximation is reported for review.
                    notes.append(f"{function_name} case {constant}: "
                                 f"input condition dropped ({condition})")
                else:
                    guard_text = f"{guard_text} && ({condition})"
            try:
                guard_ast = parse_jml_expression(guard_text, fields=names)
                value_ast = parse_jml_expression(effect_value, fields=names)
            except Exception:
                continue
            transitions.append({"name": f"{function_name}_{constant.lower()}",
                                "guard": guard_ast, "target": field,
                                "value": value_ast})
    return transitions


def _infer_c_transitions(text: str, fields: list[tuple[str, str]],
                         enums: dict[str, int] | None = None,
                         notes: list[str] | None = None) -> list[dict]:
    """Guarded scalar assignments over ``ptr->field`` / ``value.field`` receivers.

    Two dialects, both deterministic: guarded writes (``if (c->state == A)
    { c->state = B; }``) and switch dispatch (``case A: ... c->state = B;
    break;``) over enum-resolved constants. Guards accept the comparison
    family (==, !=, <=, >=, <, >); effects are literal state writes or
    bounded increments. Everything else is skipped with a reviewer note.
    """
    enums = enums or {}
    notes = [] if notes is None else notes
    names = {name for name, _ in fields}
    transitions: list[dict] = []
    literal = re.compile(
        rf"if\s*\(\s*{_C_ACCESS}(?P<field>\w+)\s*(?P<op>==|!=|<=|>=|<|>)\s*"
        rf"(?P<limit>\w+)\s*\).*?"
        rf"{_C_ACCESS}(?P<target>\w+)\s*=\s*(?P<value>\w+)\s*;", re.S)
    incremental = re.compile(
        rf"if\s*\(\s*{_C_ACCESS}(?P<field>\w+)\s*(?P<op>==|!=|<=|>=|<|>)\s*"
        rf"(?P<limit>\w+)\s*\).*?"
        rf"{_C_ACCESS}(?P<target>\w+)\s*=\s*{_C_ACCESS}(?P<rhs>\w+)\s*"
        rf"(?P<op2>[+-])\s*(?P<amount>\d+)\s*;", re.S)
    # TinyUSB dialect: bare/negated boolean guards whose effect targets a
    # DIFFERENT state field — ``if (dev->connected) { dev->suspended = 1; }``.
    # The effect must live inside the guard's own brace block (no nested
    # braces), so a guard block that only calls callbacks never pairs with a
    # later assignment elsewhere in the function.
    boolean_guard = re.compile(
        rf"if\s*\(\s*(?P<neg>!\s*)?{_C_ACCESS}(?P<gfield>\w+)\s*\)\s*\{{"
        rf"(?P<gbody>[^{{}}]*?)\}}")
    boolean_effect = re.compile(
        rf"{_C_ACCESS}(?P<target>\w+)\s*=\s*(?P<value>\w+)\s*;")
    # M10: postfix counters. Protocol parsers count with `f++`/`f--` rather
    # than `f = f + 1`. When the postfix sits in the if-CONDITION itself
    # (curl's `if(!k->headerline++)`) the increment is a side effect of
    # evaluating the condition, so BOTH branch values increment: the pair
    # (guard == 0 -> +1, guard != 0 -> +1) models the statement faithfully.
    postfix_condition = re.compile(
        rf"if\s*\(\s*(?:!\s*)?{_C_ACCESS}(?P<pcfield>\w+)\s*"
        rf"(?P<pop>\+\+|--)\s*\)")
    postfix_effect = re.compile(
        rf"{_C_ACCESS}(?P<target>\w+)\s*(?P<pop>\+\+|--)\s*;")
    postfix_under_comparison = re.compile(
        rf"if\s*\(\s*{_C_ACCESS}(?P<field>\w+)\s*(?P<op>==|!=|<=|>=|<|>)\s*"
        rf"(?P<limit>\w+)\s*\)\s*\{{(?P<gbody>[^{{}}]*?)\}}")
    while_state_guard = re.compile(
        rf"while\s*\(\s*{_C_ACCESS}(?P<wfield>\w+)\s*\)\s*\{{")
    used_names: set[str] = set()

    def _unique(base: str) -> str:
        label, counter = base, 2
        while label in used_names:
            label, counter = f"{base}_{counter}", counter + 1
        used_names.add(label)
        return label

    c_functions = _c_void_functions(text)
    _lifecycle_notes(c_functions, names, access=_C_ACCESS, notes=notes)
    for name, body in c_functions:
        switch_transitions = _switch_case_transitions(body, name, names, enums, notes)
        if switch_transitions:
            transitions.extend(switch_transitions)
            used_names.update(item["name"] for item in switch_transitions)
            continue
        for cond_match in postfix_condition.finditer(body):
            field = cond_match["pcfield"]
            if field not in names:
                continue
            verb = "increment" if cond_match["pop"] == "++" else "decrement"
            delta = f"{field} + 1" if cond_match["pop"] == "++" else f"{field} - 1"
            for branch, comparison in (("_zero", "=="), ("_nonzero", "!=")):
                # guard/delta are internally constructed ("<field> == 0",
                # "<field> + 1"); parsing cannot fail.
                guard_ast = parse_jml_expression(
                    f"{field} {comparison} 0", fields=names)
                value_ast = parse_jml_expression(delta, fields=names)
                transitions.append({"name": _unique(f"{name}_{field}_{verb}{branch}"),
                                    "guard": guard_ast, "target": field,
                                    "value": value_ast})
        for while_match in while_state_guard.finditer(body):
            field = while_match["wfield"]
            if field not in names:
                continue
            loop_body = _brace_matched(body, while_match.end())
            counter = postfix_effect.search(loop_body)
            # The postfix fires on only SOME paths through the loop body, so
            # the transition over-approximates; the note makes that visible.
            if counter is None or counter["target"] != field:
                continue
            verb = "increment" if counter["pop"] == "++" else "decrement"
            delta = f"{field} + 1" if counter["pop"] == "++" else f"{field} - 1"
            guard_ast = parse_jml_expression(f"{field} != 0", fields=names)
            value_ast = parse_jml_expression(delta, fields=names)
            notes.append(f"{name}: while({field}) loop-body {counter['pop']} "
                         f"abstracted to an unconditional transition (over-approximation)")
            transitions.append({"name": _unique(f"{name}_{field}_{verb}"),
                                "guard": guard_ast, "target": field,
                                "value": value_ast})
        for guard_match in boolean_guard.finditer(body):
            if guard_match["gfield"] not in names:
                continue
            guard_text = (f"{guard_match['gfield']} == 0" if guard_match["neg"]
                          else f"{guard_match['gfield']} != 0")
            counter = postfix_effect.search(guard_match["gbody"])
            effect = boolean_effect.search(guard_match["gbody"])
            if counter is not None and counter["target"] in names:
                delta = (f"{counter['target']} + 1" if counter["pop"] == "++"
                         else f"{counter['target']} - 1")
                guard_ast = parse_jml_expression(guard_text, fields=names)
                value_ast = parse_jml_expression(delta, fields=names)
                label = _unique(f"{name}_{counter['target']}")
                transitions.append({"name": label, "guard": guard_ast,
                                    "target": counter["target"], "value": value_ast})
                continue
            if effect is None or effect["target"] not in names:
                continue
            resolved = _resolve_c_constant(effect["value"], enums)
            if resolved is None:
                continue
            # guard_text ("<state field> == 0") and resolved (a canonical
            # integer string) are internally constructed, so parsing cannot
            # fail here — no defensive except is needed.
            guard_ast = parse_jml_expression(guard_text, fields=names)
            value_ast = parse_jml_expression(resolved, fields=names)
            label = _unique(f"{name}_{effect['target']}")
            transitions.append({"name": label, "guard": guard_ast,
                                "target": effect["target"], "value": value_ast})
        # comparison-guarded postfix counter: `if (f < N) { f++; }` — the
        # classic bounded-counter shape, effect confined to the guard block.
        for cmp_match in postfix_under_comparison.finditer(body):
            if cmp_match["field"] not in names:
                continue
            counter = postfix_effect.search(cmp_match["gbody"])
            if (counter is None or counter["target"] != cmp_match["field"]
                    or counter["target"] not in names):
                continue
            limit = _resolve_c_constant(cmp_match["limit"], enums)
            if limit is None:
                continue
            delta = (f"{cmp_match['field']} + 1" if counter["pop"] == "++"
                     else f"{cmp_match['field']} - 1")
            guard_ast = parse_jml_expression(
                f"{cmp_match['field']} {cmp_match['op']} {limit}", fields=names)
            value_ast = parse_jml_expression(delta, fields=names)
            transitions.append({"name": _unique(name), "guard": guard_ast,
                                "target": cmp_match["field"], "value": value_ast})
        increment = incremental.search(body)
        if increment is not None:
            match = increment
            value_text = f"{match['field']} {match['op2']} {match['amount']}"
        else:
            match = literal.search(body)
            if match is None:
                continue
            resolved = _resolve_c_constant(match["value"], enums)
            if resolved is None:
                continue
            value_text = resolved
        if match["field"] not in names or match["target"] != match["field"]:
            continue
        if increment is not None and match["rhs"] != match["field"]:
            continue
        limit = _resolve_c_constant(match["limit"], enums)
        if limit is None:
            continue
        guard_text = f"{match['field']} {match['op']} {limit}"
        try:
            guard_ast = parse_jml_expression(guard_text, fields=names)
            value_ast = parse_jml_expression(value_text, fields=names)
        except Exception:
            continue
        used_names.add(name)
        transitions.append({"name": name, "guard": guard_ast,
                            "target": match["field"], "value": value_ast})
    return transitions


def parse_c_enums(text: str) -> dict[str, int]:
    """Flat identifier -> integer map over every enum block in the source."""
    values: dict[str, int] = {}
    for block in re.finditer(r"enum\s+\w*\s*\{(?P<body>[^}]*)\}", text):
        current = -1
        for item in block.group("body").split(","):
            item = item.strip()
            if not item:
                continue
            if "=" in item:
                name, _, raw = item.partition("=")
                try:
                    current = int(raw.strip(), 0)
                except ValueError:
                    continue  # non-integer enumerator value: skip
            else:
                name, current = item, current + 1
            if re.fullmatch(r"\w+", name.strip()):
                values[name.strip()] = current
    return values


def _enum_tag_bounds(text: str) -> dict[str, tuple[int, int]]:
    """Tag -> (min, max) per named enum block, for enum-typed field bounds."""
    extents: dict[str, tuple[int, int]] = {}
    for block in re.finditer(r"enum\s+(?P<tag>\w+)\s*\{(?P<body>[^}]*)\}", text):
        values = [value for name, value in parse_c_enums(block.group(0)).items()]
        if values:
            extents[block.group("tag")] = (min(values), max(values))
    return extents


def _bounds_index(text: str) -> dict:
    """One-pass name -> bound evidence over ``text``.

    ``infer_field_bounds`` used to re-scan the whole text per field; on a
    monolith-size preprocessed unit (Redis networking.c: ~600 KB, hundreds of
    structs) that is quadratic and effectively hangs. This index preserves the
    exact first-match-wins semantics of the original per-field searches.
    """
    leq: dict[str, tuple[int, int]] = {}
    for match in re.finditer(r"\b(\w+)\s*(?:<=|<)\s*(\d+)", text):
        name = match.group(1)
        if name not in leq:                      # first comparison wins
            leq[name] = (0, int(match.group(2)))
    tagged: dict[str, str | None] = {}
    for match in re.finditer(r"\benum\s+(?:(\w+)\s+)?(\w+)\s*;", text):
        name = match.group(2)
        if name not in tagged:
            tagged[name] = match.group(1)
    return {"leq": leq, "tagged": tagged, "tag_bounds": _enum_tag_bounds(text)}


def infer_field_bounds(text: str, fields: list[tuple[str, str]],
                       enums: dict[str, int] | None = None,
                       _index: dict | None = None,
                       ) -> dict[str, tuple[int, int] | None]:
    """Infer a [0, N] bound per int field; None when unbounded.

    Order: explicit `<=`/`<` comparisons win; then an enum-typed declaration
    (``enum tag field;``) bounds the field to its enum's extent. ``_index`` is
    the precomputed :func:`_bounds_index` for ``text`` so monolithic units can
    share one pass across every struct.
    """
    index = _bounds_index(text) if _index is None else _index
    leq, tagged = index["leq"], index["tagged"]
    tag_bounds = index["tag_bounds"] if enums else {}
    bounds: dict[str, tuple[int, int] | None] = {}
    for name, field_type in fields:
        if field_type != "int":
            continue
        if name in leq:
            bounds[name] = leq[name]
            continue
        if name in tagged:
            tag = tagged[name]
            if tag in tag_bounds:
                bounds[name] = tag_bounds[tag]
            elif len(tag_bounds) == 1:
                bounds[name] = next(iter(tag_bounds.values()))
            else:
                bounds[name] = None
        else:
            bounds[name] = None
    return bounds


def _ast_json(node):
    value = node.model_dump(mode="json") if hasattr(node, "model_dump") else node
    if value.get("kind") == "field":
        return {"kind": "field", "name": value.get("field", value.get("name"))}
    for key, child in list(value.items()):
        if isinstance(child, dict) and "kind" in child:
            value[key] = _ast_json(child)
    return value


def build_v2_candidate_payload(class_name: str, fields: list[tuple[str, str]],
                               transitions: list[dict],
                               bounds: dict[str, tuple[int, int] | None] | None = None,
                               initials: dict[str, int | bool] | None = None) -> dict:
    """Build the strict V2 candidate payload for one extracted class.

    Without explicit ``bounds``/``initials`` the historical extraction defaults
    ([0, 5], 0/false) apply; callers that inferred real values pass their own.
    """
    bounds, initials = bounds or {}, initials or {}
    state = []
    for name, field_type in fields:
        if field_type == "boolean":
            state.append({"kind": "bool", "name": name, "initial": initials.get(name, False)})
        else:
            bound = bounds.get(name) or (0, 5)
            state.append({"kind": "int", "name": name, "bound": list(bound),
                          "initial": initials.get(name, 0)})
    operations = []
    for index, transition in enumerate(transitions, 1):
        guard = _ast_json(transition["guard"])
        value = _ast_json(transition["value"])
        operations.append({"name": transition["name"], "return_type": "void",
                           "failure_semantics": "unavailable",
                           "guards": [{"id": f"g{index}", "expression": guard}],
                           "effects": [{"id": f"e{index}", "target": transition["target"], "value": value}],
                           "frame": [transition["target"]]})
    invariants = []
    for index, item in enumerate(state, 1):
        if item["kind"] == "int":
            invariants.append({"id": f"inv{index}", "expression": {"kind": "and",
                "left": {"kind": "gte", "left": {"kind": "field", "name": item["name"]}, "right": {"kind": "integer", "value": item["bound"][0]}},
                "right": {"kind": "lte", "left": {"kind": "field", "name": item["name"]}, "right": {"kind": "integer", "value": item["bound"][1]}}}})
    return {"schema_version": 2, "review_status": "unreviewed",
            "domain_name": _pascal_name(class_name),
            "module_name": _snake_name(class_name), "actors": 1,
            "state_variables": state, "operations": operations, "tlc_invariants": invariants}


def _integer_constants(node) -> set[int]:
    """Every integer literal in a dumped expression AST."""
    found: set[int] = set()
    if isinstance(node, dict):
        if node.get("kind") == "integer":
            found.add(node.get("value"))
        for child in node.values():
            found |= _integer_constants(child)
    elif isinstance(node, list):
        for child in node:
            found |= _integer_constants(child)
    return found


def _transition_constant_bounds(transitions: list[dict]) -> dict[str, tuple[int, int]]:
    """[0, max integer constant] per target field, from the transitions' own
    guard/effect ASTs.

    Sound for extracted literal-write machines: every reachable value is an
    effect constant, a guard limit (which dominates its own increment), or the
    initial 0 — all within [0, max constant]. This is the register-time
    fallback for fields with no comparison/enum evidence (Tomcat's
    `if (phase == N)` chain compares with `==`, never `<=`).
    """
    maxima: dict[str, int] = {}
    for transition in transitions:
        constants = _integer_constants(_ast_json(transition["guard"])) | \
            _integer_constants(_ast_json(transition["value"]))
        positive = max((c for c in constants if isinstance(c, int) and c >= 0),
                       default=0)
        target = transition["target"]
        maxima[target] = max(maxima.get(target, 0), positive)
    return {name: (0, hi) for name, hi in maxima.items()}


def _register_candidate(project_root: Path, class_name: str, fields: list[tuple[str, str]],
                        transitions: list[dict],
                        bounds: dict[str, tuple[int, int] | None] | None = None,
                        initials: dict[str, int | bool] | None = None) -> Path:
    candidate_dir = project_root / "domains" / "candidates"
    candidate_dir.mkdir(parents=True, exist_ok=True)
    # Explicit comparison/enum evidence wins where it covers the machine; a
    # field it left unbounded GAINS a bound from the transitions' own
    # constants, and — soundness — a comparison bound the real writes EXCEED
    # is widened to the write maximum (code that assigns 7 cannot be bounded
    # at 2, whatever an earlier `< 2` comparison suggested).
    merged = dict(bounds or {})
    for name, (lo, hi) in _transition_constant_bounds(transitions).items():
        existing = merged.get(name)
        merged[name] = (existing[0], max(existing[1], hi)) if existing else (lo, hi)
    payload = build_v2_candidate_payload(class_name, fields, transitions,
                                         bounds=merged, initials=initials)
    path = candidate_dir / f"{_snake_name(class_name)}.v2.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def _unbounded_heap_warnings(text: str, source: Path) -> list[dict]:
    """Named refusals for dynamic heap shapes: pointer-linked C structs and
    collection-typed Java fields. The struct/class and the exact field are
    reported so the reviewer knows what to model (or capacity-bound)."""
    warnings = []
    if source.suffix.lower() in {".c", ".h", ".cc", ".cpp", ".cxx"}:
        for match in re.finditer(
                r"(?:typedef\s+)?struct\s+(\w+)\s*\{(?P<body>[^}]*)\}", text):
            for field_match in re.finditer(
                    r"(?:struct\s+)?(\w+)\s*\*\s*(\w+)\s*[;,]", match.group("body")):
                type_name, field_name = field_match.group(1), field_match.group(2)
                if type_name in {"void", "char", "int", "long"} and \
                        field_name.startswith(("fmt", "buf")):
                    continue          # string/format buffers are not heap state
                warnings.append({
                    "file": str(source), "code": "UNBOUNDED_HEAP_DETECTED",
                    "message": f"Field '{field_name}' in struct "
                               f"'{match.group(1)}' is a dynamic pointer. "
                               "Requires manual modeling or capacity bounding."})
    elif source.suffix.lower() == ".java":
        for match in re.finditer(
                r"(?:private|protected|public)\s+"
                r"(?:final\s+)?(?:[\w.]*?(?:List|ArrayList|LinkedList|Map|"
                r"HashMap|TreeMap|Set|HashSet|Collection)"
                r"(?:<[^;=]*>)?)\s+(\w+)\s*[;=]", text):
            warnings.append({
                "file": str(source), "code": "UNBOUNDED_HEAP_DETECTED",
                "message": f"Field '{match.group(1)}' uses a dynamic "
                           "collection. Requires manual modeling or capacity "
                           "bounding."})
    return warnings


def analyze_codebase(target_dir: str | Path, out_dir: str | Path = "extracted",
                     project_root: str | Path = ".") -> dict:
    root, destination = Path(target_dir), Path(out_dir)
    if not root.is_dir():
        return {"status": "FAIL", "claim": "NO_PROOF", "code": "input_unavailable", "message": str(root)}
    destination.mkdir(parents=True, exist_ok=True)
    components, domains, warnings = [], [], []
    c_structs: dict[str, list[tuple[str, str]]] = {}
    c_texts: dict[str, str] = {}
    sources = sorted(path for ext in ("*.java", "*.rs", "*.c", "*.h", "*.cpp", "*.cc", "*.cxx", "*.ll")
                     for path in root.rglob(ext))
    # Production C keeps its enums and structs in headers while transitions
    # live in .c files: share one enum map across the analyzed C-family tree.
    c_enums: dict[str, int] = {}
    for source in sources:
        if source.suffix.lower() in {".c", ".h", ".cc", ".cpp", ".cxx"}:
            try:
                c_enums.update(parse_c_enums(source.read_text(encoding="utf-8")))
            except (OSError, UnicodeError):
                continue
    for source in sources:
        try:
            text = source.read_text(encoding="utf-8")
            if source.suffix.lower() == ".ll":
                # M32: the IR lane. Transitions come from the CFG, not the
                # source text; one candidate per (struct, field) machine in
                # the module, correspondence-checked against the dispatch
                # table that produced them.
                from .llvm_ir import (extract_ir_transitions,
                                      ir_cfg_correspondence, parse_llvm_ir)
                from .jml_ast import parse_jml_expression
                module = parse_llvm_ir(text)
                if module.get("status") != "PARSED":
                    warnings.append({"file": str(source),
                                     "code": module.get("code",
                                                        "ir_parse_error"),
                                     "message": module.get("message", "")})
                    continue
                module_notes: list[str] = []
                by_field: dict[str, list[dict]] = {}
                for ir_function in module["functions"]:
                    found, module_notes = extract_ir_transitions(
                        ir_function, notes=module_notes)
                    for item in found:
                        by_field.setdefault(item["field"], []).append(item)
                for note in module_notes:
                    warnings.append({"file": str(source),
                                     "code": "EXTRACTION_NOTE",
                                     "message": note})
                for field_name, items in sorted(by_field.items()):
                    struct_name = field_name.rsplit("_f", 1)[0]
                    # Same transition shape as the source dialect so the
                    # candidate builder and bounds inference are shared.
                    names = {field_name}
                    converted = []
                    for item in items:
                        guard = parse_jml_expression(
                            f"{field_name} == {item['case']}", fields=names)
                        value = parse_jml_expression(
                            str(item["value"]), fields=names)
                        converted.append({"name": item["name"],
                                          "guard": guard,
                                          "target": field_name,
                                          "value": value})
                    correspondence = ir_cfg_correspondence(items, text)
                    if correspondence.get("status") != "CORRESPONDENCE_PROVED":
                        warnings.append({
                            "file": str(source),
                            "code": correspondence.get(
                                "code", "ir_correspondence_failed"),
                            "message": correspondence.get("message", "")})
                        continue
                    registered = _register_candidate(
                        Path(project_root), struct_name,
                        [(field_name, "int")], converted)
                    domains.append(str(registered))
                    warnings.append({
                        "file": str(source), "code": "IR_MACHINE_EXTRACTED",
                        "message": f"{len(items)} transitions for field "
                                   f"{field_name} from the {source.name} "
                                   "CFG (deterministic correspondence "
                                   "proved)"})
                continue
            warnings.extend(_unbounded_heap_warnings(text, source))
            declarations, had_parse_errors = _tree_sitter_declarations(source, text)
            if declarations is None:
                declarations = _polyglot_declarations(source, text)
            elif had_parse_errors:
                warnings.append({"file": str(source), "code": "UNPARSEABLE_SOURCE",
                                 "message": "tree-sitter reported parse errors; "
                                            "well-formed declarations were still extracted"})
            if source.suffix.lower() == ".java":
                # A dynamic-collection field is occupancy, not scalar state:
                # drop it from the declaration so it never becomes a bogus
                # int (the named UNBOUNDED_HEAP_DETECTED warning documents
                # exactly what the reviewer must model instead).
                for declaration in declarations:
                    declared = set(re.findall(
                        r"(?:private|protected|public)\s+(?:final\s+)?"
                        r"[\w.]*?(?:List|ArrayList|LinkedList|Map|HashMap|"
                        r"TreeMap|Set|HashSet|Collection)(?:<[^;=]*>)?\s+(\w+)\s*[;=]",
                        text))
                    declaration["fields"] = [(name, field_type)
                                             for name, field_type
                                             in declaration.get("fields", [])
                                             if name not in declared]
        except (OSError, UnicodeError) as exc:
            warnings.append({"file": str(source), "code": "UNPARSEABLE_SOURCE", "message": str(exc)})
            continue
        # one bounds pass per file, shared by every declaration in it
        file_bounds_index = _bounds_index(text) if declarations else None
        for declaration in declarations:
            name = declaration["name"]
            is_interface = declaration.get("interface", False)
            fields = declaration.get("fields", [])
            domain_name = name.lower()
            component = {"name": name, "type": "interface" if is_interface else "core",
                         "external": is_interface, "domain": None if is_interface else domain_name,
                         "file": source.name, "review_status": "unreviewed",
                         "lang": "c" if source.suffix.lower() == ".h" else
                         "java" if source.suffix.lower() == ".java" else source.suffix[1:],
                         "language": "c" if source.suffix.lower() == ".h" else
                         "java" if source.suffix.lower() == ".java" else source.suffix[1:],
                         "fields": [{"name": field, "type": field_type} for field, field_type in fields]}
            components.append(component)
            if fields and not is_interface:
                state = []
                unbounded = False
                suffix = source.suffix.lower()
                enums = c_enums if suffix in {".c", ".h", ".cc", ".cpp", ".cxx"} else {}
                inferred = infer_field_bounds(text, fields, enums=enums or None,
                                              _index=file_bounds_index)
                for field_name, field_type in fields:
                    item = {"name": field_name, "type": field_type}
                    if field_type == "int":
                        bound = inferred.get(field_name)
                        if bound:
                            item["bound"] = list(bound)
                        else:
                            unbounded = True
                    state.append(item)
                if unbounded:
                    warnings.append({"file": str(source), "code": "UNBOUNDED_STATE_REQUIRES_MANUAL_REVIEW"})
                candidate = {"schema_version": 2, "name": domain_name,
                             "review_status": "unreviewed", "state_variables": state,
                             "operations": [], "transitions": [],
                             "warnings": (["UNBOUNDED_STATE_REQUIRES_MANUAL_REVIEW"] if unbounded else [])}
                path = destination / f"{domain_name}.v2.json"
                path.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
                domains.append(str(path))
                suffix = source.suffix.lower()
                if suffix == ".java":
                    notes: list[str] = []
                    transitions = _infer_java_transitions(text, fields, notes=notes)
                    for note in notes:
                        warnings.append({"file": str(source), "code": "EXTRACTION_NOTE",
                                         "message": note})
                    registered = _register_candidate(Path(project_root), name, fields,
                                                      transitions, bounds=inferred)
                    domains.append(str(registered))
                elif suffix in {".c", ".h", ".cc", ".cpp", ".cxx"}:
                    c_structs.setdefault(name, fields)
                    c_texts.setdefault(name, text)
    # Production C splits the struct (header) from its transitions (.c files):
    # register C candidates only after the whole tree is known, attributing
    # each transition to every struct that declares its target field.
    if c_structs:
        union_fields = sorted({name for fields in c_structs.values()
                               for name, _ in fields})
        typed_fields = [(field, "int") for field in union_fields]
        combined = "\n".join(c_texts.values())
        all_transitions: list[dict] = []
        for source in sources:
            if source.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
                continue
            try:
                text = source.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            notes: list[str] = []
            all_transitions.extend(_infer_c_transitions(
                text, typed_fields, enums=c_enums, notes=notes))
            for note in notes:
                warnings.append({
                    "file": str(source),
                    "code": ("INPUT_CONDITION_DROPPED"
                             if "input condition dropped" in note
                             else "EXTRACTION_NOTE"),
                    "message": note})
        combined_index = _bounds_index(combined)
        for name, fields in c_structs.items():
            field_names = {field for field, _ in fields}
            transitions = [item for item in all_transitions
                           if item["target"] in field_names]
            inferred = infer_field_bounds(combined, fields, enums=c_enums or None,
                                          _index=combined_index)
            registered = _register_candidate(Path(project_root), name, fields,
                                              transitions, bounds=inferred)
            domains.append(str(registered))
    architecture = {"name": "ExtractedSystem", "components": components, "use_cases": [],
                    "review_status": "unreviewed", "warnings": warnings}
    architecture_path = destination / "extracted_architecture.json"
    architecture_path.write_text(json.dumps(architecture, indent=2) + "\n", encoding="utf-8")
    return {"status": "EXTRACTED", "claim": "UNREVIEWED_EXTRACTION_CANDIDATE",
            "architecture": str(architecture_path), "domains": domains,
            "components": components, "warnings": warnings,
            "validation": {"status": "NOT_RUN", "reason": "human review required"}}
