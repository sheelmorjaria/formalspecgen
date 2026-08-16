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
    ".cpp": tree_sitter_cpp.language() if Parser else None,
}


def _tree_sitter_declarations(source: Path, text: str) -> list[dict] | None:
    language = _TS_LANGUAGES.get(source.suffix.lower())
    if language is None:
        return None
    parser = Parser(); parser.language = Language(language)
    tree = parser.parse(text.encode("utf-8"))
    if tree.root_node.has_error:
        return None
    types = {".java": {"class_declaration": False, "interface_declaration": True},
             ".rs": {"struct_item": False},
             ".c": {"struct_specifier": False},
             ".cpp": {"class_specifier": False, "struct_specifier": False}}[source.suffix.lower()]
    declarations = []
    def walk(node):
        if node.type in types:
            name_node = next((child for child in node.children if child.type in {"identifier", "type_identifier"}), None)
            if name_node:
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
                                for n in names:
                                    fields.append((n.text.decode(), "boolean" if "bool" in type_text else "int"))
                            stack.extend(current.children)
                unique_fields = list(dict.fromkeys(fields))
                declarations.append({"name": name_node.text.decode(), "interface": types[node.type], "fields": unique_fields})
        for child in node.children:
            walk(child)
    walk(tree.root_node)
    return declarations


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
        return _tree_sitter_declarations(path, path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError):
        return None


def _snake_name(value: str) -> str:
    return re.sub(r"(?<!^)([A-Z])", r"_\1", value).lower()


def _infer_java_transitions(text: str, fields: list[tuple[str, str]]) -> list[dict]:
    names = {name for name, _ in fields}
    transitions = []
    pattern = re.compile(r"(?:public|protected)\s+void\s+(\w+)\s*\([^)]*\)\s*\{(?P<body>.*?)\}", re.S)
    for method in pattern.finditer(text):
        name, body = method.group(1), method.group("body")
        if name in {"<init>"}:
            continue
        match = re.search(r"if\s*\(\s*(?:this\.)?(\w+)\s*(<=|>=|<|>)\s*(-?\d+)\s*\).*?\b(?:this\.)?\1\s*=\s*(?:this\.)?\1\s*([+-])\s*(\d+)", body, re.S)
        if not match or match.group(1) not in names:
            continue
        field, operator, limit, arithmetic, amount = match.groups()
        guard = f"{field} {operator} {limit}"
        value = f"{field} {arithmetic} {amount}"
        try:
            guard_ast = parse_jml_expression(guard, fields=names)
            value_ast = parse_jml_expression(value, fields=names)
        except Exception:
            continue
        transitions.append({"name": name, "guard": guard_ast, "target": field, "value": value_ast})
    return transitions


_C_ACCESS = r"\w+(?:->|\.)"


def _infer_c_transitions(text: str, fields: list[tuple[str, str]]) -> list[dict]:
    """Guarded scalar assignments over ``ptr->field`` / ``value.field`` receivers.

    Mirrors the Java lane's narrow boundary: one void function, one guarded
    assignment whose field is declared state. Guards accept the comparison
    family (==, !=, <=, >=, <, >) and effects are either literal state writes
    (``c->state = 2``) or bounded increments (``c->state = c->state + 1``).
    """
    names = {name for name, _ in fields}
    transitions = []
    functions = re.compile(r"\bvoid\s+(\w+)\s*\([^)]*\)\s*\{(?P<body>.*?)\}", re.S)
    literal = re.compile(
        rf"if\s*\(\s*{_C_ACCESS}(?P<field>\w+)\s*(?P<op>==|!=|<=|>=|<|>)\s*"
        rf"(?P<limit>-?\d+)\s*\).*?"
        rf"{_C_ACCESS}(?P<target>\w+)\s*=\s*(?P<value>-?\d+)\s*;", re.S)
    incremental = re.compile(
        rf"if\s*\(\s*{_C_ACCESS}(?P<field>\w+)\s*(?P<op>==|!=|<=|>=|<|>)\s*"
        rf"(?P<limit>-?\d+)\s*\).*?"
        rf"{_C_ACCESS}(?P<target>\w+)\s*=\s*{_C_ACCESS}(?P<rhs>\w+)\s*"
        rf"(?P<op2>[+-])\s*(?P<amount>\d+)\s*;", re.S)
    for function in functions.finditer(text):
        name, body = function.group(1), function.group("body")
        increment = incremental.search(body)
        if increment is not None:
            match = increment
            value_text = f"{match['field']} {match['op2']} {match['amount']}"
        else:
            match = literal.search(body)
            if match is None:
                continue
            value_text = match["value"]
        if match["field"] not in names or match["target"] != match["field"]:
            continue
        if increment is not None and match["rhs"] != match["field"]:
            continue
        guard_text = f"{match['field']} {match['op']} {match['limit']}"
        try:
            guard_ast = parse_jml_expression(guard_text, fields=names)
            value_ast = parse_jml_expression(value_text, fields=names)
        except Exception:
            continue
        transitions.append({"name": name, "guard": guard_ast,
                            "target": match["field"], "value": value_ast})
    return transitions


def infer_field_bounds(text: str, fields: list[tuple[str, str]]) -> dict[str, tuple[int, int] | None]:
    """Infer a [0, N] bound per int field from `<=`/`<` comparisons; None when unbounded."""
    bounds: dict[str, tuple[int, int] | None] = {}
    for name, field_type in fields:
        if field_type != "int":
            continue
        match = re.search(rf"\b{re.escape(name)}\s*(?:<=|<)\s*(\d+)", text)
        bounds[name] = (0, int(match.group(1))) if match else None
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
            "domain_name": class_name, "module_name": _snake_name(class_name), "actors": 1,
            "state_variables": state, "operations": operations, "tlc_invariants": invariants}


def _register_candidate(project_root: Path, class_name: str, fields: list[tuple[str, str]],
                        transitions: list[dict],
                        bounds: dict[str, tuple[int, int] | None] | None = None,
                        initials: dict[str, int | bool] | None = None) -> Path:
    candidate_dir = project_root / "domains" / "candidates"
    candidate_dir.mkdir(parents=True, exist_ok=True)
    payload = build_v2_candidate_payload(class_name, fields, transitions,
                                         bounds=bounds, initials=initials)
    path = candidate_dir / f"{_snake_name(class_name)}.v2.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def analyze_codebase(target_dir: str | Path, out_dir: str | Path = "extracted",
                     project_root: str | Path = ".") -> dict:
    root, destination = Path(target_dir), Path(out_dir)
    if not root.is_dir():
        return {"status": "FAIL", "claim": "NO_PROOF", "code": "input_unavailable", "message": str(root)}
    destination.mkdir(parents=True, exist_ok=True)
    components, domains, warnings = [], [], []
    for source in sorted(path for ext in ("*.java", "*.rs", "*.c", "*.cpp", "*.cc", "*.cxx") for path in root.rglob(ext)):
        try:
            text = source.read_text(encoding="utf-8")
            declarations = extract_components_ts(source)
            if declarations is None:
                declarations = _polyglot_declarations(source, text)
                if source.suffix.lower() == ".java" and not declarations:
                    warnings.append({"file": str(source), "code": "UNPARSEABLE_SOURCE", "message": "Tree-sitter parse error"})
        except (OSError, UnicodeError) as exc:
            warnings.append({"file": str(source), "code": "UNPARSEABLE_SOURCE", "message": str(exc)})
            continue
        for declaration in declarations:
            name = declaration["name"]
            is_interface = declaration.get("interface", False)
            fields = declaration.get("fields", [])
            domain_name = name.lower()
            component = {"name": name, "type": "interface" if is_interface else "core",
                         "external": is_interface, "domain": None if is_interface else domain_name,
                         "file": source.name, "review_status": "unreviewed",
                         "lang": "java" if source.suffix.lower() == ".java" else source.suffix[1:],
                         "language": "java" if source.suffix.lower() == ".java" else source.suffix[1:],
                         "fields": [{"name": field, "type": field_type} for field, field_type in fields]}
            components.append(component)
            if fields and not is_interface:
                state = []
                unbounded = False
                inferred = infer_field_bounds(text, fields)
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
                if suffix in {".java", ".c"}:
                    transitions = (_infer_java_transitions(text, fields) if suffix == ".java"
                                   else _infer_c_transitions(text, fields))
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
