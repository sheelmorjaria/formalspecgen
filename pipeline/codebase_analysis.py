"""Conservative bottom-up extraction of architecture and unreviewed domain candidates."""
from __future__ import annotations

import json
from pathlib import Path
import re

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


def analyze_codebase(target_dir: str | Path, out_dir: str | Path = "extracted") -> dict:
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
                for field_name, field_type in fields:
                    item = {"name": field_name, "type": field_type}
                    if field_type == "int":
                        bound = re.search(rf"\b{re.escape(field_name)}\s*<\s*(\d+)", text)
                        if bound:
                            item["bound"] = [0, int(bound.group(1))]
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
    architecture = {"name": "ExtractedSystem", "components": components, "use_cases": [],
                    "review_status": "unreviewed", "warnings": warnings}
    architecture_path = destination / "extracted_architecture.json"
    architecture_path.write_text(json.dumps(architecture, indent=2) + "\n", encoding="utf-8")
    return {"status": "EXTRACTED", "claim": "UNREVIEWED_EXTRACTION_CANDIDATE",
            "architecture": str(architecture_path), "domains": domains,
            "components": components, "warnings": warnings,
            "validation": {"status": "NOT_RUN", "reason": "human review required"}}
