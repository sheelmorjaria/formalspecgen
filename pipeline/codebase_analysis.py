"""Conservative bottom-up extraction of architecture and unreviewed domain candidates."""
from __future__ import annotations

import json
from pathlib import Path
import re
import javalang


def analyze_codebase(target_dir: str | Path, out_dir: str | Path = "extracted") -> dict:
    root, destination = Path(target_dir), Path(out_dir)
    if not root.is_dir():
        return {"status": "FAIL", "claim": "NO_PROOF", "code": "input_unavailable", "message": str(root)}
    destination.mkdir(parents=True, exist_ok=True)
    components, domains, warnings = [], [], []
    for source in sorted(root.rglob("*.java")):
        try:
            text = source.read_text(encoding="utf-8")
            tree = javalang.parse.parse(text)
        except (OSError, javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError) as exc:
            warnings.append({"file": str(source), "code": "UNPARSEABLE_SOURCE", "message": str(exc)})
            continue
        declarations = [node for node in tree.types if isinstance(node, (javalang.tree.ClassDeclaration, javalang.tree.InterfaceDeclaration))]
        for declaration in declarations:
            name = declaration.name
            is_interface = isinstance(declaration, javalang.tree.InterfaceDeclaration)
            fields = [(node, declarator) for node in getattr(declaration, "fields", [])
                      for declarator in node.declarators
                      if getattr(node.type, "name", "") in {"int", "boolean", "bool"}]
            domain_name = name.lower()
            component = {"name": name, "type": "interface" if is_interface else "core",
                         "external": is_interface, "domain": None if is_interface else domain_name,
                         "file": source.name, "review_status": "unreviewed"}
            components.append(component)
            if fields and not is_interface:
                state = []
                unbounded = False
                for node, declarator in fields:
                    field_type = "int" if getattr(node.type, "name", "") == "int" else "boolean"
                    item = {"name": declarator.name, "type": field_type}
                    if field_type == "int":
                        bound = re.search(rf"\b{re.escape(declarator.name)}\s*<\s*(\d+)", text)
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
