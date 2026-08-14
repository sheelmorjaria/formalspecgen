# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Hash-bound deterministic Java refactoring profiles."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import javalang

from .java_inspection import _mask_non_code, _matching_brace


def extract_method_from_inspection(source_path: str | Path, inspection_path: str | Path,
                                   method_name: str) -> dict:
    source_file, evidence_file = Path(source_path), Path(inspection_path)
    try:
        source = source_file.read_text(encoding="utf-8")
        evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        return _fail("input_unavailable", str(exc))
    digest = hashlib.sha256(source.encode()).hexdigest()
    if (evidence.get("status") != "INSPECTED" or
            evidence.get("claim") != "STATIC_INSPECTION" or
            evidence.get("source_sha256") != digest):
        return _fail("inspection_binding_mismatch",
                     "Inspection must be successful and hash-bound to the source")
    long_lines = {item.get("line") for item in evidence.get("findings", [])
                  if item.get("code") == "long-method"}
    try:
        tree = javalang.parse.parse(source)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError,
            TypeError) as exc:
        return _fail("unsupported_java_syntax", str(exc))
    matches = [node for _, node in tree.filter(javalang.tree.MethodDeclaration)
               if node.name == method_name]
    if len(matches) != 1:
        return _fail("method_not_unique", "Method name must identify exactly one declaration")
    method = matches[0]
    if method.position is None or method.position.line not in long_lines:
        return _fail("method_not_inspected_long",
                     "The hash-bound inspection did not classify this method as long")
    if method.body is None or not ({"public", "protected"} & set(method.modifiers)):
        return _fail("unsupported_method_shape", "Method must be concrete and public/protected")
    helper_name = f"{method_name}Extracted"
    if any(node.name == helper_name for _, node in tree.filter(
            javalang.tree.MethodDeclaration)):
        return _fail("helper_name_collision", f"Method {helper_name} already exists")
    try:
        transformed = _extract(source, method, helper_name)
    except ValueError as exc:
        return _fail("unsupported_method_span", str(exc))
    return {"status": "TRANSFORMED", "claim": "DETERMINISTIC_REFACTOR_CANDIDATE",
            "pattern": "Extract Method", "method": method_name,
            "source_sha256": digest,
            "refactored_sha256": hashlib.sha256(transformed.encode()).hexdigest(),
            "source": transformed, "formal_preservation_proved": False,
            "requires_refactor_gate": True}


def extract_decorator_from_inspection(source_path: str | Path, inspection_path: str | Path) -> dict:
    """Emit a decorator wrapper for a narrowly inspected interface implementation."""
    source_file, evidence_file = Path(source_path), Path(inspection_path)
    try:
        source = source_file.read_text(encoding="utf-8")
        evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        return _fail("input_unavailable", str(exc))
    digest = hashlib.sha256(source.encode()).hexdigest()
    finding = next((item for item in evidence.get("findings", [])
                    if item.get("code") == "cross-cutting-delegation"), None)
    if (evidence.get("status") != "INSPECTED" or evidence.get("claim") != "STATIC_INSPECTION" or
            evidence.get("source_sha256") != digest or finding is None or
            len(finding.get("interfaces", [])) != 1 or len(finding.get("wrapped_fields", [])) != 1):
        return _fail("inspection_binding_mismatch", "A unique hash-bound Decorator finding is required")
    try:
        tree = javalang.parse.parse(source)
        declaration = next(node for node in tree.types if isinstance(node, javalang.tree.ClassDeclaration))
        methods = [node for node in declaration.methods if node.name in finding.get("methods", [])]
        if len(methods) != len(finding["methods"]):
            raise ValueError("decorated methods are not uniquely available")
        files = _decorator_files(source, declaration, methods, finding)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError, TypeError) as exc:
        return _fail("unsupported_java_syntax", str(exc))
    except (StopIteration, ValueError) as exc:
        return _fail("unsupported_decorator_shape", str(exc))
    return {"status": "TRANSFORMED", "claim": "DETERMINISTIC_MULTIFILE_REFACTOR_CANDIDATE",
            "pattern": "Decorator", "source_sha256": digest, "files": files,
            "formal_preservation_proved": False, "requires_multifile_refactor_gate": True}


def extract_facade_from_inspection(source_path: str | Path, inspection_path: str | Path) -> dict:
    """Emit a narrow public-surface facade for a hash-bound God-class finding."""
    source_file, evidence_file = Path(source_path), Path(inspection_path)
    try:
        source = source_file.read_text(encoding="utf-8")
        evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        return _fail("input_unavailable", str(exc))
    digest = hashlib.sha256(source.encode()).hexdigest()
    finding = next((item for item in evidence.get("findings", []) if item.get("code") == "god-class"), None)
    if (evidence.get("status") != "INSPECTED" or evidence.get("claim") != "STATIC_INSPECTION" or
            evidence.get("source_sha256") != digest or finding is None):
        return _fail("inspection_binding_mismatch", "A hash-bound Facade finding is required")
    try:
        tree = javalang.parse.parse(source)
        declaration = next(node for node in tree.types if isinstance(node, javalang.tree.ClassDeclaration))
        methods = [node for node in declaration.methods if "public" in node.modifiers and
                   "static" not in node.modifiers and node.body is not None]
        if not methods:
            raise ValueError("Facade requires public instance methods")
        facade = _facade_source(declaration.name, methods)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError, TypeError) as exc:
        return _fail("unsupported_java_syntax", str(exc))
    except (StopIteration, ValueError) as exc:
        return _fail("unsupported_facade_shape", str(exc))
    return {"status": "TRANSFORMED", "claim": "DETERMINISTIC_MULTIFILE_REFACTOR_CANDIDATE",
            "pattern": "Facade", "source_sha256": digest,
            "files": {source_file.name: source, f"{declaration.name}Facade.java": facade},
            "formal_preservation_proved": False, "requires_multifile_refactor_gate": True}


def _facade_source(class_name: str, methods: list) -> str:
    lines = [f"public class {class_name}Facade {{",
             f"    private final {class_name} delegate;", "",
             f"    public {class_name}Facade({class_name} delegate) {{ this.delegate = delegate; }}", ""]
    for method in methods:
        return_type = getattr(method.return_type, "name", "void") if method.return_type else "void"
        params = []
        args = []
        for parameter in method.parameters:
            type_name = getattr(parameter.type, "name", "")
            if not type_name:
                raise ValueError("Facade parameter type is unsupported")
            params.append(f"{type_name} {parameter.name}"); args.append(parameter.name)
        lines.append(f"    public {return_type} {method.name}({', '.join(params)}) {{")
        call = f"delegate.{method.name}({', '.join(args)})"
        lines.append(f"        {'return ' if return_type != 'void' else ''}{call};")
        lines.extend(["    }", ""])
    lines.append("}")
    return "\n".join(lines) + "\n"


def _decorator_files(source: str, declaration, methods: list, finding: dict) -> dict[str, str]:
    interface, wrapped = finding["interfaces"][0], finding["wrapped_fields"][0]
    for method in methods:
        if method.return_type is not None or method.parameters:
            raise ValueError("Decorator profile requires void methods without parameters")
        fields = {node.member for _, node in method.filter(javalang.tree.MemberReference)}
        if fields - {wrapped}:
            raise ValueError("Decorator method depends on additional instance state")
    class_name = declaration.name + "Decorator"
    methods_text = []
    masked = _mask_non_code(source)
    for method in methods:
        lines = source.splitlines(keepends=True)
        start = sum(len(line) for line in lines[:method.position.line - 1])
        opening = masked.find("{", start); end = _matching_brace(masked, opening)
        if opening < 0 or end <= opening:
            raise ValueError("decorator method span could not be reconstructed")
        declaration_text = source[start:opening].strip()
        declaration_text = re.sub(r"\b(?:public|protected|private)\b\s*", "public ",
                                  declaration_text, count=1)
        methods_text.append("    " + declaration_text + source[opening:end + 1].replace("\n", "\n    "))
    body = "\n".join(methods_text)
    wrapper = (f"public class {class_name} implements {interface} {{\n"
               f"    private final {interface} {wrapped};\n\n"
               f"    public {class_name}({interface} {wrapped}) {{ this.{wrapped} = {wrapped}; }}\n\n"
               f"{body}\n}}\n")
    return {source_file_name(source): source, f"{class_name}.java": wrapper}


def extract_factory_from_inspection(source_path: str | Path, inspection_path: str | Path,
                                    method_name: str) -> dict:
    """Extract one closed conditional-creation method into deterministic factory files."""
    source_file, evidence_file = Path(source_path), Path(inspection_path)
    try:
        source = source_file.read_text(encoding="utf-8")
        evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        return _fail("input_unavailable", str(exc))
    digest = hashlib.sha256(source.encode()).hexdigest()
    findings = [item for item in evidence.get("findings", [])
                if item.get("code") == "conditional-object-creation" and
                item.get("method") == method_name]
    if (evidence.get("status") != "INSPECTED" or
            evidence.get("claim") != "STATIC_INSPECTION" or
            evidence.get("source_sha256") != digest or len(findings) != 1):
        return _fail("inspection_binding_mismatch",
                     "A unique hash-bound Factory Method finding is required")
    try:
        tree = javalang.parse.parse(source)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError,
            TypeError) as exc:
        return _fail("unsupported_java_syntax", str(exc))
    matches = [node for _, node in tree.filter(javalang.tree.MethodDeclaration)
               if node.name == method_name]
    if len(matches) != 1:
        return _fail("method_not_unique", "Method name must identify exactly one declaration")
    method = matches[0]
    creators = [node for _, node in method.filter(javalang.tree.ClassCreator)]
    returns = [node for _, node in method.filter(javalang.tree.ReturnStatement)]
    parameters = {parameter.name for parameter in method.parameters}
    references = {node.member for _, node in method.filter(javalang.tree.MemberReference)}
    invocations = [node for _, node in method.filter(javalang.tree.MethodInvocation)]
    if (method.body is None or len(method.body) != 1 or
            not isinstance(method.body[0], javalang.tree.IfStatement) or
            len(creators) < 2 or any(creator.arguments for creator in creators) or
            not returns or any(not isinstance(item.expression, javalang.tree.ClassCreator)
                               for item in returns) or
            not references.issubset(parameters) or
            any(not invocation.qualifier or invocation.qualifier not in parameters
                for invocation in invocations)):
        return _fail("unsupported_factory_shape",
                     "Factory extraction requires a closed if/else of zero-argument creations")
    returned = getattr(method.return_type, "name", "")
    if not returned:
        return _fail("unsupported_factory_shape", "Factory method requires a reference return type")
    try:
        files = _factory_files(source, method, returned)
    except ValueError as exc:
        return _fail("unsupported_method_span", str(exc))
    return {"status": "TRANSFORMED", "claim": "DETERMINISTIC_MULTIFILE_REFACTOR_CANDIDATE",
            "pattern": "Factory Method", "method": method_name, "source_sha256": digest,
            "files": files, "formal_preservation_proved": False,
            "requires_multifile_refactor_gate": True}


def _factory_files(source: str, method, product_type: str) -> dict[str, str]:
    lines = source.splitlines(keepends=True)
    start = sum(len(line) for line in lines[:method.position.line - 1])
    masked = _mask_non_code(source); opening = masked.find("{", start)
    end = _matching_brace(masked, opening)
    declaration, body = source[start:opening], source[opening:end + 1]
    name_match = re.search(rf"\b{re.escape(method.name)}\s*(?=\()", declaration)
    class_close = masked.rfind("}")
    if opening < 0 or end <= opening or name_match is None or class_close <= end:
        raise ValueError("AST factory span could not be reconstructed")
    factory_type, concrete_type = f"{product_type}Factory", f"Default{product_type}Factory"
    if factory_type in source or concrete_type in source:
        raise ValueError("generated factory type collides with baseline source")
    indent = re.match(r"[ \t]*", declaration).group(0)
    arguments = ", ".join(parameter.name for parameter in method.parameters)
    wrapper = declaration + "{\n" + indent + f"    return productFactory.{method.name}({arguments});\n" + indent + "}"
    field = f"\n    private final {factory_type} productFactory = new {concrete_type}();\n"
    primary = source[:start] + wrapper + source[end + 1:class_close] + field + source[class_close:]
    contracts = _leading_jml_contract(source, start)
    signature = re.sub(r"\b(?:public|protected|private)\b\s*", "", declaration, count=1).strip()
    interface = f"public interface {factory_type} {{\n{contracts}    {signature};\n}}\n"
    implementation_declaration = re.sub(
        r"\b(?:protected|private)\b", "public", declaration, count=1)
    concrete = (f"public class {concrete_type} implements {factory_type} {{\n" + contracts +
                implementation_declaration + body + "\n}\n")
    return {source_file_name(source): primary, f"{factory_type}.java": interface,
            f"{concrete_type}.java": concrete}


def extract_state_from_inspection(source_path: str | Path, inspection_path: str | Path,
                                  method_name: str) -> dict:
    """Extract a narrow scalar-state dispatch into stateless handler classes."""
    source_file, evidence_file = Path(source_path), Path(inspection_path)
    try:
        source = source_file.read_text(encoding="utf-8")
        evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        return _fail("input_unavailable", str(exc))
    digest = hashlib.sha256(source.encode()).hexdigest()
    finding = next((item for item in evidence.get("findings", [])
                    if item.get("code") == "repeated-state-dispatch" and
                    method_name in item.get("methods", [])), None)
    if (evidence.get("status") != "INSPECTED" or evidence.get("claim") != "STATIC_INSPECTION" or
            evidence.get("source_sha256") != digest or finding is None):
        return _fail("inspection_binding_mismatch", "A hash-bound State finding is required")
    try:
        tree = javalang.parse.parse(source)
        method = next(node for _, node in tree.filter(javalang.tree.MethodDeclaration)
                       if node.name == method_name)
        files = _state_files(source, method, finding["field"])
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError, TypeError) as exc:
        return _fail("unsupported_java_syntax", str(exc))
    except (StopIteration, ValueError) as exc:
        return _fail("unsupported_state_shape", str(exc))
    return {"status": "TRANSFORMED", "claim": "DETERMINISTIC_MULTIFILE_REFACTOR_CANDIDATE",
            "pattern": "State", "method": method_name, "source_sha256": digest,
            "files": files, "formal_preservation_proved": False,
            "requires_multifile_refactor_gate": True,
            "heap_topology_equivalence_proved": False}


def _state_files(source: str, method, field: str) -> dict[str, str]:
    if method.body is None or method.return_type is None:
        raise ValueError("State method must be concrete and return a value")
    lines = source.splitlines(keepends=True)
    start = sum(len(line) for line in lines[:method.position.line - 1])
    masked = _mask_non_code(source); opening = masked.find("{", start)
    end = _matching_brace(masked, opening)
    body = source[opening + 1:end]
    branch = re.compile(rf"if\s*\(\s*(?:this\.)?{re.escape(field)}\s*==\s*"
                        r"(?P<value>-?\d+)\s*\)\s*\{\s*return\s+"
                        r"(?P<expr>[A-Za-z0-9_ .+*()\"'-]+);\s*\}")
    branches = list(branch.finditer(body))
    if len(branches) < 2 or len({item["value"] for item in branches}) != len(branches):
        raise ValueError("State requires two or more distinct scalar return branches")
    return_type = getattr(method.return_type, "name", "")
    if not return_type:
        raise ValueError("State method return type is unsupported")
    signature = f"{return_type} handle();"
    files = {"State.java": f"public interface State {{\n    {signature}\n}}\n"}
    transformed = body
    for index, item in reversed(list(enumerate(branches))):
        state_type = f"StateHandler{index + 1}"
        files[f"{state_type}.java"] = (f"public class {state_type} implements State {{\n"
            f"    public {return_type} handle() {{ return {item['expr'].strip()}; }}\n}}\n")
        replacement = f"return new {state_type}().handle();"
        return_start = item.start("expr") - len("return ")
        return_start = body.rfind("return", 0, item.start("expr"))
        transformed = transformed[:return_start] + replacement + transformed[item.end("expr") + 1:]
    files[source_file_name(source)] = source[:opening + 1] + transformed + source[end:]
    return files


def source_file_name(source: str) -> str:
    match = re.search(r"\bpublic\s+class\s+([A-Za-z_$][\w$]*)", source)
    if not match:
        raise ValueError("public primary class is required")
    return match.group(1) + ".java"


def _extract(source: str, method, helper_name: str) -> str:
    lines = source.splitlines(keepends=True)
    start = sum(len(line) for line in lines[:method.position.line - 1])
    masked = _mask_non_code(source)
    opening = masked.find("{", start)
    end = _matching_brace(masked, opening)
    declaration = source[start:opening]
    body = source[opening:end + 1]
    name_match = re.search(rf"\b{re.escape(method.name)}\s*(?=\()", declaration)
    if opening < 0 or end <= opening or name_match is None:
        raise ValueError("AST method span could not be reconstructed")
    indent = re.match(r"[ \t]*", declaration).group(0)
    arguments = ", ".join(parameter.name for parameter in method.parameters)
    call = f"{helper_name}({arguments});"
    if method.return_type is not None:
        call = "return " + call
    wrapper = declaration + "{\n" + indent + "    " + call + "\n" + indent + "}"
    helper_declaration = (declaration[:name_match.start()] + helper_name +
                          declaration[name_match.end():])
    helper_declaration = re.sub(r"\b(?:public|protected)\b", "private",
                                helper_declaration, count=1)
    contracts = _leading_jml_contract(source, start)
    helper = contracts + helper_declaration + body
    return source[:start] + wrapper + "\n\n" + helper + source[end + 1:]


def _leading_jml_contract(source: str, declaration_start: int) -> str:
    prefix = source[:declaration_start]
    lines = prefix.splitlines(keepends=True)
    selected = []
    for line in reversed(lines):
        if line.strip().startswith("//@"):
            selected.append(line); continue
        if not line.strip() and selected:
            continue
        break
    return "".join(reversed(selected))


def _fail(code: str, message: str) -> dict:
    return {"status": "FAIL", "claim": "NO_PROOF", "code": code, "message": message,
            "formal_preservation_proved": False, "requires_refactor_gate": True}
