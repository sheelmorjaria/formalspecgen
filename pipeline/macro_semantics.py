# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M35: semantic macro expansion — macros to V2 logic, natively.

The macro wall, mechanized. Historically (the lwIP port) macro-heavy C was
cleared by running ``gcc -E -P`` with hand-written stub headers and
reviewing preprocessor soup; this lane replaces that with three honest
phases:

1. DICTIONARY (deterministic): a reviewed ``macros.json`` maps macro names
   to closed-set V2 categories — ``container_of: V2::StructuralRelationship``,
   ``READ_ONCE: V2::Read``. Dictionary hits translate deterministically,
   no LLM in the loop.
2. LLM SYNTHESIS (proposal): macros #define'd in the source but NOT in
   the dictionary are classified by the LLM into the same closed set.
   A proposal is RECORDED with its provenance (``llm_proposed``) — it
   guides synthesis but never silently enters the trusted dictionary;
   promotion to the dictionary is the reviewer's act.
3. SYNTHESIS + PROOF: the source is rewritten (V2::Write /
   V2::Transition invocations become plain assignments, V2::Read becomes
   a parenthesized read) and mined by the EXISTING deterministic
   transition extractor; the synthesized model's bounds invariant is then
   proved inductive by REAL Z3 (SMT-LIB2: initiation Init => Inv and
   consecution Inv && Trans => Inv').

Epistemics: dictionary translations are deterministic; LLM categories are
proposals carrying provenance; the safety claim is machine-proved by Z3
over the deterministic SMT encoding, with sufficiency-of-encoding the
reviewable artifact (the emitted .smt2 text).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

MACRO_CATEGORIES = {
    "V2::StructuralRelationship",
    "V2::Read",
    "V2::Write",
    "V2::Transition",
    "V2::Guard",
}

_DEFINE = re.compile(
    r"^#\s*define\s+(?P<name>[A-Za-z_]\w*)"
    r"(?P<params>\([^)\n]*\))(?P<body>.*)$", re.M)
_INVOCATION = r"(?<![A-Za-z0-9_]){}\s*\("


def _fail(code: str, message: str) -> dict:
    return {"status": "MACRO_TRANSLATION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def load_macro_dictionary(path: str | Path) -> dict:
    """Phase 1 / Test 1.1: load and validate a macros.json dictionary."""
    source = Path(path)
    if not source.is_file():
        return _fail("input_unavailable", str(source))
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError) as error:
        return _fail("dictionary_malformed",
                     f"macros.json is not valid JSON: {error}")
    if not isinstance(data, dict) or not data:
        return _fail("dictionary_malformed",
                     "macros.json must be a non-empty object mapping macro "
                     "names to V2 categories")
    for name, category in data.items():
        if not re.fullmatch(r"[A-Za-z_]\w*", name):
            return _fail("dictionary_malformed",
                         f"dictionary key {name!r} is not a C identifier")
        if category not in MACRO_CATEGORIES:
            return _fail(
                "dictionary_invalid_category",
                f"macro {name!r} maps to {category!r}; the closed category "
                f"set is {sorted(MACRO_CATEGORIES)}")
    return {"status": "MACRO_DICTIONARY_LOADED",
            "dictionary": dict(data), "entries": len(data),
            "categories": sorted(set(data.values()))}


def _source_macros(text: str) -> dict[str, str]:
    """Function-like #defines in the source: name -> body (LLM context)."""
    out = {}
    for match in _DEFINE.finditer(text):
        out[match.group("name")] = match.group("body").strip()
    return out


def _balanced_call(text: str, open_paren: int) -> tuple[int, str]:
    """Return (close_index, argument_text) for the call opened at
    open_paren (index of '(')."""
    level = 0
    for position in range(open_paren, len(text)):
        if text[position] == "(":
            level += 1
        elif text[position] == ")":
            level -= 1
            if level == 0:
                return position, text[open_paren + 1:position]
    return len(text) - 1, text[open_paren + 1:-1]


def _split_args(argument_text: str) -> list[str]:
    args, depth, current = [], 0, ""
    for char in argument_text:
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        if char == "," and depth == 0:
            args.append(current.strip())
            current = ""
        else:
            current += char
    if current.strip():
        args.append(current.strip())
    return args


def _llm_propose(name: str, body: str, provider: str) -> str:
    """Phase 2: the LLM classifies an unknown macro into the closed set.

    Returns the category string; raises RuntimeError on unavailable
    providers and on two consecutive out-of-set answers (never guessed).
    """
    from .llm import _chat_fn
    schema = {
        "type": "object",
        "properties": {"category": {"type": "string",
                                    "enum": sorted(MACRO_CATEGORIES)}},
        "required": ["category"], "additionalProperties": False,
    }
    prompt = [
        {"role": "system", "content":
            "You classify C macros for state-machine synthesis. Answer with "
            "exactly one category from the enum."},
        {"role": "user", "content":
            f"Macro: #define {name} {body}\n\nCategories:\n"
            "- V2::Write: expands to a state-field assignment "
            "(target, value)\n"
            "- V2::Read: reads a state field without mutating\n"
            "- V2::Transition: expands to a guarded state write / dispatch\n"
            "- V2::Guard: a pure condition over state\n"
            "- V2::StructuralRelationship: pointer/structure plumbing "
            "(e.g. container_of), not scalar state\n\n"
            "Which category?"},
    ]
    chat = _chat_fn(provider, json_schema=schema)
    for _ in range(2):
        raw, _, _ = chat(prompt, None, 0.0)
        try:
            answer = json.loads(raw)
            category = answer.get("category")
        except (json.JSONDecodeError, AttributeError):
            category = None
        if category in MACRO_CATEGORIES:
            return category
    raise RuntimeError(
        f"LLM failed to classify macro {name!r} into the closed category "
        "set after two attempts")


def translate_macros(source: str | Path, dictionary: dict,
                      *, provider: str | None = None) -> dict:
    """Phases 1-2 / Tests 1.2, 1.3, 2.1, 2.2: every macro invocation in
    the source gets a category — dictionary hits deterministic, unknown
    #define'd macros via a recorded LLM proposal."""
    path = Path(source)
    if not path.is_file():
        return _fail("input_unavailable", str(path))
    if path.suffix.lower() not in {".c", ".h"}:
        return _fail("UNSUPPORTED_BOUNDARY",
                     "the macro lane reads .c/.h sources")
    text = path.read_text(encoding="utf-8")
    known_bodies = _source_macros(text)
    translations, invocations = {}, {}
    for name in sorted(set(dictionary) | set(known_bodies)):
        pattern = re.compile(_INVOCATION.format(re.escape(name)))
        calls = []
        for match in pattern.finditer(text):
            line_start = text.rfind("\n", 0, match.start()) + 1
            if text[line_start:match.start()].lstrip().startswith("#"):
                continue  # the #define line defines, it does not invoke
            close, args_text = _balanced_call(text, text.index(
                "(", match.end() - 1))
            calls.append({"args": _split_args(args_text),
                          "line": text.count("\n", 0, match.start()) + 1})
        if not calls:
            continue
        invocations[name] = calls
        if name in dictionary:
            translations[name] = {"macro": name,
                                  "category": dictionary[name],
                                  "source": "dictionary",
                                  "v2": _v2_shape(dictionary[name], calls)}
        elif provider is not None:
            try:
                category = _llm_propose(name, known_bodies[name], provider)
            except RuntimeError as error:
                if "classify" in str(error):
                    return _fail("macro_translation_failed", str(error))
                return _fail("llm_unavailable", str(error))
            translations[name] = {
                "macro": name, "category": category,
                "source": "llm_proposed",
                "body_sha256": hashlib.sha256(
                    known_bodies[name].encode()).hexdigest()[:16],
                "v2": _v2_shape(category, calls),
                "note": "an LLM proposal recorded with provenance; "
                        "promotion into macros.json is the reviewer's act"}
        else:
            translations[name] = {"macro": name, "category": None,
                                  "source": "untranslated",
                                  "note": "no dictionary entry and no "
                                          "provider given for synthesis"}
    return {"status": "MACROS_TRANSLATED", "invocations": invocations,
            "translations": translations,
            "translated": sorted(translations),
            "dictionary_hits": sorted(n for n, t in translations.items()
                                      if t["source"] == "dictionary"),
            "llm_proposed": sorted(n for n, t in translations.items()
                                   if t["source"] == "llm_proposed")}


def _v2_shape(category: str, calls: list[dict]) -> dict:
    """The V2 construct a category translates an invocation into."""
    if category in {"V2::Write", "V2::Transition"}:
        first = calls[0]["args"]
        return {"effect": {"target": first[0] if first else None,
                           "value": first[1] if len(first) > 1 else None}}
    if category == "V2::Read":
        return {"read": calls[0]["args"][0] if calls[0]["args"] else None}
    if category == "V2::Guard":
        return {"guard": calls[0]["args"] if calls[0]["args"] else None}
    return {"relationship": "enclosing_structure",
            "args": calls[0]["args"]}


def rewrite_source(text: str, translations: dict) -> str:
    """V2::Write/V2::Transition invocations become plain assignments,
    V2::Read becomes a parenthesized read — the deterministic rewrite the
    existing extractor's dialects then mine. Structural/Guard macros are
    record-only (no rewrite: pointer plumbing and pure conditions are not
    scalar state writes)."""
    out = text
    for name, translation in sorted(translations.items(),
                                    key=lambda item: -len(item[0])):
        category = translation.get("category")
        if category not in {"V2::Write", "V2::Transition", "V2::Read"}:
            continue
        pattern = re.compile(_INVOCATION.format(re.escape(name)))
        while True:
            match = pattern.search(out)
            if not match:
                break
            open_paren = out.index("(", match.end() - 1)
            close, _ = _balanced_call(out, open_paren)
            # a macro's own #define line is a definition, not an invocation
            line_start = out.rfind("\n", 0, match.start()) + 1
            if out[line_start:match.start()].lstrip().startswith("#"):
                out = (out[:match.end() - 1] + "\x00" +
                       out[match.end() - 1:])
                continue
            _, args_text = _balanced_call(out, open_paren)
            args = _split_args(args_text)
            if category == "V2::Read":
                replacement = f"({args[0]})" if args else None
            elif len(args) >= 2:
                # plain assignment — the extractor's guarded-write dialect
                replacement = f"{args[0]} = {args[1]}"
            else:
                replacement = None    # malformed arity: leave verbatim
            if replacement is None:
                out = (out[:match.end() - 1] + "\x00" +
                       out[match.end() - 1:])
                continue
            out = out[:match.start()] + replacement + out[close + 1:]
    return out.replace("\x00", "")


def synthesize_v2_from_macros(source: str | Path, dictionary_path: str | Path,
                              *, provider: str | None = None,
                              project_root: str | Path | None = None,
                              verify: bool = True) -> dict:
    """Phase 3 / Tests 3.1-3.2: translate, rewrite, mine the V2 model with
    the existing deterministic extractor, and (by default) prove the
    synthesized model's bounds invariant inductive with real Z3."""
    loaded = load_macro_dictionary(dictionary_path)
    if loaded.get("status") != "MACRO_DICTIONARY_LOADED":
        return loaded
    dictionary = loaded["dictionary"]
    translated = translate_macros(source, dictionary, provider=provider)
    if translated.get("status") != "MACROS_TRANSLATED":
        return translated
    path = Path(source)
    rewritten = rewrite_source(path.read_text(encoding="utf-8"),
                               translated["translations"])
    root = Path(project_root) if project_root else path.parent
    from .codebase_analysis import analyze_codebase
    with tempfile.TemporaryDirectory() as directory:
        stage = Path(directory) / path.name
        stage.write_text(rewritten, encoding="utf-8")
        analysis = analyze_codebase(directory, directory, project_root=root)
        import yaml
        candidates = []
        for domain_path in analysis.get("domains", []):
            # only the strict V2 candidates carry the verification shape;
            # the .v2.json sibling is the unbounded-refusal marker
            if not domain_path.endswith(".v2.yaml"):
                continue
            payload = yaml.safe_load(
                Path(domain_path).read_text(encoding="utf-8"))
            entry = {"candidate": str(domain_path),
                     "name": payload.get("module_name",
                                         payload.get("domain_name")),
                     "operations": len(payload.get("operations", []))}
            if verify:
                entry["verification"] = verify_macro_model(payload)
            candidates.append(entry)
    result = dict(translated)
    result["status"] = "V2_SYNTHESIZED_FROM_MACROS"
    result["rewritten_excerpt"] = None if rewritten == path.read_text(
        encoding="utf-8") else rewritten[:400]
    result["candidates"] = candidates
    result["analysis_warnings"] = analysis.get("warnings", [])
    if verify and candidates and all(
            c.get("verification", {}).get("status")
            == "MACRO_MODEL_SAFETY_PROVED" for c in candidates
            if c["operations"]):
        result["claim"] = "MACRO_SYNTHESIS_PROVED"
    else:
        result["claim"] = "NO_PROOF"
    return result


# --- Phase 3 proof: real Z3 over a deterministic SMT-LIB2 encoding ------

# The serialized JML AST vocabulary (pipeline/jml_ast.py _BINARY + unary
# kinds) mapped to SMT-LIB2. `=`/`distinct` are polymorphic over Int/Bool.
_SMT_KINDS = {
    "eq": "=", "neq": "distinct", "lt": "<", "lte": "<=",
    "gt": ">", "gte": ">=", "add": "+", "sub": "-", "mul": "*",
    "div": "div", "and": "and", "or": "or", "implies": "=>",
    "iff": "=",
}


class _Unsupported(Exception):
    pass


def _smt(node, fields: dict[str, str], prime: bool = False) -> str:
    """Translate a serialized JML AST node to SMT-LIB2. Fail-closed on
    any node kind outside the extractor's vocabulary."""
    if not isinstance(node, dict) or "kind" not in node:
        raise _Unsupported("expression node without a kind")
    kind = node["kind"]
    if kind == "integer":
        return str(node["value"])
    if kind == "boolean":
        return "true" if node.get("value") in (True, "true") else "false"
    if kind == "field":
        name = node.get("name")
        if name not in fields:
            raise _Unsupported(f"unknown field {name!r}")
        return f"s_{name}_next" if prime else f"s_{name}"
    if kind == "not":
        return f"(not {_smt(node['operand'], fields, prime)})"
    if kind == "neg":
        return f"(- {_smt(node['operand'], fields, prime)})"
    if kind in _SMT_KINDS:
        left = _smt(node["left"], fields, prime)
        right = _smt(node["right"], fields, prime)
        return f"({_SMT_KINDS[kind]} {left} {right})"
    raise _Unsupported(f"expression kind {kind!r}")


def _encode_smt2(payload: dict) -> str:
    state = payload.get("state_variables", [])
    fields = {item["name"]: ("bool" if item["kind"] == "bool" else "int")
              for item in state}
    lines = ["; M35 synthesized-model safety: Init => Inv, Inv & Trans => Inv'"]
    for name, kind in sorted(fields.items()):
        smt_kind = "Bool" if kind == "bool" else "Int"
        lines.append(f"(declare-const s_{name} {smt_kind})")
        lines.append(f"(declare-const s_{name}_next {smt_kind})")
    init_terms = []
    for item in sorted(state, key=lambda entry: entry["name"]):
        initial = item.get("initial", 0)
        if isinstance(initial, bool):   # int 0 is NOT False here
            value = "true" if initial else "false"
        elif isinstance(initial, str):
            value = {"true": "true", "false": "false"}.get(
                initial.lower(), initial)
        else:
            value = str(initial)
        init_terms.append(f"(= s_{item['name']} {value})")
    init = f"(and {' '.join(init_terms)})" if init_terms else "true"

    trans_terms = []
    for operation in payload.get("operations", []):
        arm_terms = []
        for guard in operation.get("guards", []):
            arm_terms.append(_smt(guard["expression"], fields))
        targets = set()
        for effect in operation.get("effects", []):
            target = effect["target"]
            if target not in fields:
                raise _Unsupported(f"effect target {target!r} not a field")
            targets.add(target)
            arm_terms.append(
                f"(= s_{target}_next {_smt(effect['value'], fields)})")
        for name in sorted(fields):
            if name not in targets:   # frame: untouched fields persist
                arm_terms.append(f"(= s_{name}_next s_{name})")
        trans_terms.append(f"(and {' '.join(arm_terms)})" if arm_terms
                           else "false")
    trans = f"(or {' '.join(trans_terms)})" if trans_terms else "false"

    invariants = payload.get("tlc_invariants", [])
    inv_terms = [_smt(invariant["expression"], fields)
                 for invariant in invariants]
    if not inv_terms:
        raise _Unsupported("model carries no invariant — refusing a "
                           "vacuous proof")
    inv = f"(and {' '.join(inv_terms)})"
    inv_terms_next = [_smt(invariant["expression"], fields, prime=True)
                      for invariant in invariants]
    inv_next = f"(and {' '.join(inv_terms_next)})"

    lines.append(f"(define-fun Init () Bool {init})")
    lines.append(f"(define-fun Trans () Bool {trans})")
    lines.append(f"(define-fun Inv () Bool {inv})")
    lines.append(f"(define-fun InvNext () Bool {inv_next})")
    lines.append("(push 1)")
    lines.append("(assert (and Init (not Inv)))")
    lines.append("(check-sat)")
    lines.append("(pop 1)")
    lines.append("(push 1)")
    lines.append("(assert (and Inv Trans (not InvNext)))")
    lines.append("(check-sat)")
    lines.append("(pop 1)")
    return "\n".join(lines) + "\n"


def verify_macro_model(payload: dict) -> dict:
    """Test 3.2: real Z3 proves the synthesized model's invariant
    inductive (initiation + 1-step consecution) over the deterministic
    SMT-LIB2 encoding."""
    z3_binary = shutil.which(os.environ.get("Z3_BIN", "z3"))
    if not z3_binary:
        return {"status": "MACRO_MODEL_VERIFICATION_FAILED", "claim":
                "NO_PROOF", "code": "z3_unavailable",
                "message": "z3 binary not found (Z3_BIN)"}
    try:
        smt2 = _encode_smt2(payload)
    except _Unsupported as error:
        return {"status": "MACRO_MODEL_VERIFICATION_FAILED", "claim":
                "NO_PROOF", "code": "unsupported_expression",
                "message": str(error)}
    try:
        process = subprocess.run([z3_binary, "-in"], input=smt2,
                                 capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, TimeoutError, OSError):
        return {"status": "MACRO_MODEL_VERIFICATION_FAILED", "claim":
                "NO_PROOF", "code": "z3_timeout",
                "message": "Z3 timed out on the encoding"}
    stdout = process.stdout or ""
    if "(error" in stdout:   # z3 still prints sat/unsat after errors —
        # those verdicts are about a broken encoding, never trust them
        return {"status": "MACRO_MODEL_VERIFICATION_FAILED", "claim":
                "NO_PROOF", "code": "smt_encoding_error",
                "message": "Z3 rejected the encoding: " + stdout[-300:]}
    answers = [line.strip().lower() for line in stdout.splitlines()
               if line.strip().lower() in {"sat", "unsat", "unknown"}]
    if len(answers) != 2:
        return {"status": "MACRO_MODEL_VERIFICATION_FAILED", "claim":
                "NO_PROOF", "code": "z3_no_verdict",
                "message": "unexpected Z3 output: " + stdout[-300:]}
    initiation, consecution = answers
    proved = initiation == "unsat" and consecution == "unsat"
    return {
        "status": ("MACRO_MODEL_SAFETY_PROVED" if proved
                   else "MACRO_MODEL_SAFETY_FAILED"),
        "claim": "MACRO_SYNTHESIS_PROVED" if proved else "NO_PROOF",
        "solver": "z3", "encoding": "smtlib2_initiation_consecution",
        "initiation": initiation, "consecution": consecution,
        "invariant": "state bounds (machine-derived from transitions)",
        "smt2": smt2,
        "note": "inductive invariant proved by real Z3 over the "
                "deterministic encoding; the encoding itself is the "
                "reviewable artifact (smt2 field)",
    }
