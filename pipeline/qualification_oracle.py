#!/usr/bin/env python3
"""M75 independent golden-vector oracle; deliberately imports no project code."""
import hashlib
import json
import re
import sys
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def fail(code, vector=None):
    print(json.dumps({"status": "ORACLE_FAILED", "code": code,
                      "vector": vector}))
    return 1


def main():
    if len(sys.argv) != 2:
        return fail("USAGE")
    try:
        artifact = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return fail("ARTIFACT_INVALID", str(exc))
    if artifact.get("schema_version") != 1:
        return fail("SCHEMA_UNSUPPORTED")
    passed = []
    for vector in artifact.get("vectors", []):
        vector_id = vector.get("id")
        if vector.get("kind") == "serializer_ast_identity":
            source = canonical(vector.get("reviewed_ast"))
            emitted = canonical(vector.get("emitted_ast"))
            digest = hashlib.sha256(source).hexdigest()
            if source != emitted:
                return fail("AST_SEMANTIC_DRIFT", vector_id)
            if digest != vector.get("expected_semantic_sha256"):
                return fail("GOLDEN_DIGEST_MISMATCH", vector_id)
        elif vector.get("kind") == "smt_boolean_mapping":
            parsed = {}
            pattern = re.compile(
                r"^\(assert \(= ([A-Za-z_][A-Za-z0-9_]*) (true|false)\)\)$")
            for assertion in vector.get("emitted_assertions", []):
                match = pattern.fullmatch(assertion)
                if match is None or match.group(1) in parsed:
                    return fail("SMT_ASSERTION_INVALID", vector_id)
                parsed[match.group(1)] = match.group(2) == "true"
            if parsed != vector.get("reviewed_assignments"):
                return fail("SMT_SEMANTIC_DRIFT", vector_id)
        else:
            return fail("VECTOR_KIND_UNSUPPORTED", vector_id)
        passed.append(vector_id)
    if not passed:
        return fail("VECTOR_CORPUS_EMPTY")
    print(json.dumps({"status": "INDEPENDENT_ORACLE_PASSED",
                      "vectors_passed": passed, "vector_count": len(passed)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
