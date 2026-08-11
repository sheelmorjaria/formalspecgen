# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Validate a JML stub with `openjml -check`. Shared by the server (/validate, /refine),
the refine flow, and the eval harness.

ok requires exit 0 AND a real class — `openjml -check` returns 0 on an empty file, which
must never count as a pass (the false-VERIFIED trap).
"""
import tempfile
from pathlib import Path

from pipeline import jml_io
from pipeline.verify import verify, classify
from pipeline.parse_check import parse_check


def check_stub(stub: str):
    """Return (ok, errors: list[str])."""
    if not stub.strip() or jml_io.class_name(stub) is None:
        return False, ["no parseable Java class in stub"]
    cname = jml_io.class_name(stub)
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / f"{cname}.java"
        p.write_text(stub, encoding="utf-8")
        code_exit, text = verify(p, mode="check")
    ok = (code_exit == 0 and classify(code_exit) == "VERIFIED")
    errs = [v.detail or v.raw for v in parse_check(text)] if not ok else []
    return ok, errs
