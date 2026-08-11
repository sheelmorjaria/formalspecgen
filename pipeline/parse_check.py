# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Parse OpenJML `-check`/`-parse` output into VC-like rows.

The primary validator for this project is `openjml -check` (grammar + types + JML
well-formedness + scope). Its diagnostics are compiler-style, e.g.:

    BankAccount.java:7: error: cannot find symbol ...
    BankAccount.java:12: warning: ...

This complements parse_vcs.py (which handles the `-esc` `verify:` format). The output
rows feed both the UI and the repair-loop stall fingerprinting (strategy.vc_fingerprint).
Best-effort: if `-check` emits a format we don't recognize, the orchestrator falls back
to a raw-text fingerprint so stall detection still works.
"""
import re
from .schemas import VC

# file:line: error|warning: message
_CHK = re.compile(
    r'^(?P<file>.+):(?P<line>\d+): (?P<cat>error|warning): (?P<detail>.*)$'
)


def parse_check(text: str):
    seen, out = set(), []
    for ln in text.splitlines():
        m = _CHK.match(ln.rstrip())
        if not m:
            continue
        key = (m["file"], m["line"], m["cat"], m["detail"])
        if key in seen:
            continue
        seen.add(key)
        out.append(VC(file=m["file"], line=int(m["line"]), category=m["cat"],
                      detail=m["detail"], raw=ln.rstrip()))
    return out
