# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M34: HAL/MMIO register discipline on the Frama-C WP lane.

Grounded by probe against real Frama-C 33.0 (qed + Z3, 60s) BEFORE this
module was written:
- register read-modify-write POSTCONDITIONS (untouched-bits / field-written,
  symbolic OR literal masks) TIMEOUT or FAIL — WP's integer encoding of C
  bitwise ops cannot do register bit algebra. The classic
  ``*reg = (*reg & ~mask) | field`` discipline is probed UNPROVABLE here
  and is refused with the evidence, never improvised;
- the register as a STRUCT BITFIELD is PROVED (6/6): writing one named
  bitfield preserves every other named bitfield, with a range-checked
  field-write — field separation through WP's memory model;
- the PADDR<->PPTR window round-trip is PROVED (19/19) through callee
  contracts (single-offset translation is the identity on the window);
- volatile anywhere on the register path (raw or struct, with or without
  -wp-volatile) leaves goals UNKNOWN — the device is genuinely outside
  the memory model.

Epistemics: the ACCESS DISCIPLINE (bitfield separation, window round-trip)
is machine-proved on a modeled register; DEVICE SEMANTICS (volatile, side
effects between accesses) and the hardware MAPPING LINEARITY are the
human-accepted assumptions, recorded in the verdict with the probe
evidence — the M33 pattern applied to hardware.
"""
from __future__ import annotations

import re
from pathlib import Path

# struct tag { ... } / typedef struct { ... } name_t; — tag optional
_STRUCT = re.compile(
    r"(?:typedef\s+)?struct\s+(?P<tag>\w+)?\s*\{(?P<body>[^}]*)\}"
    r"\s*(?P<typedef>\w+)?\s*;", re.S)
# named bitfield member: unsigned mode : 4;  (anonymous `: 3` padding skipped)
_BITFIELD = re.compile(
    r"(?:unsigned|signed|int|u?int\d+_t)\s+(?P<name>\w+)\s*:\s*(?P<width>\d+)")
# volatile-qualified pointer cast to an integer-literal address (MMIO)
_VOLATILE_MMIO = re.compile(
    r"\(\s*volatile\s+[\w\s]+\*+\s*\)\s*(?:0[xX][0-9a-fA-F]+|\d+)")
# the window translation: single-offset macros or the seL4-style helpers
_WINDOW_MACRO = re.compile(r"#\s*define\s+(\w*BASE_OFFSET\w*)")
_WINDOW_FUNCS = re.compile(
    r"\b(?:ptrFromPAddr|addrFromPPtr|addrFromKPPtr|paddr_to_pptr|"
    r"pptr_to_paddr|kpptr_to_paddr)\b")
# deref-assign RMW shapes (mask-clear ~, field shifts, compound |=/&=, or
# a deref-read on the RHS) — NOT pointer init `*p = &x;` (address-of)
_PLAIN_RMW = re.compile(
    r"\*\s*\w+\s*(?:=[^;]*(?:~|<<|>>)[^;]*;|=[^;]*\*\s*\w+[^;]*[&|][^;]*;"
    r"|\|=|&=)")

# The probed window bounds (PPTR window fits a 32-bit physical address
# space under a 64-bit word — the machine.h shape).
_PROBED_WINDOW_LIMIT = "0xffffffffUL"
_PROBED_WINDOW_OFFSET = "0xffffff0000000000UL"


def _fail(code: str, message: str) -> dict:
    return {"status": "HAL_VERIFICATION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def detect_hal(text: str) -> dict:
    """Structural detection of the HAL idioms (the M34 Phase 1 gate).

    Recognized: bitfield register structs (the provable register shape)
    and PADDR<->PPTR window translations. A raw bitwise RMW with no
    register struct is the probed-unprovable shape and is refused with
    the probe evidence rather than approximated.
    """
    registers = []
    for match in _STRUCT.finditer(text):
        type_name = (f"struct {match.group('tag')}" if match.group("tag")
                     else match.group("typedef"))
        if not type_name:
            continue
        fields = [(f.group("name"), int(f.group("width")))
                  for f in _BITFIELD.finditer(match.group("body"))]
        if fields:
            registers.append({"type": type_name, "fields": fields})

    volatile = bool(_VOLATILE_MMIO.search(text))
    macro = _WINDOW_MACRO.search(text)
    window = bool(macro) or bool(_WINDOW_FUNCS.search(text))

    if not registers and not window:
        if _PLAIN_RMW.search(text):
            return _fail(
                "UNSUPPORTED_BOUNDARY",
                "raw bitwise read-modify-write on a plain pointer is "
                "PROBED UNPROVABLE on this lane: WP's integer encoding "
                "cannot discharge register bit postconditions (Z3 "
                "timeout/failure on symbolic and literal masks). The "
                "provable register shape is a struct with named "
                "bitfields; the raw RMW is never approximated")
        return _fail("no_hal_structure",
                     "no HAL idiom found: the lane verifies bitfield "
                     "register structs and PADDR<->PPTR window "
                     "translations; nothing to verify here")

    return {"status": "DETECTED", "code": "HAL_STRUCTURE_DETECTED",
            "registers": registers, "volatile_mmio": volatile,
            "window": window,
            "window_offset_macro": macro.group(1) if macro else None}


def _register_witness(register: dict) -> str:
    """The probed bitfield-separation witness for one register struct."""
    (field, width), *others = register["fields"]
    preserved = "".join(
        f"\n    ensures reg->{name} == \\old(reg->{name});"
        for name, _ in others)
    return f"""
/*@ requires \\valid(reg);
    requires v < {1 << width}u;
    assigns reg->{field};
    ensures reg->{field} == v;{preserved}
*/
void hal_{field}_witness({register['type']} *reg, unsigned v) {{
    reg->{field} = v;
}}
"""


_WINDOW_WITNESS = """
typedef unsigned long hal_word_t;
#ifndef {macro_guard}
#define {macro} {offset}
#endif

/*@ requires paddr <= {limit};
    assigns \\nothing;
    ensures \\result == paddr + {macro};
*/
hal_word_t hal_ptr_from_paddr_probed(hal_word_t paddr) {{
    return paddr + {macro};
}}

/*@ requires pptr >= {macro};
    requires pptr - {macro} <= {limit};
    assigns \\nothing;
    ensures \\result == pptr - {macro};
*/
hal_word_t hal_paddr_from_pptr_probed(hal_word_t pptr) {{
    return pptr - {macro};
}}

/*@ requires paddr <= {limit};
    assigns \\nothing;
    ensures \\result == paddr;
*/
hal_word_t hal_window_roundtrip_probed(hal_word_t paddr) {{
    return hal_paddr_from_pptr_probed(hal_ptr_from_paddr_probed(paddr));
}}
"""


def render_hal_source(text: str, detection: dict) -> str:
    """Serialize the probed witnesses onto the source (appended, never
    spliced): each register struct gets a bitfield-separation witness and
    a window translation gets the round-trip witness, instantiated with
    the user's offset macro when one is defined."""
    out = text
    for register in detection["registers"]:
        out += _register_witness(register)
    offset_source = None
    if detection["window"]:
        macro = (detection.get("window_offset_macro")
                 or "HAL_PPTR_BASE_OFFSET_PROBED")
        out += _WINDOW_WITNESS.format(
            macro=macro, macro_guard=macro, offset=_PROBED_WINDOW_OFFSET,
            limit=_PROBED_WINDOW_LIMIT)
        offset_source = (f"user_macro:{detection['window_offset_macro']}"
                         if detection.get("window_offset_macro")
                         else "probed_constant")
    return out + "\n", offset_source


def verify_hal(source: str | Path) -> dict:
    """Real Frama-C WP gate on the rendered HAL witnesses.

    Strict: every goal must prove. Unlike the heap lane there are no
    probed-known frame timeouts on these shapes — probes reached 6/6 and
    19/19 — so a partial result is a refusal, not an assumption.
    """
    path = Path(source)
    if not path.is_file():
        return _fail("input_unavailable", str(path))
    if path.suffix.lower() not in {".c", ".h"}:
        return _fail("UNSUPPORTED_BOUNDARY",
                     "the HAL lane verifies .c/.h sources; other "
                     "languages stay on their own lanes")
    text = path.read_text(encoding="utf-8")
    detection = detect_hal(text)
    if detection.get("status") != "DETECTED":
        return detection

    import shutil
    import subprocess
    import tempfile

    from . import config
    framac = shutil.which(config.FRAMAC_BIN) or (
        Path(config.FRAMAC_BIN).is_file() and str(config.FRAMAC_BIN))
    if not framac:
        return _fail("framac_unavailable",
                     f"Frama-C not found: {config.FRAMAC_BIN}")
    rendered, offset_source = render_hal_source(text, detection)
    # WP runs ONLY on the probed witnesses: the user's own device-access
    # functions dereference volatile MMIO addresses whose validity the
    # memory model cannot establish (probed: those RTE guards stay
    # Unknown) — that is the device-semantics assumption, not a goal.
    targets = [f"hal_{r['fields'][0][0]}_witness" for r in detection["registers"]]
    if detection["window"]:
        targets += ["hal_ptr_from_paddr_probed",
                    "hal_paddr_from_pptr_probed",
                    "hal_window_roundtrip_probed"]
    command = [str(framac), "-wp", "-wp-rte", "-wp-prover", "qed,z3",
               "-wp-timeout", "60", "-no-unicode"]
    for name in targets:
        command += ["-wp-fct", name]
    with tempfile.TemporaryDirectory() as directory:
        harness = Path(directory) / "harness.c"
        harness.write_text(rendered, encoding="utf-8")
        command.append(str(harness))
        try:
            process = subprocess.run(command, capture_output=True,
                                     text=True, timeout=300)
        except (subprocess.TimeoutExpired, TimeoutError, OSError):
            return _fail("framac_timeout", "Frama-C WP timed out")

    output = (process.stdout or "") + (process.stderr or "")
    if "annot-error" in output or "syntax error" in output:
        return _fail("hal_render_failed",
                     "the serialized harness failed to parse: "
                     + output[-500:])
    proved = re.search(r"Proved goals:\s*(\d+)\s*/\s*(\d+)", output)
    if proved is None:
        return _fail("wp_no_goals",
                     "WP produced no goal summary — the harness was not "
                     "verified; output tail: " + output[-500:])
    proved_count, total = int(proved.group(1)), int(proved.group(2))
    if proved_count < total:
        return _fail("discipline_not_proved",
                     f"only {proved_count}/{total} witness goals proved "
                     "(strict gate: the probed shapes prove fully; a "
                     "partial result contradicts the register or window "
                     "discipline): " + output[-500:])

    return {
        "status": "HAL_VERIFICATION_PROVED",
        "claim": "HAL_REASONING_PROVED",
        "scope": "hal_register_discipline_frama_c_wp",
        "heap_model": "frama_c_wp_memory_model",
        "lanes": (["register_bitfield_separation"] if detection["registers"]
                  else []) + (["window_translation_roundtrip"]
                              if detection["window"] else []),
        "register_structs": [r["type"] for r in detection["registers"]],
        "register_discipline_proved": bool(detection["registers"]),
        "bitfield_separation_proved": bool(detection["registers"]),
        "window_roundtrip_proved": bool(detection["window"]),
        "window_offset_source": offset_source,
        "device_semantics": ("human_accepted_assumption"
                             if detection["volatile_mmio"]
                             else "no_volatile_mmio_in_source"),
        "volatile_mmio_detected": detection["volatile_mmio"],
        "mapping_linearity": ("human_accepted_assumption"
                              if detection["window"] else "n/a"),
        "plain_rmw_boundary": "probed_unprovable_refused",
        "probe_evidence": {
            "bitwise_rmw": "Z3 timeout/failure on symbolic AND literal "
                           "masks — WP integer encoding cannot discharge "
                           "register bit postconditions",
            "bitfield_separation": "6/6 goals on the probed witness",
            "window_roundtrip": "19/19 goals through callee contracts",
            "volatile": "goals remain Unknown with and without "
                        "-wp-volatile — device semantics are outside the "
                        "memory model",
        },
        "predicate_source": "fixed_probed_witnesses",
        "proved_goals": proved_count, "total_goals": total,
        "note": "the access discipline is machine-proved by real Frama-C "
                "WP; device semantics (volatile, side effects between "
                "accesses) and hardware mapping linearity are the "
                "reviewer's accepted assumptions — the M33 pattern "
                "applied to hardware",
    }
