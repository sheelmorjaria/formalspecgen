#!/usr/bin/env python3
"""Generate boot/src/boot_order.rs from the PROVEN composition artifact.

The boot order executed by the image is not hand-written: it is
compiled from kernel/composition.json — the same artifact the M46 gate
proved (SYSTEM_COMPOSITION_PROVED). Regenerate with:
    python3 scripts/gen_boot_order.py
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
comp = json.loads((ROOT / "examples/formalkernel/kernel/composition.json")
                  .read_text())
names = [step["name"] for step in comp["steps"]]
facts = {str(f): str(s["name"]) for s in comp["steps"]
         for f in s.get("establishes", [])}
out = ROOT / "examples/formalkernel/boot/src/boot_order.rs"
out.write_text(
    "// GENERATED from examples/formalkernel/kernel/composition.json by\n"
    "// scripts/gen_boot_order.py — do not edit by hand.\n"
    "// The proven (M46) boot order, compiled into the image:\n"
    f"pub const BOOT_ORDER: [&str; {len(names)}] = [\n" +
    "".join(f'    "{name}",\n' for name in names) +
    "];\n"
    f"pub const FACTS: [&str; {len(facts)}] = [\n" +
    "".join(f'    "{fact}",\n' for fact in sorted(facts)) +
    "];\n", encoding="utf-8")
print(f"wrote {out}: {len(names)} steps, {len(facts)} facts")
