# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Small local retrieval index over empirically observed OpenJML limitations."""
import json
import re
from functools import lru_cache
from pathlib import Path

_DB = Path(__file__).with_name("limitations.json")


@lru_cache(maxsize=1)
def entries() -> list[dict]:
    return json.loads(_DB.read_text())


def retrieve(text: str, limit: int = 4) -> list[dict]:
    haystack = text.lower()
    tokens = set(re.findall(r"[a-z0-9_]+", haystack))
    ranked = []
    for entry in entries():
        score = 0
        for keyword in entry["keywords"]:
            needle = keyword.lower()
            if needle in haystack:
                score += 3 if " " in needle or "\\" in needle else 2
            elif needle in tokens:
                score += 1
        if score:
            ranked.append((score, entry))
    ranked.sort(key=lambda item: (-item[0], item[1]["id"]))
    return [entry for _score, entry in ranked[:limit]]


def prompt_guardrails(text: str) -> str:
    relevant = retrieve(text)
    if not relevant:
        return ""
    lines = ["\n\nRETRIEVED TOOLCHAIN GUARDRAILS (empirical; obey these):"]
    lines.extend(f"- [{item['id']}] {item['warning']}" for item in relevant)
    return "\n".join(lines)


def reviewed_domain_guardrails(text: str) -> str:
    """Inject exact reviewed APIs when a requirement selects a known domain."""
    lowered = text.lower()
    if "traffic light" not in lowered and "traffic-light" not in lowered:
        return ""
    return r'''

REVIEWED TRAFFIC-LIGHT DOMAIN CONTRACT (mandatory for architecture compatibility):
- Class: TrafficLightController.
- State fields: `int ns_light` and `int ew_light`, both `/*@ spec_public @*/`.
- Constructor ensures `ns_light == 0 && ew_light == 0`.
- Emit exactly these six public void operations:
  `turnNsGreen`, `turnNsYellow`, `turnNsRed`, `turnEwGreen`, `turnEwYellow`, `turnEwRed`.
- `turnNsGreen` requires `ew_light == 0`, assigns only `ns_light`, ensures `ns_light == 2`.
- `turnNsYellow` requires `ns_light == 2`, assigns only `ns_light`, ensures `ns_light == 1`.
- `turnNsRed` requires `ns_light == 1`, assigns only `ns_light`, ensures `ns_light == 0`.
- Apply the symmetric rules to EW: green requires `ns_light == 0`; yellow requires
  `ew_light == 2`; red requires `ew_light == 1`; each assigns only `ew_light`.
- Do not rename methods or fields, replace the six actions with reset, or weaken `== 0`
  to `!= 2`. Unknown variants cannot enter the reviewed TLA+ refinement adapter.'''
