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
