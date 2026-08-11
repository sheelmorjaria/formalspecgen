# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Interactive NL -> validated domain specification -> deterministic YAML.

The model asks questions and proposes JSON.  Pydantic owns acceptance and PyYAML owns
serialization; model text is never treated as YAML or executable plugin code.
"""
from __future__ import annotations

import json
from typing import Any, Callable

import yaml
from pydantic import ValidationError

from .elicit import _extract_json, normalize_questions
from .llm import LLMError
from .scaffold_domain import DomainSpec


DOMAIN_QUESTIONS_SYSTEM = """You are eliciting a bounded domain model for deterministic TLA+ plugin scaffolding.
Do not write YAML, code, TLA+, or a domain specification yet. Ask only questions needed
to determine: state variables and small integer bounds, atomic operations, guards,
effects, permitted frames, and named safety invariants.

Return JSON only:
{"questions":[{"id":"q1","category":"state|bounds|operation|guard|effect|frame|invariant|abstraction|other","question":"...","required":true}]}

Use at most 8 concise questions. Do not ask for facts already present in the idea.
"""

DOMAIN_SPEC_SYSTEM = """Propose a bounded domain-plugin declaration from the idea and authoritative human answers.
Return JSON only, with exactly this schema:
{"domain_name":"PascalCase","module_name":"snake_case","state_variables":[{"name":"snake_case","type":"int|dict","bound":[0,4]}],"operations":[{"name":"identifier","guards":["snake_case"],"effect":"snake_case","frame":["declared_state_name"],"ast_pattern":"documented JML post-state pattern"}],"tlc_invariants":["PascalCaseName"]}

Rules: use small finite bounds (upper bound at most 100); every operation has a nonempty
frame containing only declared state variables; identifiers are unique; do not invent
answers that conflict with the human; do not emit YAML, Markdown, TLA+, or Python.
The ast_pattern is documentation for a human-reviewed AST adapter, never executable text.
"""

_DOMAIN_CATEGORIES = {"state", "bounds", "operation", "guard", "effect", "frame",
                      "invariant", "abstraction", "other"}


def elicit_domain_questions(idea: str, chat_fn: Callable, model: str | None = None):
    if not idea.strip():
        raise ValueError("domain idea is required")
    content, used, usage = chat_fn(
        [{"role": "system", "content": DOMAIN_QUESTIONS_SYSTEM},
         {"role": "user", "content": "Domain idea:\n" + idea.strip()}], model, 0.0)
    questions = normalize_questions(_extract_json(content), _DOMAIN_CATEGORIES)
    return questions, used, usage


def compile_domain_spec(idea: str, questions: list[dict[str, Any]],
                        answers: list[dict[str, Any]], chat_fn: Callable,
                        model: str | None = None) -> tuple[DomainSpec, str, str, dict]:
    normalized = normalize_questions(questions, _DOMAIN_CATEGORIES)
    answer_map = {str(item.get("id", "")): str(item.get("answer", "")).strip()
                  for item in answers if isinstance(item, dict)}
    missing = [item["question"] for item in normalized
               if item["required"] and not answer_map.get(item["id"])]
    if missing:
        raise ValueError("required domain clarification unanswered: " + "; ".join(missing))
    context = ["Domain idea:", idea.strip(), "", "Human clarifications (authoritative):"]
    for item in normalized:
        if answer_map.get(item["id"]):
            context.extend([f"- Q: {item['question']}", f"  A: {answer_map[item['id']]}"])
    content, used, usage = chat_fn(
        [{"role": "system", "content": DOMAIN_SPEC_SYSTEM},
         {"role": "user", "content": "\n".join(context)}], model, 0.0)
    value = _extract_json(content)
    try:
        spec = DomainSpec.model_validate(value)
    except ValidationError as exc:
        raise LLMError("INVALID_DOMAIN_SPEC", str(exc)) from exc
    yaml_text = yaml.safe_dump(spec.model_dump(mode="json"), sort_keys=False,
                               allow_unicode=True, default_flow_style=False)
    return spec, yaml_text, used, usage
