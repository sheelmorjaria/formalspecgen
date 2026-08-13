# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Interactive requirement elicitation before formal-contract drafting.

The model is used only to identify proof-relevant ambiguity.  This module validates and
normalizes its JSON so malformed or overly broad questions never become trusted input.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Iterable

from .llm import LLMError

MAX_QUESTIONS = 8
MAX_QUESTION_LENGTH = 500

ELICIT_SYSTEM = """You are a rigorous requirements analyst for formal verification.
Do not draft code or contracts. Identify only unresolved facts that materially change a
formal specification: numeric bounds and overflow behavior, invalid-input behavior,
failure/exception semantics, mutability and frame conditions, null/empty cases,
concurrency/atomicity, ordering, and environmental assumptions.

Return JSON only, with this exact shape:
{"questions":[{"id":"q1","category":"bounds|failure|state|frame|nullability|concurrency|ordering|environment|type|other","question":"...","required":true}]}

Use at most 8 concise, non-duplicative questions. Do not ask for facts already stated in
the requirement. Set required=true only when no sound contract can be drafted without the
answer. If the requirement is sufficiently precise, return {"questions":[]}.
"""

_CATEGORIES = {"bounds", "failure", "state", "frame", "nullability", "concurrency",
               "ordering", "environment", "type", "other"}

QUESTION_JSON_REPAIR_SYSTEM = """Repair the rejected requirements-elicitation response.
Return exactly one JSON object with a questions array and no prose, Markdown, or code fences:
{"questions":[{"id":"q1","category":"other","question":"...","required":true}]}
Use an empty questions array when nothing needs clarification. Preserve the original request;
do not draft a specification or implementation."""


def _extract_json(text: str) -> Any:
    """Extract exactly one JSON value while tolerating a fence or surrounding prose."""
    value = text.strip()
    fenced = re.findall(r"```(?:json)?\s*(.*?)```", value, re.DOTALL | re.IGNORECASE)
    if len(fenced) > 1:
        raise LLMError("INVALID_ELICITATION_JSON",
                       "ambiguity analysis returned multiple JSON fences")
    if fenced:
        value = fenced[0].strip()
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        decoder = json.JSONDecoder()
        opening = re.search(r"[\[{]", value)
        if opening:
            try:
                item, end = decoder.raw_decode(value, opening.start())
            except json.JSONDecodeError:
                item = None
            if item is not None:
                trailing = value[end:]
                for next_opening in re.finditer(r"[\[{]", trailing):
                    try:
                        decoder.raw_decode(trailing, next_opening.start())
                    except json.JSONDecodeError:
                        continue
                    raise LLMError("INVALID_ELICITATION_JSON",
                                   "ambiguity analysis returned multiple JSON values") from exc
                return item
        reason = f"ambiguity analysis did not return valid JSON: {exc.msg}"
        raise LLMError("INVALID_ELICITATION_JSON", reason) from exc


def normalize_questions(value: Any, categories: set[str] | None = None) -> list[dict[str, Any]]:
    """Validate model output and assign stable, unique question identifiers."""
    allowed_categories = categories or _CATEGORIES
    raw = value.get("questions") if isinstance(value, dict) else value
    if not isinstance(raw, list):
        raise LLMError("INVALID_ELICITATION_JSON", "expected a questions array")
    questions: list[dict[str, Any]] = []
    seen_text: set[str] = set()
    used_ids: set[str] = set()
    for index, item in enumerate(raw[:MAX_QUESTIONS], 1):
        if isinstance(item, str):
            item = {"question": item}
        if not isinstance(item, dict):
            continue
        question = str(item.get("question", "")).strip()[:MAX_QUESTION_LENGTH]
        key = re.sub(r"\s+", " ", question).casefold()
        if not question or key in seen_text:
            continue
        seen_text.add(key)
        candidate = re.sub(r"[^a-zA-Z0-9_-]", "", str(item.get("id", ""))) or f"q{index}"
        while candidate in used_ids:
            candidate += "_"
        used_ids.add(candidate)
        category = str(item.get("category", "other")).lower()
        questions.append({"id": candidate,
                          "category": category if category in allowed_categories else "other",
                          "question": question,
                          "required": bool(item.get("required", True))})
    return questions


def request_questions(messages: list[dict[str, str]], chat_fn: Callable,
                      model: str | None = None,
                      categories: set[str] | None = None):
    """Request question JSON with bounded syntax-only repair retries."""
    last_error: LLMError | None = None
    rejected = ""
    for attempt in range(3):
        request_messages = messages
        if attempt:
            request_messages = [
                {"role": "system", "content": QUESTION_JSON_REPAIR_SYSTEM},
                {"role": "user", "content": (
                    "Original request:\n" + messages[-1]["content"] +
                    "\n\nRejected response:\n" + rejected[:4000] +
                    "\n\nReturn the corrected JSON object only.")},
            ]
        content, used, usage = chat_fn(request_messages, model, 0.0)
        rejected = content if isinstance(content, str) else str(content)
        try:
            questions = normalize_questions(_extract_json(rejected), categories)
            if attempt:
                usage = {**usage, "elicitation_json_repair_attempts": attempt}
            return questions, used, usage
        except LLMError as exc:
            last_error = exc
    assert last_error is not None
    raise last_error


def extract_ambiguities(nl_text: str, chat_fn: Callable, model: str | None = None):
    """Return ``(questions, model_used, usage)`` for one natural-language requirement."""
    requirement = nl_text.strip()
    if not requirement:
        raise ValueError("nl_text is required")
    messages = [{"role": "system", "content": ELICIT_SYSTEM},
                {"role": "user", "content": "Requirement:\n" + requirement}]
    return request_questions(messages, chat_fn, model)


def augment_spec(original_nl: str, questions: Iterable[dict[str, Any]],
                 answers: Iterable[dict[str, Any]]) -> str:
    """Build an auditable requirement containing question/answer pairs.

    Unknown answer IDs are ignored; required unanswered questions are rejected so the UI
    cannot accidentally draft while claiming the requirement has been clarified.
    """
    normalized = normalize_questions(list(questions))
    answer_map = {str(item.get("id", "")): str(item.get("answer", "")).strip()
                  for item in answers if isinstance(item, dict)}
    missing = [q["question"] for q in normalized if q["required"] and not answer_map.get(q["id"])]
    if missing:
        raise ValueError("required clarification unanswered: " + "; ".join(missing))
    lines = [original_nl.strip(), "", "Clarifications (human-provided and authoritative):"]
    for question in normalized:
        answer = answer_map.get(question["id"])
        if answer:
            lines.extend([f"- Q: {question['question']}", f"  A: {answer}"])
    return "\n".join(lines).strip()
