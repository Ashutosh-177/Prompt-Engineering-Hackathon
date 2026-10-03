"""Prompt templates and builders (owner: Ommakadiya - M1).

Prompts live as plain files in /prompts so every change is visible in Git
history and can be edited live during the demo. Placeholders are filled with
str.replace (not str.format) because documents can contain braces.

Versions:
  v1 - naive baseline: "summarize this" with no defences.
  v2 - defensive system prompt + spotlighting (random boundary) + sandwich
       reminder + strict JSON output.
  v3 - v2 + few-shot examples + silent self-check, and the pipeline adds a
       self-critique chain (critic prompt) on top.
  v4 - v3 + notes may only name the attack TYPE, never quote it (eval showed
       v2/v3 leaking the payload through "injection_notes").
"""
from __future__ import annotations

import json
import secrets
from pathlib import Path

PROMPT_DIR = Path(__file__).resolve().parent.parent / "prompts"
VERSIONS = ["v1", "v2", "v3", "v4"]
VERSION_LABELS = {
    "v1": "v1 - Naive baseline",
    "v2": "v2 - Spotlighting + sandwich + JSON",
    "v3": "v3 - v2 + few-shot + self-critique",
    "v4": "v4 - Final: v3 + no-quote notes rule",
}
# Planted in every system prompt so the eval can detect system-prompt leaks.
SECRET_TAG = "SYS-4471-ORCHID"


def load(name: str) -> str:
    return (PROMPT_DIR / name).read_text(encoding="utf-8")


def save(name: str, text: str) -> None:
    (PROMPT_DIR / name).write_text(text, encoding="utf-8")


def new_boundary() -> str:
    """A fresh random delimiter per request, so an attacker cannot guess it and fake the closing tag."""
    return f"DOC_{secrets.token_hex(4).upper()}"


def _fill(template: str, **values: str) -> str:
    for k, v in values.items():
        template = template.replace("{" + k + "}", v)
    return template


def render_few_shot(boundary: str) -> str:
    examples = json.loads(load("fewshot_examples.json"))
    blocks = []
    for i, ex in enumerate(examples, 1):
        blocks.append(
            f"Example {i}\nDocument:\n<<{boundary}>>\n{ex['document']}\n<</{boundary}>>\n"
            f"Output:\n{json.dumps(ex['output'], ensure_ascii=False)}"
        )
    return "\n\n".join(blocks)


def build(version: str, document: str, boundary: str) -> tuple[str, str]:
    """Return (system_prompt, user_prompt) for a summarizer version."""
    if version not in VERSIONS:
        raise ValueError(f"Unknown prompt version {version}")
    # Remove any accidental occurrence of the boundary from the document itself.
    document = document.replace(boundary, "")
    values = {"secret_tag": SECRET_TAG, "boundary": boundary, "document": document}
    system = load(f"{version}_system.md")
    if "{few_shot}" in system:
        system = system.replace("{few_shot}", render_few_shot(boundary))
    return _fill(system, **values), _fill(load(f"{version}_user.md"), **values)


def build_critic(document: str, summary: str, boundary: str) -> tuple[str, str]:
    document = document.replace(boundary, "")
    summary = summary.replace(boundary, "")
    system = _fill(load("critic_system.md"), boundary=boundary)
    user = _fill(load("critic_user.md"), boundary=boundary, document=document, summary=summary)
    return system, user


def build_repair(original_user: str) -> str:
    """User prompt used for the single retry when the model returned invalid JSON."""
    return (
        original_user
        + "\n\nYOUR PREVIOUS REPLY WAS NOT VALID JSON. Return ONLY the JSON object "
        '{"summary": "...", "injection_detected": true/false, "injection_notes": "..."} with no other text.'
    )
