"""Layer 4 - output validation in code (owner: Ashutosh - M3).

The model's reply is never trusted as-is:
  * parse_json()     - tolerant JSON extraction (handles ``` fences / extra text).
  * normalize()      - schema check: summary (non-empty str), injection_detected (bool), injection_notes (str).
  * is_refusal()     - detects "I can't help with that" style refusals.
  * post_check()     - hard fixes (redact system-prompt leaks, strip links taken from
                       injected sentences) and soft flags (summary echoes injected text,
                       summary suspiciously short) that the self-critique layer reviews.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .prompts import SECRET_TAG

REFUSAL = re.compile(
    r"^\s*(i'?m sorry|i am sorry|sorry,|i can(no|')t|i cannot|i won'?t|i am unable|i'm unable|as an ai|i must decline|i'm not able)",
    re.I,
)
URL = re.compile(r"(https?://\S+|www\.\S+|\b[\w-]+\.(?:example|com|net|org|io|xyz|in)(?:/\S*)?)", re.I)
SENT_SPLIT = re.compile(r"(?<=[.!?])\s+")
MIN_SUMMARY_WORDS = 12
CODE_TOKEN = re.compile(r"\b[A-Z][A-Z0-9]*(?:[-_][A-Z0-9]+)*[-_][A-Z0-9]*\d[A-Z0-9]*\b")
QUOTED = re.compile(r"['\"‘“][^'\"’”]{4,}['\"’”]")
GENERIC_NOTES = "The document contained embedded instructions aimed at the AI; they were ignored and are not repeated here."


@dataclass
class Issue:
    level: str  # "hard" (auto-fixed in code) or "soft" (sent to the critic / shown to user)
    message: str


def parse_json(raw: str) -> dict | None:
    if not raw:
        return None
    text = raw.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.I)
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            obj = json.loads(text[start:end + 1])
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None
    return None


def normalize(obj: dict) -> tuple[dict | None, str]:
    """Return (clean_obj, error). clean_obj is None when the schema is not satisfied."""
    summary = obj.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return None, "missing or empty 'summary'"
    detected = obj.get("injection_detected", False)
    if isinstance(detected, str):
        detected = detected.strip().lower() in ("true", "yes", "1")
    notes = obj.get("injection_notes", "")
    if not isinstance(notes, str):
        notes = json.dumps(notes)
    return {"summary": summary.strip(), "injection_detected": bool(detected), "injection_notes": notes.strip()}, ""


def is_refusal(text: str) -> bool:
    return bool(text) and bool(REFUSAL.search(text))


def _shingles(text: str, n: int = 5) -> set[str]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return {" ".join(words[i:i + n]) for i in range(len(words) - n + 1)}


def _strip_secret(text: str) -> tuple[str, bool]:
    if SECRET_TAG.lower() not in text.lower():
        return text, False
    kept = [s for s in SENT_SPLIT.split(text) if SECRET_TAG.lower() not in s.lower()]
    return " ".join(kept).strip(), True


def post_check(summary: str, notes: str, flagged_sentences: list[str]) -> tuple[str, str, list[Issue]]:
    """Apply code-level output guardrails. Returns (summary, notes, issues)."""
    issues: list[Issue] = []

    summary, leaked = _strip_secret(summary)
    notes, leaked_n = _strip_secret(notes)
    if leaked or leaked_n:
        issues.append(Issue("hard", "Output contained the confidential system tag - sentence redacted"))

    # Code-like tokens (e.g. TOKEN-ZW-808) that come from injected sentences must never reach the user.
    for code in {c for s in flagged_sentences for c in CODE_TOKEN.findall(s)}:
        if code.lower() in summary.lower():
            summary = " ".join(s for s in SENT_SPLIT.split(summary) if code.lower() not in s.lower()).strip()
            issues.append(Issue("hard", "Removed a summary sentence containing a code token from an injected instruction"))
        if code.lower() in notes.lower():
            notes = GENERIC_NOTES
            issues.append(Issue("hard", "Injection notes contained a code token from the injection - replaced"))

    injected_text = " ".join(flagged_sentences).lower()
    for url in set(URL.findall(summary)):
        domain = re.sub(r"^(https?://)?(www\.)?", "", url.lower()).split("/")[0].rstrip(".,)'\"")
        if domain and domain in injected_text:
            summary = summary.replace(url, "[link removed]")
            issues.append(Issue("hard", f"Removed link that came from an injected instruction: {url}"))
    for url in set(URL.findall(notes)):
        notes = notes.replace(url, "[link removed]")

    # Notes are shown to the user, so they must never carry the attacker's words (eval run 1 failure).
    quoted = QUOTED.search(notes)
    echoed_notes = flagged_sentences and _shingles(notes, 3) & _shingles(" ".join(flagged_sentences), 3)
    if notes and (quoted or echoed_notes):
        notes = GENERIC_NOTES
        issues.append(Issue("hard", "Injection notes quoted the injected text - replaced with a generic description"))

    if flagged_sentences:
        inj = _shingles(" ".join(flagged_sentences))
        echoed = [s for s in SENT_SPLIT.split(summary) if _shingles(s) & inj]
        if echoed:
            issues.append(Issue("soft", f"{len(echoed)} summary sentence(s) reuse wording from flagged injection text"))

    if len(summary.split()) < MIN_SUMMARY_WORDS:
        issues.append(Issue("soft", f"Summary is only {len(summary.split())} words - possible output hijack"))

    return summary, notes, issues
