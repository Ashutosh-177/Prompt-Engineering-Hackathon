"""Layer 1 - input gate, injection scanner and sanitizer (owner: Ashutosh - M3).

Runs in plain Python BEFORE the model sees anything:
  * check_document(): off-topic / empty / non-document input is rejected by the app.
  * scan(): flags injection patterns, decodes base64 blobs and scans them too,
    strips invisible zero-width characters and hidden HTML comments.
The scanner never blocks a document on its own (a security article that quotes
"ignore previous instructions" is legitimate); its findings are passed to the
validator and shown in the defence trace.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

MIN_WORDS = 25
MAX_CHARS = 20000

ZERO_WIDTH = re.compile("[​‌‍‎‏⁠⁡⁢⁣﻿­]")
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")

# (category, severity 1-3, regex). Kept readable so any member can extend it.
PATTERNS: list[tuple[str, int, re.Pattern]] = [
    ("instruction_override", 3, re.compile(
        r"\b(ignore|disregard|forget|override|bypass|skip)\b[\w\s,'-]{0,40}?\b(previous|prior|above|earlier|all|your|the|any)\b[\w\s'-]{0,30}?\b(instructions?|rules|prompts?|directions|task|guidelines)\b", re.I)),
    ("new_instructions", 2, re.compile(
        r"\b(new|updated|real|actual|revised)\s+(instructions?|task|rules|policy|objective)\b|\btask is cancelled\b|\binstead (reply|respond|write|output|print)\b", re.I)),
    ("addressed_to_ai", 2, re.compile(
        r"\b(note|message|attention|instruction|hey)\s+(to\s+)?(the\s+)?(ai|llm|assistant|summari[sz]er|model|chatbot)\b|\bif you are an? (ai|llm|language model|assistant|model|summari[sz]er)\b|\bto the (ai|assistant|model)\b|\b(ai|summari[sz]er) instruction\b|\battention (ai|assistant)\b", re.I)),
    ("role_play", 2, re.compile(
        r"\byou are (now|no longer)\b|\bfrom now on,? you\b|\bact as\b|\bpretend (to be|you are)\b|\bdeveloper mode\b|\bjailbreak|\bno (rules|restrictions|filters)\b", re.I)),
    ("fake_system_or_delimiter", 3, re.compile(
        r"(^|\n)\s*(\[?system\]?\s*:|#+\s*system|<\|?/?(system|im_start|im_end|end)\|?>|</?(document|doc|context|data|instructions?)>|system override)", re.I)),
    ("prompt_leak", 3, re.compile(
        r"\b(reveal|print|repeat|show|output|display|disclose|leak)\b[\w\s,'-]{0,40}?\b(system prompt|instructions|hidden prompt|initial prompt|configuration|deployment tag|rules)\b", re.I)),
    ("output_hijack", 2, re.compile(
        r"\b(respond|reply|answer|output|say|print)\b[\w\s,'-]{0,25}?\b(only|exactly|just|nothing else|entire answer)\b|\bdo not (write|produce) (a|the) summary\b", re.I)),
    ("link_or_contact_injection", 2, re.compile(
        r"\b(include|add|append|insert|end your summary with|tell the reader)\b[^.]{0,80}?(https?://|www\.|\blink\b|\burl\b|\bcall\b|\bverify\b)", re.I)),
    ("output_field_tampering", 2, re.compile(
        r"\b(set|mark|make)\s+(the\s+)?\"?injection_detected\"?\b|\bpre-?approved\b|\bverified safe\b", re.I)),
    ("payload_splitting", 2, re.compile(
        r"\blet\s+\w+\s*=\s*['\"].+?['\"]|\b(carry out|execute|run|follow)\b[^.]{0,30}\b\w+\s*\+\s*\w+", re.I)),
    ("fake_dialogue", 2, re.compile(r"(^|\n)\s*(user|human)\s*:.*\n\s*(assistant|ai|bot)\s*:", re.I)),
    ("encoded_instruction", 2, re.compile(r"\b(decode|base64|rot13)\b[^.]{0,40}\b(execute|follow|run|instruction|obey)\b", re.I)),
    ("non_english_override", 3, re.compile(
        r"\b(ignora|ignorez|ignoriere|ignorar)\b|\binstrucciones anteriores\b|\binstructions précédentes\b|पिछले निर्देश|निर्देशों को अनदेखा", re.I)),
]


@dataclass
class Finding:
    category: str
    severity: int
    evidence: str


@dataclass
class ScanResult:
    sanitized: str
    findings: list[Finding] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    flagged_sentences: list[str] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        return sum(f.severity for f in self.findings)

    @property
    def risk_level(self) -> str:
        s = self.risk_score
        return "high" if s >= 5 else "medium" if s >= 2 else "low"

    @property
    def categories(self) -> list[str]:
        return sorted({f.category for f in self.findings})


def check_document(text: str) -> tuple[bool, str]:
    """Off-topic gate: the app only summarizes documents, not chat requests."""
    stripped = (text or "").strip()
    if not stripped:
        return False, "Input is empty. Paste or upload a document to summarize."
    words = len(stripped.split())
    if words < MIN_WORDS:
        return False, (f"Input has only {words} words. This tool summarizes documents "
                       f"(at least {MIN_WORDS} words); it does not answer questions or perform other tasks.")
    return True, ""


SENTENCE_END = re.compile(r"[.!?](?=\s|$)|\n")


def _sentence_around(text: str, start: int, end: int) -> str:
    """Expand a match to its full sentence (dots inside URLs/numbers do not end a sentence)."""
    left = 0
    for m in SENTENCE_END.finditer(text, 0, start):
        left = m.end()
    m = SENTENCE_END.search(text, end)
    right = m.end() if m else len(text)
    return text[left:right].strip()


def _scan_patterns(text: str, prefix: str = "") -> tuple[list[Finding], list[str]]:
    findings, sentences = [], []
    for category, severity, rx in PATTERNS:
        for m in rx.finditer(text):
            sent = _sentence_around(text, m.start(), m.end())
            findings.append(Finding(category, severity, prefix + m.group(0).strip()[:120]))
            if sent and sent not in sentences:
                sentences.append(sent)
    return findings, sentences


def _try_b64(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        txt = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in txt) / max(len(txt), 1)
    return txt if printable > 0.95 and len(txt.split()) >= 3 else None


def scan(text: str) -> ScanResult:
    actions: list[str] = []
    extra_findings: list[Finding] = []
    clean = text

    if len(clean) > MAX_CHARS:
        clean = clean[:MAX_CHARS]
        actions.append(f"Truncated document to {MAX_CHARS} characters")

    zw = ZERO_WIDTH.findall(clean)
    if zw:
        clean = ZERO_WIDTH.sub("", clean)
        actions.append(f"Removed {len(zw)} invisible zero-width characters")
        extra_findings.append(Finding("hidden_characters", 1, f"{len(zw)} zero-width characters"))

    hidden: list[str] = []

    def _drop_comment(m: re.Match) -> str:
        hidden.append(m.group(1).strip())
        return "[hidden HTML comment removed by scanner]"

    clean = HTML_COMMENT.sub(_drop_comment, clean)
    if hidden:
        actions.append(f"Removed {len(hidden)} hidden HTML comment(s)")
        for h in hidden:
            extra_findings.append(Finding("hidden_html_comment", 2, h[:120]))

    decoded: list[str] = []

    def _drop_b64(m: re.Match) -> str:
        txt = _try_b64(m.group(0))
        if txt is None:
            return m.group(0)
        decoded.append(txt)
        return "[encoded text removed by scanner]"

    clean = BASE64_BLOB.sub(_drop_b64, clean)
    if decoded:
        actions.append(f"Decoded and removed {len(decoded)} base64 blob(s)")

    findings, sentences = _scan_patterns(clean)
    # Hidden and decoded content is scanned too, so its instructions are reported.
    for h in hidden:
        f, s = _scan_patterns(h, "[hidden] ")
        findings += f
        sentences += [x for x in s if x not in sentences]
    for d in decoded:
        extra_findings.append(Finding("encoded_payload", 2, f"base64 -> {d[:100]}"))
        f, s = _scan_patterns(d, "[decoded] ")
        findings += f
        sentences += [x for x in s if x not in sentences]

    return ScanResult(sanitized=clean, findings=extra_findings + findings, actions=actions, flagged_sentences=sentences)
