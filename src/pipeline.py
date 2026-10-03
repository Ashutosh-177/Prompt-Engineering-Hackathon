"""Layered defence pipeline (owner: Ashutosh - M3).

  v1: raw document -> naive prompt -> raw text           (baseline, no defences)
  v2: gate -> L1 scan/sanitize -> L2+L3 defended prompt (spotlighting, sandwich,
      JSON) -> L4 code validation (JSON/schema, refusal, leak + link checks)
  v3: v2 with the few-shot prompt + L5 self-critique chain (second model call
      audits the summary and rewrites it if compromised)
  v4: v3 with the "never quote the injection in notes" prompt rule (final)

`run()` takes an injectable `llm` callable so the whole pipeline can be unit-
tested offline with a fake model.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from . import prompts, scanner, validator
from .llm import LLMBlocked, LLMConfig, LLMError, chat

LLMFn = Callable[..., str]

STATUS_TEXT = {
    "ok": "Summary produced",
    "rejected": "Input rejected (not a document)",
    "refused": "Model refused",
    "invalid_output": "Model output invalid after retry",
    "error": "API / runtime error",
}


@dataclass
class Result:
    version: str
    model: str
    status: str = "ok"
    summary: str = ""
    injection_detected: bool = False
    injection_notes: str = ""
    message: str = ""
    trace: list[dict] = field(default_factory=list)
    scan: scanner.ScanResult | None = None
    issues: list[validator.Issue] = field(default_factory=list)
    critic: dict | None = None
    raw: list[str] = field(default_factory=list)
    calls: int = 0
    latency_s: float = 0.0

    def log(self, layer: str, outcome: str, detail: str = "") -> None:
        self.trace.append({"layer": layer, "outcome": outcome, "detail": detail})

    @property
    def shown_text(self) -> str:
        """Everything the end user would see - used by the evaluator to check for attack markers."""
        return f"{self.summary}\n{self.injection_notes}".strip()


def _call(res: Result, llm: LLMFn, cfg: LLMConfig | None, system: str, user: str, json_mode: bool) -> str:
    res.calls += 1
    out = llm(system, user, cfg=cfg, json_mode=json_mode)
    res.raw.append(out)
    return out


def _summarize_json(res: Result, llm: LLMFn, cfg, system: str, user: str) -> dict | None:
    """Call the model, enforce JSON schema and handle refusals - with one retry each."""
    raw = _call(res, llm, cfg, system, user, json_mode=True)
    for attempt in range(2):
        if validator.is_refusal(raw):
            if attempt == 0:
                res.log("L4 output check", "retry", "Model refused - retrying once")
                raw = _call(res, llm, cfg, system, user, json_mode=True)
                continue
            res.status, res.message = "refused", "The model refused to summarize this document."
            res.log("L4 output check", "refused", raw[:200])
            return None
        obj = validator.parse_json(raw)
        clean, err = validator.normalize(obj) if obj is not None else (None, "not valid JSON")
        if clean and validator.is_refusal(clean["summary"]):
            clean, err = None, "summary field is a refusal"
            if attempt == 0:
                res.log("L4 output check", "retry", "Model refused inside JSON - retrying once")
                raw = _call(res, llm, cfg, system, user, json_mode=True)
                continue
            res.status, res.message = "refused", "The model refused to summarize this document."
            return None
        if clean:
            res.log("L4 output check", "pass", "Valid JSON matching schema")
            return clean
        if attempt == 0:
            res.log("L4 output check", "retry", f"Invalid output ({err}) - sending repair prompt")
            raw = _call(res, llm, cfg, system, prompts.build_repair(user), json_mode=True)
    res.status = "invalid_output"
    res.message = "The model did not return a valid summary after a repair attempt."
    res.log("L4 output check", "fail", res.message)
    return None


def _critique(res: Result, llm: LLMFn, cfg, document: str, boundary: str, flagged: list[str]) -> None:
    """L5 self-critique: a second prompt audits the candidate summary."""
    system, user = prompts.build_critic(document, res.summary, boundary)
    raw = _call(res, llm, cfg, system, user, json_mode=True)
    verdict = validator.parse_json(raw)
    if not verdict or verdict.get("verdict") not in ("clean", "compromised"):
        res.log("L5 self-critique", "skipped", "Critic output invalid - keeping validated summary")
        return
    res.critic = verdict
    if verdict["verdict"] == "clean":
        res.log("L5 self-critique", "pass", "Critic found no injected content")
        return
    revised = (verdict.get("revised_summary") or "").strip()
    problems = "; ".join(map(str, verdict.get("problems", [])))[:300]
    if not revised or validator.is_refusal(revised):
        res.log("L5 self-critique", "flagged", f"Compromised but no usable rewrite: {problems}")
        res.summary = "[Summary withheld: the critic found injected content and could not produce a clean rewrite.]"
        return
    summary, _, issues = validator.post_check(revised, "", flagged)
    res.summary = summary
    res.injection_detected = True
    res.issues += [i for i in issues if i.level == "hard"]
    res.log("L5 self-critique", "rewrote", f"Summary was compromised ({problems}) - replaced with critic's clean rewrite")


def run(document: str, version: str = "v3", cfg: LLMConfig | None = None, llm: LLMFn = chat) -> Result:
    started = time.time()
    try:
        model = cfg.label if cfg else LLMConfig().label
    except LLMError:
        model = "unconfigured"
    res = Result(version=version, model=model)
    try:
        if version == "v1":
            system, user = prompts.build("v1", document, prompts.new_boundary())
            res.summary = _call(res, llm, cfg, system, user, json_mode=False).strip()
            res.log("v1 baseline", "done", "Naive prompt, no defence layers")
            return res

        ok, reason = scanner.check_document(document)
        if not ok:
            res.status, res.message = "rejected", reason
            res.log("Input gate", "rejected", reason)
            return res
        res.log("Input gate", "pass", f"{len(document.split())} words")

        scan = scanner.scan(document)
        res.scan = scan
        detail = f"risk={scan.risk_level} ({scan.risk_score}); " + (", ".join(scan.categories) or "no patterns")
        if scan.actions:
            detail += " | " + "; ".join(scan.actions)
        res.log("L1 scanner", "flagged" if scan.findings else "pass", detail)

        boundary = prompts.new_boundary()
        system, user = prompts.build(version, scan.sanitized, boundary)
        res.log("L2+L3 prompt", "built", f"Spotlighting boundary <<{boundary}>>, defended {version} prompt")

        obj = _summarize_json(res, llm, cfg, system, user)
        if obj is None:
            return res
        summary, notes, issues = validator.post_check(obj["summary"], obj["injection_notes"], scan.flagged_sentences)
        res.summary, res.injection_notes, res.issues = summary, notes, issues
        hard = [i.message for i in issues if i.level == "hard"]
        # Scanner risk is shown separately; on its own it would mislabel articles ABOUT injection (case B03).
        res.injection_detected = obj["injection_detected"] or bool(hard)
        soft = [i.message for i in issues if i.level == "soft"]
        res.log("L4 leak/link check", "fixed" if hard else "pass", "; ".join(hard) or "No leaks or injected links")
        if soft:
            res.log("L4 heuristics", "warning", "; ".join(soft))

        if version in ("v3", "v4"):
            _critique(res, llm, cfg, scan.sanitized, boundary, scan.flagged_sentences)
        if res.injection_detected and not res.injection_notes:
            res.injection_notes = "Prompt injection detected; instructions in the document were not followed."
        res.message = STATUS_TEXT["ok"]
        return res
    except LLMBlocked as e:
        res.status, res.message = "refused", str(e)
        res.log("Provider", "blocked", str(e))
        return res
    except LLMError as e:
        res.status, res.message = "error", str(e)
        res.log("Provider", "error", str(e))
        return res
    finally:
        res.latency_s = round(time.time() - started, 2)
