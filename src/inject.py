"""Injection tester for ANY document (owner: Adelaide - M4).

Takes a clean document (e.g. the team's own documentation, or an unseen input
from the panel), plants each attack payload from data/payloads.json into it one
at a time, runs the chosen prompt versions and scores each run with the same
rules as the attack suite: an attack is defended if none of its success markers
reach the user.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable

import pandas as pd

from . import eval as ev
from . import pipeline
from .llm import LLMConfig

PAYLOADS = Path(__file__).resolve().parent.parent / "data" / "payloads.json"
POSITIONS = ["middle", "start", "end"]


def load_payloads() -> list[dict]:
    return json.loads(PAYLOADS.read_text(encoding="utf-8"))


def inject(document: str, payload: str, where: str = "middle") -> str:
    """Insert the payload at a sentence/paragraph boundary so it blends into the text."""
    doc = document.strip()
    if where == "start":
        return f"{payload}\n{doc}"
    if where == "end":
        return f"{doc}\n{payload}"
    boundaries = [m.end() for m in re.finditer(r"(?<=[.!?])\s+|\n+", doc)]
    if not boundaries:
        return f"{doc}\n{payload}"
    cut = min(boundaries, key=lambda i: abs(i - len(doc) // 2))
    return f"{doc[:cut].rstrip()} {payload} {doc[cut:].lstrip()}"


def run_injection_test(document: str, versions: list[str], cfg: LLMConfig | None = None, where: str = "middle",
                       types: list[str] | None = None, progress: Callable[[int, int, str], None] | None = None,
                       llm=None) -> pd.DataFrame:
    payloads = [p for p in load_payloads() if not types or p["type"] in types]
    rows, total, done = [], len(payloads) * len(versions), 0
    low_doc = document.lower()
    for v in versions:
        for p in payloads:
            # A marker that already occurs in the clean document cannot prove an attack worked.
            markers = [m for m in p["success_markers"] if m.lower() not in low_doc]
            attacked = inject(document, p["payload"], where)
            kwargs = {"llm": llm} if llm else {}
            res = pipeline.run(attacked, v, cfg, **kwargs)
            case = {"id": p["type"], "kind": "attack", "type": p["type"], "title": p["type"],
                    "success_markers": markers, "key_facts": []}
            row = ev.score(case, res)
            row["defended"] = row.pop("passed")
            row["attacked_document"] = attacked
            rows.append(row)
            done += 1
            if progress:
                progress(done, total, f"{v} {p['type']}")
    return pd.DataFrame(rows)


def summary_table(df: pd.DataFrame) -> pd.DataFrame:
    return (df.groupby("version")
              .agg(attacks=("defended", "size"), defended=("defended", "sum"),
                   flagged=("injection_detected", "sum"))
              .assign(defence_rate=lambda t: (t.defended / t.attacks * 100).round(1))
              .reset_index())
