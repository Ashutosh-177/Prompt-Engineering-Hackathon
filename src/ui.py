"""Presentation helpers for the Streamlit app (owner: Duclas - M5).

Static CSS + small HTML components rendered with st.html. Every dynamic value is
HTML-escaped because trace details can contain model or document text.
"""
from __future__ import annotations

from html import escape
from pathlib import Path

import pandas as pd
import streamlit as st

REPORTS = Path(__file__).resolve().parent.parent / "reports"

CSS = """
<style>
@keyframes rise {from {opacity:0; transform:translateY(8px);} to {opacity:1; transform:none;}}
@keyframes sweep {0% {background-position:0% 50%;} 100% {background-position:200% 50%;}}
@keyframes pulse {0%,100% {box-shadow:0 0 0 0 rgba(20,184,166,.45);} 50% {box-shadow:0 0 0 10px rgba(20,184,166,0);}}
.hero {position:relative; overflow:hidden; border-radius:18px; padding:28px 30px 24px; color:#E2E8F0;
       background:radial-gradient(1200px 300px at 85% -40%, rgba(20,184,166,.35), transparent 60%),
                  linear-gradient(135deg,#0F172A 0%,#13283a 55%,#0F3D3A 100%);
       animation:rise .5s ease-out both;}
.hero .eyebrow {display:inline-flex; align-items:center; gap:8px; font-size:.78rem; letter-spacing:.08em;
                text-transform:uppercase; color:#5EEAD4; font-weight:600;}
.hero .dot {width:9px; height:9px; border-radius:50%; background:#14B8A6; animation:pulse 2.2s infinite;}
.hero h1 {font-family:'Space Grotesk',sans-serif; font-size:2.1rem; line-height:1.15; margin:.45rem 0 .35rem;
          background:linear-gradient(90deg,#F8FAFC,#5EEAD4,#F8FAFC); background-size:200% auto;
          -webkit-background-clip:text; background-clip:text; color:transparent; animation:sweep 6s linear infinite;}
.hero p {margin:0; color:#94A3B8; max-width:760px; font-size:.98rem;}
.kpis {display:flex; flex-wrap:wrap; gap:12px; margin-top:20px;}
.kpi {flex:1 1 170px; background:rgba(255,255,255,.06); border:1px solid rgba(148,163,184,.22); border-radius:12px;
      padding:12px 14px; animation:rise .6s ease-out both;}
.kpi .v {font-family:'Space Grotesk',sans-serif; font-size:1.45rem; font-weight:700; color:#F8FAFC;}
.kpi .v .arrow {color:#5EEAD4; padding:0 4px;}
.kpi .l {font-size:.78rem; color:#94A3B8; margin-top:2px;}
.flow {display:flex; flex-wrap:wrap; align-items:center; gap:6px; margin-top:18px;}
.flow .step {font-size:.76rem; font-weight:600; color:#CCFBF1; background:rgba(20,184,166,.14);
             border:1px solid rgba(94,234,212,.35); border-radius:999px; padding:4px 11px; animation:rise .5s ease-out both;}
.flow .sep {color:#475569; font-size:.8rem;}
.chips {display:flex; flex-wrap:wrap; gap:8px; margin:6px 0 4px;}
.chip {display:flex; flex-direction:column; min-width:118px; border-radius:10px; padding:8px 11px; border:1px solid;
       animation:rise .45s ease-out both;}
.chip .lyr {font-size:.7rem; text-transform:uppercase; letter-spacing:.06em; opacity:.75; font-weight:600;}
.chip .out {font-size:.92rem; font-weight:700; text-transform:capitalize;}
.chip.ok {background:#ECFDF5; border-color:#A7F3D0; color:#065F46;}
.chip.warn {background:#FFFBEB; border-color:#FDE68A; color:#92400E;}
.chip.bad {background:#FEF2F2; border-color:#FECACA; color:#991B1B;}
.chip.info {background:#EFF6FF; border-color:#BFDBFE; color:#1E40AF;}
</style>
"""

OUTCOME_CLASS = {
    "pass": "ok", "done": "ok", "built": "info", "skipped": "info",
    "flagged": "warn", "fixed": "warn", "warning": "warn", "retry": "warn", "rewrote": "warn",
    "rejected": "bad", "refused": "bad", "fail": "bad", "error": "bad", "blocked": "bad",
}
FLOW = ["Input gate", "L1 Scanner", "L2 Spotlighting", "L3 Defence prompt", "LLM", "L4 Output checks", "L5 Self-critique"]


def _rate(csv: str, version: str, kind: str | None = None) -> float | None:
    path = REPORTS / csv
    if not path.exists():
        return None
    df = pd.read_csv(path)
    df = df[df.version == version]
    if kind:
        df = df[df.kind == kind]
    return round(df.passed.mean() * 100, 1) if len(df) else None


def hero(n_attacks: int, n_types: int, n_cases: int) -> None:
    claude = (_rate("latest_results.csv", "v1"), _rate("latest_results.csv", "v4"))
    groq = (_rate("results_20261003_122535.csv", "v1"), _rate("results_20261003_122535.csv", "v4"))

    def kpi(pair, label, delay):
        if None in pair:
            return ""
        return (f'<div class="kpi" style="animation-delay:{delay}ms"><div class="v">{pair[0]:g}%'
                f'<span class="arrow">&rarr;</span>{pair[1]:g}%</div><div class="l">{escape(label)}</div></div>')

    flow = '<span class="sep">&rsaquo;</span>'.join(
        f'<span class="step" style="animation-delay:{150 + i * 80}ms">{escape(s)}</span>' for i, s in enumerate(FLOW))
    st.html(CSS + f"""
<div class="hero">
  <div class="eyebrow"><span class="dot"></span>Problem 18 &middot; Prompt Injection Defense &middot; Team 6, MB306</div>
  <h1>Injection-safe document summarizer</h1>
  <p>Summarizes any document while ignoring malicious instructions hidden inside it, using five layers of defence
     in prompts and code.</p>
  <div class="kpis">
    {kpi(claude, "Pass rate v1 → v4 · Claude Haiku 4.5", 100)}
    {kpi(groq, "Pass rate v1 → v4 · Groq gpt-oss-120b", 180)}
    <div class="kpi" style="animation-delay:260ms"><div class="v">{n_attacks} / {n_types}</div>
      <div class="l">Attacks / attack types in the suite</div></div>
    <div class="kpi" style="animation-delay:340ms"><div class="v">{n_cases}</div>
      <div class="l">Labelled test cases</div></div>
  </div>
  <div class="flow">{flow}</div>
</div>""")


def trace_chips(trace: list[dict]) -> None:
    items = "".join(
        f'<div class="chip {OUTCOME_CLASS.get(t["outcome"], "info")}" style="animation-delay:{i * 90}ms">'
        f'<span class="lyr">{escape(t["layer"])}</span><span class="out">{escape(t["outcome"])}</span></div>'
        for i, t in enumerate(trace))
    st.html(f'<div class="chips">{items}</div>')
