# Injection-safe document summarizer

**Problem 18 - Prompt Injection Defense** (Theme D: Reliability, Hallucination and Safety)
Team 6, MB306 - Prompt Engineering for Generative AI Hackathon, 3 October 2026

A document summarizer that ignores malicious instructions hidden inside the document. It uses five defence layers and comes with an automated attack suite (14 attacks, 13 types) that produces a pass-rate report.

## Quick start

```powershell
pip install -r requirements.txt
copy .env.example .env        # then put your API key in .env
streamlit run app.py
```

Provider is set by `LLM_PROVIDER` in `.env` (`gemini`, `groq` or `anthropic`) or in the app sidebar. Paste an API key into the sidebar to override `.env`.

Run the attack suite from the command line:

```powershell
python -m src.eval --versions v1 v2 v3 v4         # full suite, writes reports/
python -m src.eval --versions v1 v4 --delay 4     # slower, for free-tier rate limits
python -m src.eval --versions v4 --only A06 B03   # selected cases
python -m pytest -q                               # offline tests, no API key needed
```

## How it works

```
document --> [Gate] --> [L1 Scanner] --> [L2 Spotlighting + L3 Defence prompt] --> LLM
                                                                                   |
     user <-- [L5 Self-critique (v3+)] <-- [L4 Output checks: JSON, refusal, leak, links]
```

| Layer | Where | What it does |
|---|---|---|
| Gate | code `src/scanner.py` | Rejects empty, chat-style or non-document input (< 25 words) |
| L1 Scanner | code `src/scanner.py` | 13 regex pattern families; decodes base64 and scans it; strips zero-width characters and hidden HTML comments |
| L2 Spotlighting | prompt `prompts/v2_user.md` | Document wrapped in a random boundary `<<DOC_XXXXXXXX>>` that changes on every request |
| L3 Defence prompt | prompt `prompts/v4_system.md` | Priority rules, sandwich reminder after the document, silent self-check, 3 few-shot examples |
| L4 Output checks | code `src/validator.py` | JSON schema with one repair retry, refusal detection with retry, system-tag leak redaction, removal of links taken from injected text, replacement of notes that quote the attack |
| L5 Self-critique | prompt `prompts/critic_system.md` | A second model call audits the summary and rewrites it if it was compromised |

**Prompt versions:** v1 naive baseline, v2 defended prompt + spotlighting + JSON + code checks, v3 = v2 + few-shot + self-critique chain, v4 (final) = v3 + "never quote the attack in notes" rule.

**Prompting techniques combined:** role and rule prompting, spotlighting with delimiters, sandwich defence, few-shot examples, prompt chaining with self-critique, and structured JSON output validated in code.

## App tabs
- **Summarize**: any pasted or uploaded document (.txt, .md, .pdf), with a full defence trace.
- **Side-by-side**: two prompt versions on one model, or two models on one version, on the same input.
- **Attack suite**: runs the labelled test set and shows metrics, a per-attack-type chart and a CSV download.
- **Report**: the latest pass-rate report from `reports/`.
- **Prompts**: edit a prompt file live and re-test it.

## Repository layout
```
app.py                  Streamlit UI                         (Duclas - M5)
src/llm.py              provider-agnostic LLM wrapper         (Duclas - M5)
src/prompts.py          prompt builders                       (Ommakadiya - M1)
prompts/                all prompt text, versioned in Git     (Ommakadiya - M1)
data/                   labelled attack / benign / off-topic  (Sai Nikhil - M2)
src/scanner.py          gate + L1 scanner                     (Ashutosh - M3)
src/validator.py        L4 output checks                      (Ashutosh - M3)
src/pipeline.py         layered pipeline v1/v2/v3             (Ashutosh - M3)
src/eval.py             attack suite + metrics + report       (Adelaide - M4)
tests/                  offline + UI tests                    (Adelaide - M4, Duclas - M5)
docs/                   prompt documentation, iteration log, contribution table
```
