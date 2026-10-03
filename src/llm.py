"""Provider-agnostic LLM wrapper (owner: Duclas - M5).

One function, `chat()`, talks to Gemini, Groq or Anthropic (Claude) over plain
HTTPS so the team can switch to whichever tool is permitted by changing one
setting. Temperature defaults to 0 so evaluation runs are repeatable.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass

import requests
from dotenv import load_dotenv

load_dotenv()

DEFAULT_MODELS = {
    "gemini": "gemini-2.5-flash",
    "groq": "openai/gpt-oss-120b",
    "anthropic": "claude-haiku-4-5-20251001",
}
KEY_ENV = {
    "gemini": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}
TIMEOUT_S = 60
MAX_RETRIES = 4


class LLMError(Exception):
    """Raised when the provider cannot return a usable answer."""


class LLMBlocked(LLMError):
    """Raised when the provider's own safety filter blocks the request."""


@dataclass
class LLMConfig:
    provider: str = ""
    model: str = ""
    api_key: str = ""

    def resolved(self) -> "LLMConfig":
        provider = (self.provider or os.getenv("LLM_PROVIDER") or "gemini").lower().strip()
        if provider not in DEFAULT_MODELS:
            raise LLMError(f"Unknown provider '{provider}'. Use one of: {', '.join(DEFAULT_MODELS)}")
        model = self.model or os.getenv("LLM_MODEL") or DEFAULT_MODELS[provider]
        key = self.api_key or os.getenv(KEY_ENV[provider], "")
        return LLMConfig(provider, model, key)

    @property
    def label(self) -> str:
        c = self.resolved()
        return f"{c.provider}/{c.model}"


def _post(url: str, headers: dict, body: dict) -> dict:
    """POST with retry/backoff on rate limits and transient server errors."""
    delay = 2.0
    for attempt in range(MAX_RETRIES):
        try:
            r = requests.post(url, headers=headers, json=body, timeout=TIMEOUT_S)
        except requests.RequestException as e:
            if attempt == MAX_RETRIES - 1:
                raise LLMError(f"Network error: {e}") from e
            time.sleep(delay)
            delay *= 2
            continue
        if r.status_code == 200:
            return r.json()
        if r.status_code in (429, 500, 502, 503, 504) and attempt < MAX_RETRIES - 1:
            time.sleep(delay)
            delay *= 2
            continue
        raise LLMError(f"HTTP {r.status_code}: {r.text[:300]}")
    raise LLMError("Exhausted retries")


def _gemini(cfg: LLMConfig, system: str, user: str, temperature: float, json_mode: bool) -> str:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{cfg.model}:generateContent"
    gen = {"temperature": temperature}
    if json_mode:
        gen["responseMimeType"] = "application/json"
    body = {
        "system_instruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": gen,
    }
    data = _post(url, {"x-goog-api-key": cfg.api_key, "Content-Type": "application/json"}, body)
    if data.get("promptFeedback", {}).get("blockReason"):
        raise LLMBlocked(f"Blocked by provider: {data['promptFeedback']['blockReason']}")
    cands = data.get("candidates") or []
    if not cands:
        raise LLMError("Empty response from Gemini")
    parts = cands[0].get("content", {}).get("parts") or []
    text = "".join(p.get("text", "") for p in parts)
    if not text and cands[0].get("finishReason") in ("SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST"):
        raise LLMBlocked(f"Blocked by provider: {cands[0]['finishReason']}")
    return text


def _groq(cfg: LLMConfig, system: str, user: str, temperature: float, json_mode: bool) -> str:
    """Groq exposes a chat-completions style endpoint."""
    body = {
        "model": cfg.model,
        "temperature": temperature,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    data = _post("https://api.groq.com/openai/v1/chat/completions", {"Authorization": f"Bearer {cfg.api_key}"}, body)
    choice = data["choices"][0]
    if choice.get("finish_reason") == "content_filter":
        raise LLMBlocked("Blocked by provider content filter")
    msg = choice["message"]
    if msg.get("refusal"):
        return msg["refusal"]
    return msg.get("content") or ""


def _anthropic(cfg: LLMConfig, system: str, user: str, temperature: float, json_mode: bool) -> str:
    body = {
        "model": cfg.model,
        "max_tokens": 1024,
        "temperature": temperature,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }
    headers = {"x-api-key": cfg.api_key, "anthropic-version": "2023-06-01"}
    data = _post("https://api.anthropic.com/v1/messages", headers, body)
    if data.get("stop_reason") == "refusal":
        raise LLMBlocked("Model refused (stop_reason=refusal)")
    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


def chat(system: str, user: str, cfg: LLMConfig | None = None, temperature: float = 0.0, json_mode: bool = False) -> str:
    """Send one system+user turn and return the model's text."""
    c = (cfg or LLMConfig()).resolved()
    if not c.api_key:
        raise LLMError(f"No API key for {c.provider}. Set {KEY_ENV[c.provider]} in .env or in the sidebar.")
    if c.provider == "gemini":
        return _gemini(c, system, user, temperature, json_mode)
    if c.provider == "groq":
        return _groq(c, system, user, temperature, json_mode)
    return _anthropic(c, system, user, temperature, json_mode)
