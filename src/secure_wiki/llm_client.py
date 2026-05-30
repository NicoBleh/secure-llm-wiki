"""LLM client abstraction supporting Ollama and Anthropic (Spec 7).

Provider and model selection via environment variables:
  LLM_PROVIDER      = "ollama" | "anthropic"     (default: "ollama")
  EXTRACTION_MODEL  = model for claim extraction  (default: llama3.2 / claude-haiku-4-5)
  REVIEW_MODEL      = model for adversarial review (default: mistral / claude-haiku-4-5)
  OLLAMA_HOST       = Ollama server URL           (default: http://localhost:11434)

REVIEW_MODEL should differ from EXTRACTION_MODEL to preserve 4-eyes independence:
a jailbreak that compromises the extractor must not simultaneously compromise the reviewer.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field


@dataclass
class UsageInfo:
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def __add__(self, other: "UsageInfo") -> "UsageInfo":
        return UsageInfo(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
        )


@dataclass
class CompletionResult:
    text: str
    usage: UsageInfo = field(default_factory=UsageInfo)


def strip_fences(text: str) -> str:
    """Remove markdown code fences that some models add despite instructions."""
    text = text.strip()
    text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
    text = re.sub(r"\n?```$", "", text)
    return text.strip()


def extract_json_object(text: str) -> str:
    """Extract the first complete JSON object from text that may have trailing prose."""
    text = strip_fences(text)
    # Fast path: entire text is already valid JSON
    try:
        import json
        json.loads(text)
        return text
    except (json.JSONDecodeError, ValueError):
        pass
    # Find the first {...} span by scanning for balanced braces
    start = text.find("{")
    if start == -1:
        return text
    depth = 0
    in_string = False
    escape = False
    for i, ch in enumerate(text[start:], start):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return text


class OllamaClient:
    def __init__(self, model: str, host: str) -> None:
        import ollama
        self._client = ollama.Client(host=host)
        self._model = model

    def complete(self, system: str, user: str) -> CompletionResult:
        response = self._client.chat(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            options={"temperature": 0},
        )
        usage = UsageInfo(
            input_tokens=getattr(response, "prompt_eval_count", 0) or 0,
            output_tokens=getattr(response, "eval_count", 0) or 0,
        )
        return CompletionResult(text=response.message.content, usage=usage)

    def embed(self, text: str) -> list[float]:
        response = self._client.embed(model=self._model, input=text)
        return response.embeddings[0]


class AnthropicClient:
    def __init__(self, model: str) -> None:
        import anthropic
        self._client = anthropic.Anthropic()
        self._model = model

    def complete(self, system: str, user: str) -> CompletionResult:
        msg = self._client.messages.create(
            model=self._model,
            max_tokens=2048,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        usage = UsageInfo(
            input_tokens=msg.usage.input_tokens,
            output_tokens=msg.usage.output_tokens,
        )
        return CompletionResult(text=msg.content[0].text, usage=usage)

    def embed(self, text: str) -> list[float]:
        raise NotImplementedError("Anthropic provider does not support embeddings; set LLM_PROVIDER=ollama for Gate 5 similarity checks")


_EXTRACTION_DEFAULTS: dict[str, str] = {
    "ollama": "llama3.2",
    "anthropic": "claude-haiku-4-5-20251001",
}
_REVIEW_DEFAULTS: dict[str, str] = {
    "ollama": "mistral",
    "anthropic": "claude-haiku-4-5-20251001",
}
_EMBED_DEFAULTS: dict[str, str] = {
    "ollama": "nomic-embed-text",
    "anthropic": "",
}


def _build_client(role: str) -> OllamaClient | AnthropicClient:
    provider = os.environ.get("LLM_PROVIDER", "ollama").lower()
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    if role == "extraction":
        defaults, env_key = _EXTRACTION_DEFAULTS, "EXTRACTION_MODEL"
    elif role == "review":
        defaults, env_key = _REVIEW_DEFAULTS, "REVIEW_MODEL"
    else:
        defaults, env_key = _EMBED_DEFAULTS, "EMBED_MODEL"
    model = os.environ.get(env_key, defaults.get(provider, ""))
    if provider == "anthropic":
        return AnthropicClient(model)
    return OllamaClient(model, host=host)


def get_extraction_client() -> OllamaClient | AnthropicClient:
    return _build_client("extraction")


def get_review_client() -> OllamaClient | AnthropicClient:
    return _build_client("review")


def get_embed_client() -> OllamaClient | AnthropicClient:
    return _build_client("embed")
