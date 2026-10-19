"""Opt-in Gemini analyst transport; model output remains advisory and validated elsewhere."""

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from vulnassess.ai_boundary import SYSTEM_BOUNDARY_PROMPT
from vulnassess.errors import ConfigError, LLMUnavailable, ProviderUnavailable

MODEL = "gemini-3.5-flash-lite"
ENDPOINT = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"
KEY_FILE = Path(__file__).resolve().parents[1] / ".env.google"
MAX_PROMPT_BYTES = 20 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_COMPLETION_TOKENS = 3200


def load_api_key() -> str:
    value = os.environ.get("GEMINI_API_KEY", "").strip()
    if value:
        return value
    if not KEY_FILE.is_file():
        return ""
    try:
        lines = KEY_FILE.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ConfigError("Cannot read the local Gemini key file") from error
    for line in lines:
        if line.startswith("GEMINI_API_KEY="):
            return line.partition("=")[2].strip().strip("\"'")
    return ""


class GeminiClient:
    model = MODEL
    source = "google_gemini_3_5_flash_lite_grounded_analysis"

    def __init__(self, api_key: str | None = None, timeout: float = 120.0) -> None:
        if not 0 < timeout <= 120:
            raise ConfigError("Gemini timeout must be in (0, 120] seconds")
        self.key = api_key if api_key is not None else load_api_key()
        self.timeout = timeout

    def available(self) -> bool:
        if not self.key:
            raise LLMUnavailable("GEMINI_API_KEY is missing; add it to .env.google")
        return True

    def generate_structured(
        self,
        prompt: str,
        schema: dict[str, Any],
        *,
        num_predict: int = MAX_COMPLETION_TOKENS,
        num_ctx: int = 16384,
        on_progress: Callable[[int], None] | None = None,
        on_raw: Callable[[bytes], None] | None = None,
    ) -> dict[str, Any]:
        self.available()
        if len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
            raise ConfigError("Gemini analyst prompt exceeds its byte budget")
        if not 1 <= num_predict <= MAX_COMPLETION_TOKENS:
            raise ConfigError("Gemini completion token budget exceeded")
        if not 512 <= num_ctx <= 131072:
            raise ConfigError("Gemini context budget is invalid")
        body = {
            "systemInstruction": {"parts": [{"text": SYSTEM_BOUNDARY_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseJsonSchema": schema,
                "maxOutputTokens": num_predict,
                "temperature": 0,
            },
        }
        request = urllib.request.Request(
            ENDPOINT,
            data=json.dumps(body, ensure_ascii=True).encode("utf-8"),
            headers={"x-goog-api-key": self.key, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            if error.code == 429:
                raise ProviderUnavailable(
                    "Gemini rate limit reached; no automatic retry"
                ) from error
            if error.code in (401, 403):
                raise ProviderUnavailable("Gemini rejected the key or account access") from error
            raise ProviderUnavailable(f"Gemini request failed with HTTP {error.code}") from error
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            raise ProviderUnavailable("Gemini is unavailable; no automatic retry") from error
        if len(raw) > MAX_RESPONSE_BYTES:
            raise LLMUnavailable("Gemini response exceeded the byte budget")
        if on_progress is not None:
            on_progress(len(raw))
        if on_raw is not None:
            on_raw(raw)
        try:
            envelope = json.loads(raw)
            candidate = envelope["candidates"][0]
            if candidate.get("finishReason") not in (None, "STOP"):
                raise ValueError("incomplete response")
            content = "".join(
                part["text"] for part in candidate["content"]["parts"] if "text" in part
            )
            result = json.loads(content)
        except (ValueError, TypeError, KeyError, IndexError) as error:
            raise LLMUnavailable("Gemini returned an invalid structured response") from error
        if not isinstance(result, dict):
            raise LLMUnavailable("Gemini analyst response must be a JSON object")
        return result
