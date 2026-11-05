"""Keeps the agent alive when the AI service is overloaded.

Wraps the Gemini client. If a call fails with a temporary error (503
overloaded, 429 rate limit, timeout), it retries with a growing wait, then
falls back to a second model. Every retry and fallback goes in the audit log.
Permanent errors (bad key, bad request) are raised straight away.
"""
import time

# Models are retired over time. If one stops working, the agent skips it
# and tries the next, but keep this list current.
FALLBACK_MODELS = ("gemini-3.5-flash", "gemini-3.7-flash")
TRANSIENT_CODES = {429, 500, 502, 503, 504}
TRANSIENT_WORDS = ("unavailable", "overloaded", "high demand", "resource_exhausted",
                   "timed out", "timeout", "temporarily", "try again later",
                   "503", "429")


UNAVAILABLE_WORDS = ("no longer available", "not_found", "is not found",
                     "does not exist", "is not supported")


def is_daily_quota(error) -> bool:
    """True when a per-DAY free-tier limit is used up. Waiting a few seconds
    will not help, so the model is skipped until tomorrow."""
    text = str(error).lower().replace("_", "").replace(" ", "")
    return "perday" in text


def is_model_unavailable(error) -> bool:
    """True when the model itself is gone (retired, wrong name)."""
    code = getattr(error, "code", None) or getattr(error, "status_code", None)
    if code == 404:
        return True
    text = str(error).lower()
    return any(word in text for word in UNAVAILABLE_WORDS)


def is_transient(error) -> bool:
    code = getattr(error, "code", None) or getattr(error, "status_code", None)
    if code in TRANSIENT_CODES:
        return True
    text = str(error).lower()
    return any(word in text for word in TRANSIENT_WORDS)


class _Models:
    def __init__(self, client, audit, fallbacks, retries, wait):
        self._client = client
        self._audit = audit
        self._fallbacks = fallbacks
        self._retries = retries
        self._wait = wait
        self.used = []          # models that gave an answer, in order of first use

    def _log(self, event, **data):
        if self._audit is not None:
            self._audit.add(event, **data)

    def generate_content(self, model, contents, config=None, **kwargs):
        order = [model] + [m for m in self._fallbacks if m != model]
        last_error = None
        for index, name in enumerate(order):
            for attempt in range(1, self._retries + 1):
                try:
                    result = self._client.models.generate_content(
                        model=name, contents=contents, config=config, **kwargs)
                    if name not in self.used:
                        self.used.append(name)
                    return result
                except Exception as e:
                    if is_daily_quota(e):
                        last_error = e
                        self._log("llm_quota_exhausted", model=name,
                                  error=str(e)[:150])
                        break                      # daily limit: next model
                    if is_model_unavailable(e):
                        last_error = e
                        self._log("llm_model_unavailable", model=name,
                                  error=str(e)[:150])
                        break                      # skip to the next model
                    if not is_transient(e):
                        raise
                    last_error = e
                    self._log("llm_retry", model=name, attempt=attempt,
                              error=str(e)[:150])
                    if attempt < self._retries:
                        time.sleep(self._wait * attempt)
            if index + 1 < len(order):
                self._log("llm_fallback", failed_model=name,
                          next_model=order[index + 1])
        raise RuntimeError(
            f"AI service unavailable after retries and fallback: {last_error}")


class ResilientClient:
    """Drop-in replacement for genai.Client (only .models.generate_content)."""

    def __init__(self, client, audit=None, fallbacks=FALLBACK_MODELS,
                 retries=3, wait=3.0):
        self.models = _Models(client, audit, fallbacks, retries, wait)
