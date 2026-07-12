"""
src/core_engine.py — Local Analysis Engine
Sends security log events to a locally-running Ollama instance (Llama 3)
and robustly parses the structured threat-assessment response.
"""

import json
import logging
import re
import time
from typing import Any

import requests

# Import config lazily so the module can be imported before load_env() runs.
import config

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM PROMPT
# ─────────────────────────────────────────────────────────────────────────────
_SYSTEM_PROMPT = (
    "You are a Tier-1 SOC analyst embedded in an Endpoint Detection and "
    "Response (EDR) system.  Your ONLY job is to triage raw log lines and "
    "return a structured threat assessment.\n\n"
    "You MUST respond with a single JSON object and NOTHING ELSE — no "
    "markdown, no code fences, no prose before or after the object.\n\n"
    "The JSON object MUST contain exactly these three keys:\n"
    '  "verdict"       : one of the strings SAFE, SUSPICIOUS, or MALICIOUS\n'
    '  "confidence"    : a float between 0.0 and 1.0 representing how certain '
    "you are of the verdict\n"
    '  "justification" : a concise one-to-three sentence explanation\n\n'
    "Example of a valid response:\n"
    '{"verdict":"MALICIOUS","confidence":0.94,'
    '"justification":"The log shows a known Mimikatz LSASS dump pattern '
    'combined with lateral movement to a domain controller."}'
)

_USER_PROMPT_TEMPLATE = (
    "Analyze the following raw security log event and return your structured "
    "threat assessment JSON:\n\n"
    "--- BEGIN LOG ---\n"
    "{log}\n"
    "--- END LOG ---"
)

# ─────────────────────────────────────────────────────────────────────────────
# DEFAULT / ERROR RESPONSE SKELETON
# ─────────────────────────────────────────────────────────────────────────────
def _make_error_result(reason: str) -> dict[str, Any]:
    """Return a safe fallback dict when local analysis cannot complete."""
    return {
        "verdict": "SUSPICIOUS",
        "confidence": 0.0,
        "justification": f"Local analysis failed: {reason}",
        "_local_error": True,
    }


# ─────────────────────────────────────────────────────────────────────────────
# ROBUST JSON EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────
def _extract_json_from_text(text: str) -> dict[str, Any] | None:
    """
    Attempt multiple strategies to extract a valid JSON object from raw model
    output.  Small local models frequently wrap JSON in markdown fences,
    include trailing commas, or emit partial objects.

    Strategies (in order):
      1. Direct json.loads on the stripped text.
      2. Strip common markdown code-fence wrappers and retry.
      3. Find the first {...} block via regex and parse it.
      4. Field-by-field regex extraction as a last resort.

    Returns a dict if successful, or None if all strategies fail.
    """
    text = text.strip()

    # ── Strategy 1: clean direct parse ────────────────────────────────────
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # ── Strategy 2: strip markdown fences ─────────────────────────────────
    fence_pattern = re.compile(
        r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE
    )
    match = fence_pattern.search(text)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # ── Strategy 3: extract first {...} block ─────────────────────────────
    brace_pattern = re.compile(r"\{[^{}]*\}", re.DOTALL)
    for candidate in brace_pattern.finditer(text):
        try:
            return json.loads(candidate.group())
        except json.JSONDecodeError:
            continue

    # ── Strategy 4: greedy multi-line brace scan ──────────────────────────
    # Handles nested structures by tracking brace depth.
    start = text.find("{")
    if start != -1:
        depth = 0
        for i, ch in enumerate(text[start:], start=start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start : i + 1]
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        break

    # ── Strategy 5: regex field extraction ────────────────────────────────
    verdict_match = re.search(
        r'"?verdict"?\s*:\s*"?(SAFE|SUSPICIOUS|MALICIOUS)"?',
        text,
        re.IGNORECASE,
    )
    confidence_match = re.search(
        r'"?confidence"?\s*:\s*([0-9]*\.?[0-9]+)',
        text,
        re.IGNORECASE,
    )
    justification_match = re.search(
        r'"?justification"?\s*:\s*"([^"]+)"',
        text,
        re.IGNORECASE,
    )

    if verdict_match or confidence_match:
        extracted: dict[str, Any] = {}

        if verdict_match:
            extracted["verdict"] = verdict_match.group(1).upper()
        if confidence_match:
            try:
                extracted["confidence"] = float(confidence_match.group(1))
            except ValueError:
                extracted["confidence"] = 0.0
        if justification_match:
            extracted["justification"] = justification_match.group(1)

        if extracted:
            logger.warning(
                "core_engine | JSON parse fell back to regex field extraction; "
                "recovered fields: %s",
                list(extracted.keys()),
            )
            return extracted

    return None


# ─────────────────────────────────────────────────────────────────────────────
# RESPONSE VALIDATOR / NORMALISER
# ─────────────────────────────────────────────────────────────────────────────
_VALID_VERDICTS = {"SAFE", "SUSPICIOUS", "MALICIOUS"}


def _normalise_result(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Ensure mandatory keys are present and have the correct types.
    Fills in safe defaults for any missing or malformed fields so downstream
    code never has to guard against KeyError / TypeError.
    """
    # Verdict
    verdict_raw = str(raw.get("verdict", "")).upper().strip()
    if verdict_raw not in _VALID_VERDICTS:
        logger.warning(
            "core_engine | Unexpected verdict value '%s'; defaulting to SUSPICIOUS",
            verdict_raw,
        )
        verdict_raw = "SUSPICIOUS"

    # Confidence
    try:
        confidence = float(raw.get("confidence", 0.0))
        confidence = max(0.0, min(1.0, confidence))   # clamp to [0, 1]
    except (TypeError, ValueError):
        logger.warning(
            "core_engine | Unparseable confidence value '%s'; defaulting to 0.0",
            raw.get("confidence"),
        )
        confidence = 0.0

    # Justification
    justification = str(raw.get("justification", "No justification provided.")).strip()
    if not justification:
        justification = "No justification provided."

    return {
        "verdict": verdict_raw,
        "confidence": confidence,
        "justification": justification,
    }


# ─────────────────────────────────────────────────────────────────────────────
# OLLAMA API CALL (with retry)
# ─────────────────────────────────────────────────────────────────────────────
def _call_ollama(prompt_messages: list[dict], attempt: int = 0) -> str:
    """
    POST to the Ollama /api/chat endpoint and return the raw assistant text.
    Retries on connection errors with exponential back-off.
    Raises RuntimeError if all retries are exhausted.
    """
    ollama_host = config.get_ollama_host()
    url = f"{ollama_host}/api/chat"

    payload = {
        "model": config.OLLAMA_MODEL,
        "messages": prompt_messages,
        "stream": False,
        "keep_alive": "30m",       # keep the model resident between triage calls
        "options": {
            "temperature": 0.1,    # near-deterministic for structured output
            "num_predict": 512,
        },
    }

    max_attempts = config.MAX_RETRIES
    delay = config.RETRY_BASE_DELAY

    for attempt_num in range(1, max_attempts + 1):
        try:
            logger.debug(
                "core_engine | Ollama request attempt %d/%d → %s",
                attempt_num,
                max_attempts,
                url,
            )
            response = requests.post(
                url,
                json=payload,
                timeout=config.OLLAMA_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()

            # Ollama /api/chat wraps the reply in message.content
            content = (
                data.get("message", {}).get("content")
                or data.get("response")
                or ""
            )
            return content.strip()

        except requests.exceptions.ConnectionError as exc:
            logger.warning(
                "core_engine | Ollama connection error (attempt %d/%d): %s",
                attempt_num,
                max_attempts,
                exc,
            )
        except requests.exceptions.Timeout:
            logger.warning(
                "core_engine | Ollama timed out after %ds (attempt %d/%d)",
                config.OLLAMA_TIMEOUT,
                attempt_num,
                max_attempts,
            )
        except requests.exceptions.HTTPError as exc:
            logger.error(
                "core_engine | Ollama HTTP error %s (attempt %d/%d)",
                exc.response.status_code,
                attempt_num,
                max_attempts,
            )
            # 4xx errors are not retriable
            if exc.response.status_code < 500:
                raise

        if attempt_num < max_attempts:
            sleep_time = min(delay * (2 ** (attempt_num - 1)), config.RETRY_MAX_DELAY)
            logger.info("core_engine | Retrying in %.1fs …", sleep_time)
            time.sleep(sleep_time)

    raise RuntimeError(
        f"Ollama unreachable after {max_attempts} attempts. "
        "Ensure `ollama serve` is running and OLLAMA_HOST is correct."
    )


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC INTERFACE
# ─────────────────────────────────────────────────────────────────────────────
def evaluate_threat_locally(raw_log_string: str) -> dict[str, Any]:
    """
    Send *raw_log_string* to the local Ollama/Llama3 instance for triage.

    Returns a normalised dict with keys:
      - verdict       : "SAFE" | "SUSPICIOUS" | "MALICIOUS"
      - confidence    : float in [0.0, 1.0]
      - justification : str
      - _local_error  : bool (only present when analysis failed)

    This function NEVER raises; all errors are caught, logged, and converted
    into a low-confidence SUSPICIOUS result so the cloud fallback takes over.
    """
    logger.info("core_engine | Starting local threat evaluation …")
    logger.debug("core_engine | Log snippet: %.120s", raw_log_string)

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {
            "role": "user",
            "content": _USER_PROMPT_TEMPLATE.format(log=raw_log_string),
        },
    ]

    # ── Step 1: call Ollama ────────────────────────────────────────────────
    try:
        raw_output = _call_ollama(messages)
    except RuntimeError as exc:
        logger.error("core_engine | Ollama call failed: %s", exc)
        return _make_error_result(str(exc))

    logger.debug("core_engine | Raw Ollama output: %s", raw_output)

    if not raw_output:
        logger.error("core_engine | Ollama returned an empty response.")
        return _make_error_result("Empty response from Ollama")

    # ── Step 2: extract JSON ───────────────────────────────────────────────
    parsed = _extract_json_from_text(raw_output)
    if parsed is None:
        logger.error(
            "core_engine | Could not extract JSON from Ollama output:\n%s",
            raw_output,
        )
        return _make_error_result(
            f"JSON extraction failed. Raw output: {raw_output[:200]}"
        )

    # ── Step 3: normalise and return ──────────────────────────────────────
    result = _normalise_result(parsed)
    logger.info(
        "core_engine | Local result → verdict=%s  confidence=%.2f",
        result["verdict"],
        result["confidence"],
    )
    return result
