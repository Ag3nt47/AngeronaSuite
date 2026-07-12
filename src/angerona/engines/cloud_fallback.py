"""
cloud_fallback.py — Cloud Escalation Router
"""
import json
import logging
import re
import time
import os
import concurrent.futures
from typing import Any

import requests
from google import genai

logger = logging.getLogger(__name__)

_CLOUD_SYSTEM_PROMPT = (
    "You are a Tier-3 SOC analyst. Review this security event triaged by a local AI model.\n"
    "Produce a definitive verdict with high confidence as a JSON object containing:\n"
    '  "verdict"        : "SAFE", "SUSPICIOUS", or "MALICIOUS"\n'
    '  "confidence"     : float 0.0–1.0\n'
    '  "justification"  : 2–4 sentence explanation\n'
    '  "containment"    : list of containment steps\n'
)

def _extract_json(text: str) -> dict[str, Any] | None:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    return None

def query_gemini_live(prompt: str, system_prompt: str) -> dict:
    try:
        # NOTE: the rest of this codebase uses GEMINI_API_KEYS (plural, comma-separated
        # pool) -- this was checking the singular GEMINI_API_KEY and would always report
        # "API Key missing" even with a valid pool configured. Fixed to check the pool.
        api_keys = [k.strip() for k in os.getenv("GEMINI_API_KEYS", "").split(",") if k.strip()]
        if not api_keys:
            return {"engine": "GEMINI-CLOUD", "error": "API Key missing"}
        client = genai.Client()
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config={
                'system_instruction': system_prompt,
                'response_mime_type': 'application/json'
            }
        )
        data = _extract_json(response.text)
        return {"engine": "GEMINI-CLOUD", "data": data if data else {"verdict": "UNKNOWN"}}
    except Exception as e:
        return {"engine": "GEMINI-CLOUD", "error": str(e)}

def evaluate_consensus_across_all_ais(prompt: str, local_ollama_res: dict, system_prompt: str) -> dict:
    """
    Multi-engine verdict voting: combines a local Ollama result with a live
    Gemini call and reconciles them into one verdict (CRITICAL beats
    SUSPICIOUS beats SAFE).

    NOT currently called from agent.py's live AI routing (query_ai /
    query_ai_with_cti in agent.py is the actual escalation path the running
    agent uses). Kept correct and available rather than wired in, for two
    concrete reasons -- worth fixing before activating this, not just
    flipping it on:

    1. Schema mismatch: this expects local_ollama_res to look like the dict
       _CLOUD_SYSTEM_PROMPT's "containment" field implies (verdict,
       confidence, justification, containment), but agent.py's actual local
       tier (core_engine.evaluate_threat_locally) returns only verdict /
       confidence / justification -- no containment field. The Gemini side
       of the vote would always have a containment list that just gets
       silently dropped on merge, since compiled_justification only reads
       'justification'.

    2. Running query_ai_with_cti's CTI-grounded single-call waterfall
       *and* this voting consensus would mean two independent AI escalation
       systems making decisions for the same alert. That's worth doing
       deliberately if you want true multi-engine consensus instead of a
       single-call-with-fallback design, but it's a real architecture
       decision, not something to silently turn on alongside the existing
       path.
    """
    results = {"LOCAL-OLLAMA": local_ollama_res}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future_tasks = {
            executor.submit(query_gemini_live, prompt, system_prompt): "GEMINI"
        }
        for future in concurrent.futures.as_completed(future_tasks):
            res = future.result()
            engine_name = res["engine"]
            if "error" not in res:
                results[engine_name] = res["data"]
            else:
                results[engine_name] = {"verdict": "UNKNOWN", "justification": res["error"]}

    verdict_votes = []
    for engine, engine_res in results.items():
        v = str(engine_res.get("verdict", "SAFE")).upper()
        if v in ("MALICIOUS", "CRITICAL"):
            verdict_votes.append("CRITICAL")
        elif v == "SUSPICIOUS":
            verdict_votes.append("SUSPICIOUS")
        elif v == "SAFE":
            verdict_votes.append("SAFE")
        # NOTE: UNKNOWN (an engine erroring out -- rate limit, network failure,
        # bad key) is deliberately excluded from the vote rather than treated
        # as SAFE. A cloud-tier outage should never silently count as evidence
        # of safety; the original logic let any non-matching verdict fall
        # through to the SAFE bucket, which is the wrong failure direction
        # for a security tool.

    if "CRITICAL" in verdict_votes:
        final_verdict = "CRITICAL"
    elif verdict_votes.count("SUSPICIOUS") >= 1:
        final_verdict = "SUSPICIOUS"
    elif verdict_votes:
        final_verdict = "SAFE"
    else:
        # Every engine returned UNKNOWN (e.g. all errored) -- there's no
        # actual evidence of safety here, so don't claim SAFE.
        final_verdict = "UNKNOWN"

    compiled_justification = "\n".join([
        f"[{engine}]: {res.get('justification', 'No explanation given.')}" 
        for engine, res in results.items() if "justification" in res
    ])

    return {
        "verdict": final_verdict,
        "justification": compiled_justification,
        "escalation_source": "AI-CONSENSUS-GRID"
    }