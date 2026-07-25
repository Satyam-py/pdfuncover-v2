# modules/threat_intel_pipeline.py
"""
Orchestration-layer integration between IOC extraction
(modules/parsers/iocs.py) and the frozen Threat Intelligence engine
(modules/threat_intel/engine.py + modules/threat_intel/models.py).

Per Step 9's explicit requirement — "The orchestration layer should
call the Threat Intelligence engine. Do not move enrichment logic
into providers or other modules." — this is the ONLY place enrichment
logic lives. It is called exactly once, from
modules/embedded_extraction.py (the orchestrator), right after
modules.parsers.iocs.extract_iocs() finishes. iocs.py itself no longer
performs enrichment — see its updated docstring/tail.

This module performs NO detection and NO new IOC extraction. It:

    1. Takes the already-extracted, already-deduplicated IOC lists
       iocs.py produces ("URLs" / "Domains" / "IPs").
    2. Builds one typed Ioc per unique (type, value) pair — deduped
       across the WHOLE ioc_data dict, not just within one category —
       so the engine is never asked to look up the same indicator
       twice, even if (for example) a URL's own host happens to also
       appear in the Domains list.
    3. Calls modules.threat_intel.engine.enrich_ioc() exactly once per
       unique Ioc (concurrently, capped at MAX_WORKERS), using
       whatever provider credentials are supplied.
    4. Converts every returned EnrichmentResult into the SAME
       "Threat Intelligence" report shape already consumed by
       modules.correlation, modules.attack_chain,
       modules.evidence_explorer, and modules.report — so none of
       those modules need to change to start consuming real,
       typed-engine-backed data instead of the old system's output.
    5. Also attaches the raw, typed EnrichmentResult objects under a
       "_typed" key, for any current or future caller that wants full
       typed access (individual ReputationFinding/DomainContext/
       IPContext/etc. fields) rather than the flattened legacy shape.
    6. Never raises. A provider failing, a missing API key, no
       internet at all, or the engine being unavailable for any
       reason all degrade to an empty or partial enrichment block —
       analysis continues exactly as before Step 9.

The Threat Intelligence engine/models/providers themselves are
FROZEN and are only ever imported here, never modified.
"""

import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from modules.threat_intel.models import (
    Ioc,
    IocType,
    EnrichmentResult,
    ProviderResult,
    ThreatIntelResult,
    LookupError,
)
from modules.threat_intel.engine import enrich_ioc


# ==========================================
# LOGGING SETUP
# ==========================================

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/threat_intel.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)


# ==========================================
# CONFIGURATION
# ==========================================
#
# The frozen engine's enrich_ioc(ioc, config) takes a plain dict of
# provider credentials, e.g. {"virustotal_api_key": "...", ...} — see
# the config_key values on each ProviderRegistration in
# modules/threat_intel/engine.py's PROVIDERS list. This loader is
# intentionally independent of the OLDER modules/config.py (the
# previous, now-superseded provider system's config loader) — it reads
# the same environment variables / local JSON file directly rather
# than importing anything from that older system, so this module has
# no dependency on it either way.

MAX_WORKERS = 5

_CONFIG_FILE = ".threat_intel_config.json"

# provider config_key (as used by ProviderRegistration in engine.py) -> env var
_ENV_KEY_NAMES: Dict[str, str] = {
    "virustotal_api_key": "VT_API_KEY",
    "otx_api_key": "OTX_API_KEY",
    "abuseipdb_api_key": "ABUSEIPDB_API_KEY",
}


def load_provider_config() -> Dict[str, Any]:
    """
    Best-effort provider credential loader.

    Resolution order per key: environment variable, then the local
    JSON config file, matching the precedence the previous provider
    system used. Never raises — a missing or malformed config file, or
    no credentials configured at all, simply resolves to an empty (or
    partially empty) dict, which the frozen engine already handles
    gracefully (providers requiring a key it doesn't have are skipped,
    not treated as failures).
    """

    config: Dict[str, Any] = {}

    if os.path.exists(_CONFIG_FILE):
        try:
            with open(_CONFIG_FILE, "r") as f:
                data = json.load(f)

            providers = data.get("providers", {}) if isinstance(data, dict) else {}

            for config_key in _ENV_KEY_NAMES:
                provider_name = config_key[: -len("_api_key")]
                entry = providers.get(provider_name, {})
                if isinstance(entry, dict) and entry.get("api_key"):
                    config[config_key] = entry["api_key"]

        except (OSError, ValueError) as e:
            log.error(f"Could not read {_CONFIG_FILE}: {e}")

    for config_key, env_var in _ENV_KEY_NAMES.items():
        env_val = os.environ.get(env_var)
        if env_val:
            config[config_key] = env_val  # env overrides the file

    return config


# ==========================================
# IOC COLLECTION (dedup)
# ==========================================

_CATEGORY_TO_TYPE: Dict[str, IocType] = {
    "URLs": IocType.URL,
    "Domains": IocType.DOMAIN,
    "IPs": IocType.IP,
}


def _collect_jobs(ioc_data: Dict[str, List[str]]) -> List[Tuple[str, Ioc]]:
    """
    Build a flat [(category, Ioc), ...] job list from the already-
    extracted, already-deduplicated IOC lists, with an additional
    defensive dedup pass across the whole dict by (type, value) — so
    "perform one enrichment and reuse the result" holds even if the
    same value could theoretically appear under more than one
    category. Only IOC types iocs.py actually extracts (URL, DOMAIN,
    IP) are ever produced here — HASH IOCs are simply never
    constructed, which is how "skip unsupported IOC types
    automatically" is satisfied for this integration point.
    """

    jobs: List[Tuple[str, Ioc]] = []
    seen: set = set()

    for category, ioc_type in _CATEGORY_TO_TYPE.items():

        for value in ioc_data.get(category, []) or []:

            key = (ioc_type, value)

            if key in seen:
                continue

            seen.add(key)
            jobs.append((category, Ioc(value=value, type=ioc_type)))

    return jobs


# ==========================================
# TYPED -> LEGACY SHAPE ADAPTER
# ==========================================
#
# modules.correlation, modules.attack_chain, modules.evidence_explorer,
# and modules.report all already read
# embedded_results["IOCs"]["Threat Intelligence"][category][value] as:
#     {"score": int, "confidence": str, "verdict": str,
#      "providers": {name: {"status": str, "malicious": bool|None,
#                            "reason": str|None}}}
# Producing that exact shape here — instead of asking every downstream
# consumer to learn the new typed models — is what satisfies "make the
# minimum changes required so they can consume the enrichment
# results" without touching any of those modules.

_MALICIOUS_SCORE_THRESHOLD = 70
_SUSPICIOUS_SCORE_THRESHOLD = 30


def _score_and_verdict(result: ThreatIntelResult) -> Tuple[int, str]:
    """
    Derive a 0-100 score and a malicious/suspicious/clean/unknown
    verdict from the aggregated ReputationFinding(s) already present
    on the typed ThreatIntelResult. Each provider's own malicious/total
    ratio is weighted equally and averaged — the engine already treats
    every ReputationFinding it aggregates as an equally legitimate
    signal (see models.merge_* / engine._aggregate), so this adapter
    does the same rather than re-introducing per-provider weighting.
    """

    ratios = [
        r.malicious / r.total
        for r in result.reputations
        if r.total > 0
    ]

    if not ratios:
        return 0, "unknown"

    score = int(round(min(100.0, max(0.0, (sum(ratios) / len(ratios)) * 100.0))))

    if score >= _MALICIOUS_SCORE_THRESHOLD:
        verdict = "malicious"
    elif score >= _SUSPICIOUS_SCORE_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return score, verdict


def _confidence_for(result: ThreatIntelResult) -> str:
    """
    Confidence reflects how many providers actually returned a
    reputation finding for this IOC — more independent corroboration
    is higher confidence, same rationale the previous system used.
    """

    responded = len(result.reputations)

    if responded == 0:
        return "None"
    if responded == 1:
        return "Low"
    if responded == 2:
        return "Medium"
    return "High"


def _provider_status(pr: ProviderResult) -> str:
    if pr.success:
        return "success"
    if pr.error is None:
        return "error"
    return pr.error.value


def _provider_malicious_flag(pr: ProviderResult) -> Optional[bool]:
    """
    True/False if this specific provider returned a reputation finding
    (ratio-based), None if it's a context-only provider (WHOIS/RDAP)
    or the lookup didn't succeed — matches the previous system's
    per-provider "malicious": bool|None convention.
    """

    if not pr.success or pr.data is None or pr.data.reputation is None:
        return None

    rep = pr.data.reputation

    if rep.total <= 0:
        return None

    return (rep.malicious / rep.total) >= (_SUSPICIOUS_SCORE_THRESHOLD / 100.0)


def _provider_detail(pr: ProviderResult) -> Dict[str, Any]:
    return {
        "status": _provider_status(pr),
        "malicious": _provider_malicious_flag(pr),
        "reason": pr.error_message,
    }


def _legacy_entry(enrichment: EnrichmentResult) -> Dict[str, Any]:
    """One IOC's full legacy-shaped Threat Intelligence entry."""

    score, verdict = _score_and_verdict(enrichment.result)
    confidence = _confidence_for(enrichment.result)

    providers = {
        pr.provider: _provider_detail(pr)
        for pr in enrichment.provider_results
    }

    return {
        "score": score,
        "confidence": confidence,
        "verdict": verdict,
        "providers": providers,
    }


# ==========================================
# PUBLIC ENTRY POINT
# ==========================================

def enrich_extracted_iocs(
    ioc_data: Dict[str, List[str]],
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Enrich every URL/Domain/IP already present in `ioc_data` (as
    produced by modules.parsers.iocs.extract_iocs()) via the frozen
    Threat Intelligence engine, and return the combined result.

    This is the ONLY function the orchestrator
    (modules/embedded_extraction.py) needs to call, and the ONLY place
    in the codebase enrichment logic lives, per Step 9's requirements.

    Args:
        ioc_data: {"URLs": [...], "Domains": [...], "IPs": [...]} —
            exactly what extract_iocs() already returns. Not mutated.
        config: provider credentials dict for the engine (see
            load_provider_config()). Defaults to loading it here if
            omitted, so callers don't have to.

    Returns:
        {
            "URLs":    {"<url>":    {"score": int, "confidence": str,
                                      "verdict": str, "providers": {...}}, ...},
            "Domains": {"<domain>": {...}, ...},
            "IPs":     {"<ip>":     {...}, ...},
            "_typed":  {"URLs": {"<url>": EnrichmentResult, ...},
                        "Domains": {...}, "IPs": {...}},
        }

    Always returns this shape — with empty sub-dicts as needed — and
    never raises. If the engine is unavailable, no providers are
    configured, there's no internet, or every lookup fails, this is
    simply an empty-but-valid "Threat Intelligence" block and PDF
    analysis continues unaffected, exactly as before Step 9.
    """

    legacy: Dict[str, Dict[str, Any]] = {"URLs": {}, "Domains": {}, "IPs": {}}
    typed: Dict[str, Dict[str, EnrichmentResult]] = {"URLs": {}, "Domains": {}, "IPs": {}}

    try:
        jobs = _collect_jobs(ioc_data or {})
    except Exception as e:
        log.error(f"Failed to build threat-intel job list: {e}")
        return {**legacy, "_typed": typed}

    if not jobs:
        return {**legacy, "_typed": typed}

    if config is None:
        try:
            config = load_provider_config()
        except Exception as e:
            log.error(f"Failed to load threat-intel provider config: {e}")
            config = {}

    # Cache by (type, value) so the SAME unique IOC — already
    # deduplicated by _collect_jobs() — is only ever enriched once,
    # even under concurrent execution.
    cache: Dict[Tuple[IocType, str], EnrichmentResult] = {}

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

            future_to_job = {
                executor.submit(enrich_ioc, ioc, config): (category, ioc)
                for category, ioc in jobs
            }

            for future in as_completed(future_to_job):

                category, ioc = future_to_job[future]
                cache_key = (ioc.type, ioc.value)

                try:
                    enrichment = future.result()
                except Exception as e:
                    # One provider/engine failure must never affect the
                    # others or abort enrichment as a whole — log and
                    # move on, leaving this IOC unenriched.
                    log.error(
                        f"Threat intel enrichment failed for "
                        f"{ioc.type.value} '{ioc.value}': {e}"
                    )
                    continue

                cache[cache_key] = enrichment
                typed[category][ioc.value] = enrichment

                try:
                    legacy[category][ioc.value] = _legacy_entry(enrichment)
                except Exception as e:
                    log.error(
                        f"Failed to adapt threat-intel result for "
                        f"{ioc.type.value} '{ioc.value}': {e}"
                    )

    except Exception as e:
        # Executor-level failure (e.g. thread creation issues) — fall
        # back to whatever partial results were already gathered
        # rather than losing everything.
        log.error(f"Threat intel enrichment pass failed: {e}")

    return {**legacy, "_typed": typed}