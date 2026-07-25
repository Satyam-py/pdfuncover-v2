# modules/parsers/ioc_enrichment.py
#
# Threat-intelligence enrichment for already-extracted IOCs.
#
# This module does NOT extract or validate IOCs — modules/parsers/iocs.py
# owns all of that (regexes, validation, dedup) and is unchanged. This
# module's only job is: given the final, already-deduplicated
# "URLs" / "Domains" / "IPs" lists iocs.py already produces, look each
# one up via modules.threat_intel.ThreatIntelManager and return a
# normalized "Threat Intelligence" block iocs.py can attach alongside
# its existing output.
#
# Design constraints (per integration requirements):
#   - Threat intelligence is entirely optional. No internet, no API
#     keys, every provider failing, or the threat-intel modules being
#     unavailable at all must never stop or alter PDF analysis — this
#     module always returns a (possibly empty) dict, never raises.
#   - No duplicate lookups: iocs.py's URL/Domain/IP lists are already
#     deduplicated (see iocs.py's `seen_*` sets), so looking up each
#     list entry once is sufficient — this module does not need its
#     own separate dedup layer, but does guard against the same IOC
#     appearing in a list twice regardless, as a defensive measure.
#   - Lookups run concurrently via ThreadPoolExecutor, capped at 5
#     workers total across all IOC types in a single enrichment pass.
#   - Failures are logged (via the standard `logging` module, into the
#     same log file iocs.py already writes to) — never printed, and
#     never raised as a stack trace to the terminal.

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple


# ==========================================
# LOGGING SETUP
# ==========================================

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/embedded_extraction.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)


# ==========================================
# CONFIGURATION
# ==========================================

MAX_WORKERS = 5

# Internal provider name -> display name used in output, so report
# consumers see "VirusTotal" / "URLHaus" / "OTX" etc. rather than the
# lowercase internal registry keys. Any provider not listed here falls
# back to its internal name unchanged.
_PROVIDER_DISPLAY_NAMES: Dict[str, str] = {
    "virustotal":            "VirusTotal",
    "urlhaus":                "URLHaus",
    "threatfox":              "ThreatFox",
    "malwarebazaar":          "MalwareBazaar",
    "otx":                    "OTX",
    "abuseipdb":              "AbuseIPDB",
    "google_safe_browsing":   "GoogleSafeBrowsing",
    "urlscan":                "Urlscan",
}

# Which ThreatIntelManager method to call for each IOC category this
# module handles.
_LOOKUP_METHOD_BY_CATEGORY = {
    "URLs":    "lookup_url",
    "Domains": "lookup_domain",
    "IPs":     "lookup_ip",
}


# ==========================================
# LAZY / SAFE MANAGER SINGLETON
# ==========================================
#
# The manager is built once and reused across calls (avoids re-reading
# config / re-instantiating providers per PDF). If the threat-intel
# modules can't be imported, or the manager fails to construct for any
# reason, this is cached as "unavailable" so every subsequent call
# short-circuits immediately instead of retrying and failing again.

_manager = None
_manager_unavailable = False


def _get_manager():
    """
    Return a shared ThreatIntelManager instance, or None if threat
    intelligence isn't available for any reason (missing dependency,
    construction failure, etc.). Never raises.
    """

    global _manager, _manager_unavailable

    if _manager_unavailable:
        return None

    if _manager is not None:
        return _manager

    try:
        from modules.threat_intel import ThreatIntelManager
        _manager = ThreatIntelManager()
        return _manager

    except Exception as e:
        log.error(f"Threat intelligence unavailable — continuing without it: {e}")
        _manager_unavailable = True
        return None


# ==========================================
# NORMALIZATION
# ==========================================

def _display_provider_name(name: str) -> str:
    return _PROVIDER_DISPLAY_NAMES.get(name, name)


def _normalize_entry(unified_response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert one modules.reputation.build_unified_response() result into
    the compact per-IOC shape attached to the report:

        {
            "score": int,
            "confidence": "High"|"Medium"|"Low"|"None",
            "verdict": "malicious"|"suspicious"|"clean"|"unknown",
            "providers": {
                "VirusTotal": {"status": "...", "malicious": bool|None, "reason": str|None},
                ...
            }
        }
    """

    providers_detail = {}

    for entry in unified_response.get("providers", []) or []:
        provider_name = _display_provider_name(entry.get("provider", "unknown"))
        providers_detail[provider_name] = {
            "status": entry.get("status"),
            "malicious": entry.get("malicious"),
            "reason": entry.get("reason"),
        }

    return {
        "score": unified_response.get("reputation_score", 0),
        "confidence": unified_response.get("confidence", "None"),
        "verdict": unified_response.get("verdict", "unknown"),
        "providers": providers_detail,
    }


# ==========================================
# ENRICHMENT
# ==========================================

def _build_jobs(ioc_data: Dict[str, List[str]]) -> List[Tuple[str, str]]:
    """
    Build a flat, de-duplicated (category, ioc) job list from the
    already-extracted, already-deduplicated IOC lists. Defensive
    dedup here too, in case a caller ever hands in a list with repeats
    — "the same URL appearing 20 times" must still resolve to exactly
    one lookup.
    """

    jobs: List[Tuple[str, str]] = []
    seen: set = set()

    for category in _LOOKUP_METHOD_BY_CATEGORY:

        for ioc in ioc_data.get(category, []) or []:

            key = (category, ioc)

            if key in seen:
                continue

            seen.add(key)
            jobs.append(key)

    return jobs


def enrich_iocs(ioc_data: Dict[str, List[str]]) -> Dict[str, Dict[str, Any]]:
    """
    Look up every URL/Domain/IP already present in `ioc_data` via the
    ThreatIntelManager and return the "Threat Intelligence" block:

        {
            "URLs":    {"<url>":    {"score": ..., "confidence": ..., "providers": {...}}, ...},
            "Domains": {"<domain>": {...}, ...},
            "IPs":     {"<ip>":     {...}, ...},
        }

    Always returns this shape (with empty sub-dicts as needed) — never
    raises. If threat intelligence is unavailable (no manager, no
    providers configured, no internet, every lookup fails), the
    result is simply empty dicts and PDF analysis continues normally.
    """

    result: Dict[str, Dict[str, Any]] = {
        "URLs": {},
        "Domains": {},
        "IPs": {},
    }

    try:
        jobs = _build_jobs(ioc_data)
    except Exception as e:
        log.error(f"Failed to build IOC enrichment job list: {e}")
        return result

    if not jobs:
        return result

    manager = _get_manager()

    if manager is None:
        # No manager available at all — treat exactly like "every
        # provider failed": continue normally with empty enrichment.
        return result

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

            future_to_job = {}

            for category, ioc in jobs:

                method_name = _LOOKUP_METHOD_BY_CATEGORY[category]
                method = getattr(manager, method_name, None)

                if method is None:
                    continue

                future = executor.submit(method, ioc)
                future_to_job[future] = (category, ioc)

            for future in as_completed(future_to_job):

                category, ioc = future_to_job[future]

                try:
                    unified_response = future.result()
                    result[category][ioc] = _normalize_entry(unified_response)

                except Exception as e:
                    # A single IOC lookup failing (network error, bad
                    # response, provider bug, etc.) must never affect
                    # the others or abort enrichment as a whole.
                    singular = category[:-1] if category.endswith("s") else category
                    log.error(
                        f"Threat intel lookup failed for {singular} "
                        f"'{ioc}': {e}"
                    )

    except Exception as e:
        # Executor-level failure (e.g. thread creation issues) — fall
        # back to whatever partial results were already gathered
        # rather than losing everything.
        log.error(f"Threat intel enrichment pass failed: {e}")

    return result