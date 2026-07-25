# modules/reputation.py
"""
Turns a list of raw per-provider lookup results (as returned by the
provider classes in modules/providers.py) into a single, unified
reputation verdict for one IOC.

Responsibilities:
    - Normalizing each provider's raw response into a common shape
    - Correlating results across providers (how many actually
      responded, how many flagged the IOC as malicious)
    - Calculating a confidence level for the verdict, based on
      provider coverage/agreement
    - Calculating a single 0-100 reputation score
    - Returning one unified response dict

This module performs no network I/O itself and does not know about
any specific provider's API — it only consumes the standardized
`make_result(...)` shape defined in modules/providers.py. It is not
wired into analyzer.py, iocs.py, or report generation; it exists as a
reusable building block for modules/threat_intel.py.
"""

import logging
import os
from typing import Any, Dict, List, Optional


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
# CONSTANTS
# ==========================================

STATUS_SUCCESS = "success"
STATUS_ERROR = "error"
STATUS_SKIPPED = "skipped"
STATUS_NOT_SUPPORTED = "not_supported"

CONFIDENCE_HIGH = "High"
CONFIDENCE_MEDIUM = "Medium"
CONFIDENCE_LOW = "Low"
CONFIDENCE_NONE = "None"

VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_CLEAN = "clean"
VERDICT_UNKNOWN = "unknown"

# Providers considered more authoritative get slightly more weight in
# the aggregate score, without letting any single provider dominate it
# outright. Any provider not listed here defaults to WEIGHT_DEFAULT.
PROVIDER_WEIGHTS: Dict[str, float] = {
    "virustotal":            1.5,
    "google_safe_browsing":  1.3,
    "abuseipdb":              1.1,
    "urlhaus":                1.1,
    "threatfox":              1.0,
    "malwarebazaar":          1.0,
    "otx":                    0.9,
    "urlscan":                0.8,
}
WEIGHT_DEFAULT = 1.0


# ==========================================
# NORMALIZATION
# ==========================================

def normalize_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a single raw provider result (from
    modules.providers.make_result) into a consistent shape this module
    can reason about uniformly, regardless of which provider produced
    it or how "malicious"/"score" were populated.

    Returns:
        {
            "provider": str,
            "status": "success"|"error"|"skipped"|"not_supported",
            "responded": bool,   # status == "success"
            "malicious": bool | None,
            "weight": float,
        }
    """

    provider = result.get("provider", "unknown")
    status = result.get("status", STATUS_ERROR)
    malicious = result.get("malicious")

    if status != STATUS_SUCCESS:
        # A provider that errored, was skipped, or doesn't support
        # this IOC type contributes no verdict of its own.
        malicious = None

    return {
        "provider": provider,
        "status": status,
        "responded": status == STATUS_SUCCESS,
        "malicious": malicious,
        "weight": PROVIDER_WEIGHTS.get(provider, WEIGHT_DEFAULT),
    }


def normalize_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize a list of raw provider results."""
    return [normalize_result(r) for r in (results or [])]


# ==========================================
# CORRELATION
# ==========================================

def correlate_results(normalized: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Cross-reference normalized results to see how providers agree or
    disagree on this IOC.

    Returns:
        {
            "total_providers": int,       # providers actually queried
            "responded": int,              # status == success
            "skipped": int,                # no API key configured
            "errored": int,                # request failed
            "not_supported": int,          # provider doesn't do this IOC type
            "flagged_malicious": int,      # responded AND malicious=True
            "flagged_clean": int,          # responded AND malicious=False
            "agreement_ratio": float,      # flagged_malicious / responded (0 if none responded)
            "flagged_by": [str, ...],      # provider names that flagged it malicious
        }
    """

    total = len(normalized)
    responded = [n for n in normalized if n["responded"]]
    skipped = [n for n in normalized if n["status"] == STATUS_SKIPPED]
    errored = [n for n in normalized if n["status"] == STATUS_ERROR]
    not_supported = [n for n in normalized if n["status"] == STATUS_NOT_SUPPORTED]

    flagged_malicious = [n for n in responded if n["malicious"] is True]
    flagged_clean = [n for n in responded if n["malicious"] is False]

    agreement_ratio = (
        len(flagged_malicious) / len(responded) if responded else 0.0
    )

    return {
        "total_providers": total,
        "responded": len(responded),
        "skipped": len(skipped),
        "errored": len(errored),
        "not_supported": len(not_supported),
        "flagged_malicious": len(flagged_malicious),
        "flagged_clean": len(flagged_clean),
        "agreement_ratio": round(agreement_ratio, 2),
        "flagged_by": [n["provider"] for n in flagged_malicious],
    }


# ==========================================
# CONFIDENCE
# ==========================================

def calculate_confidence(correlation: Dict[str, Any]) -> str:
    """
    Confidence reflects how much we can trust the verdict — driven by
    how many providers actually responded and, if any flagged the IOC
    malicious, how much they agree with each other. It is deliberately
    independent of the reputation score itself: a single provider
    flagging something malicious is a different confidence situation
    than five providers agreeing.
    """

    responded = correlation["responded"]

    if responded == 0:
        return CONFIDENCE_NONE

    if responded == 1:
        return CONFIDENCE_LOW

    ratio = correlation["agreement_ratio"]

    # Multiple providers responded. High agreement (all say malicious,
    # or all say clean) is high confidence either way; split verdicts
    # across providers are inherently less certain.
    if ratio == 0.0 or ratio == 1.0:
        return CONFIDENCE_HIGH if responded >= 3 else CONFIDENCE_MEDIUM

    return CONFIDENCE_MEDIUM


# ==========================================
# REPUTATION SCORE
# ==========================================

def calculate_reputation_score(
    normalized: List[Dict[str, Any]],
    correlation: Dict[str, Any],
) -> int:
    """
    Compute a single 0-100 reputation score for the IOC:

        - 0   means no provider that responded found anything malicious
        - 100 means maximum confidence this IOC is malicious

    The score is a weighted vote: each responding provider contributes
    its configured weight toward either the "malicious" or "clean"
    side, and the score is the malicious side's share of total weight
    cast, scaled to 0-100. Providers that didn't respond (skipped,
    errored, not supported) contribute nothing either way, so a
    single confident detection from one provider still registers
    strongly rather than being diluted by unrelated non-responses.
    """

    responded = [n for n in normalized if n["responded"]]

    if not responded:
        return 0

    malicious_weight = sum(n["weight"] for n in responded if n["malicious"] is True)
    total_weight = sum(n["weight"] for n in responded)

    if total_weight <= 0:
        return 0

    score = (malicious_weight / total_weight) * 100.0

    return int(round(min(100.0, max(0.0, score))))


def _determine_verdict(score: int, correlation: Dict[str, Any]) -> str:
    """Map a reputation score (+ correlation context) to a plain verdict label."""

    if correlation["responded"] == 0:
        return VERDICT_UNKNOWN

    if score >= 70:
        return VERDICT_MALICIOUS

    if score >= 30:
        return VERDICT_SUSPICIOUS

    return VERDICT_CLEAN


# ==========================================
# UNIFIED RESPONSE
# ==========================================

def build_unified_response(
    ioc: str,
    ioc_type: str,
    raw_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Full pipeline: normalize -> correlate -> score -> confidence,
    assembled into the single response modules/threat_intel.py hands
    back to its caller for one IOC lookup.

    Returns:
        {
            "ioc": str,
            "ioc_type": str,
            "verdict": "malicious"|"suspicious"|"clean"|"unknown",
            "reputation_score": int,       # 0-100
            "confidence": "High"|"Medium"|"Low"|"None",
            "correlation": {...},          # see correlate_results()
            "providers": [                 # per-provider detail, in input order
                {
                    "provider": str,
                    "status": str,
                    "malicious": bool | None,
                    "reason": str | None,
                },
                ...
            ],
        }
    """

    normalized = normalize_results(raw_results)
    correlation = correlate_results(normalized)
    score = calculate_reputation_score(normalized, correlation)
    confidence = calculate_confidence(correlation)
    verdict = _determine_verdict(score, correlation)

    provider_detail = [
        {
            "provider": r.get("provider", "unknown"),
            "status": r.get("status", STATUS_ERROR),
            "malicious": r.get("malicious"),
            "reason": r.get("reason"),
        }
        for r in (raw_results or [])
    ]

    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "verdict": verdict,
        "reputation_score": score,
        "confidence": confidence,
        "correlation": correlation,
        "providers": provider_detail,
    }