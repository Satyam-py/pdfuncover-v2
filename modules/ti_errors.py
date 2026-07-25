# modules/ti_errors.py
"""
Closed error model for the threat-intelligence layer (Step 1).

Replaces free-text failure reasons (as used throughout the legacy
modules/providers.py and modules/reputation.py) with a small, closed
enum plus a structured LookupError. A caller can branch on *why* a
lookup failed instead of pattern-matching strings.

This module does no I/O and knows nothing about any specific provider.
It is a pure data model, imported by modules/ti_provider.py and
modules/ti_models.py.

Note: unsupported IOC types (e.g. calling a hash lookup on a provider
that only does URLs) are NOT represented as a LookupError — per the
provider interface contract, those return None. LookupError is
reserved for "this provider is a fit for this IOC type, but the
lookup itself did not produce a usable result."
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class LookupErrorReason(Enum):
    """
    Closed set of reasons a provider lookup can fail to produce a
    finding. Deliberately small — this is a dispatch key for callers,
    not a full error taxonomy. Anything that doesn't cleanly fit one
    of these is LOOKUP_FAILED with the detail in `LookupError.detail`.
    """

    # Provider has no usable API key / is administratively disabled.
    # Equivalent to today's status="skipped" in modules/providers.py.
    NOT_CONFIGURED = "not_configured"

    # Provider responded with a rate-limit signal (HTTP 429 or
    # equivalent). Distinct from LOOKUP_FAILED because callers may
    # want to back off and retry rather than treat this as permanent.
    RATE_LIMITED = "rate_limited"

    # The IOC value itself was malformed for this provider's API
    # (e.g. an IP string that fails validation) — not a network or
    # provider problem.
    INVALID_IOC = "invalid_ioc"

    # Provider responded successfully but had nothing on record for
    # this IOC. Distinct from LOOKUP_FAILED: the lookup worked, there
    # is just no data — e.g. VirusTotal's 404 case in the current
    # VirusTotalProvider._stats_result().
    NO_RESULTS = "no_results"

    # Catch-all: network error, HTTP error, malformed response body,
    # timeout, or any other failure mode where the lookup itself did
    # not complete successfully. Equivalent to today's status="error".
    LOOKUP_FAILED = "lookup_failed"


@dataclass(frozen=True)
class LookupError:
    """
    A single failed lookup attempt, attributable to one provider and
    one reason. `detail` is optional human-readable context for logs
    only — callers should branch on `reason`, never on `detail`.
    """

    provider: str
    reason: LookupErrorReason
    detail: Optional[str] = None