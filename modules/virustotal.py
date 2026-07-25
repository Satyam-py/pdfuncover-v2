# modules/virustotal.py
#
# TODO REMOVE AFTER FULL MIGRATION
#
# This module is a thin compatibility shim over the new typed
# VirusTotal provider (modules/threat_intel/providers/virustotal.py).
# main.py and modules/analyzer.py still call query_virustotal(sha256,
# api_key) and expect the old flat dict shape
# ({"Found", "Malicious", "Suspicious", "Harmless", "Undetected",
# "Link"}). This wrapper adapts the new ProviderResult to that shape
# so no other module needs to change yet.
#
# Once main.py / analyzer.py are migrated to consume ProviderResult /
# ThreatIntelResult directly, delete this file and update their
# imports to modules.threat_intel.providers.virustotal.

from modules.threat_intel.providers.virustotal import lookup_hash
from modules.threat_intel.models import LookupError


def query_virustotal(sha256, api_key):
    """
    TODO REMOVE AFTER FULL MIGRATION
    Legacy-shaped wrapper around the new lookup_hash() provider call.
    """

    result = lookup_hash(sha256, api_key)

    if not result.success:

        if result.error == LookupError.NOT_FOUND:
            return {
                "Found": True,
                "Known Sample": False,
                "Message": "Hash not found in VirusTotal"
            }

        return {
            "Found": False,
            "Error": result.error.value if result.error else "unknown error"
        }

    rep = result.data.reputation

    return {
        "Found": True,
        "Malicious": rep.malicious,
        "Suspicious": rep.suspicious,
        "Harmless": rep.harmless,
        "Undetected": rep.undetected,
        "Total": rep.total,
        "Link": rep.permalink,
    }