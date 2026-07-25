# modules/attack_chain.py
"""
Attack Chain Reconstruction Engine.

Reconstructs the MOST LIKELY attack chain for a PDF using results that
already exist elsewhere in the codebase — it performs no dynamic
analysis and recalculates nothing. Every step below is built entirely
from static evidence already produced by:

    metadata               -> modules.metadata.extract_metadata()
    embedded_results        -> modules.embedded_extraction.extract_embedded_objects()
                                (JavaScript, OpenAction, Embedded Files,
                                Streams, IOCs + nested Threat Intelligence,
                                Evidence)
    analysis                 -> modules.analyzer.analyze_results()
                                (Evidence Report — used for richer, already
                                -written evidence text when available)
    correlation_result       -> optional modules.correlation.ThreatCorrelationEngine()
                                result (used only to read already-computed
                                hash-reputation correlated findings; this
                                module does not hash anything itself)

This module is intentionally standalone, exactly like
modules/correlation.py before it:
    - It does not modify, call into, or depend on analyzer.py.
    - It does not modify parsers, Threat Intelligence, the Correlation
      Engine, the Evidence Explorer, the Report Engine, or main.py.
    - It performs NO new detection, scoring, hashing, or network I/O.
    - It is NOT wired into main.py yet. It exposes a pure function /
      class a future integration step can call.

STEP 11 MIGRATION NOTE: this module now reads Threat Intelligence
verdicts directly from the typed EnrichmentResult / ThreatIntelResult
/ ReputationFinding objects the frozen Threat Intelligence engine
(modules/threat_intel/models.py, modules/threat_intel/engine.py)
produces, via modules/threat_intel_pipeline.py — whenever that typed
data is present under
embedded_results["IOCs"]["Threat Intelligence"]["_typed"]. It falls
back to parsing the legacy per-category dict shape
({"score","confidence","verdict","providers"}) whenever "_typed" is
absent. See _Context._malicious_iocs() /._suspicious_iocs() below.
This is an internal data-source migration only — every rule's
ordering, wording, confidence value, MITRE mapping, and evidence
string is unchanged, and the "Attack Chain" output schema is
identical either way.

WORDING DISCIPLINE
-------------------
This module reconstructs PROBABLE behavior from static artifacts, not
confirmed execution. A PDF's own JavaScript/OpenAction/embedded-file
structure describes what the file is *capable of* and *wired to do*
when opened in a susceptible reader — it is not proof any of it ran.
Every step description therefore uses hedged language ("likely",
"possible", "inferred", "probable") and never an absolute claim like
"executed", "ran", "downloaded", or "connected". This is enforced by
_hedge() below, which every rule's description passes through.
"""

import logging
import os
import re
from typing import Any, Dict, List, Optional

# Typed Threat Intelligence models (frozen — see
# modules/threat_intel/models.py). Imported defensively so this
# module still works in legacy-only mode if the package were ever
# unavailable; not modified here.
try:
    from modules.threat_intel.models import (
        ThreatIntelResult,
        EnrichmentResult,
        ReputationFinding,
        DomainContext,
        IPContext,
        UrlContext,
        FileContext,
    )
    _TYPED_MODELS_AVAILABLE = True
except Exception:  # pragma: no cover - defensive only
    _TYPED_MODELS_AVAILABLE = False


# ==========================================
# LOGGING SETUP
# ==========================================

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/attack_chain.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)


# ==========================================
# CONFIDENCE VOCABULARY
# ==========================================
#
# Same three-tier vocabulary used throughout the rest of the codebase
# (modules/parsers/evidence.py, modules/correlation.py) for
# consistency. Confidence here reflects how directly the static
# evidence supports the *inferred step*, not whether the step actually
# happened — it never happened as far as this module is concerned; see
# module docstring.

CONFIDENCE_HIGH = "High"
CONFIDENCE_MEDIUM = "Medium"
CONFIDENCE_LOW = "Low"


# ==========================================
# LOCAL, SELF-CONTAINED CONSTANTS
# ==========================================
#
# Deliberately local/minimal rather than imported from analyzer.py or
# correlation.py, matching the zero-coupling pattern correlation.py
# itself already uses. These are read-only classification lists, not
# new detection.

_JS_OBFUSCATION_KEYWORDS = frozenset({
    "eval", "unescape", "fromCharCode", "atob",
})

_JS_EXPLOIT_API_KEYWORDS = frozenset({
    "app.launchURL", "this.exportDataObject",
    "Collab.collectEmailInfo", "util.printf",
})

_EXECUTABLE_EXTENSIONS = (
    ".exe", ".dll", ".scr", ".cpl", ".com", ".bat", ".cmd",
    ".ps1", ".vbs", ".hta", ".msi",
)

_ARCHIVE_EXTENSIONS = (".zip", ".jar", ".rar", ".7z")

_MALICIOUS_SCORE_THRESHOLD = 70
_SUSPICIOUS_SCORE_THRESHOLD = 30


def _score_from_reputations(result: Any) -> int:
    """
    Derive a 0-100 score from a typed ThreatIntelResult's
    ReputationFinding(s), using the exact same weighted-average
    formula modules.threat_intel_pipeline._score_and_verdict() already
    uses (that function is frozen/private to the pipeline module, so
    this duplicates only the arithmetic, not any policy) — guaranteeing
    this module computes the identical number whether it reads a
    typed ThreatIntelResult directly or the legacy dict's precomputed
    "score" field.
    """

    reputations = getattr(result, "reputations", None) or []

    ratios = [
        r.malicious / r.total
        for r in reputations
        if getattr(r, "total", 0) > 0
    ]

    if not ratios:
        return 0

    return int(round(min(100.0, max(0.0, (sum(ratios) / len(ratios)) * 100.0))))


# ==========================================
# HEDGING
# ==========================================
#
# Any description text that does not already contain a hedge word is
# given one. This is a safety net, not the primary mechanism — every
# rule below is written with hedged language directly — but it means a
# future rule added carelessly still can't slip an absolute claim into
# the output.

_HEDGE_WORDS = (
    "likely", "possible", "possibly", "inferred", "probable", "probably",
    "may", "could", "suggests", "consistent with", "appears",
)

_ABSOLUTE_VERBS_RE = re.compile(
    r"\b(executed|ran|downloaded|connected|exfiltrated|installed|"
    r"launched|stole|compromised)\b",
    re.IGNORECASE,
)


def _hedge(text: str) -> str:
    """
    Ensure a step description reads as inferred behavior, never a
    claim of confirmed execution. Softens a small set of absolute
    verbs into their static-inference equivalents, and prefixes
    "Likely " if no hedge word is present at all.
    """

    def _soften(match: "re.Match") -> str:
        verb = match.group(0).lower()
        replacements = {
            "executed": "likely executes",
            "ran": "likely runs",
            "downloaded": "possibly downloads",
            "connected": "possibly connects",
            "exfiltrated": "possibly exfiltrates",
            "installed": "possibly installs",
            "launched": "possibly launches",
            "stole": "possibly attempts to steal",
            "compromised": "possibly compromises",
        }
        return replacements.get(verb, match.group(0))

    text = _ABSOLUTE_VERBS_RE.sub(_soften, text)

    lowered = text.lower()
    if not any(h in lowered for h in _HEDGE_WORDS):
        text = "Likely: " + text

    return text


# ==========================================
# SMALL HELPERS
# ==========================================

def safe_get(d: Any, *keys: str, default: Any = None) -> Any:
    """Safely traverse nested dicts without KeyError."""

    current = d
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
        if current is default:
            return default
    return current


def _step(
    title: str,
    description: str,
    evidence: List[str],
    confidence: str,
    mitre: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build one attack-chain step (step number assigned later, in
    narrative order, by reconstruct_attack_chain())."""

    return {
        "title": title,
        "description": _hedge(description),
        "evidence": [e for e in evidence if e],
        "confidence": confidence,
        "mitre": mitre or [],
    }


class _EvidenceLookup:
    """
    Thin helper over the already-computed Evidence list (preferring
    analysis["Evidence Report"]["evidence"] when available — it is the
    richer, analyzer-level list — and falling back to the raw
    embedded_results["Evidence"] list from the extraction layer).
    Used only to reuse existing evidence text verbatim rather than
    re-describing findings in this module's own words.
    """

    def __init__(self, analysis: Dict[str, Any], embedded_results: Dict[str, Any]):

        evidence_list = safe_get(analysis, "Evidence Report", "evidence", default=None)

        if evidence_list is None:
            evidence_list = embedded_results.get("Evidence") or []

        self._by_id: Dict[str, Dict[str, Any]] = {
            e.get("id"): e for e in evidence_list if isinstance(e, dict) and e.get("id")
        }
        self._by_prefix: Dict[str, List[Dict[str, Any]]] = {}

        for e in evidence_list:
            eid = e.get("id", "") if isinstance(e, dict) else ""
            if eid:
                self._by_prefix.setdefault(eid.split(".")[0], []).append(e)

    def text(self, evidence_id: str, fallback: str) -> str:
        item = self._by_id.get(evidence_id)
        return item.get("evidence", fallback) if item else fallback

    def has(self, evidence_id: str) -> bool:
        return evidence_id in self._by_id


# ==========================================
# CONTEXT
# ==========================================
#
# One pass over the already-computed results, gathering the flags each
# rule needs, so individual rules stay short and declarative. Building
# this context performs no new detection — every field is copied
# straight out of embedded_results / metadata / correlation_result.

class _Context:

    def __init__(
        self,
        metadata: Dict[str, Any],
        embedded_results: Dict[str, Any],
        analysis: Dict[str, Any],
        correlation_result: Optional[Dict[str, Any]],
    ):
        self.metadata = metadata
        self.embedded_results = embedded_results
        self.analysis = analysis
        self.correlation_result = correlation_result or {}
        self.evidence = _EvidenceLookup(analysis, embedded_results)

        js = embedded_results.get("JavaScript") or {}
        self.js_detected = bool(js.get("JavaScript Detected"))
        self.openaction = bool(js.get("OpenAction Found"))
        self.js_keywords = list(js.get("Suspicious Keywords") or [])
        self.js_preview = js.get("Decoded JS Preview", "")

        self.has_eval = "eval" in self.js_keywords
        self.obfuscation_keywords = [
            k for k in self.js_keywords if k in _JS_OBFUSCATION_KEYWORDS
        ]
        self.exploit_keywords = [
            k for k in self.js_keywords if k in _JS_EXPLOIT_API_KEYWORDS
        ]

        iocs = embedded_results.get("IOCs") or {}
        self.urls = list(iocs.get("URLs") or [])
        self.ti_block = iocs.get("Threat Intelligence") or {}

        self.malicious_urls = self._malicious_iocs("URLs")
        self.suspicious_urls = self._suspicious_iocs("URLs")

        embedded = embedded_results.get("Embedded Files") or {}
        self.extracted_files = list(embedded.get("Extracted Files") or [])
        self.suspicious_files = list(embedded.get("Suspicious Files") or [])

        self.embedded_exes = [
            p for p in self.extracted_files
            if os.path.splitext(p.lower())[1] in _EXECUTABLE_EXTENSIONS
        ]
        self.embedded_archives = [
            p for p in self.extracted_files
            if os.path.splitext(p.lower())[1] in _ARCHIVE_EXTENSIONS
        ]

        streams = embedded_results.get("Streams") or {}
        self.high_entropy_streams = list(streams.get("High Entropy Streams") or [])

        # Known-malware-hash corroboration is read verbatim from a
        # caller-supplied correlation_result, if present — this module
        # never hashes files or queries threat intel itself.
        self.hash_matched_titles = [
            f.get("Title", "")
            for f in (self.correlation_result.get("Correlated Findings") or [])
            if "Known Malware Hash" in (f.get("Title") or "")
        ]

    def _typed_section(self, category: str) -> Optional[Dict[str, Any]]:
        """
        Return the typed {value: EnrichmentResult} mapping for this
        category from ti_block["_typed"], if present — including when
        it's an empty dict (meaning the typed pipeline ran but found
        no IOCs of this type, which is still "typed data available"
        and must NOT fall back to legacy). Returns None only when no
        typed block exists at all for this category, signaling the
        legacy fallback path should be used instead.
        """

        typed_block = self.ti_block.get("_typed")

        if isinstance(typed_block, dict) and category in typed_block:
            section = typed_block.get(category)
            if isinstance(section, dict):
                return section

        return None

    def _verdict_from_typed(self, enrichment: Any) -> str:
        """Same score -> verdict mapping as _verdict_for_score(), fed
        from a typed EnrichmentResult's aggregated ReputationFinding(s)
        instead of a legacy dict's precomputed "score" field."""

        result = getattr(enrichment, "result", None)
        if result is None:
            return "unknown"

        return self._verdict_for_score(_score_from_reputations(result))

    def _verdict_for_score(self, score: Any) -> str:
        try:
            score = float(score)
        except (TypeError, ValueError):
            return "unknown"
        if score >= _MALICIOUS_SCORE_THRESHOLD:
            return "malicious"
        if score >= _SUSPICIOUS_SCORE_THRESHOLD:
            return "suspicious"
        return "clean"

    def _iocs_with_verdict(self, category: str, target_verdict: str) -> List[str]:
        """
        Shared implementation for _malicious_iocs()/_suspicious_iocs():
        prefers the typed EnrichmentResult section for `category` when
        present (Step 11), falling back to the legacy per-category dict
        shape ({"score","confidence","verdict","providers"}) exactly as
        before whenever no typed data is available.
        """

        typed_section = self._typed_section(category)

        if typed_section is not None:
            return [
                value
                for value, enrichment in typed_section.items()
                if self._verdict_from_typed(enrichment) == target_verdict
            ]

        out = []
        for value, entry in (self.ti_block.get(category) or {}).items():
            verdict = entry.get("verdict") or self._verdict_for_score(entry.get("score"))
            if verdict == target_verdict:
                out.append(value)
        return out

    def _malicious_iocs(self, category: str) -> List[str]:
        return self._iocs_with_verdict(category, "malicious")

    def _suspicious_iocs(self, category: str) -> List[str]:
        return self._iocs_with_verdict(category, "suspicious")


# ==========================================
# CHAIN RULES
# ==========================================
#
# Each rule inspects the context built above and, if (and only if) its
# specific static pattern is present, returns one step describing the
# inferred behavior. A rule returning None means that link in the
# chain wasn't observed — it is simply omitted, never guessed at.
#
# Rules are evaluated in narrative order (roughly matching the order a
# PDF would be processed by a reader: open -> trigger -> script ->
# decode -> network -> payload), NOT severity order — this module
# tells a story, not a ranked findings list.

def _rule_openaction_trigger(ctx: _Context) -> Optional[Dict[str, Any]]:

    if not ctx.openaction:
        return None

    return _step(
        title="Automatic Trigger on Document Open",
        description=(
            "The document contains an /OpenAction entry, which is likely "
            "wired to fire automatically the moment the file is opened in "
            "a compliant PDF reader, without any further user interaction."
        ),
        evidence=[
            ctx.evidence.text("js.openaction", "/OpenAction entry present in the document catalog."),
        ],
        confidence=CONFIDENCE_HIGH,
        mitre=["T1204.002"],
    )


def _rule_auto_js_execution(ctx: _Context) -> Optional[Dict[str, Any]]:

    if not (ctx.openaction and ctx.js_detected):
        return None

    return _step(
        title="Automatic JavaScript Execution",
        description=(
            "With both an /OpenAction trigger and embedded JavaScript "
            "present, the script is likely set up to run automatically "
            "as soon as the document opens, ahead of any explicit action "
            "from the victim."
        ),
        evidence=[
            ctx.evidence.text("js.detected", "Document contains a /JavaScript object."),
            ctx.evidence.text("js.openaction", "/OpenAction entry present in the document catalog."),
        ],
        confidence=CONFIDENCE_HIGH,
        mitre=["T1204.002", "T1059.007"],
    )


def _rule_code_execution_via_eval(ctx: _Context) -> Optional[Dict[str, Any]]:

    if not (ctx.js_detected and ctx.has_eval):
        return None

    return _step(
        title="Dynamic Code Execution",
        description=(
            "The embedded JavaScript calls eval(), which is commonly used "
            "to run a string as code at runtime — this is likely how any "
            "obfuscated or staged payload inside the script would end up "
            "executing."
        ),
        evidence=[
            "JavaScript uses eval() " + (
                f'(preview: "{ctx.js_preview}")' if ctx.js_preview else "(decoded content not extracted)."
            ),
        ],
        confidence=CONFIDENCE_MEDIUM,
        mitre=["T1059.007", "T1027"],
    )


def _rule_payload_decoding(ctx: _Context) -> Optional[Dict[str, Any]]:

    if not (ctx.js_detected and ctx.obfuscation_keywords):
        return None

    return _step(
        title="Possible Payload Decoding",
        description=(
            "The JavaScript uses obfuscation-associated API calls ("
            f"{', '.join(ctx.obfuscation_keywords)}), which are commonly "
            "used to decode or reconstruct a hidden payload at runtime "
            "rather than store it in plain, scannable form — the script "
            "possibly unpacks additional logic just before it would run."
        ),
        evidence=[
            ctx.evidence.text(
                "js.obfuscation",
                f"Suspicious API/keyword usage: {', '.join(ctx.obfuscation_keywords)}.",
            ),
        ],
        confidence=CONFIDENCE_MEDIUM,
        mitre=["T1027"],
    )


def _rule_network_communication(ctx: _Context) -> Optional[Dict[str, Any]]:

    if not (ctx.js_detected and ctx.urls):
        return None

    sample = ", ".join(ctx.urls[:3]) + (" ..." if len(ctx.urls) > 3 else "")

    return _step(
        title="Possible Network Communication",
        description=(
            "JavaScript is present alongside a URL referenced inside the "
            f"document ({sample}), which is consistent with a possible "
            "outbound network call — for a second-stage payload fetch, a "
            "tracking beacon, or a phishing redirect — once the script "
            "runs."
        ),
        evidence=[
            ctx.evidence.text(
                f"ioc.url.{ctx.urls[0]}" if ctx.urls else "",
                f"URL(s) referenced inside the document: {sample}",
            ),
        ],
        confidence=CONFIDENCE_LOW,
        mitre=["T1071.001"],
    )


def _rule_known_malicious_infrastructure(ctx: _Context) -> Optional[Dict[str, Any]]:

    if not ctx.malicious_urls:
        return None

    sample = ", ".join(ctx.malicious_urls[:3]) + (" ..." if len(ctx.malicious_urls) > 3 else "")

    return _step(
        title="Known-Malicious Infrastructure Referenced",
        description=(
            f"At least one referenced URL ({sample}) is independently "
            "flagged as malicious by threat intelligence, so any outbound "
            "request the document's script possibly makes would likely "
            "reach infrastructure already associated with malicious "
            "activity."
        ),
        evidence=[
            f"Threat intelligence verdict 'malicious' for: {sample}",
        ],
        confidence=CONFIDENCE_HIGH,
        mitre=["T1071.001", "T1583.001"],
    )


def _rule_embedded_exe_delivery(ctx: _Context) -> Optional[Dict[str, Any]]:

    if not ctx.embedded_exes:
        return None

    names = ", ".join(os.path.basename(p) for p in ctx.embedded_exes[:3])

    return _step(
        title="Possible Payload Delivery via Embedded Executable",
        description=(
            f"The document carries an embedded executable ({names}), "
            "which is consistent with the PDF acting as a dropper — the "
            "executable is possibly staged for delivery to the victim's "
            "machine, pending extraction or an automated launch action."
        ),
        evidence=[
            f"Embedded executable extracted: {names}",
            *[s for s in ctx.suspicious_files if any(
                os.path.basename(p) in s for p in ctx.embedded_exes
            )],
        ],
        confidence=CONFIDENCE_MEDIUM,
        mitre=["T1204.002", "T1105"],
    )


def _rule_embedded_zip_secondary_payload(ctx: _Context) -> Optional[Dict[str, Any]]:

    if not ctx.embedded_archives:
        return None

    names = ", ".join(os.path.basename(p) for p in ctx.embedded_archives[:3])

    return _step(
        title="Possible Secondary Payload via Embedded Archive",
        description=(
            f"The document carries an embedded archive ({names}). "
            "Archives are a common wrapper for a secondary payload, so "
            "this possibly represents a staged second stage rather than "
            "the final payload itself."
        ),
        evidence=[
            f"Embedded archive extracted: {names}",
        ],
        confidence=CONFIDENCE_LOW,
        mitre=["T1027", "T1105"],
    )


def _rule_known_malware_delivery(ctx: _Context) -> Optional[Dict[str, Any]]:

    if not ctx.hash_matched_titles:
        return None

    return _step(
        title="Known Malware Delivery",
        description=(
            "An embedded file's hash matches a sample already known to "
            "threat intelligence as malicious, so the file this document "
            "carries is likely a known malware sample rather than a novel "
            "or benign payload."
        ),
        evidence=list(dict.fromkeys(ctx.hash_matched_titles)),
        confidence=CONFIDENCE_HIGH,
        mitre=["T1204.002", "T1105"],
    )


def _rule_compound_delivery_attempt(ctx: _Context) -> Optional[Dict[str, Any]]:
    """
    OpenAction + JavaScript + malicious URL, all together — the
    strongest static corroboration of an end-to-end delivery attempt
    this module can infer without dynamic analysis.
    """

    if not (ctx.openaction and ctx.js_detected and ctx.malicious_urls):
        return None

    sample = ", ".join(ctx.malicious_urls[:3])

    return _step(
        title="Probable Automatic Malware Delivery Attempt",
        description=(
            "Taken together, the automatic /OpenAction trigger, the "
            "embedded JavaScript it is likely wired to run, and a "
            "document-referenced URL already flagged malicious "
            f"({sample}) form a probable end-to-end delivery chain: open "
            "the document, automatically run the script, and possibly "
            "reach out to known-malicious infrastructure — all without "
            "further user interaction."
        ),
        evidence=[
            "OpenAction + JavaScript + malicious URL corroboration "
            f"(URL: {sample})",
        ],
        confidence=CONFIDENCE_HIGH,
        mitre=["T1204.002", "T1059.007", "T1071.001"],
    )


# Narrative order. Each function is (name, rule) purely so a failing
# rule can be logged with context; the name itself has no effect on
# output.
_RULES = [
    ("openaction_trigger", _rule_openaction_trigger),
    ("auto_js_execution", _rule_auto_js_execution),
    ("code_execution_via_eval", _rule_code_execution_via_eval),
    ("payload_decoding", _rule_payload_decoding),
    ("network_communication", _rule_network_communication),
    ("known_malicious_infrastructure", _rule_known_malicious_infrastructure),
    ("embedded_exe_delivery", _rule_embedded_exe_delivery),
    ("embedded_zip_secondary_payload", _rule_embedded_zip_secondary_payload),
    ("known_malware_delivery", _rule_known_malware_delivery),
    ("compound_delivery_attempt", _rule_compound_delivery_attempt),
]


# ==========================================
# MAIN ENTRY POINT
# ==========================================

def reconstruct_attack_chain(
    metadata: Optional[Dict[str, Any]] = None,
    embedded_results: Optional[Dict[str, Any]] = None,
    analysis: Optional[Dict[str, Any]] = None,
    correlation_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Reconstruct the most likely attack chain from already-computed
    static analysis results.

    Every argument is optional and defaults to an empty dict, so a
    caller mid-pipeline still gets a valid (possibly empty) result
    rather than an exception. A single rule raising unexpectedly is
    caught and logged so it can never take down the whole
    reconstruction pass.

    Returns:
        {
            "Attack Chain": [
                {
                    "step": int,
                    "title": str,
                    "description": str,   # always hedged — see _hedge()
                    "evidence": [str, ...],
                    "confidence": "High"|"Medium"|"Low",
                    "mitre": [str, ...],
                },
                ...
            ]
        }

    If no static pattern in _RULES matches, "Attack Chain" is an empty
    list — this module never fabricates a chain from nothing.
    """

    metadata = metadata or {}
    embedded_results = embedded_results or {}
    analysis = analysis or {}

    try:
        ctx = _Context(metadata, embedded_results, analysis, correlation_result)
    except Exception as e:
        log.error(f"Failed to build attack-chain context: {e}")
        return {"Attack Chain": []}

    chain: List[Dict[str, Any]] = []

    for name, rule in _RULES:
        try:
            result = rule(ctx)
        except Exception as e:
            log.error(f"Attack-chain rule '{name}' failed: {e}")
            continue

        if result:
            chain.append(result)

    for i, step in enumerate(chain, start=1):
        step["step"] = i
        # Re-order keys so "step" reads first in any serialized output,
        # without changing any value.
        ordered = {
            "step": step["step"],
            "title": step["title"],
            "description": step["description"],
            "evidence": step["evidence"],
            "confidence": step["confidence"],
            "mitre": step["mitre"],
        }
        chain[i - 1] = ordered

    return {"Attack Chain": chain}


# ==========================================
# MODULE-LEVEL CONVENIENCE ALIAS
# ==========================================
#
# Matches the naming pattern modules/correlation.py uses
# (correlate_threats() alongside ThreatCorrelationEngine) so a future
# integration step can pick whichever style fits main.py.

def build_attack_chain(
    metadata: Optional[Dict[str, Any]] = None,
    embedded_results: Optional[Dict[str, Any]] = None,
    analysis: Optional[Dict[str, Any]] = None,
    correlation_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Alias of reconstruct_attack_chain() for naming-convention parity
    with modules.correlation.correlate_threats()."""

    return reconstruct_attack_chain(
        metadata=metadata,
        embedded_results=embedded_results,
        analysis=analysis,
        correlation_result=correlation_result,
    )