# modules/report/model.py
"""
The Report Model.

This is the ONE internal representation every renderer (JSON, Markdown,
HTML, Plain Text — see modules/report/renderers.py) consumes. It exists
so formatting logic is written exactly once per format, and so that
adding a new output format never requires touching detection/scoring
code again.

build_report_model() performs NO new detection, scoring, or
correlation. It only reads results that already exist elsewhere in the
codebase:

    metadata            -> modules.metadata.extract_metadata()
    embedded_results     -> modules.embedded_extraction.extract_embedded_objects()
    analysis              -> modules.analyzer.analyze_results()
    evidence_graph        -> modules.evidence_explorer.build_evidence_graph()   (optional)
    correlation_result    -> modules.correlation.ThreatCorrelationEngine()      (optional,
                             standalone engine — not wired into the pipeline elsewhere)

Every field on ReportModel is either copied verbatim from one of those
inputs, or is a light, purely-presentational transformation (grouping,
deduplication, counting) of data that already exists. No severity,
verdict, score, or MITRE mapping is invented here.

STEP 13 MIGRATION NOTE: for Threat Intelligence data specifically,
_build_threat_intelligence() now reads the typed EnrichmentResult /
ThreatIntelResult / ReputationFinding objects the frozen Threat
Intelligence engine (modules/threat_intel/models.py,
modules/threat_intel/engine.py) produces, via
modules/threat_intel_pipeline.py — whenever that typed data is present
under embedded_results["IOCs"]["Threat Intelligence"]["_typed"]. It
falls back to the legacy per-category dict shape
({"score","confidence","verdict","providers"}) whenever "_typed" is
absent for a given category. The score/verdict/confidence values are
recomputed from ReputationFinding data using the exact same formula
the (frozen, unmodified) modules/threat_intel_pipeline.py adapter
already uses, so the resulting ThreatIntelEntry objects — and every
rendered report — are identical either way. This is an internal
data-source migration only.
"""

import hashlib
import logging
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional

# Typed Threat Intelligence models (frozen — see
# modules/threat_intel/models.py). Imported via a module alias, not
# individual names, since this file already defines its own local
# ProviderResult dataclass (the report model's per-provider display
# row) that would otherwise collide with the typed models' own
# ProviderResult class. Imported defensively so this module still
# works in legacy-only mode if the package were ever unavailable.
try:
    from modules.threat_intel import models as ti_models
    _TYPED_MODELS_AVAILABLE = True
except Exception:  # pragma: no cover - defensive only
    _TYPED_MODELS_AVAILABLE = False


# ==========================================
# LOGGING SETUP
# ==========================================

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/report.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)


TOOL_VERSION = "PDFUncover 1.0 — Professional Report Engine v1.0"


# ==========================================
# SUB-MODELS
# ==========================================

@dataclass
class ExecutiveSummary:
    overall_verdict: str = "UNKNOWN"
    risk_score: int = 0
    confidence: str = "None"
    threat_level: str = "UNKNOWN"
    overall_recommendation: str = ""


@dataclass
class ThreatSummary:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    total: int = 0


@dataclass
class ProviderResult:
    name: str
    status: Optional[str] = None
    malicious: Optional[bool] = None
    reason: Optional[str] = None


@dataclass
class ThreatIntelEntry:
    ioc: str
    ioc_type: str
    verdict: str = "unknown"
    score: int = 0
    confidence: str = "None"
    providers: List[ProviderResult] = field(default_factory=list)


@dataclass
class CorrelatedFinding:
    title: str
    severity: str = "Informational"
    confidence: str = "Low"
    evidence: str = ""
    recommendation: str = ""
    mitre: List[str] = field(default_factory=list)


@dataclass
class EvidenceTreeNode:
    id: str
    type: str
    name: str
    summary: str = ""
    risk: Optional[str] = None
    children: List["EvidenceTreeNode"] = field(default_factory=list)


@dataclass
class EmbeddedFileEntry:
    filename: str
    path: str
    file_type: str = "unknown"
    size_human: str = "unknown"
    sha256: Optional[str] = None
    threat_intel: Optional[str] = None
    risk: Optional[str] = None
    reasons: List[str] = field(default_factory=list)


@dataclass
class JavaScriptSection:
    detected: bool = False
    openaction: bool = False
    obfuscated: bool = False
    suspicious_functions: List[str] = field(default_factory=list)
    decoded_preview: str = ""


@dataclass
class NetworkIndicators:
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    hashes: List[str] = field(default_factory=list)


@dataclass
class MitreEntry:
    tactic: str
    technique: str
    reason: str


@dataclass
class Appendix:
    metadata: Dict[str, Any] = field(default_factory=dict)
    hashes: Dict[str, str] = field(default_factory=dict)
    parser_info: List[str] = field(default_factory=list)
    analysis_timestamp: str = ""
    tool_version: str = TOOL_VERSION


@dataclass
class ReportModel:
    target: str = ""
    executive_summary: ExecutiveSummary = field(default_factory=ExecutiveSummary)
    threat_summary: ThreatSummary = field(default_factory=ThreatSummary)
    threat_intelligence: List[ThreatIntelEntry] = field(default_factory=list)
    correlated_findings: List[CorrelatedFinding] = field(default_factory=list)
    evidence_tree: Optional[EvidenceTreeNode] = None
    embedded_files: List[EmbeddedFileEntry] = field(default_factory=list)
    javascript: JavaScriptSection = field(default_factory=JavaScriptSection)
    network_indicators: NetworkIndicators = field(default_factory=NetworkIndicators)
    mitre_mappings: List[MitreEntry] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    appendix: Appendix = field(default_factory=Appendix)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==========================================
# SMALL HELPERS
# ==========================================

def safe_get(d: Any, *keys: str, default: Any = None) -> Any:
    current = d
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
        if current is default:
            return default
    return current


def _hash_file(path: str) -> Optional[str]:
    """Best-effort SHA256 of an already-extracted file. Never raises."""

    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()
    except OSError as e:
        log.error(f"Could not hash {path}: {e}")
        return None


def _human_size(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} bytes"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    return f"{num_bytes / (1024 * 1024):.2f} MB"


def _file_type_guess(path: str, data_head: bytes) -> str:
    """Best-effort content-type label from magic bytes/extension only —
    presentational, mirrors the same signatures embedded.py already
    inspects for its own suspicious-file heuristics."""

    ext = os.path.splitext(path.lower())[1]

    if data_head.startswith(b"MZ"):
        return "Windows Executable (MZ)"
    if data_head.startswith(b"PK\x03\x04"):
        return "ZIP/Office Archive"
    if data_head.startswith(b"%PDF-"):
        return "PDF Document"
    if data_head[:4] == b"\x7fELF":
        return "ELF Executable"
    if ext:
        return f"File ({ext})"
    return "Unknown"


# ==========================================
# SECTION BUILDERS
# ==========================================

def _build_executive_summary(
    analysis: Dict[str, Any],
    correlation_result: Optional[Dict[str, Any]],
) -> ExecutiveSummary:

    threat_level = analysis.get("Threat Level", "UNKNOWN")
    risk_score = analysis.get("Risk Score", 0)

    # Confidence: prefer the standalone correlation engine's aggregate
    # IOC confidence when supplied; otherwise derive a simple
    # presentational confidence from whether any Critical/High
    # evidence is present. No new scoring — just picking which
    # already-computed confidence value to surface.
    confidence = "Medium"
    if correlation_result:
        confidence = safe_get(
            correlation_result, "Overall IOC Reputation", "Confidence",
            default=confidence
        )
    else:
        evidence = safe_get(analysis, "Evidence Report", "evidence", default=[])
        if any(e.get("severity") == "Critical" for e in evidence):
            confidence = "High"
        elif any(e.get("severity") == "High" for e in evidence):
            confidence = "Medium"
        elif evidence:
            confidence = "Low"
        else:
            confidence = "None"

    recommendation_by_level = {
        "CLEAN": "No significant threats identified. Routine handling is sufficient.",
        "LOW": "Low risk. Review the findings below before further distribution.",
        "MEDIUM": "Medium risk. Handle with caution and verify flagged indicators.",
        "HIGH": "High risk. Do not open this file outside an isolated environment.",
        "CRITICAL": "Critical risk. Treat as confirmed malicious; escalate to incident response immediately.",
    }

    return ExecutiveSummary(
        overall_verdict=threat_level,
        risk_score=risk_score,
        confidence=confidence,
        threat_level=threat_level,
        overall_recommendation=recommendation_by_level.get(
            threat_level, "Review findings and escalate as appropriate."
        ),
    )


def _build_threat_summary(analysis: Dict[str, Any]) -> ThreatSummary:

    summary = safe_get(analysis, "Evidence Report", "summary", default={})

    return ThreatSummary(
        critical=summary.get("Critical", 0),
        high=summary.get("High", 0),
        medium=summary.get("Medium", 0),
        low=summary.get("Low", 0),
        informational=summary.get("Informational", 0),
        total=summary.get("Total Evidence", 0),
    )


# ==========================================
# THREAT INTELLIGENCE: TYPED -> REPORT-MODEL ADAPTER (Step 13)
# ==========================================
#
# _build_threat_intelligence() below still produces the exact same
# List[ThreatIntelEntry] it always has. What changed is WHERE each
# entry's score/verdict/confidence/providers come from: preferring the
# typed EnrichmentResult objects under
# threat_intelligence["_typed"][category] when present, computing the
# identical formula modules/threat_intel_pipeline.py's (frozen,
# unmodified) _legacy_entry() adapter already uses — so the two
# sources are numerically interchangeable — and falling back to the
# legacy per-category dict only when no typed section exists for that
# category at all.

_MALICIOUS_SCORE_THRESHOLD = 70
_SUSPICIOUS_SCORE_THRESHOLD = 30


def _verdict_for_score(score: Any) -> str:
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if score >= _MALICIOUS_SCORE_THRESHOLD:
        return "malicious"
    if score >= _SUSPICIOUS_SCORE_THRESHOLD:
        return "suspicious"
    return "clean"


def _score_from_reputations(result: Any) -> int:
    """
    Derive a 0-100 score from a typed ThreatIntelResult's
    ReputationFinding(s) — the same weighted-average formula
    modules/threat_intel_pipeline.py's frozen adapter uses (duplicated
    here as plain arithmetic, not imported, since that helper is
    private to the pipeline module), so this module computes the
    identical number whether it reads a typed ThreatIntelResult
    directly or the legacy dict's precomputed "score" field.
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


def _confidence_from_reputations(result: Any) -> str:
    """Same provider-count-based confidence tiering as
    modules/threat_intel_pipeline.py's frozen adapter."""

    responded = len(getattr(result, "reputations", None) or [])

    if responded == 0:
        return "None"
    if responded == 1:
        return "Low"
    if responded == 2:
        return "Medium"
    return "High"


def _provider_status(pr: Any) -> str:
    if getattr(pr, "success", False):
        return "success"
    error = getattr(pr, "error", None)
    if error is None:
        return "error"
    return getattr(error, "value", "error")


def _provider_malicious_flag(pr: Any) -> Optional[bool]:
    """True/False if this provider returned a reputation finding,
    None for context-only providers (WHOIS/RDAP) or failed lookups —
    matches the legacy per-provider "malicious": bool|None convention."""

    if not getattr(pr, "success", False):
        return None

    data = getattr(pr, "data", None)
    rep = getattr(data, "reputation", None) if data is not None else None
    if rep is None:
        return None

    total = getattr(rep, "total", 0)
    if total <= 0:
        return None

    return (rep.malicious / total) >= (_SUSPICIOUS_SCORE_THRESHOLD / 100.0)


def _threat_intel_entry_from_typed(
    ioc_value: str, ioc_type: str, enrichment: Any
) -> ThreatIntelEntry:
    """Build a ThreatIntelEntry directly from a typed EnrichmentResult."""

    result = getattr(enrichment, "result", None)

    if result is None:
        score, verdict, confidence = 0, "unknown", "None"
    else:
        score = _score_from_reputations(result)
        verdict = _verdict_for_score(score)
        confidence = _confidence_from_reputations(result)

    providers = [
        ProviderResult(
            name=pr.provider,
            status=_provider_status(pr),
            malicious=_provider_malicious_flag(pr),
            reason=getattr(pr, "error_message", None),
        )
        for pr in (getattr(enrichment, "provider_results", None) or [])
    ]

    return ThreatIntelEntry(
        ioc=ioc_value,
        ioc_type=ioc_type,
        verdict=verdict,
        score=score,
        confidence=confidence,
        providers=providers,
    )


def _threat_intel_entry_from_legacy(
    ioc_value: str, ioc_type: str, entry: Dict[str, Any]
) -> ThreatIntelEntry:
    """Build a ThreatIntelEntry from the legacy per-category dict
    shape — unchanged from the original implementation."""

    providers = [
        ProviderResult(
            name=pname,
            status=pdetail.get("status"),
            malicious=pdetail.get("malicious"),
            reason=pdetail.get("reason"),
        )
        for pname, pdetail in (entry.get("providers") or {}).items()
    ]

    return ThreatIntelEntry(
        ioc=ioc_value,
        ioc_type=ioc_type,
        verdict=entry.get("verdict", "unknown"),
        score=entry.get("score", 0),
        confidence=entry.get("confidence", "None"),
        providers=providers,
    )


def _ti_entries_for_category(
    ti_block: Dict[str, Any], category: str, ioc_type: str
) -> List[ThreatIntelEntry]:
    """
    Resolve every ThreatIntelEntry for one IOC category, preferring
    the typed "_typed" block when present for `category` — including
    when it's an empty dict (meaning the typed pipeline ran and found
    nothing of this type), which correctly overrides any stale legacy
    dict rather than falling back to it. Falls back to the legacy
    per-category dict shape only when no typed section exists for
    `category` at all.
    """

    typed_block = ti_block.get("_typed")

    if isinstance(typed_block, dict) and category in typed_block:
        section = typed_block.get(category)
        if isinstance(section, dict):
            return [
                _threat_intel_entry_from_typed(ioc_value, ioc_type, enrichment)
                for ioc_value, enrichment in section.items()
            ]

    section = ti_block.get(category) or {}
    return [
        _threat_intel_entry_from_legacy(ioc_value, ioc_type, entry)
        for ioc_value, entry in section.items()
    ]


def _build_threat_intelligence(embedded_results: Dict[str, Any]) -> List[ThreatIntelEntry]:

    ti_block = safe_get(embedded_results, "IOCs", "Threat Intelligence", default={})
    entries: List[ThreatIntelEntry] = []

    category_to_type = {"URLs": "url", "Domains": "domain", "IPs": "ip"}

    for category, ioc_type in category_to_type.items():
        entries.extend(_ti_entries_for_category(ti_block, category, ioc_type))

    return entries

    return entries


def _build_correlated_findings(
    analysis: Dict[str, Any],
    correlation_result: Optional[Dict[str, Any]],
) -> List[CorrelatedFinding]:

    findings: List[CorrelatedFinding] = []
    seen_titles = set()

    for item in safe_get(analysis, "Evidence Report", "correlations", default=[]):
        title = item.get("title", "Correlated Finding")
        if title in seen_titles:
            continue
        seen_titles.add(title)
        findings.append(CorrelatedFinding(
            title=title,
            severity=item.get("severity", "Informational"),
            confidence=item.get("confidence", "Low"),
            evidence=item.get("evidence", ""),
            recommendation=item.get("recommendation", ""),
            mitre=list(item.get("mitre") or []),
        ))

    if correlation_result:
        for item in correlation_result.get("Correlated Findings", []) or []:
            title = item.get("Title", "Correlated Finding")
            if title in seen_titles:
                continue
            seen_titles.add(title)
            findings.append(CorrelatedFinding(
                title=title,
                severity=item.get("Severity", "Informational"),
                confidence=item.get("Confidence", "Low"),
                evidence=item.get("Evidence", ""),
                recommendation=item.get("Recommendation", ""),
                mitre=list(item.get("MITRE ATT&CK") or []),
            ))

    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    findings.sort(key=lambda f: severity_rank.get(f.severity, 5))

    return findings


def _build_evidence_tree(
    evidence_graph: Optional[Dict[str, Any]],
    analysis: Dict[str, Any],
    metadata: Dict[str, Any],
) -> Optional[EvidenceTreeNode]:
    """
    Render the investigation tree. Prefers the real graph from
    modules.evidence_explorer.build_evidence_graph() (Artifacts +
    Relationships) when the caller supplies one. Falls back to a
    minimal PDF -> Metadata / Findings tree built purely from
    already-computed analysis fields when it isn't available, so the
    section is never simply empty.
    """

    if evidence_graph and evidence_graph.get("Artifacts"):

        artifacts = {a["id"]: a for a in evidence_graph["Artifacts"]}
        root_id = next(
            (aid for aid, a in artifacts.items() if a.get("parent") is None),
            None,
        )

        if root_id is None:
            return None

        def _build(node_id: str) -> EvidenceTreeNode:
            a = artifacts[node_id]
            return EvidenceTreeNode(
                id=a["id"],
                type=a["type"],
                name=a["name"],
                summary=a.get("summary", ""),
                risk=a.get("risk"),
                children=[_build(cid) for cid in a.get("children", []) if cid in artifacts],
            )

        return _build(root_id)

    # ---- Fallback: minimal tree from analysis alone ----

    root = EvidenceTreeNode(
        id="pdf:root",
        type="PDF",
        name=metadata.get("File Name", "Document"),
        summary=f"Threat Level: {analysis.get('Threat Level', 'UNKNOWN')}",
    )

    meta_node = EvidenceTreeNode(
        id="metadata",
        type="Metadata",
        name="Document Metadata",
        summary=", ".join(metadata.get("Suspicious Flags", [])) or "No anomalies",
    )
    root.children.append(meta_node)

    for item in safe_get(analysis, "Evidence Report", "evidence", default=[]):
        root.children.append(EvidenceTreeNode(
            id=f"evidence:{item.get('id', '')}",
            type=item.get("category", "Finding"),
            name=item.get("title", "Finding"),
            summary=item.get("evidence", ""),
            risk=item.get("severity"),
        ))

    return root


def _build_embedded_files(
    embedded_results: Dict[str, Any],
) -> List[EmbeddedFileEntry]:

    embedded_data = embedded_results.get("Embedded Files") or {}
    extracted = embedded_data.get("Extracted Files") or []
    suspicious = embedded_data.get("Suspicious Files") or []

    entries: List[EmbeddedFileEntry] = []

    for path in extracted:

        fname = os.path.basename(path)
        matching_flags = [s for s in suspicious if s.startswith(fname)]

        size_human = "unknown"
        file_type = "unknown"
        sha256 = None

        try:
            size_human = _human_size(os.path.getsize(path))
            with open(path, "rb") as f:
                head = f.read(16)
            file_type = _file_type_guess(path, head)
            sha256 = _hash_file(path)
        except OSError as e:
            log.error(f"Could not inspect embedded file {path}: {e}")

        entries.append(EmbeddedFileEntry(
            filename=fname,
            path=path,
            file_type=file_type,
            size_human=size_human,
            sha256=sha256,
            threat_intel="Not available (no hash-reputation lookup configured)",
            risk="Suspicious" if matching_flags else None,
            reasons=matching_flags,
        ))

    return entries


def _build_javascript(embedded_results: Dict[str, Any]) -> JavaScriptSection:

    js = embedded_results.get("JavaScript") or {}
    keywords = js.get("Suspicious Keywords", []) or []

    # A finding is "obfuscation" if any keyword overlaps the parser
    # layer's own EXPLOIT_API_KEYWORDS-complement — reuse whatever the
    # parser already flagged rather than re-deriving anything.
    exploit_keywords = {
        "app.launchURL", "this.exportDataObject",
        "Collab.collectEmailInfo", "util.printf",
    }
    obfuscation_keywords = [k for k in keywords if k not in exploit_keywords]

    return JavaScriptSection(
        detected=bool(js.get("JavaScript Detected")),
        openaction=bool(js.get("OpenAction Found")),
        obfuscated=bool(obfuscation_keywords),
        suspicious_functions=keywords,
        decoded_preview=js.get("Decoded JS Preview", ""),
    )


def _build_network_indicators(embedded_results: Dict[str, Any]) -> NetworkIndicators:

    iocs = embedded_results.get("IOCs") or {}

    return NetworkIndicators(
        urls=list(iocs.get("URLs", []) or []),
        domains=list(iocs.get("Domains", []) or []),
        ips=list(iocs.get("IPs", []) or []),
        emails=[],  # No email-address extraction exists upstream today.
        hashes=[],  # Embedded-file hashes are surfaced per-file in Section 6.
    )


def _build_mitre_mappings(
    analysis: Dict[str, Any],
) -> List[MitreEntry]:
    """
    Every MITRE technique already attached to an Evidence item is
    surfaced here as (Technique, Reason). No tactic taxonomy is
    tracked anywhere upstream, so "Tactic" is reported as "N/A" rather
    than guessed. Deduplicated by (technique, reason) pair.
    """

    entries: List[MitreEntry] = []
    seen = set()

    for item in safe_get(analysis, "Evidence Report", "evidence", default=[]):
        title = item.get("title", "Finding")
        for technique in item.get("mitre", []) or []:
            key = (technique, title)
            if key in seen:
                continue
            seen.add(key)
            entries.append(MitreEntry(tactic="N/A", technique=technique, reason=title))

    return entries


def _build_recommendations(
    analysis: Dict[str, Any],
    correlated_findings: List[CorrelatedFinding],
    network: NetworkIndicators,
    embedded_files: List[EmbeddedFileEntry],
) -> List[str]:
    """
    Actionable recommendations, built entirely from recommendations
    already attached to findings plus a small set of standard
    baseline actions gated on what was actually found (never invented
    detection — only "what to do about it").
    """

    recs: List[str] = []
    seen = set()

    def _add(text: str) -> None:
        if text and text not in seen:
            seen.add(text)
            recs.append(text)

    for f in correlated_findings:
        _add(f.recommendation)

    if network.urls or network.domains or network.ips:
        _add("Block the identified malicious IOC(s) at the firewall/proxy.")
        _add("Hunt for the same IOC(s) across the environment (SIEM/EDR retro-search).")

    if embedded_files:
        _add("Extract and statically analyze the embedded payload(s) in an isolated environment.")
        _add("Submit each extracted sample to a sandbox for dynamic analysis.")

    threat_level = analysis.get("Threat Level")
    if threat_level in ("HIGH", "CRITICAL"):
        _add("Investigate any endpoint where this file was opened.")
        _add("Review related email attachments/senders for the same campaign.")

    _add("Submit the file hash to VirusTotal or an equivalent multi-engine scanner.")

    return recs


def _build_appendix(
    metadata: Dict[str, Any],
    embedded_results: Dict[str, Any],
) -> Appendix:

    hashes = {
        "MD5": metadata.get("MD5", "N/A"),
        "SHA1": metadata.get("SHA1", "N/A"),
        "SHA256": metadata.get("SHA256", "N/A"),
    }

    parser_info = [
        name for name, present in {
            "pdf-parser": True,
            "pdfinfo": "pdfinfo" not in metadata or metadata.get("pdfinfo") != "Not installed",
            "exiftool": "exiftool" not in metadata or metadata.get("exiftool") != "Not installed",
            "qpdf": "Error" not in (embedded_results.get("Encryption") or {}),
            "pdfimages": "Error" not in (embedded_results.get("Images") or {}),
        }.items() if present
    ]

    return Appendix(
        metadata={k: v for k, v in metadata.items() if k != "Suspicious Flags"},
        hashes=hashes,
        parser_info=parser_info,
        analysis_timestamp=datetime.now().isoformat(),
        tool_version=TOOL_VERSION,
    )


# ==========================================
# MAIN ENTRY POINT
# ==========================================

def build_report_model(
    pdf_path: str,
    metadata: Dict[str, Any],
    embedded_results: Dict[str, Any],
    analysis: Dict[str, Any],
    evidence_graph: Optional[Dict[str, Any]] = None,
    correlation_result: Optional[Dict[str, Any]] = None,
) -> ReportModel:
    """
    Build the single Report Model every renderer consumes.

    All arguments except pdf_path are optional and default to an
    empty dict, so a caller mid-pipeline still gets a valid, partial
    model rather than an exception. This function performs no new
    detection/scoring — it only reorganizes results already produced
    by modules.metadata, modules.embedded_extraction, modules.analyzer,
    modules.evidence_explorer, and (optionally) modules.correlation.
    """

    metadata = metadata or {}
    embedded_results = embedded_results or {}
    analysis = analysis or {}

    correlated_findings = _build_correlated_findings(analysis, correlation_result)
    network = _build_network_indicators(embedded_results)
    embedded_files = _build_embedded_files(embedded_results)

    return ReportModel(
        target=metadata.get("File Name") or os.path.basename(pdf_path or "") or pdf_path,
        executive_summary=_build_executive_summary(analysis, correlation_result),
        threat_summary=_build_threat_summary(analysis),
        threat_intelligence=_build_threat_intelligence(embedded_results),
        correlated_findings=correlated_findings,
        evidence_tree=_build_evidence_tree(evidence_graph, analysis, metadata),
        embedded_files=embedded_files,
        javascript=_build_javascript(embedded_results),
        network_indicators=network,
        mitre_mappings=_build_mitre_mappings(analysis),
        recommendations=_build_recommendations(
            analysis, correlated_findings, network, embedded_files
        ),
        appendix=_build_appendix(metadata, embedded_results),
    )