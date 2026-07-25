# modules/evidence_explorer.py
"""
Evidence Explorer.

Turns the results PDFUncover has ALREADY computed elsewhere in the
pipeline — modules/metadata.py, modules/embedded_extraction.py (+
modules/parsers/*), modules/analyzer.py's Evidence Report, and,
optionally, a standalone modules/correlation.py ThreatCorrelationEngine
result the caller already ran — into a single investigation graph: a
tree of Artifacts connected by Relationships, in the shape a DFIR
analyst would click through:

    PDF
    +-- Metadata
    |   +-- Hash
    |       +-- Threat Intelligence (VirusTotal)
    +-- Object "12 0 obj"
    |   +-- Stream (evidence)
    +-- URL
    |   +-- Threat Intelligence Summary
    |       +-- VirusTotal
    |       +-- URLHaus
    +-- Embedded File
    +-- Correlated Finding

This module performs NO detection and NO scoring of its own. Every
"risk" field on an Artifact is copied verbatim from a severity /
confidence / verdict / threat-level value that analyzer.py, the
parser Evidence model (modules/parsers/evidence.py), or the threat
intel reputation layer already assigned — never computed here. It
only reorganizes information that already exists into a queryable,
JSON-serializable graph.

It is intentionally read-only with respect to every other module: it
never calls into modules/parsers, modules/correlation, or the Threat
Intelligence engine/providers. Callers hand it whatever result dicts
they already produced (metadata, embedded results, the analyzer's
`analysis` dict, and optionally a ThreatCorrelationEngine result);
this module only walks those dicts.

STEP 12 MIGRATION NOTE: for Threat Intelligence data specifically,
this module now reads the typed EnrichmentResult / ThreatIntelResult
/ ReputationFinding objects the frozen Threat Intelligence engine
(modules/threat_intel/models.py, modules/threat_intel/engine.py)
produces, via modules/threat_intel_pipeline.py — whenever that typed
data is present under
embedded_results["IOCs"]["Threat Intelligence"]["_typed"]. It falls
back to the legacy per-category dict shape
({"score","confidence","verdict","providers"}) whenever "_typed" is
absent for a given category. This is the one place this module reads
a typed model's dataclass fields directly (see _entry_from_typed()
below) — it still performs no scoring of its own; the score/verdict/
confidence values are recomputed from ReputationFinding data using
the exact same formula the (frozen, unmodified)
modules/threat_intel_pipeline.py adapter already uses, so output is
identical either way. This is an internal data-source migration
only — every Artifact/Relationship this module produces, its shape,
its ordering, and its field values are unchanged.

Correlation to a *specific* underlying PDF object is only as good as
the data already carries: stream-level Evidence items already record
which stream they came from ("Stream 3"), so those group naturally.
Several other evidence kinds (JavaScript, IOCs, AcroForm) are not
tagged with an object number anywhere upstream today, so — rather
than guess — those artifacts attach directly to the PDF root. The one
best-effort exception is documented inline where it happens (pairing
extracted embedded files with pdf-parser's embedded-object headers
when, and only when, the two lists are the same length).

Public API:
    build_evidence_graph(
        pdf_path,
        metadata=None,
        embedded_results=None,
        analysis=None,
        correlation_result=None,
    ) -> dict
        {
            "Artifacts": [ {id, type, name, parent, children,
                             summary, risk, evidence, references}, ... ],
            "Relationships": [ {source, target, type}, ... ],
            "Artifact Count": int,
        }

    ArtifactType — the fixed vocabulary of artifact "type" values.
"""

import logging
import os
import re
from dataclasses import dataclass, field, asdict
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
    filename="logs/evidence_explorer.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)


# ==========================================
# ARTIFACT TYPE VOCABULARY
# ==========================================

class ArtifactType:
    """Fixed vocabulary of artifact "type" values, per spec."""

    PDF = "PDF"
    METADATA = "Metadata"
    OBJECT = "Indirect Object"
    STREAM = "Stream"
    JAVASCRIPT = "JavaScript"
    OPENACTION = "OpenAction"
    ACROFORM = "AcroForm"
    EMBEDDED_FILE = "Embedded File"
    IMAGE = "Image"
    URL = "URL"
    DOMAIN = "Domain"
    IP = "IP"
    HASH = "Hash"
    THREAT_INTEL = "Threat Intelligence"
    CORRELATED_FINDING = "Correlated Finding"


# ==========================================
# DATA MODEL
# ==========================================

@dataclass
class Artifact:
    """One node in the investigation graph."""

    id: str
    type: str
    name: str
    parent: Optional[str] = None
    children: List[str] = field(default_factory=list)
    summary: str = ""
    risk: Optional[str] = None
    evidence: List[Any] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Relationship:
    """One edge in the investigation graph."""

    source: str
    target: str
    type: str  # "contains" | "references" | "enriches" | "flags"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==========================================
# EVIDENCE ID -> ARTIFACT TYPE MAPPING
# ==========================================
#
# modules/parsers/evidence.py's make_evidence()/build_evidence() and
# modules/analyzer.py's analyzer-level evidence builders already tag
# every Evidence object with a stable, prefixed "id" (e.g.
# "js.openaction", "ioc.url.<slug>", "correlation.js_auto_exec").
# This table only maps those existing prefixes onto the fixed artifact
# vocabulary above — it adds no new classification logic beyond that
# lookup.

_EVIDENCE_TYPE_PREFIXES = (
    ("correlation.",           ArtifactType.CORRELATED_FINDING),
    ("vt.malicious",           ArtifactType.THREAT_INTEL),
    ("js.",                    ArtifactType.JAVASCRIPT),
    ("stream.",                ArtifactType.STREAM),
    ("ioc.url.",                ArtifactType.URL),
    ("ioc.ip.",                  ArtifactType.IP),
    ("embedded.executable.",    ArtifactType.EMBEDDED_FILE),
    ("embedded.file",           ArtifactType.EMBEDDED_FILE),
    ("compression.",            ArtifactType.STREAM),
    ("encryption.",             ArtifactType.METADATA),
    ("acroform.",                ArtifactType.ACROFORM),
    ("metadata.anomaly.",       ArtifactType.METADATA),
    ("header.",                  ArtifactType.METADATA),
)


def _evidence_artifact_type(evidence_id: str) -> str:
    """Map an existing Evidence object's id to an ArtifactType."""

    for prefix, atype in _EVIDENCE_TYPE_PREFIXES:
        if evidence_id.startswith(prefix):
            return atype

    return ArtifactType.METADATA


def _slug(text: str) -> str:
    """Short id-safe slug, used only to build stable artifact ids."""

    return re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")[:60]


# ==========================================
# THREAT INTELLIGENCE: TYPED -> LEGACY-SHAPED ADAPTER (Step 12)
# ==========================================
#
# The rest of this module (see the IOC/Threat Intelligence section of
# build_evidence_graph()) reads a `ti_entry` dict as
# {"score", "verdict", "confidence", "providers": {name: {"status",
# "malicious", "reason"}}} — the same legacy shape it always has. That
# code is unchanged. What changed is WHERE `ti_entry` comes from:
# _ti_entry_for() below prefers the typed EnrichmentResult objects
# under threat_intelligence["_typed"] when present, computing the
# exact same score/verdict/confidence formula
# modules/threat_intel_pipeline.py's (frozen, unmodified)
# _legacy_entry() adapter already uses — so the two sources are
# numerically interchangeable — and falls back to the legacy
# per-category dict only when no typed section exists for that
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


def _entry_from_typed(enrichment: Any) -> Optional[Dict[str, Any]]:
    """Build the same legacy-shaped entry dict from a typed
    EnrichmentResult, so every existing consumer below needs no
    changes at all."""

    result = getattr(enrichment, "result", None)
    if result is None:
        return None

    score = _score_from_reputations(result)

    providers = {}
    for pr in getattr(enrichment, "provider_results", None) or []:
        providers[pr.provider] = {
            "status": _provider_status(pr),
            "malicious": _provider_malicious_flag(pr),
            "reason": getattr(pr, "error_message", None),
        }

    return {
        "score": score,
        "verdict": _verdict_for_score(score),
        "confidence": _confidence_from_reputations(result),
        "providers": providers,
    }


def _ti_entry_for(
    ti_block: Dict[str, Any], category: str, value: str
) -> Optional[Dict[str, Any]]:
    """
    Resolve one IOC's Threat Intelligence entry, preferring the typed
    "_typed" block for `category` when present — including when it's
    an empty dict (meaning the typed pipeline ran and simply found no
    data for this IOC type), which correctly overrides any stale
    legacy dict rather than falling back to it. Falls back to the
    legacy per-category dict shape only when no typed section exists
    for `category` at all.
    """

    typed_block = ti_block.get("_typed")

    if isinstance(typed_block, dict) and category in typed_block:
        section = typed_block.get(category)
        if isinstance(section, dict):
            enrichment = section.get(value)
            if enrichment is None:
                return None
            return _entry_from_typed(enrichment)

    return (ti_block.get(category) or {}).get(value)


# ==========================================
# GRAPH BUILDER
# ==========================================

class InvestigationGraph:
    """
    Thin bookkeeping wrapper: holds Artifacts keyed by id plus a flat
    Relationships list, and keeps parent/child pointers and the
    Relationships list in sync so callers never have to do both by
    hand.
    """

    def __init__(self) -> None:
        self.artifacts: Dict[str, Artifact] = {}
        self.relationships: List[Relationship] = []

    def add(self, artifact: Artifact) -> None:
        """Register a new artifact. Duplicate ids are logged and skipped."""

        if artifact.id in self.artifacts:
            log.error(f"Duplicate artifact id skipped: {artifact.id}")
            return

        self.artifacts[artifact.id] = artifact

    def link(self, parent_id: str, child_id: str, rel_type: str = "contains") -> None:
        """Attach child_id under parent_id (tree edge)."""

        parent = self.artifacts.get(parent_id)
        child = self.artifacts.get(child_id)

        if parent is None or child is None:
            log.error(f"link() referenced missing artifact: {parent_id} -> {child_id}")
            return

        if child_id not in parent.children:
            parent.children.append(child_id)

        if child.parent is None:
            child.parent = parent_id

        self.relationships.append(Relationship(parent_id, child_id, rel_type))

    def reference(self, source_id: str, target_id: str, rel_type: str = "references") -> None:
        """Record a non-tree cross-link (e.g. a finding citing an IOC)."""

        source = self.artifacts.get(source_id)

        if source is None or target_id not in self.artifacts:
            log.error(f"reference() referenced missing artifact: {source_id} -> {target_id}")
            return

        if target_id not in source.references:
            source.references.append(target_id)

        self.relationships.append(Relationship(source_id, target_id, rel_type))

    def to_result(self) -> Dict[str, Any]:
        return {
            "Artifacts": [a.to_dict() for a in self.artifacts.values()],
            "Relationships": [r.to_dict() for r in self.relationships],
            "Artifact Count": len(self.artifacts),
        }


# ==========================================
# MAIN ENTRY POINT
# ==========================================

def build_evidence_graph(
    pdf_path: str,
    metadata: Optional[Dict[str, Any]] = None,
    embedded_results: Optional[Dict[str, Any]] = None,
    analysis: Optional[Dict[str, Any]] = None,
    correlation_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build the investigation graph from results already produced by:

        metadata            -> modules.metadata.extract_metadata()
        embedded_results     -> modules.embedded_extraction.extract_embedded_objects()
        analysis              -> modules.analyzer.analyze_results()
        correlation_result   -> modules.correlation.ThreatCorrelationEngine().correlate()
                                 (optional — that engine is not wired into the
                                 pipeline yet; pass its result in if you have it)

    Every argument except pdf_path is optional and defaults to an
    empty dict, so a caller mid-pipeline (e.g. before threat analysis
    has run) still gets a valid, partial graph rather than an
    exception.

    Returns {"Artifacts": [...], "Relationships": [...], "Artifact Count": int}.
    """

    metadata = metadata or {}
    embedded_results = embedded_results or {}
    analysis = analysis or {}

    graph = InvestigationGraph()

    # ---------------------------------------------------------
    # ROOT: the PDF itself
    # ---------------------------------------------------------

    root_id = "pdf:root"
    file_name = metadata.get("File Name") or os.path.basename(pdf_path or "") or "Unknown PDF"

    threat_level = analysis.get("Threat Level")
    risk_score = analysis.get("Risk Score")

    summary_parts = []
    if threat_level is not None:
        summary_parts.append(f"Threat Level: {threat_level}")
    if risk_score is not None:
        summary_parts.append(f"Risk Score: {risk_score}/100")

    root = Artifact(
        id=root_id,
        type=ArtifactType.PDF,
        name=file_name,
        summary="; ".join(summary_parts) or "PDF document",
        risk=threat_level,
    )
    graph.add(root)

    # ---------------------------------------------------------
    # METADATA (+ HASH, + hash-level VirusTotal if present)
    # ---------------------------------------------------------

    meta_id = "metadata:root"
    meta_summary = ", ".join(
        f"{k}: {metadata[k]}"
        for k in ("Title", "Author", "Creator", "Producer",
                   "CreationDate", "ModDate", "Pages")
        if metadata.get(k)
    )
    meta_artifact = Artifact(
        id=meta_id,
        type=ArtifactType.METADATA,
        name="Document Metadata",
        summary=meta_summary or "Extracted document metadata",
        evidence=list(metadata.get("Suspicious Flags", []) or []),
    )
    graph.add(meta_artifact)
    graph.link(root_id, meta_id)

    sha256 = metadata.get("SHA256")
    if sha256 and sha256 != "Error":

        hash_id = f"hash:{sha256}"
        hash_artifact = Artifact(
            id=hash_id,
            type=ArtifactType.HASH,
            name=sha256,
            summary=f"MD5: {metadata.get('MD5', 'N/A')}  SHA1: {metadata.get('SHA1', 'N/A')}",
        )
        graph.add(hash_artifact)
        graph.link(meta_id, hash_id)

        # main.py / analyzer.py both read metadata.get("VirusTotal", {})
        # for a hash-level VT verdict when a caller has populated it;
        # surface that here too, if present.
        vt = metadata.get("VirusTotal") or {}
        if vt.get("Found"):
            malicious = vt.get("Malicious", 0)
            vt_id = f"ti:hash:{sha256}:virustotal"
            vt_artifact = Artifact(
                id=vt_id,
                type=ArtifactType.THREAT_INTEL,
                name="VirusTotal",
                summary=(
                    f"{malicious} engine(s) flagged this hash as malicious"
                    if malicious else "No VirusTotal detections for this hash"
                ),
                risk="malicious" if malicious else "clean",
                evidence=[vt],
            )
            graph.add(vt_artifact)
            graph.link(hash_id, vt_id)

    # ---------------------------------------------------------
    # EVIDENCE REPORT ITEMS -> ARTIFACTS
    # ---------------------------------------------------------
    # Prefer analyzer.py's full Evidence Report (parser evidence +
    # VT + metadata anomalies + correlated findings, all in one list);
    # fall back to the raw parser-level Evidence list if analysis
    # hasn't been run yet.

    evidence_report = analysis.get("Evidence Report") or {}
    evidence_list = evidence_report.get("evidence") or embedded_results.get("Evidence") or []

    object_artifacts: Dict[str, str] = {}   # object label -> artifact id

    def _object_artifact_for(obj_label: str) -> str:
        """Get-or-create an Indirect Object artifact for a known object label."""

        if obj_label not in object_artifacts:
            oid = f"object:{obj_label}"
            art = Artifact(
                id=oid,
                type=ArtifactType.OBJECT,
                name=obj_label,
                summary=f"PDF construct: {obj_label}",
            )
            graph.add(art)
            graph.link(root_id, oid)
            object_artifacts[obj_label] = oid

        return object_artifacts[obj_label]

    evidence_artifact_ids_by_id: Dict[str, str] = {}   # evidence "id" -> artifact id

    for item in evidence_list:

        eid = item.get("id", "") or ""
        art_id = f"evidence:{eid or _slug(item.get('title', 'finding'))}"

        if art_id in graph.artifacts:
            continue

        parent_id = root_id
        obj_label = item.get("object")
        if obj_label:
            parent_id = _object_artifact_for(obj_label)

        art = Artifact(
            id=art_id,
            type=_evidence_artifact_type(eid),
            name=item.get("title") or eid or "Finding",
            summary=item.get("evidence") or "",
            risk=item.get("severity"),
            evidence=[item],
            references=list(item.get("mitre") or []),
        )
        graph.add(art)
        graph.link(parent_id, art_id)
        evidence_artifact_ids_by_id[eid] = art_id

    # ---------------------------------------------------------
    # IOCs (URLs / Domains / IPs) + their Threat Intelligence
    # ---------------------------------------------------------
    # Built from the raw extracted lists (not just the Evidence
    # items above) because Domains have no dedicated Evidence entry
    # in modules/parsers/evidence.py today — only URLs and IPs do.

    ioc_data = embedded_results.get("IOCs") or {}
    ti_block = ioc_data.get("Threat Intelligence") or {}

    ioc_type_map = {
        "URLs": (ArtifactType.URL, "url"),
        "Domains": (ArtifactType.DOMAIN, "domain"),
        "IPs": (ArtifactType.IP, "ip"),
    }

    ioc_artifact_ids: Dict[str, Dict[str, str]] = {"URLs": {}, "Domains": {}, "IPs": {}}

    for category, (atype, prefix) in ioc_type_map.items():

        for value in ioc_data.get(category, []) or []:

            art_id = f"ioc:{prefix}:{value}"
            if art_id in graph.artifacts:
                continue

            art = Artifact(
                id=art_id,
                type=atype,
                name=value,
                summary=f"{atype} referenced inside the document",
            )
            graph.add(art)
            graph.link(root_id, art_id)
            ioc_artifact_ids[category][value] = art_id

            # Cross-reference the matching Evidence artifact, if one
            # exists (URLs/IPs only — see comment above re: Domains).
            for eid, eart_id in evidence_artifact_ids_by_id.items():
                if not (eid.startswith("ioc.url.") or eid.startswith("ioc.ip.")):
                    continue
                eart = graph.artifacts.get(eart_id)
                if eart and value in (eart.summary or ""):
                    graph.reference(eart_id, art_id, "references")

            # Threat Intelligence, one summary node + one node per
            # provider that actually responded.
            ti_entry = _ti_entry_for(ti_block, category, value)

            if ti_entry:

                overall_id = f"ti:{prefix}:{value}:overall"
                overall_art = Artifact(
                    id=overall_id,
                    type=ArtifactType.THREAT_INTEL,
                    name="Threat Intelligence Summary",
                    summary=(
                        f"Verdict: {ti_entry.get('verdict')}, "
                        f"Score: {ti_entry.get('score')}, "
                        f"Confidence: {ti_entry.get('confidence')}"
                    ),
                    risk=ti_entry.get("verdict"),
                    evidence=[ti_entry],
                )
                graph.add(overall_art)
                graph.link(art_id, overall_id, rel_type="enriches")

                for provider_name, provider_detail in (ti_entry.get("providers") or {}).items():

                    p_id = f"ti:{prefix}:{value}:{_slug(provider_name)}"
                    reason = provider_detail.get("reason")

                    p_art = Artifact(
                        id=p_id,
                        type=ArtifactType.THREAT_INTEL,
                        name=provider_name,
                        summary=(
                            f"status={provider_detail.get('status')}, "
                            f"malicious={provider_detail.get('malicious')}"
                            + (f", reason={reason}" if reason else "")
                        ),
                        risk=(
                            "malicious" if provider_detail.get("malicious")
                            else provider_detail.get("status")
                        ),
                        evidence=[provider_detail],
                    )
                    graph.add(p_art)
                    graph.link(overall_id, p_id, rel_type="enriches")

    # ---------------------------------------------------------
    # EMBEDDED FILES (per-file artifacts, from the extracted-file list)
    # ---------------------------------------------------------

    embedded_files_data = embedded_results.get("Embedded Files") or {}
    extracted_files = embedded_files_data.get("Extracted Files") or []
    suspicious_entries = embedded_files_data.get("Suspicious Files") or []
    embedded_object_headers = embedded_files_data.get("Embedded Objects") or []

    # Best-effort correlation ONLY: if the two lists are the same
    # length, pair extracted files with the object headers pdf-parser
    # reported in the same extraction pass, index-for-index. When they
    # don't line up (Strategy 2's inline files with no object number,
    # more than one embedded file per object, etc.) files are attached
    # directly to the PDF root instead of guessed at — this module
    # does not invent a correlation the upstream data doesn't support.
    paired_objects = (
        embedded_object_headers
        if len(embedded_object_headers) == len(extracted_files)
        else []
    )

    for idx, file_path in enumerate(extracted_files):

        fname = os.path.basename(file_path)
        art_id = f"embedded_file:{file_path}"

        parent_id = root_id
        if idx < len(paired_objects):
            parent_id = _object_artifact_for(paired_objects[idx])

        matching_flags = [s for s in suspicious_entries if s.startswith(fname)]

        art = Artifact(
            id=art_id,
            type=ArtifactType.EMBEDDED_FILE,
            name=fname,
            summary=f"Extracted to {file_path}",
            risk="suspicious" if matching_flags else None,
            evidence=matching_flags,
        )
        graph.add(art)
        graph.link(parent_id, art_id)

    # ---------------------------------------------------------
    # IMAGES (summary-level — pdfimages output isn't per-file elsewhere)
    # ---------------------------------------------------------

    image_data = embedded_results.get("Images") or {}
    if image_data.get("Images Found"):

        img_id = "images:summary"
        img_art = Artifact(
            id=img_id,
            type=ArtifactType.IMAGE,
            name="Extracted Images",
            summary=(
                f"{image_data.get('Image Count', 0)} image(s) extracted to "
                f"{image_data.get('Extracted To', 'None')}"
            ),
            evidence=list(image_data.get("Parser Errors") or []),
        )
        graph.add(img_art)
        graph.link(root_id, img_id)

    # ---------------------------------------------------------
    # OPTIONAL: standalone ThreatCorrelationEngine result
    # ---------------------------------------------------------
    # modules/correlation.py is not wired into the pipeline yet (see
    # its own module docstring). If a caller ran it separately and
    # passes the result in, its findings are folded into the graph
    # the same way analyzer.py's own correlated Evidence items are
    # above — reusing the already-computed Title/Severity/Confidence/
    # Evidence/MITRE fields verbatim.

    if correlation_result:

        for finding in correlation_result.get("Correlated Findings", []) or []:

            title = finding.get("Title", "Correlated Finding")
            art_id = f"correlation:{_slug(title)}"

            if art_id in graph.artifacts:
                continue

            art = Artifact(
                id=art_id,
                type=ArtifactType.CORRELATED_FINDING,
                name=title,
                summary=finding.get("Evidence", ""),
                risk=finding.get("Severity"),
                evidence=[finding],
                references=list(finding.get("MITRE ATT&CK") or []),
            )
            graph.add(art)
            graph.link(root_id, art_id)

            # Best-effort reference links to any IOC artifact this
            # finding's own evidence text happens to mention — reusing
            # text the engine already wrote, not inferring anything new.
            evidence_text = finding.get("Evidence", "") or ""
            for category_map in ioc_artifact_ids.values():
                for value, ioc_art_id in category_map.items():
                    if value and value in evidence_text:
                        graph.reference(art_id, ioc_art_id, "references")

        overall_rep = correlation_result.get("Overall IOC Reputation")
        if overall_rep:

            rep_id = "ti:overall_reputation"
            rep_art = Artifact(
                id=rep_id,
                type=ArtifactType.THREAT_INTEL,
                name="Overall IOC Reputation",
                summary=(
                    f"Verdict: {overall_rep.get('Overall Verdict')}, "
                    f"Confidence: {overall_rep.get('Confidence')}, "
                    f"{overall_rep.get('Malicious', 0)} malicious / "
                    f"{overall_rep.get('Total IOCs Checked', 0)} IOC(s) checked"
                ),
                risk=overall_rep.get("Overall Verdict"),
                evidence=[overall_rep],
            )
            graph.add(rep_art)
            graph.link(root_id, rep_id, rel_type="enriches")

    return graph.to_result()