# modules/report/engine.py
"""
Public entry point for the Professional Report Engine.

generate_professional_report() builds the Report Model (see
modules/report/model.py) from results that already exist elsewhere in
the pipeline, then renders it to every requested output format via
modules/report/renderers.py, writing each to disk.

This module performs no detection/scoring of its own — see the
module docstrings in model.py and renderers.py for the same guarantee.

This is additive: it does not replace or alter
modules.analyzer.generate_report(), which remains available for
backward compatibility with any existing caller/report format.
"""

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from modules.report.model import build_report_model
from modules.report.renderers import RENDERERS


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


DEFAULT_FORMATS = ("json", "markdown", "html", "text")

_EXTENSION_BY_FORMAT = {
    "json": "json",
    "markdown": "md",
    "md": "md",
    "html": "html",
    "text": "txt",
    "txt": "txt",
}


def generate_professional_report(
    pdf_path: str,
    metadata: Dict[str, Any],
    embedded_results: Dict[str, Any],
    analysis: Dict[str, Any],
    evidence_graph: Optional[Dict[str, Any]] = None,
    correlation_result: Optional[Dict[str, Any]] = None,
    output_dir: str = "output/reports",
    formats: Optional[List[str]] = None,
) -> Dict[str, str]:
    """
    Build the Report Model and render it to every requested format.

    Args:
        pdf_path: path to the analyzed PDF.
        metadata: modules.metadata.extract_metadata() output.
        embedded_results: modules.embedded_extraction.extract_embedded_objects() output.
        analysis: modules.analyzer.analyze_results() output.
        evidence_graph: optional modules.evidence_explorer.build_evidence_graph() output.
        correlation_result: optional modules.correlation.ThreatCorrelationEngine().correlate() output.
        output_dir: directory reports are written to.
        formats: subset of ("json", "markdown", "html", "text"); defaults to all four.

    Returns:
        {format_name: file_path} for every format successfully written.
        A format that fails to render/write is logged and simply
        omitted from the result — one bad format never blocks the
        others.
    """

    formats = formats or list(DEFAULT_FORMATS)

    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        log.error(f"Could not create report output directory {output_dir}: {e}")
        return {}

    try:
        model = build_report_model(
            pdf_path=pdf_path,
            metadata=metadata,
            embedded_results=embedded_results,
            analysis=analysis,
            evidence_graph=evidence_graph,
            correlation_result=correlation_result,
        )
    except Exception as e:
        log.error(f"Failed to build report model: {e}")
        return {}

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    written: Dict[str, str] = {}

    for fmt in formats:

        renderer = RENDERERS.get(fmt)

        if renderer is None:
            log.error(f"Unknown report format requested: {fmt}")
            continue

        ext = _EXTENSION_BY_FORMAT.get(fmt, fmt)
        out_path = os.path.join(output_dir, f"dfir_report_{timestamp}.{ext}")

        try:
            content = renderer(model)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(content)
            written[fmt] = out_path
        except Exception as e:
            log.error(f"Failed to render/write '{fmt}' report: {e}")
            continue

    return written