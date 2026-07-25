# modules/report/__init__.py
"""
Professional Report Engine for PDFUncover.

Public API:
    generate_professional_report(...) -> {format_name: file_path}

See modules/report/engine.py for the full entry point,
modules/report/model.py for the internal Report Model, and
modules/report/renderers.py for the per-format renderers.
"""

from modules.report.engine import generate_professional_report
from modules.report.model import build_report_model, ReportModel

__all__ = [
    "generate_professional_report",
    "build_report_model",
    "ReportModel",
]