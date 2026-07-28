# modules/report/renderers.py
"""
Renderers for the Report Model (modules/report/model.py).

Every renderer here consumes exactly one ReportModel and produces one
output format. No renderer performs any detection, scoring, or
correlation — they are purely presentational, and every renderer
follows the same 11-section order defined in the spec:

    1. Executive Summary
    2. Threat Summary
    3. Threat Intelligence
    4. Correlated Findings
    5. Evidence Explorer
    6. Embedded Files
    7. JavaScript Analysis
    8. Network Indicators
    9. MITRE ATT&CK Mapping
    10. Analyst Recommendations
    11. Attack Chain
    12. Appendix

Shared section-ordering / labeling logic lives in _SECTION_TITLES so
the four renderers can't drift out of sync with each other.
"""

import html as html_lib
import json
from typing import List

from modules.report.model import (
    ReportModel, EvidenceTreeNode, CorrelatedFinding, ThreatIntelEntry,
    AttackChainStep,
)


SECTION_TITLES = [
    "Executive Summary",
    "Threat Summary",
    "Threat Intelligence",
    "Correlated Findings",
    "Evidence Explorer",
    "Embedded Files",
    "JavaScript Analysis",
    "Network Indicators",
    "MITRE ATT&CK Mapping",
    "Analyst Recommendations",
    "Attack Chain",
    "Appendix",
]


# ==========================================
# JSON
# ==========================================

def render_json(model: ReportModel, output_dir: str) -> str:
    """Full machine-readable dump of the report model.
    
    Args:
        model: The ReportModel to render.
        output_dir: Directory where the report file will be written.
    
    Returns:
        Path to the written file, or None if writing failed.
    """

    import os
    
    content = json.dumps(model.to_dict(), indent=2, default=str)
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        report_path = os.path.join(output_dir, "report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(content)
        return report_path
    except Exception as e:
        return None


# ==========================================
# PLAIN TEXT
# ==========================================

def _txt_tree(node: EvidenceTreeNode, prefix: str = "", lines: List[str] = None) -> List[str]:
    """Render an EvidenceTreeNode as ASCII-art lines (plain-text renderer)."""

    if lines is None:
        lines = [f"{node.name} [{node.type}]"]

    for i, child in enumerate(node.children):
        last = i == len(node.children) - 1
        connector = "`-- " if last else "+-- "
        risk = f" (risk: {child.risk})" if child.risk else ""
        lines.append(f"{prefix}{connector}{child.name} [{child.type}]{risk}")
        new_prefix = prefix + ("    " if last else "|   ")
        _txt_tree(child, new_prefix, lines)

    return lines


def render_text(model: ReportModel, output_dir: str) -> str:
    """Render report as plain text.
    
    Args:
        model: The ReportModel to render.
        output_dir: Directory where the report file will be written.
    
    Returns:
        Path to the written file, or None if writing failed.
    """

    import os
    
    sep = "=" * 70
    lines: List[str] = []

    def w(s: str = "") -> None:
        lines.append(s)

    w(sep)
    w("  PDFUNCOVER — DFIR INVESTIGATION REPORT")
    w(sep)
    w(f"  Target: {model.target}")
    w()

    # 1. Executive Summary
    es = model.executive_summary
    w(sep); w(f"  1. {SECTION_TITLES[0].upper()}"); w(sep)
    w(f"  Overall Verdict       : {es.overall_verdict}")
    w(f"  Risk Score            : {es.risk_score}/100")
    w(f"  Confidence            : {es.confidence}")
    w(f"  Threat Level          : {es.threat_level}")
    w(f"  Overall Recommendation: {es.overall_recommendation}")
    w()

    # 2. Threat Summary
    ts = model.threat_summary
    w(sep); w(f"  2. {SECTION_TITLES[1].upper()}"); w(sep)
    w(f"  Critical: {ts.critical}   High: {ts.high}   Medium: {ts.medium}   "
      f"Low: {ts.low}   Informational: {ts.informational}   (Total: {ts.total})")
    w()

    # 3. Threat Intelligence
    w(sep); w(f"  3. {SECTION_TITLES[2].upper()}"); w(sep)
    if model.threat_intelligence:
        for entry in model.threat_intelligence:
            w(f"  [{entry.ioc_type.upper()}] {entry.ioc}")
            w(f"      Reputation : {entry.verdict}  (score {entry.score}/100, confidence {entry.confidence})")
            if entry.providers:
                w("      Providers  : " + ", ".join(
                    f"{p.name}({p.status})" for p in entry.providers
                ))
            w()
    else:
        w("  No IOCs were checked against threat intelligence.")
        w()

    # 4. Correlated Findings
    w(sep); w(f"  4. {SECTION_TITLES[3].upper()}"); w(sep)
    if model.correlated_findings:
        for f in model.correlated_findings:
            w(f"  [{f.severity}] {f.title}  (confidence: {f.confidence})")
            w(f"      Evidence       : {f.evidence}")
            if f.recommendation:
                w(f"      Recommendation : {f.recommendation}")
            if f.mitre:
                w(f"      MITRE ATT&CK   : {', '.join(f.mitre)}")
            w()
    else:
        w("  No correlated (cross-signal) findings.")
        w()

    # 5. Evidence Explorer
    w(sep); w(f"  5. {SECTION_TITLES[4].upper()}"); w(sep)
    if model.evidence_tree:
        for line in _txt_tree(model.evidence_tree):
            w("  " + line)
    else:
        w("  No investigation tree available.")
    w()

    # 6. Embedded Files
    w(sep); w(f"  6. {SECTION_TITLES[5].upper()}"); w(sep)
    if model.embedded_files:
        for ef in model.embedded_files:
            w(f"  {ef.filename}")
            w(f"      Type         : {ef.file_type}")
            w(f"      Size         : {ef.size_human}")
            w(f"      SHA256       : {ef.sha256 or 'N/A'}")
            w(f"      Threat Intel : {ef.threat_intel}")
            w(f"      Risk         : {ef.risk or 'None'}")
            if ef.reasons:
                for r in ef.reasons:
                    w(f"        - {r}")
            w()
    else:
        w("  No embedded files were extracted.")
        w()

    # 7. JavaScript Analysis
    js = model.javascript
    w(sep); w(f"  7. {SECTION_TITLES[6].upper()}"); w(sep)
    w(f"  Detected            : {js.detected}")
    w(f"  OpenAction          : {js.openaction}")
    w(f"  Obfuscation Status  : {'Obfuscated' if js.obfuscated else 'Not obfuscated'}")
    w(f"  Suspicious Functions: {', '.join(js.suspicious_functions) or 'None'}")
    if js.decoded_preview:
        w(f"  Decoded Preview     : {js.decoded_preview}")
    w()

    # 8. Network Indicators
    ni = model.network_indicators
    w(sep); w(f"  8. {SECTION_TITLES[7].upper()}"); w(sep)
    w(f"  URLs    : {', '.join(ni.urls) or 'None'}")
    w(f"  Domains : {', '.join(ni.domains) or 'None'}")
    w(f"  IPs     : {', '.join(ni.ips) or 'None'}")
    w(f"  Emails  : {', '.join(ni.emails) or 'None'}")
    w()

    # 9. MITRE ATT&CK Mapping
    w(sep); w(f"  9. {SECTION_TITLES[8].upper()}"); w(sep)
    if model.mitre_mappings:
        for m in model.mitre_mappings:
            w(f"  [{m.tactic}] {m.technique} — {m.reason}")
    else:
        w("  No MITRE ATT&CK techniques mapped.")
    w()

    # 10. Analyst Recommendations
    w(sep); w(f"  10. {SECTION_TITLES[9].upper()}"); w(sep)
    if model.recommendations:
        for r in model.recommendations:
            w(f"  - {r}")
    else:
        w("  No specific recommendations.")
    w()

    # 11. Attack Chain
    w(sep); w(f"  11. {SECTION_TITLES[10].upper()}"); w(sep)
    if model.attack_chain:
        for step in model.attack_chain:
            conf = step.confidence
            w(f"  Step {step.step}: {step.title}  [{conf} confidence]")
            w(f"      {step.description}")
            if step.evidence:
                for ev in step.evidence:
                    w(f"        · {ev}")
            if step.mitre:
                w(f"      MITRE ATT&CK : {', '.join(step.mitre)}")
            w()
    else:
        w("  No attack chain reconstructed from static evidence.")
        w()

    # 12. Appendix
    ap = model.appendix
    w(sep); w(f"  12. {SECTION_TITLES[11].upper()}"); w(sep)
    w(f"  Analysis Timestamp : {ap.analysis_timestamp}")
    w(f"  Tool Version       : {ap.tool_version}")
    w(f"  Parsers Used       : {', '.join(ap.parser_info) or 'None'}")
    w(f"  MD5                : {ap.hashes.get('MD5', 'N/A')}")
    w(f"  SHA1               : {ap.hashes.get('SHA1', 'N/A')}")
    w(f"  SHA256             : {ap.hashes.get('SHA256', 'N/A')}")
    w()
    for k in ("Title", "Author", "Creator", "Producer", "CreationDate",
              "ModDate", "Pages", "PDF version", "Encrypted"):
        if ap.metadata.get(k):
            w(f"  {k:<18}: {ap.metadata[k]}")
    w(sep)

    content = "\n".join(lines)
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        report_path = os.path.join(output_dir, "report.txt")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(content)
        return report_path
    except Exception as e:
        return None


# ==========================================
# MARKDOWN
# ==========================================

def _md_tree(node: EvidenceTreeNode, depth: int = 0) -> List[str]:

    lines = []
    indent = "  " * depth
    marker = "-"
    risk = f" `{node.risk}`" if node.risk else ""
    lines.append(f"{indent}{marker} **{node.name}** _{node.type}_{risk}")

    for child in node.children:
        lines.extend(_md_tree(child, depth + 1))

    return lines


def render_markdown(model: ReportModel, output_dir: str) -> str:
    """Render report as Markdown.
    
    Args:
        model: The ReportModel to render.
        output_dir: Directory where the report file will be written.
    
    Returns:
        Path to the written file, or None if writing failed.
    """

    import os
    
    lines: List[str] = []

    def w(s: str = "") -> None:
        lines.append(s)

    w(f"# PDFUncover — DFIR Investigation Report")
    w(f"**Target:** `{model.target}`")
    w()

    es = model.executive_summary
    w("## 1. Executive Summary")
    w(f"| Field | Value |")
    w(f"|---|---|")
    w(f"| Overall Verdict | **{es.overall_verdict}** |")
    w(f"| Risk Score | {es.risk_score}/100 |")
    w(f"| Confidence | {es.confidence} |")
    w(f"| Threat Level | {es.threat_level} |")
    w(f"| Recommendation | {es.overall_recommendation} |")
    w()

    ts = model.threat_summary
    w("## 2. Threat Summary")
    w("| Severity | Count |")
    w("|---|---|")
    w(f"| Critical | {ts.critical} |")
    w(f"| High | {ts.high} |")
    w(f"| Medium | {ts.medium} |")
    w(f"| Low | {ts.low} |")
    w(f"| Informational | {ts.informational} |")
    w(f"| **Total** | **{ts.total}** |")
    w()

    w("## 3. Threat Intelligence")
    if model.threat_intelligence:
        for entry in model.threat_intelligence:
            w(f"### {entry.ioc_type.upper()}: `{entry.ioc}`")
            w(f"- **Reputation:** {entry.verdict} (score {entry.score}/100, confidence {entry.confidence})")
            if entry.providers:
                w("- **Providers:**")
                for p in entry.providers:
                    flag = "malicious" if p.malicious else ("clean" if p.malicious is False else p.status)
                    w(f"  - {p.name}: {flag}")
            w()
    else:
        w("_No IOCs were checked against threat intelligence._")
        w()

    w("## 4. Correlated Findings")
    if model.correlated_findings:
        for f in model.correlated_findings:
            w(f"### [{f.severity}] {f.title}")
            w(f"- **Confidence:** {f.confidence}")
            w(f"- **Evidence:** {f.evidence}")
            if f.recommendation:
                w(f"- **Recommendation:** {f.recommendation}")
            if f.mitre:
                w(f"- **MITRE ATT&CK:** {', '.join(f.mitre)}")
            w()
    else:
        w("_No correlated (cross-signal) findings._")
        w()

    w("## 5. Evidence Explorer")
    if model.evidence_tree:
        w("\n".join(_md_tree(model.evidence_tree)))
    else:
        w("_No investigation tree available._")
    w()

    w("## 6. Embedded Files")
    if model.embedded_files:
        for ef in model.embedded_files:
            w(f"### {ef.filename}")
            w(f"- **Type:** {ef.file_type}")
            w(f"- **Size:** {ef.size_human}")
            w(f"- **SHA256:** `{ef.sha256 or 'N/A'}`")
            w(f"- **Threat Intel:** {ef.threat_intel}")
            w(f"- **Risk:** {ef.risk or 'None'}")
            for r in ef.reasons:
                w(f"  - {r}")
            w()
    else:
        w("_No embedded files were extracted._")
        w()

    js = model.javascript
    w("## 7. JavaScript Analysis")
    w(f"- **Detected:** {js.detected}")
    w(f"- **OpenAction:** {js.openaction}")
    w(f"- **Obfuscation Status:** {'Obfuscated' if js.obfuscated else 'Not obfuscated'}")
    w(f"- **Suspicious Functions:** {', '.join(js.suspicious_functions) or 'None'}")
    if js.decoded_preview:
        w(f"- **Decoded Preview:** `{js.decoded_preview}`")
    w()

    ni = model.network_indicators
    w("## 8. Network Indicators")
    w(f"- **URLs:** {', '.join(ni.urls) or 'None'}")
    w(f"- **Domains:** {', '.join(ni.domains) or 'None'}")
    w(f"- **IPs:** {', '.join(ni.ips) or 'None'}")
    w(f"- **Emails:** {', '.join(ni.emails) or 'None'}")
    w()

    w("## 9. MITRE ATT&CK Mapping")
    if model.mitre_mappings:
        w("| Tactic | Technique | Reason |")
        w("|---|---|---|")
        for m in model.mitre_mappings:
            w(f"| {m.tactic} | {m.technique} | {m.reason} |")
    else:
        w("_No MITRE ATT&CK techniques mapped._")
    w()

    w("## 10. Analyst Recommendations")
    if model.recommendations:
        for r in model.recommendations:
            w(f"- {r}")
    else:
        w("_No specific recommendations._")
    w()

    w("## 11. Attack Chain")
    if model.attack_chain:
        for step in model.attack_chain:
            w(f"### Step {step.step}: {step.title}")
            w(f"- **Confidence:** {step.confidence}")
            w(f"- **Description:** {step.description}")
            if step.evidence:
                w("- **Evidence:**")
                for ev in step.evidence:
                    w(f"  - {ev}")
            if step.mitre:
                w(f"- **MITRE ATT&CK:** {', '.join(step.mitre)}")
            w()
    else:
        w("_No attack chain reconstructed from static evidence._")
        w()

    ap = model.appendix
    w("## 12. Appendix")
    w(f"- **Analysis Timestamp:** {ap.analysis_timestamp}")
    w(f"- **Tool Version:** {ap.tool_version}")
    w(f"- **Parsers Used:** {', '.join(ap.parser_info) or 'None'}")
    w(f"- **MD5:** `{ap.hashes.get('MD5', 'N/A')}`")
    w(f"- **SHA1:** `{ap.hashes.get('SHA1', 'N/A')}`")
    w(f"- **SHA256:** `{ap.hashes.get('SHA256', 'N/A')}`")
    w()
    w("| Metadata Field | Value |")
    w("|---|---|")
    for k in ("Title", "Author", "Creator", "Producer", "CreationDate",
              "ModDate", "Pages", "PDF version", "Encrypted"):
        if ap.metadata.get(k):
            w(f"| {k} | {ap.metadata[k]} |")

    content = "\n".join(lines)
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        report_path = os.path.join(output_dir, "report.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(content)
        return report_path
    except Exception as e:
        return None


# ==========================================
# HTML
# ==========================================

_HTML_STYLE = """
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 2rem;
         background: #0f1117; color: #e6e6e6; }
  h1 { font-size: 1.6rem; border-bottom: 2px solid #333; padding-bottom: .5rem; }
  h2 { font-size: 1.2rem; margin-top: 2rem; color: #7dd3fc; border-bottom: 1px solid #2a2a2a; padding-bottom: .3rem; }
  h3 { font-size: 1rem; color: #f0abfc; margin-bottom: .2rem; }
  table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; }
  th, td { border: 1px solid #333; padding: .4rem .6rem; text-align: left; font-size: .9rem; }
  th { background: #1c1f2b; }
  code, .mono { font-family: SFMono-Regular, Consolas, monospace; background: #1c1f2b; padding: .1rem .3rem; border-radius: 3px; }
  ul { margin: .3rem 0 1rem 1.2rem; }
  .badge { display: inline-block; padding: .1rem .5rem; border-radius: 10px; font-size: .78rem; font-weight: 600; }
  .Critical, .critical, .CRITICAL { background: #7f1d1d; color: #fecaca; }
  .High, .high, .HIGH { background: #7c2d12; color: #fed7aa; }
  .Medium, .medium, .MEDIUM { background: #78350f; color: #fde68a; }
  .Low, .low, .LOW { background: #164e63; color: #a5f3fc; }
  .Informational, .informational, .CLEAN { background: #14532d; color: #bbf7d0; }
  .tree { font-family: monospace; white-space: pre; line-height: 1.5; }
  .card { background: #171a24; border: 1px solid #262a38; border-radius: 8px; padding: 1rem; margin: .6rem 0; }
</style>
"""


def _esc(text) -> str:
    return html_lib.escape(str(text)) if text is not None else ""


def _badge(label: str) -> str:
    return f'<span class="badge {_esc(label)}">{_esc(label)}</span>'


def _html_tree(node: EvidenceTreeNode, depth: int = 0) -> str:

    risk = f' {_badge(node.risk)}' if node.risk else ""
    out = f'{"  " * depth}├─ <b>{_esc(node.name)}</b> <i>({_esc(node.type)})</i>{risk}\n'
    for child in node.children:
        out += _html_tree(child, depth + 1)
    return out


def render_html(model: ReportModel, output_dir: str) -> str:
    """Render report as HTML.
    
    Args:
        model: The ReportModel to render.
        output_dir: Directory where the report file will be written.
    
    Returns:
        Path to the written file, or None if writing failed.
    """

    import os
    
    es = model.executive_summary
    ts = model.threat_summary
    js = model.javascript
    ni = model.network_indicators
    ap = model.appendix

    parts: List[str] = []
    parts.append(f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
                 f"<title>PDFUncover Report — {_esc(model.target)}</title>{_HTML_STYLE}</head><body>")
    parts.append(f"<h1>PDFUncover — DFIR Investigation Report</h1>")
    parts.append(f"<p><b>Target:</b> <span class='mono'>{_esc(model.target)}</span></p>")

    # 1
    parts.append("<h2>1. Executive Summary</h2><div class='card'><table>")
    parts.append(f"<tr><th>Overall Verdict</th><td>{_badge(es.overall_verdict)}</td></tr>")
    parts.append(f"<tr><th>Risk Score</th><td>{es.risk_score}/100</td></tr>")
    parts.append(f"<tr><th>Confidence</th><td>{_esc(es.confidence)}</td></tr>")
    parts.append(f"<tr><th>Threat Level</th><td>{_badge(es.threat_level)}</td></tr>")
    parts.append(f"<tr><th>Recommendation</th><td>{_esc(es.overall_recommendation)}</td></tr>")
    parts.append("</table></div>")

    # 2
    parts.append("<h2>2. Threat Summary</h2><table>"
                 "<tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Informational</th><th>Total</th></tr>")
    parts.append(f"<tr><td>{ts.critical}</td><td>{ts.high}</td><td>{ts.medium}</td>"
                 f"<td>{ts.low}</td><td>{ts.informational}</td><td><b>{ts.total}</b></td></tr></table>")

    # 3
    parts.append("<h2>3. Threat Intelligence</h2>")
    if model.threat_intelligence:
        for entry in model.threat_intelligence:
            parts.append("<div class='card'>")
            parts.append(f"<h3>{_esc(entry.ioc_type.upper())}: <span class='mono'>{_esc(entry.ioc)}</span></h3>")
            parts.append(f"<p>Reputation: {_badge(entry.verdict)} — score {entry.score}/100, "
                         f"confidence {_esc(entry.confidence)}</p>")
            if entry.providers:
                parts.append("<ul>")
                for p in entry.providers:
                    flag = "malicious" if p.malicious else ("clean" if p.malicious is False else p.status)
                    parts.append(f"<li>{_esc(p.name)}: {_esc(flag)}</li>")
                parts.append("</ul>")
            parts.append("</div>")
    else:
        parts.append("<p><i>No IOCs were checked against threat intelligence.</i></p>")

    # 4
    parts.append("<h2>4. Correlated Findings</h2>")
    if model.correlated_findings:
        for f in model.correlated_findings:
            parts.append("<div class='card'>")
            parts.append(f"<h3>{_badge(f.severity)} {_esc(f.title)}</h3>")
            parts.append(f"<p><b>Confidence:</b> {_esc(f.confidence)}</p>")
            parts.append(f"<p><b>Evidence:</b> {_esc(f.evidence)}</p>")
            if f.recommendation:
                parts.append(f"<p><b>Recommendation:</b> {_esc(f.recommendation)}</p>")
            if f.mitre:
                parts.append(f"<p><b>MITRE ATT&amp;CK:</b> {_esc(', '.join(f.mitre))}</p>")
            parts.append("</div>")
    else:
        parts.append("<p><i>No correlated (cross-signal) findings.</i></p>")

    # 5
    parts.append("<h2>5. Evidence Explorer</h2>")
    if model.evidence_tree:
        parts.append(f"<div class='tree'>{_html_tree(model.evidence_tree)}</div>")
    else:
        parts.append("<p><i>No investigation tree available.</i></p>")

    # 6
    parts.append("<h2>6. Embedded Files</h2>")
    if model.embedded_files:
        for ef in model.embedded_files:
            parts.append("<div class='card'>")
            parts.append(f"<h3>{_esc(ef.filename)}</h3><table>")
            parts.append(f"<tr><th>Type</th><td>{_esc(ef.file_type)}</td></tr>")
            parts.append(f"<tr><th>Size</th><td>{_esc(ef.size_human)}</td></tr>")
            parts.append(f"<tr><th>SHA256</th><td class='mono'>{_esc(ef.sha256 or 'N/A')}</td></tr>")
            parts.append(f"<tr><th>Threat Intel</th><td>{_esc(ef.threat_intel)}</td></tr>")
            parts.append(f"<tr><th>Risk</th><td>{_badge(ef.risk) if ef.risk else 'None'}</td></tr>")
            if ef.reasons:
                parts.append(f"<tr><th>Reasons</th><td><ul>")
                for r in ef.reasons:
                    parts.append(f"<li>{_esc(r)}</li>")
                parts.append("</ul></td></tr>")
            parts.append("</table></div>")
    else:
        parts.append("<p><i>No embedded files were extracted.</i></p>")

    # 7
    parts.append("<h2>7. JavaScript Analysis</h2><div class='card'><table>")
    parts.append(f"<tr><th>Detected</th><td>{js.detected}</td></tr>")
    parts.append(f"<tr><th>OpenAction</th><td>{js.openaction}</td></tr>")
    parts.append(f"<tr><th>Obfuscation</th><td>{'Obfuscated' if js.obfuscated else 'Not obfuscated'}</td></tr>")
    parts.append(f"<tr><th>Suspicious Functions</th><td>{_esc(', '.join(js.suspicious_functions) or 'None')}</td></tr>")
    if js.decoded_preview:
        parts.append(f"<tr><th>Decoded Preview</th><td class='mono'>{_esc(js.decoded_preview)}</td></tr>")
    parts.append("</table></div>")

    # 8
    parts.append("<h2>8. Network Indicators</h2><div class='card'><table>")
    parts.append(f"<tr><th>URLs</th><td>{_esc(', '.join(ni.urls) or 'None')}</td></tr>")
    parts.append(f"<tr><th>Domains</th><td>{_esc(', '.join(ni.domains) or 'None')}</td></tr>")
    parts.append(f"<tr><th>IPs</th><td>{_esc(', '.join(ni.ips) or 'None')}</td></tr>")
    parts.append(f"<tr><th>Emails</th><td>{_esc(', '.join(ni.emails) or 'None')}</td></tr>")
    parts.append("</table></div>")

    # 9
    parts.append("<h2>9. MITRE ATT&CK Mapping</h2>")
    if model.mitre_mappings:
        parts.append("<table><tr><th>Tactic</th><th>Technique</th><th>Reason</th></tr>")
        for m in model.mitre_mappings:
            parts.append(f"<tr><td>{_esc(m.tactic)}</td><td>{_esc(m.technique)}</td><td>{_esc(m.reason)}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p><i>No MITRE ATT&CK techniques mapped.</i></p>")

    # 10
    parts.append("<h2>10. Analyst Recommendations</h2><div class='card'>")
    if model.recommendations:
        parts.append("<ul>")
        for r in model.recommendations:
            parts.append(f"<li>{_esc(r)}</li>")
        parts.append("</ul>")
    else:
        parts.append("<p><i>No specific recommendations.</i></p>")
    parts.append("</div>")

    # 11
    parts.append("<h2>11. Attack Chain</h2>")
    if model.attack_chain:
        for step in model.attack_chain:
            parts.append("<div class='card'>")
            parts.append(f"<h3>Step {step.step}: {_esc(step.title)}</h3>")
            parts.append(f"<p><b>Confidence:</b> {_esc(step.confidence)}</p>")
            parts.append(f"<p><b>Description:</b> {_esc(step.description)}</p>")
            if step.evidence:
                parts.append("<p><b>Evidence:</b><ul>")
                for ev in step.evidence:
                    parts.append(f"<li>{_esc(ev)}</li>")
                parts.append("</ul></p>")
            if step.mitre:
                parts.append(f"<p><b>MITRE ATT&amp;CK:</b> {_esc(', '.join(step.mitre))}</p>")
            parts.append("</div>")
    else:
        parts.append("<p><i>No attack chain reconstructed from static evidence.</i></p>")

    # 12
    parts.append("<h2>12. Appendix</h2><div class='card'><table>")
    parts.append(f"<tr><th>Analysis Timestamp</th><td>{_esc(ap.analysis_timestamp)}</td></tr>")
    parts.append(f"<tr><th>Tool Version</th><td>{_esc(ap.tool_version)}</td></tr>")
    parts.append(f"<tr><th>Parsers Used</th><td>{_esc(', '.join(ap.parser_info) or 'None')}</td></tr>")
    parts.append(f"<tr><th>MD5</th><td class='mono'>{_esc(ap.hashes.get('MD5', 'N/A'))}</td></tr>")
    parts.append(f"<tr><th>SHA1</th><td class='mono'>{_esc(ap.hashes.get('SHA1', 'N/A'))}</td></tr>")
    parts.append(f"<tr><th>SHA256</th><td class='mono'>{_esc(ap.hashes.get('SHA256', 'N/A'))}</td></tr>")
    for k in ("Title", "Author", "Creator", "Producer", "CreationDate",
              "ModDate", "Pages", "PDF version", "Encrypted"):
        if ap.metadata.get(k):
            parts.append(f"<tr><th>{_esc(k)}</th><td>{_esc(ap.metadata[k])}</td></tr>")
    parts.append("</table></div>")

    parts.append("</body></html>")
    content = "".join(parts)
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        report_path = os.path.join(output_dir, "report.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(content)
        return report_path
    except Exception as e:
        return None