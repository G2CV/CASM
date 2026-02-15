from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import Flowable
from reportlab.platypus.tableofcontents import TableOfContents

from brain.core.pdf_styles import get_casm_styles
from brain.core.diff import diff_sarif, DiffFinding
from brain.core.schema_version import SCHEMA_VERSION
from brain.core.version import get_casm_version


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
CASM_LOGO_DARK = colors.HexColor("#0A1628")
CASM_LOGO_BLUE = colors.HexColor("#2E5BFF")


class CasmLogoFlowable(Flowable):
    def __init__(self, width: float = 250, height: float = 72, wordmark_font: str = "Helvetica-Bold") -> None:
        super().__init__()
        self.width = width
        self.height = height
        self.wordmark_font = wordmark_font

    def draw(self) -> None:
        _draw_casm_wordmark(self.canv, 0, 0, self.width, self.height, self.wordmark_font)

    def wrap(self, aW: float, aH: float) -> tuple[float, float]:
        del aW, aH
        return self.width, self.height


@dataclass
class FindingRecord:
    rule_id: str
    severity: str
    message: str
    url: str
    method: str
    fingerprint: str


def generate_pdf_report(
    engagement_id: str,
    run_id: str,
    output_dir: Path,
    evidence_store: object | None,
    branding_config: Optional[dict] = None,
    diff_config: Optional[dict] = None,
) -> Path:
    """Generate a PDF report for the given run.

    Args:
        engagement_id (str): Engagement identifier.
        run_id (str): Run identifier.
        output_dir (Path): Output directory containing evidence and artifacts.
        evidence_store (object | None): Reserved for future evidence access.
        branding_config (dict | None): Optional branding overrides.

    Returns:
        Path: Path to the generated PDF report.

    Raises:
        FileNotFoundError: When required evidence files are missing.
    """
    del evidence_store
    output_dir = Path(output_dir)
    evidence_path = output_dir / "evidence.jsonl"
    if not evidence_path.exists():
        raise FileNotFoundError(f"Missing evidence file: {evidence_path}")

    targets_path = output_dir / "targets.jsonl"
    sarif_path = output_dir / "results.sarif"

    branding = _validate_branding(branding_config)
    diff_settings = _diff_settings(diff_config)
    styles = get_casm_styles(branding)
    palette = styles["_palette"]

    summary = calculate_summary_stats(evidence_path, targets_path, sarif_path)
    findings = summary.findings

    pdf_path = output_dir / "report.pdf"
    doc = _build_doc(pdf_path, engagement_id, run_id, summary.report_date, styles)
    doc.afterFlowable = _after_flowable(doc)

    story: list[Flowable] = []
    story.extend(create_cover_page(engagement_id, run_id, summary.report_date, styles, branding))
    story.append(NextPageTemplate("Body"))
    story.append(PageBreak())
    story.extend(create_executive_summary(summary, styles))
    story.append(PageBreak())

    diff_section = create_diff_section(
        engagement_id=engagement_id,
        run_id=run_id,
        output_dir=output_dir,
        summary=summary,
        styles=styles,
        settings=diff_settings,
    )
    if diff_section:
        story.extend(diff_section)
        story.append(PageBreak())
    story.extend(create_table_of_contents(styles))
    story.append(PageBreak())
    story.extend(create_scope_section(summary, styles))
    story.append(PageBreak())
    story.extend(create_dns_section(summary, styles, palette))
    story.append(PageBreak())
    story.extend(create_findings_section(findings, styles, palette))
    story.append(PageBreak())
    story.extend(create_port_scan_section(summary, styles))
    story.append(PageBreak())
    story.extend(create_appendix(summary, styles, output_dir))

    doc.multiBuild(story)
    return pdf_path


def _build_doc(path: Path, engagement_id: str, run_id: str, report_date: str, styles: dict) -> BaseDocTemplate:
    doc = BaseDocTemplate(
        str(path),
        pagesize=letter,
        leftMargin=inch,
        rightMargin=inch,
        topMargin=inch,
        bottomMargin=inch,
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="normal")
    doc.addPageTemplates(
        [
            PageTemplate(
                id="Cover",
                frames=[frame],
                onPage=_first_page(engagement_id, run_id, report_date, styles),
            ),
            PageTemplate(
                id="Body",
                frames=[frame],
                onPage=_later_pages(engagement_id, run_id, report_date, styles),
            ),
        ]
    )
    return doc


def _after_flowable(doc: BaseDocTemplate):
    def handler(flowable):
        if hasattr(flowable, "style") and flowable.style.name in {"Heading1", "Heading2"}:
            level = 0 if flowable.style.name == "Heading1" else 1
            doc.notify("TOCEntry", (level, flowable.getPlainText(), doc.page))

    return handler


def _first_page(engagement_id: str, run_id: str, report_date: str, styles: dict):
    def handler(canvas, doc):
        del doc
        _draw_footer(canvas, engagement_id, report_date, styles, cover=True)

    return handler


def _later_pages(engagement_id: str, run_id: str, report_date: str, styles: dict):
    def handler(canvas, doc):
        _draw_header(canvas, styles)
        _draw_footer(canvas, engagement_id, report_date, styles)

    return handler


def _draw_header(canvas, styles: dict) -> None:
    canvas.saveState()
    canvas.setStrokeColor(styles["_palette"]["secondary"])
    canvas.setLineWidth(1)
    canvas.line(inch, letter[1] - inch + 6, letter[0] - inch, letter[1] - inch + 6)
    _draw_casm_mark(canvas, inch, letter[1] - inch + 12, 10)
    header_font = styles.get("_fonts", {}).get("body_regular", "Helvetica")
    canvas.setFont(header_font, 9)
    canvas.setFillColor(styles["_palette"]["primary"])
    canvas.drawString(inch + 14, letter[1] - inch + 14, "CASM Security Assessment")
    canvas.drawRightString(letter[0] - inch, letter[1] - inch + 14, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()


def _draw_footer(canvas, engagement_id: str, report_date: str, styles: dict, cover: bool = False) -> None:
    canvas.saveState()
    canvas.setStrokeColor(colors.lightgrey)
    canvas.setLineWidth(1)
    canvas.line(inch, inch - 12, letter[0] - inch, inch - 12)
    footer_font = styles.get("_fonts", {}).get("body_regular", "Helvetica")
    canvas.setFont(footer_font, 8)
    canvas.setFillColor(colors.grey)
    footer_text = styles.get("_footer_text") or "Confidential"
    canvas.drawString(inch, inch - 24, footer_text)
    canvas.drawCentredString(letter[0] / 2, inch - 24, f"Engagement: {engagement_id}")
    canvas.drawRightString(letter[0] - inch, inch - 24, f"Date: {report_date}")
    canvas.restoreState()


@dataclass
class SummaryStats:
    report_date: str
    domains_scanned: int
    dns_discoveries: list[dict]
    http_attempts: int
    findings: list[FindingRecord]
    severity_counts: dict
    unique_targets: int
    start_time: str
    end_time: str
    port_events: list[dict]
    blocked_domains: list[str]
    wildcard_events: list[dict]
    dns_executed: bool
    dns_subdomains: int
    open_ports: int


@dataclass(frozen=True)
class BaselineInfo:
    run_id: str
    sarif_path: Path
    evidence_path: Path
    targets_path: Path
    timestamp: datetime | None
    age_days: int | None
    warning: str | None


@dataclass(frozen=True)
class TrendEntry:
    date: str
    total: int
    critical: int
    high: int
    subdomains: int


def calculate_summary_stats(evidence_path: Path, targets_path: Path, sarif_path: Path) -> SummaryStats:
    """Aggregate evidence into summary metrics for PDF reporting."""
    events = _load_evidence(evidence_path)
    findings = _load_sarif_findings(sarif_path) if sarif_path.exists() else []

    dns_discoveries = [e for e in events if e.get("type") == "dns_discovery"]
    wildcard_events = [e for e in events if e.get("type") == "dns_wildcard"]
    dns_events = [e for e in events if str(e.get("type", "")).startswith("dns_")]
    http_attempts = len([e for e in events if e.get("type") == "http_attempt"])
    port_events = [e for e in events if e.get("type") == "tcp_connect"]
    open_ports = _count_open_ports(port_events)
    blocked_domains = [str(e.get("target")) for e in events if e.get("type") == "dns_blocked" and e.get("target")]

    severity_counts = {key: 0 for key in SEVERITY_ORDER}
    for finding in findings:
        key = finding.severity
        if key not in severity_counts:
            key = "info"
        severity_counts[key] += 1

    timestamps = [str(e.get("timestamp")) for e in events if e.get("timestamp")]
    start_time, end_time = _time_span(timestamps)

    targets = _load_targets(targets_path)
    unique_targets = len({t.get("target") for t in targets if t.get("target")})
    domains_scanned = len({t.get("host") for t in targets if t.get("host")})

    report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    dns_subdomains = _count_dns_subdomains(dns_discoveries)
    return SummaryStats(
        report_date=report_date,
        domains_scanned=domains_scanned,
        dns_discoveries=dns_discoveries,
        http_attempts=http_attempts,
        findings=findings,
        severity_counts=severity_counts,
        unique_targets=unique_targets,
        start_time=start_time,
        end_time=end_time,
        port_events=port_events,
        blocked_domains=blocked_domains,
        wildcard_events=wildcard_events,
        dns_executed=bool(dns_events),
        dns_subdomains=dns_subdomains,
        open_ports=open_ports,
    )


def create_cover_page(engagement_id: str, run_id: str, report_date: str, styles: dict, branding: Optional[dict]) -> list[Flowable]:
    branding = branding or {}
    casm_version = get_casm_version()
    story: list[Flowable] = []
    story.append(Spacer(1, 1.65 * inch))
    logo_path = branding.get("logo_path")
    wordmark_font = styles.get("_fonts", {}).get("body_bold", "Helvetica-Bold")
    if logo_path and os.path.exists(logo_path):
        try:
            img = Image(logo_path)
            scale = min(200 / img.imageWidth, 200 / img.imageHeight)
            img.drawWidth = img.imageWidth * scale
            img.drawHeight = img.imageHeight * scale
            img.hAlign = "CENTER"
            story.append(img)
        except Exception:
            logo = CasmLogoFlowable(wordmark_font=wordmark_font)
            logo.hAlign = "CENTER"
            story.append(logo)
    else:
        logo = CasmLogoFlowable(wordmark_font=wordmark_font)
        logo.hAlign = "CENTER"
        story.append(logo)
    story.append(Spacer(1, 0.6 * inch))
    story.append(Paragraph("Security Assessment Report", styles["CoverTitle"]))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(f"Engagement: {engagement_id}", styles["Heading2"]))
    story.append(Paragraph(f"Run: {run_id}", styles["Heading2"]))
    story.append(Spacer(1, 0.4 * inch))

    company_name = branding.get("company_name")
    if company_name:
        story.append(Paragraph(company_name, styles["BodyText"]))
    story.append(Paragraph(f"Report Date: {report_date}", styles["BodyText"]))
    story.append(Paragraph(f"CASM version: {casm_version}", styles["BodyText"]))
    story.append(Paragraph(f"Report schema: {SCHEMA_VERSION}", styles["BodyText"]))
    if branding.get("contact_email"):
        story.append(Paragraph(f"Contact: {branding.get('contact_email')}", styles["BodyText"]))
    if branding.get("contact_phone"):
        story.append(Paragraph(f"Phone: {branding.get('contact_phone')}", styles["BodyText"]))
    return story


def _draw_casm_mark(canvas: Canvas, x: float, y: float, size: float) -> None:
    scale = size / 200.0

    def sx(value: float) -> float:
        return x + value * scale

    def sy(value: float) -> float:
        return y + size - value * scale

    canvas.saveState()
    canvas.setFillColor(CASM_LOGO_BLUE)
    canvas.roundRect(sx(94), sy(44 + 100), 12 * scale, 100 * scale, 2 * scale, stroke=0, fill=1)

    canvas.setFillColor(CASM_LOGO_DARK)
    canvas.roundRect(sx(52), sy(72 + 3), 96 * scale, 3 * scale, 1 * scale, stroke=0, fill=1)
    canvas.roundRect(sx(64), sy(112 + 3), 72 * scale, 3 * scale, 1 * scale, stroke=0, fill=1)

    path = canvas.beginPath()
    points = [(100, 16), (172, 48), (172, 112), (100, 184), (28, 112), (28, 48)]
    path.moveTo(sx(points[0][0]), sy(points[0][1]))
    for px, py in points[1:]:
        path.lineTo(sx(px), sy(py))
    path.close()
    canvas.setLineWidth(3 * scale)
    canvas.setStrokeColor(CASM_LOGO_DARK)
    canvas.drawPath(path, stroke=1, fill=0)
    canvas.restoreState()


def _draw_casm_wordmark(canvas: Canvas, x: float, y: float, width: float, height: float, font_name: str) -> None:
    mark_size = height
    _draw_casm_mark(canvas, x, y, mark_size)

    canvas.saveState()
    canvas.setFillColor(CASM_LOGO_DARK)
    canvas.setFont(font_name, max(20, height * 0.42))
    canvas.drawString(x + mark_size + 14, y + height * 0.36, "CASM")
    canvas.restoreState()


def create_executive_summary(summary: SummaryStats, styles: dict) -> list[Flowable]:
    story: list[Flowable] = [Paragraph("Executive Summary", styles["Heading1"])]
    story.append(Paragraph("Assessment Overview", styles["Heading2"]))
    story.append(Paragraph(f"Domains scanned: {summary.domains_scanned}", styles["BodyText"]))
    story.append(Paragraph(f"DNS subdomains discovered: {len(summary.dns_discoveries)}", styles["BodyText"]))
    story.append(Paragraph(f"HTTP endpoints tested: {summary.http_attempts}", styles["BodyText"]))
    story.append(Paragraph(f"Total security findings: {len(summary.findings)}", styles["BodyText"]))
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph("Severity Breakdown", styles["Heading2"]))
    table = create_severity_table(summary.severity_counts, styles)
    story.append(table)

    top_concerns = summary.findings[:5]
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Key Concerns", styles["Heading2"]))
    if not top_concerns:
        story.append(Paragraph("No critical or high severity concerns identified.", styles["BodyText"]))
    else:
        for item in top_concerns:
            story.append(Paragraph(f"- {item.rule_id}: {item.message}", styles["BodyText"]))

    return story


def create_table_of_contents(styles: dict) -> list[Flowable]:
    toc = TableOfContents()
    toc.levelStyles = [
        styles["BodyText"],
        styles["BodyText"],
    ]
    return [Paragraph("Table of Contents", styles["Heading1"]), toc]


def create_scope_section(summary: SummaryStats, styles: dict) -> list[Flowable]:
    story: list[Flowable] = [Paragraph("Scope & Methodology", styles["Heading1"])]
    story.append(Paragraph("Assessment Scope", styles["Heading2"]))
    story.append(Paragraph(f"Unique targets assessed: {summary.unique_targets}", styles["BodyText"]))
    story.append(Paragraph(f"Assessment window: {summary.start_time} to {summary.end_time}", styles["BodyText"]))
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph("Methods", styles["Heading2"]))
    story.append(Paragraph("- DNS enumeration (passive and active sources)", styles["BodyText"]))
    story.append(Paragraph("- HTTP security verification", styles["BodyText"]))
    story.append(Paragraph("- TCP port scanning", styles["BodyText"]))
    return story


def create_dns_section(summary: SummaryStats, styles: dict, palette: dict) -> list[Flowable]:
    story: list[Flowable] = [Paragraph("DNS Enumeration Results", styles["Heading1"])]
    if not summary.dns_executed:
        story.append(Paragraph("DNS enumeration was not executed for this run.", styles["BodyText"]))
        return story
    story.append(Paragraph(f"Total subdomains discovered: {len(summary.dns_discoveries)}", styles["BodyText"]))
    if summary.dns_discoveries:
        story.extend(create_dns_tables(summary.dns_discoveries, styles, palette))
    else:
        story.append(Paragraph("No DNS discoveries were recorded.", styles["BodyText"]))

    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Security Concerns", styles["Heading2"]))
    if summary.wildcard_events:
        story.append(Paragraph("- Wildcard DNS responses detected.", styles["BodyText"]))
    if summary.blocked_domains:
        story.append(Paragraph("- Some domains were blocked by scope policy.", styles["BodyText"]))
    if not summary.wildcard_events and not summary.blocked_domains:
        story.append(Paragraph("No DNS-specific concerns identified.", styles["BodyText"]))
    return story


def create_findings_section(findings: list[FindingRecord], styles: dict, palette: dict) -> list[Flowable]:
    story: list[Flowable] = [Paragraph("HTTP Security Findings", styles["Heading1"])]
    grouped = _group_findings(findings)
    first = True
    for severity in SEVERITY_ORDER:
        entries = grouped.get(severity, [])
        heading = severity.upper()
        style_key = severity.capitalize() if severity != "info" else "Info"
        if not first:
            story.append(PageBreak())
        first = False
        story.append(Paragraph(f"{heading} Findings ({len(entries)})", styles["Heading1"]))
        story.append(Spacer(1, 0.1 * inch))
        if not entries:
            story.append(Paragraph("No findings in this severity tier.", styles["BodyText"]))
            continue
        for idx, finding in enumerate(entries, start=1):
            story.append(_finding_block(idx, finding, styles, style_key))
    return story


def create_port_scan_section(summary: SummaryStats, styles: dict) -> list[Flowable]:
    story: list[Flowable] = [Paragraph("Port Scan Results", styles["Heading1"])]
    if not summary.port_events:
        story.append(Paragraph("No port scan results were recorded.", styles["BodyText"]))
        return story
    table = create_port_table(summary.port_events, styles)
    story.append(table)
    return story


def create_appendix(summary: SummaryStats, styles: dict, output_dir: Path) -> list[Flowable]:
    story: list[Flowable] = [Paragraph("Appendix: Evidence", styles["Heading1"])]
    story.append(Paragraph("Raw evidence and SARIF outputs are available for programmatic access.", styles["BodyText"]))
    story.append(Paragraph(f"Evidence: {output_dir / 'evidence.jsonl'}", styles["Code"]))
    story.append(Paragraph(f"SARIF: {output_dir / 'results.sarif'}", styles["Code"]))
    story.append(Paragraph("View SARIF with compatible tooling (e.g., GitHub Code Scanning or VS Code extensions).", styles["BodyText"]))
    return story


def create_severity_table(severity_counts: dict, styles: dict) -> Table:
    data = [["Severity", "Count"]]
    for level in SEVERITY_ORDER:
        data.append([level.upper(), str(severity_counts.get(level, 0))])
    table = Table(data, hAlign="LEFT", colWidths=[2.2 * inch, 1.0 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), styles["_palette"]["secondary"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
            ]
        )
    )
    return table


def create_dns_tables(dns_discoveries: list[dict], styles: dict, palette: dict) -> list:
    rows: list[list[object]] = [["Subdomain", "Record", "Values", "Source"]]
    for item in dns_discoveries:
        data = item.get("data", {}) if isinstance(item.get("data"), dict) else item
        values = ", ".join(data.get("values", [])) if isinstance(data.get("values"), list) else str(data.get("values", ""))
        rows.append(
            [
                Paragraph(str(data.get("subdomain") or data.get("domain") or data.get("host") or ""), styles["TableBody"]),
                Paragraph(str(data.get("record_type", "")), styles["TableBody"]),
                Paragraph(values, styles["TableBody"]),
                Paragraph(str(data.get("source", "")), styles["TableBody"]),
            ]
        )

    tables = []
    page_size = 50
    for start in range(0, len(rows), page_size):
        chunk = rows[start : start + page_size]
        table = Table(chunk, hAlign="LEFT", colWidths=[2.0 * inch, 0.7 * inch, 3.1 * inch, 1.0 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), palette["secondary"]),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        tables.append(table)
        if start + page_size < len(rows):
            tables.append(PageBreak())
    return tables


def create_port_table(port_events: list[dict], styles: dict) -> Table:
    rows = [["Target", "Port", "Protocol", "Status"]]
    for event in port_events:
        data = event.get("data", {}) if isinstance(event.get("data"), dict) else {}
        target = event.get("target", "")
        port = data.get("port", "")
        protocol = data.get("protocol", "tcp")
        status = event.get("status", "")
        rows.append([target, str(port), protocol.upper(), status])
    table = Table(rows, hAlign="LEFT", colWidths=[2.6 * inch, 0.6 * inch, 0.8 * inch, 1.2 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), styles["_palette"]["secondary"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ]
        )
    )
    return table


def _finding_block(index: int, finding: FindingRecord, styles: dict, severity_style: str) -> KeepTogether:
    content: list[Flowable] = [
        Paragraph(f"Finding {index}", styles["Heading2"]),
        Paragraph(f"Severity: {finding.severity.upper()}", styles.get(severity_style, styles["BodyText"])),
        Paragraph(f"Target: {finding.url}", styles["BodyText"]),
        Paragraph(f"Rule: {finding.rule_id}", styles["BodyText"]),
        Paragraph(f"Description: {finding.message}", styles["BodyText"]),
    ]
    return KeepTogether(content)


def _group_findings(findings: list[FindingRecord]) -> dict:
    grouped = {key: [] for key in SEVERITY_ORDER}
    for finding in findings:
        key = finding.severity if finding.severity in grouped else "info"
        grouped[key].append(finding)
    for key in grouped:
        grouped[key].sort(key=lambda item: item.rule_id)
    return grouped


def _load_evidence(path: Path) -> list[dict]:
    events: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def _load_targets(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def _load_sarif_findings(path: Path) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    try:
        sarif = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return findings
    runs = sarif.get("runs", []) if isinstance(sarif, dict) else []
    for run in runs:
        if not isinstance(run, dict):
            continue
        for result in run.get("results", []) or []:
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")
            props = result.get("properties", {}) if isinstance(result.get("properties", {}), dict) else {}
            severity = props.get("severity", "info")
            url = ""
            locations = result.get("locations") or []
            if locations:
                url = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            method = props.get("method", "")
            fingerprint = props.get("finding_fingerprint", "")
            severity = str(severity).lower()
            if severity not in SEVERITY_ORDER:
                severity = "info"
            findings.append(
                FindingRecord(
                    rule_id=rule_id,
                    severity=severity,
                    message=message,
                    url=url,
                    method=method,
                    fingerprint=fingerprint,
                )
            )
    findings.sort(key=lambda item: (SEVERITY_ORDER.index(item.severity) if item.severity in SEVERITY_ORDER else 99, item.rule_id))
    return findings


def _time_span(timestamps: Iterable[str]) -> tuple[str, str]:
    parsed: list[datetime] = []
    for value in timestamps:
        try:
            parsed.append(_parse_timestamp(value))
        except ValueError:
            continue
    if not parsed:
        return "unknown", "unknown"
    parsed.sort()
    return parsed[0].isoformat(), parsed[-1].isoformat()


def _parse_timestamp(value: str) -> datetime:
    cleaned = value.strip()
    if cleaned.endswith("Z"):
        cleaned = f"{cleaned[:-1]}+00:00"
    parsed = datetime.fromisoformat(cleaned)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _format_datetime(value: datetime) -> str:
    """Format timestamps for executive-friendly display."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _default_recommendations(summary: SummaryStats) -> list[str]:
    if summary.findings:
        return [
            "Prioritize remediation of critical and high severity findings.",
            "Review exposed services and restrict access where possible.",
            "Re-scan after changes to confirm risk reduction.",
        ]
    return ["Continue monitoring and re-scan after significant changes."]


def _validate_branding(branding: Optional[dict]) -> dict:
    branding = dict(branding or {})
    logo_path = branding.get("logo_path")
    if logo_path and not os.path.exists(logo_path):
        print(f"Warning: logo_path not found: {logo_path}", file=sys.stderr)
        branding.pop("logo_path", None)
    for key in [
        "primary_color",
        "secondary_color",
        "critical_color",
        "high_color",
        "medium_color",
        "low_color",
        "info_color",
    ]:
        value = branding.get(key)
        if value and (not isinstance(value, str) or not value.startswith("#") or len(value) != 7):
            print(f"Warning: invalid color for {key}: {value}", file=sys.stderr)
            branding.pop(key, None)
    return branding


def _diff_settings(config: Optional[dict]) -> dict:
    """Normalize diff settings with safe defaults.

    Notes:
        Invalid or missing values fall back to defaults so PDF generation
        never fails due to configuration errors.
    """
    defaults = {
        "enabled": True,
        "max_new_critical": 5,
        "max_new_high": 10,
        "max_resolved": 10,
        "max_new_subdomains": 20,
        "max_removed_subdomains": 10,
        "include_trend": True,
        "baseline_age_warning_days": 60,
    }
    if not config:
        return defaults
    settings = dict(defaults)
    for key in [
        "max_new_critical",
        "max_new_high",
        "max_resolved",
        "max_new_subdomains",
        "max_removed_subdomains",
        "baseline_age_warning_days",
    ]:
        value = config.get(key)
        if isinstance(value, int) and value > 0:
            settings[key] = value
    if isinstance(config.get("enabled"), bool):
        settings["enabled"] = config["enabled"]
    if isinstance(config.get("include_trend"), bool):
        settings["include_trend"] = config["include_trend"]
    return settings


def create_diff_section(
    engagement_id: str,
    run_id: str,
    output_dir: Path,
    summary: SummaryStats,
    styles: dict,
    settings: dict,
) -> list[Flowable]:
    """Build the "Changes Since Last Scan" section when a baseline exists.

    Notes:
        The section is skipped on first scan or when baseline data is missing,
        to keep PDF generation resilient.
    """
    if not settings.get("enabled", True):
        return []

    current_sarif = output_dir / "results.sarif"
    if not current_sarif.exists():
        return []

    baseline = _find_baseline_info(
        engagement_id,
        run_id,
        output_dir.parent,
        warning_days=settings.get("baseline_age_warning_days", 60),
        current_dir_name=output_dir.name,
    )
    if not baseline:
        return []

    try:
        diff = diff_sarif(str(baseline.sarif_path), str(current_sarif), tool_filter=None)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"Diff calculation failed: {exc}", file=sys.stderr)
        return []

    current_records = _load_sarif_records(current_sarif)
    baseline_records = _load_sarif_records(baseline.sarif_path)

    current_counts = _sarif_severity_counts(current_records.values())
    baseline_counts = _sarif_severity_counts(baseline_records.values())

    baseline_events = _load_evidence(baseline.evidence_path) if baseline.evidence_path.exists() else []
    current_events = _load_evidence(output_dir / "evidence.jsonl")
    baseline_dns_events = [e for e in baseline_events if e.get("type") == "dns_discovery"]
    baseline_dns = _count_dns_subdomains(baseline_dns_events)
    current_dns = summary.dns_subdomains
    baseline_ports = _count_open_ports([e for e in baseline_events if e.get("type") == "tcp_connect"])
    current_ports = summary.open_ports

    dns_note = None
    if not baseline_dns_events:
        dns_note = "DNS comparison unavailable (no baseline DNS data)."
        new_dns, removed_dns = [], []
    elif not summary.dns_executed:
        dns_note = "DNS comparison unavailable (DNS enumeration not executed in current run)."
        new_dns, removed_dns = [], []
    else:
        new_dns, removed_dns = _diff_dns(baseline_events, current_events)

    story: list[Flowable] = []
    story.append(Paragraph("Changes Since Last Scan", styles["Heading1"]))
    story.append(Paragraph(f"Previous run: {baseline.run_id}", styles["BodyText"]))
    if baseline.timestamp:
        story.append(Paragraph(f"Previous scan time: {_format_datetime(baseline.timestamp)}", styles["BodyText"]))
    if baseline.age_days is not None:
        story.append(Paragraph(f"Elapsed time: {baseline.age_days} days", styles["BodyText"]))
    if baseline.warning:
        story.append(Paragraph(f"Note: {baseline.warning}", styles["BodyText"]))
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph("Summary", styles["Heading2"]))
    story.append(_diff_summary_table(baseline_counts, current_counts, baseline_dns, current_dns, baseline_ports, current_ports, styles))
    story.append(Spacer(1, 0.2 * inch))

    new_critical = _filter_diff(diff.added, "critical")
    new_high = _filter_diff(diff.added, "high")
    resolved = diff.removed

    if not diff.added and not diff.removed and not new_dns and not removed_dns:
        story.append(Paragraph("No changes detected since last scan.", styles["BodyText"]))
        return story

    story.extend(
        _render_new_critical(
            new_critical,
            current_records,
            styles,
            settings["max_new_critical"],
        )
    )
    story.append(Spacer(1, 0.2 * inch))
    story.extend(
        _render_new_high(
            new_high,
            current_records,
            styles,
            settings["max_new_high"],
        )
    )
    story.append(Spacer(1, 0.2 * inch))
    story.extend(
        _render_resolved(
            resolved,
            baseline_records,
            styles,
            settings["max_resolved"],
            baseline.timestamp,
        )
    )
    story.append(Spacer(1, 0.2 * inch))
    story.extend(
        _render_dns_changes(
            new_dns,
            removed_dns,
            styles,
            settings["max_new_subdomains"],
            settings["max_removed_subdomains"],
            baseline.timestamp,
            dns_note,
        )
    )

    if settings.get("include_trend", True):
        trend = _collect_trend_data(engagement_id, run_id, output_dir.parent)
        if len(trend) >= 3:
            story.append(Spacer(1, 0.2 * inch))
            story.extend(_render_trend(trend, styles))

    return story


def _find_baseline_info(
    engagement_id: str,
    current_run_id: str,
    engagement_dir: Path,
    warning_days: int = 60,
    current_dir_name: str | None = None,
) -> BaselineInfo | None:
    """Find the most recent prior run with SARIF for this engagement.

    Notes:
        Run IDs are sorted lexicographically because they encode timestamps.
        The current run is excluded by both run_id and output directory name.
    """
    if not engagement_dir.exists():
        return None
    candidates = []
    for entry in engagement_dir.iterdir():
        if not entry.is_dir():
            continue
        if entry.name == current_run_id:
            continue
        if current_dir_name and entry.name == current_dir_name:
            continue
        ts = _parse_run_timestamp(entry.name)
        candidates.append((entry.name, ts, entry))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0])
    for run_id, ts, run_dir in reversed(candidates):
        sarif_path = run_dir / "results.sarif"
        if sarif_path.exists():
            age_days = None
            warning = None
            if ts:
                age_days = (datetime.now(timezone.utc) - ts).days
                if age_days >= 90:
                    warning = f"Previous scan is {age_days} days old. Consider more frequent scanning."
                elif age_days >= warning_days:
                    warning = f"Previous scan is {age_days} days old."
            return BaselineInfo(
                run_id=run_id,
                sarif_path=sarif_path,
                evidence_path=run_dir / "evidence.jsonl",
                targets_path=run_dir / "targets.jsonl",
                timestamp=ts,
                age_days=age_days,
                warning=warning,
            )
    return None


def _parse_run_timestamp(run_id: str) -> datetime | None:
    """Parse run ID timestamps to support baseline aging warnings."""
    base = run_id.split("-", 1)[0]
    try:
        return datetime.strptime(base, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


@dataclass(frozen=True)
class SarifRecord:
    fingerprint: str
    rule_id: str
    severity: str
    uri: str
    message: str
    remediation: str


def _load_sarif_records(path: Path) -> dict[str, SarifRecord]:
    """Load SARIF results into a fingerprint-keyed map.

    Notes:
        Fingerprints are used for stable diffing across runs.
    """
    records: dict[str, SarifRecord] = {}
    try:
        sarif = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return records
    runs = sarif.get("runs", []) if isinstance(sarif, dict) else []
    for run in runs:
        if not isinstance(run, dict):
            continue
        for result in run.get("results", []) or []:
            if not isinstance(result, dict):
                continue
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")
            location = result.get("locations", [{}])[0]
            uri = (
                location.get("physicalLocation", {})
                .get("artifactLocation", {})
                .get("uri", "")
            )
            props = result.get("properties", {}) if isinstance(result.get("properties"), dict) else {}
            severity = _normalize_severity(_severity_from_result(props, result.get("level")))
            remediation = ""
            if isinstance(props.get("remediation"), str):
                remediation = props.get("remediation", "")
            elif isinstance(props.get("recommendation"), str):
                remediation = props.get("recommendation", "")
            fingerprint = _fingerprint_from_result(result, rule_id, uri, message)
            records[fingerprint] = SarifRecord(
                fingerprint=fingerprint,
                rule_id=rule_id,
                severity=severity,
                uri=uri,
                message=message,
                remediation=remediation,
            )
    return records


def _sarif_severity_counts(records: Iterable[SarifRecord]) -> dict:
    """Aggregate SARIF findings into severity counts."""
    counts = {key: 0 for key in SEVERITY_ORDER}
    for record in records:
        key = _normalize_severity(record.severity)
        counts[key] = counts.get(key, 0) + 1
    counts["total"] = sum(counts[key] for key in SEVERITY_ORDER)
    return counts


def _severity_from_result(properties: dict, level: str | None) -> str:
    severity = properties.get("severity")
    if isinstance(severity, str) and severity:
        return severity
    if level == "error":
        return "high"
    if level == "warning":
        return "medium"
    if level == "note":
        return "low"
    return "unknown"


def _normalize_severity(value: str) -> str:
    value = str(value).lower()
    if value in {"critical", "high", "medium", "low", "info"}:
        return value
    return "info"


def _fingerprint_from_result(result: dict, rule_id: str, uri: str, message: str) -> str:
    props = result.get("properties", {}) if isinstance(result.get("properties"), dict) else {}
    fingerprint = props.get("finding_fingerprint")
    if isinstance(fingerprint, str) and fingerprint:
        return fingerprint
    partial = result.get("partialFingerprints", {})
    if isinstance(partial, dict):
        primary = partial.get("primary")
        if isinstance(primary, str) and primary:
            return primary
    value = f"{rule_id}|{uri}|{message}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _diff_summary_table(
    baseline_counts: dict,
    current_counts: dict,
    baseline_dns: int,
    current_dns: int,
    baseline_ports: int,
    current_ports: int,
    styles: dict,
) -> Table:
    rows = [["Metric", "Previous", "Current", "Change"]]
    metrics = [
        ("Total findings", baseline_counts.get("total", 0), current_counts.get("total", 0)),
        ("Critical", baseline_counts.get("critical", 0), current_counts.get("critical", 0)),
        ("High", baseline_counts.get("high", 0), current_counts.get("high", 0)),
        ("Medium", baseline_counts.get("medium", 0), current_counts.get("medium", 0)),
        ("Low", baseline_counts.get("low", 0), current_counts.get("low", 0)),
        ("Info", baseline_counts.get("info", 0), current_counts.get("info", 0)),
        ("DNS subdomains", baseline_dns, current_dns),
        ("Open ports", baseline_ports, current_ports),
    ]
    for label, prev, curr in metrics:
        rows.append([label, str(prev), str(curr), _format_change(prev, curr)])
    table = Table(rows, hAlign="LEFT", colWidths=[2.3 * inch, 1.0 * inch, 1.0 * inch, 2.0 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), styles["_palette"]["secondary"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def _format_change(previous: int, current: int) -> str:
    """Format metric deltas with arrows and percentages."""
    delta = current - previous
    if delta == 0:
        return "→ 0 (stable)"
    arrow = "↑" if delta > 0 else "↓"
    if previous == 0:
        return f"{arrow} {delta:+d} (100%)"
    pct = (delta / previous) * 100
    return f"{arrow} {delta:+d} ({pct:.1f}%)"


def _filter_diff(findings: list[DiffFinding], severity: str) -> list[DiffFinding]:
    return [item for item in findings if _normalize_severity(item.severity) == severity]


def _render_new_critical(
    findings: list[DiffFinding],
    current_records: dict[str, SarifRecord],
    styles: dict,
    limit: int,
) -> list[Flowable]:
    """Render detailed new critical findings with remediation guidance."""
    story: list[Flowable] = [Paragraph(f"New Critical Findings ({len(findings)})", styles["Heading2"])]
    if not findings:
        story.append(Paragraph("No new critical findings.", styles["BodyText"]))
        return story
    shown = findings[:limit]
    for idx, item in enumerate(shown, start=1):
        record = current_records.get(item.fingerprint)
        description = record.message if record else item.message
        target = record.uri if record else item.uri
        remediation = record.remediation if record and record.remediation else "Review and remediate according to security policy."
        story.append(Paragraph(f"{idx}. {item.rule_id} @ {target}", styles["BodyText"]))
        story.append(Paragraph(f"Description: {description}", styles["BodyText"]))
        story.append(Paragraph("First seen: this scan", styles["BodyText"]))
        story.append(Paragraph(f"Recommendation: {remediation}", styles["BodyText"]))
        story.append(Spacer(1, 0.1 * inch))
    if len(findings) > limit:
        story.append(Paragraph(f"And {len(findings) - limit} more critical findings.", styles["BodyText"]))
    return story


def _render_new_high(
    findings: list[DiffFinding],
    current_records: dict[str, SarifRecord],
    styles: dict,
    limit: int,
) -> list[Flowable]:
    """Render a concise list of new high findings."""
    story: list[Flowable] = [Paragraph(f"New High Findings ({len(findings)})", styles["Heading2"])]
    if not findings:
        story.append(Paragraph("No new high findings.", styles["BodyText"]))
        return story
    shown = findings[:limit]
    for item in shown:
        record = current_records.get(item.fingerprint)
        target = record.uri if record else item.uri
        story.append(Paragraph(f"- {item.rule_id} on {target} (first seen: this scan)", styles["BodyText"]))
    if len(findings) > limit:
        story.append(Paragraph(f"And {len(findings) - limit} more high findings.", styles["BodyText"]))
    story.append(Paragraph("See HTTP Security Findings section for full details.", styles["BodyText"]))
    return story


def _render_resolved(
    findings: list[DiffFinding],
    baseline_records: dict[str, SarifRecord],
    styles: dict,
    max_total: int,
    baseline_time: datetime | None,
) -> list[Flowable]:
    """Render resolved findings grouped by severity."""
    story: list[Flowable] = [Paragraph("Resolved Findings", styles["Heading2"])]
    if not findings:
        story.append(Paragraph("No findings resolved since last scan.", styles["BodyText"]))
        return story
    grouped = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for item in findings:
        grouped[_normalize_severity(item.severity)].append(item)

    shown = 0
    for severity in ["critical", "high", "medium", "low", "info"]:
        items = grouped.get(severity, [])
        if not items:
            continue
        story.append(Paragraph(f"{severity.upper()} ({len(items)})", styles["BodyText"]))
        if severity in {"critical", "high"}:
            display_items = items
            remaining = 0
        else:
            allowed = max(0, max_total - shown)
            display_items = items[:allowed]
            remaining = len(items) - len(display_items)
        for item in display_items:
            record = baseline_records.get(item.fingerprint)
            target = record.uri if record else item.uri
            last_seen = _format_datetime(baseline_time) if baseline_time else "baseline"
            story.append(Paragraph(f"- {item.rule_id} on {target} (last seen: {last_seen}, status: fixed)", styles["BodyText"]))
        if severity not in {"critical", "high"}:
            shown += len(display_items)
        if remaining > 0:
            story.append(Paragraph(f"And {remaining} more {severity} findings resolved.", styles["BodyText"]))
    return story


def _render_dns_changes(
    new_dns: list[dict],
    removed_dns: list[dict],
    styles: dict,
    max_new: int,
    max_removed: int,
    baseline_time: datetime | None,
    dns_note: str | None,
) -> list[Flowable]:
    """Render new/removed subdomains for DNS diffs."""
    story: list[Flowable] = [Paragraph(f"New Subdomains Discovered ({len(new_dns)})", styles["Heading2"])]
    if dns_note:
        story.append(Paragraph(dns_note, styles["BodyText"]))
        return story
    if not new_dns:
        story.append(Paragraph("No new subdomains discovered.", styles["BodyText"]))
    else:
        for item in new_dns[:max_new]:
            values = ", ".join(item.get("values", []))
            story.append(
                Paragraph(
                    f"- {item.get('subdomain')} ({item.get('record_type')}): {values} (first seen: this scan)",
                    styles["BodyText"],
                )
            )
        if len(new_dns) > max_new:
            story.append(Paragraph(f"And {len(new_dns) - max_new} more new subdomains.", styles["BodyText"]))
        if len(new_dns) > 10:
            story.append(
                Paragraph(
                    "Recommendation: Review whether new subdomains should be publicly accessible.",
                    styles["BodyText"],
                )
            )

    if removed_dns:
        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph(f"Removed Subdomains ({len(removed_dns)})", styles["Heading2"]))
        for item in removed_dns[:max_removed]:
            values = ", ".join(item.get("values", []))
            last_seen = _format_datetime(baseline_time) if baseline_time else "baseline"
            story.append(
                Paragraph(
                    f"- {item.get('subdomain')} ({item.get('record_type')}): {values} (last seen: {last_seen})",
                    styles["BodyText"],
                )
            )
        if len(removed_dns) > max_removed:
            story.append(Paragraph(f"And {len(removed_dns) - max_removed} more removed subdomains.", styles["BodyText"]))
        story.append(
            Paragraph(
                "Recommendation: Verify removals were intentional and documented.",
                styles["BodyText"],
            )
        )
    return story


def _collect_trend_data(engagement_id: str, current_run_id: str, engagement_dir: Path) -> list[TrendEntry]:
    """Collect trend data from up to five previous runs."""
    if not engagement_dir.exists():
        return []
    runs = []
    for entry in engagement_dir.iterdir():
        if not entry.is_dir() or entry.name == current_run_id:
            continue
        ts = _parse_run_timestamp(entry.name)
        if not ts:
            continue
        sarif_path = entry / "results.sarif"
        if not sarif_path.exists():
            continue
        runs.append((ts, entry))
    runs.sort(key=lambda item: item[0])
    runs = runs[-5:]
    trend: list[TrendEntry] = []
    for ts, run_dir in runs:
        records = _load_sarif_records(run_dir / "results.sarif")
        counts = _sarif_severity_counts(records.values())
        events = _load_evidence(run_dir / "evidence.jsonl") if (run_dir / "evidence.jsonl").exists() else []
        dns_count = _count_dns_subdomains([e for e in events if e.get("type") == "dns_discovery"])
        trend.append(
            TrendEntry(
                date=ts.strftime("%Y-%m-%d"),
                total=counts.get("total", 0),
                critical=counts.get("critical", 0),
                high=counts.get("high", 0),
                subdomains=dns_count,
            )
        )
    return trend


def _render_trend(entries: list[TrendEntry], styles: dict) -> list[Flowable]:
    """Render trend table and a short narrative summary."""
    story: list[Flowable] = [Paragraph(f"Trend Analysis (Last {len(entries)} Scans)", styles["Heading2"])]
    rows = [["Date", "Total", "Critical", "High", "Subdomains"]]
    for entry in reversed(entries):
        rows.append([entry.date, str(entry.total), str(entry.critical), str(entry.high), str(entry.subdomains)])
    table = Table(rows, hAlign="LEFT", colWidths=[1.4 * inch, 1.0 * inch, 1.0 * inch, 1.0 * inch, 1.2 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), styles["_palette"]["secondary"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
            ]
        )
    )
    story.append(table)
    story.append(Paragraph(_trend_summary(entries), styles["BodyText"]))
    return story


def _trend_summary(entries: list[TrendEntry]) -> str:
    """Summarize changes across the oldest-to-newest trend window."""
    if len(entries) < 2:
        return "Trend data is insufficient for analysis."
    oldest = entries[0]
    newest = entries[-1]
    total_delta = newest.total - oldest.total
    critical_delta = newest.critical - oldest.critical
    sub_delta = newest.subdomains - oldest.subdomains
    return (
        f"Total findings changed by {total_delta:+d} since {oldest.date}. "
        f"Critical findings changed by {critical_delta:+d}. "
        f"Subdomains changed by {sub_delta:+d}."
    )


def _diff_dns(baseline_events: list[dict], current_events: list[dict]) -> tuple[list[dict], list[dict]]:
    """Compare DNS discoveries between baseline and current evidence."""
    baseline = _dns_records(baseline_events)
    current = _dns_records(current_events)
    new_keys = sorted(set(current.keys()) - set(baseline.keys()))
    removed_keys = sorted(set(baseline.keys()) - set(current.keys()))
    new_items = [current[key] for key in new_keys]
    removed_items = [baseline[key] for key in removed_keys]
    return new_items, removed_items


def _dns_records(events: list[dict]) -> dict[str, dict]:
    """Normalize DNS discovery events into a deduped map."""
    records: dict[str, dict] = {}
    for event in events:
        if event.get("type") != "dns_discovery":
            continue
        data = event.get("data", {}) if isinstance(event.get("data"), dict) else {}
        subdomain = data.get("subdomain") or data.get("domain") or data.get("host")
        if not subdomain:
            continue
        records[str(subdomain)] = {
            "subdomain": str(subdomain),
            "record_type": str(data.get("record_type", "")),
            "values": data.get("values", []) if isinstance(data.get("values"), list) else [str(data.get("values", ""))],
            "source": str(data.get("source", "")),
        }
    return records


def _count_open_ports(events: list[dict]) -> int:
    """Count unique open targets from probe evidence."""
    open_targets = set()
    for event in events:
        if event.get("status") not in {"success", "open"}:
            continue
        target = event.get("target")
        if target:
            open_targets.add(str(target))
    return len(open_targets)


def _count_dns_subdomains(dns_events: list[dict]) -> int:
    """Count unique subdomains from DNS discovery evidence."""
    seen = set()
    for event in dns_events:
        data = event.get("data", {}) if isinstance(event.get("data"), dict) else {}
        subdomain = data.get("subdomain") or data.get("domain") or data.get("host")
        if subdomain:
            seen.add(str(subdomain))
    return len(seen)
