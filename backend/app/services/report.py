from __future__ import annotations

from pathlib import Path

from fpdf import FPDF

from app.schemas.contracts import DetectionGapReport, FindingInput
from app.services.mitre import get_technique


class ReportPDF(FPDF):
    def header(self) -> None:
        self.set_font("Helvetica", "B", 15)
        self.set_text_color(18, 43, 70)
        self.cell(0, 10, "RedPath | Internal Purple-Team Assessment", ln=True)
        self.set_draw_color(73, 215, 232)
        self.line(10, 22, 200, 22)
        self.ln(8)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 116, 139)
        self.cell(0, 10, f"RedPath lab report | page {self.page_no()}", align="C")


def generate_pdf_report(
    output_path: str,
    findings: list[FindingInput],
    coverage: DetectionGapReport | None = None,
) -> str:
    pdf = ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(8, 17, 31)
    pdf.cell(0, 12, "Executive summary", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(45, 61, 82)
    summary = (
        f"This report summarizes {len(findings)} lab-scoped finding(s) produced by RedPath. "
        "All evidence is intended for authorized internal testing, with dry-run as the default execution mode."
    )
    pdf.multi_cell(0, 6, summary)
    pdf.ln(5)

    if coverage:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Detection coverage", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 6, f"Coverage: {coverage.coverage_percent:.2f}% | Detection gaps: {len(coverage.gaps)}")
        pdf.ln(3)

    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(8, 17, 31)
    pdf.cell(0, 10, "Technical findings", ln=True)
    for index, finding in enumerate(findings, start=1):
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(18, 43, 70)
        pdf.multi_cell(0, 6, f"{index}. {finding.title} [{finding.severity.upper()}]")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(45, 61, 82)
        pdf.multi_cell(0, 5, finding.description)
        pdf.multi_cell(
            0,
            5,
            f"Asset: {finding.asset_id or 'not specified'} | CVSS: {finding.cvss_score or 'not scored'}",
        )
        if finding.technique_id:
            technique = get_technique(finding.technique_id)
            pdf.multi_cell(0, 5, f"MITRE ATT&CK: {technique.technique_id} - {technique.name} ({technique.tactic})")
            pdf.multi_cell(0, 5, "Remediation: " + " ".join(technique.remediation))
        pdf.ln(3)

    if coverage and coverage.gaps:
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(8, 17, 31)
        pdf.cell(0, 10, "Detection gaps and recommendations", ln=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(45, 61, 82)
        for technique_id in coverage.gaps:
            observation = next(item for item in coverage.observations if item.technique_id == technique_id)
            pdf.multi_cell(0, 5, f"{technique_id}: {observation.recommendation}")

    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(target))
    return str(target)
