import csv
import io
from datetime import datetime, timezone
from typing import List, Dict, Any

from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

def generate_csv_report(bug_records: List[Dict[str, Any]]) -> str:
    """
    Generates CSV formatted string of bug reports with security risk assessment.
    Applies CSV injection protection by prefixing dangerous formula symbols.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "Bug ID", 
        "Title", 
        "Severity", 
        "Category", 
        "Affected Module", 
        "Security Related", 
        "Risk Score", 
        "Risk Level", 
        "Triage Status", 
        "Analysis Date"
    ])

    for b in bug_records:
        # Prevent CSV injection by escaping starting =, +, -, @
        def sanitize_cell(val):
            s = str(val or "")
            if s and s[0] in ('=', '+', '-', '@'):
                return f"'{s}"
            return s

        writer.writerow([
            sanitize_cell(b.get("bug_id")),
            sanitize_cell(b.get("title")),
            sanitize_cell(b.get("severity")),
            sanitize_cell(b.get("category")),
            sanitize_cell(b.get("affected_module")),
            "Yes" if b.get("is_security_related") else "No",
            b.get("risk_score", 0),
            sanitize_cell(b.get("risk_level")),
            sanitize_cell(b.get("triage_status")),
            sanitize_cell(b.get("created_at"))
        ])

    return output.getvalue()

def generate_pdf_report(bug_records: List[Dict[str, Any]], title_suffix="Executive Summary") -> bytes:
    """
    Generates an executive-ready PDF report using ReportLab.
    Includes summary statistics, security posture, and prioritized bug registry.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(letter),
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor('#475569'),
        spaceAfter=15
    )
    
    section_style = ParagraphStyle(
        'DocSection',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=10,
        spaceAfter=6
    )
    
    cell_style = ParagraphStyle(
        'CellText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#1e293b')
    )
    
    cell_bold_style = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#0f172a')
    )

    elements = []

    # Title Banner
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    elements.append(Paragraph(f"AI-Based Bug Analysis & Security Prioritization Report", title_style))
    elements.append(Paragraph(f"Generated on {now_str} • {title_suffix} • Total Records: {len(bug_records)}", subtitle_style))
    elements.append(Spacer(1, 10))

    # Executive KPI Summary Table
    total_bugs = len(bug_records)
    crit_count = sum(1 for b in bug_records if str(b.get("severity")).lower() == "critical")
    high_count = sum(1 for b in bug_records if str(b.get("severity")).lower() == "high")
    sec_count = sum(1 for b in bug_records if b.get("is_security_related"))
    high_risk_count = sum(1 for b in bug_records if b.get("risk_score", 0) >= 56)

    kpi_data = [
        [
            Paragraph("<b>Total Issues Analyzed</b>", cell_style),
            Paragraph("<b>Critical Severity</b>", cell_style),
            Paragraph("<b>High Severity</b>", cell_style),
            Paragraph("<b>Security Flagged</b>", cell_style),
            Paragraph("<b>High/Crit Risk Score</b>", cell_style)
        ],
        [
            Paragraph(f"<font size=12><b>{total_bugs}</b></font>", cell_bold_style),
            Paragraph(f"<font size=12 color='#dc2626'><b>{crit_count}</b></font>", cell_bold_style),
            Paragraph(f"<font size=12 color='#ea580c'><b>{high_count}</b></font>", cell_bold_style),
            Paragraph(f"<font size=12 color='#b91c1c'><b>{sec_count}</b></font>", cell_bold_style),
            Paragraph(f"<font size=12 color='#e11d48'><b>{high_risk_count}</b></font>", cell_bold_style),
        ]
    ]
    kpi_table = Table(kpi_data, colWidths=[140, 140, 140, 140, 140])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))
    elements.append(kpi_table)
    elements.append(Spacer(1, 15))

    # Detailed Bug Registry Table
    elements.append(Paragraph("Triage Registry & Prioritization Matrix", section_style))

    table_data = [[
        Paragraph("<b>ID</b>", cell_bold_style),
        Paragraph("<b>Bug Title</b>", cell_bold_style),
        Paragraph("<b>Severity</b>", cell_bold_style),
        Paragraph("<b>Category</b>", cell_bold_style),
        Paragraph("<b>Module</b>", cell_bold_style),
        Paragraph("<b>Risk</b>", cell_bold_style),
        Paragraph("<b>Status</b>", cell_bold_style)
    ]]

    for b in bug_records[:100]:  # Limit to 100 for PDF performance
        # Color coding for risk/severity
        risk_color = "#dc2626" if b.get("risk_score", 0) >= 81 else ("#ea580c" if b.get("risk_score", 0) >= 56 else "#2563eb")
        
        table_data.append([
            Paragraph(str(b.get("bug_id", ""))[:12], cell_style),
            Paragraph(str(b.get("title", ""))[:65], cell_style),
            Paragraph(str(b.get("severity", "")), cell_style),
            Paragraph(str(b.get("category", "")), cell_style),
            Paragraph(str(b.get("affected_module", "")), cell_style),
            Paragraph(f"<font color='{risk_color}'><b>{b.get('risk_score', 0)} ({b.get('risk_level', 'Low')})</b></font>", cell_style),
            Paragraph(str(b.get("triage_status", "")), cell_style)
        ])

    col_widths = [65, 290, 65, 85, 80, 85, 70]
    reg_table = Table(table_data, colWidths=col_widths, repeatRows=1)
    reg_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(reg_table)

    # Disclaimer Note
    elements.append(Spacer(1, 15))
    disclaimer_text = "<b>Notice:</b> This automated triage report is generated by machine learning heuristics and pattern detection. Security risk scores are prioritization aids and require verification by the application security team."
    elements.append(Paragraph(disclaimer_text, subtitle_style))

    doc.build(elements)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
