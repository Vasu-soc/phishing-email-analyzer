import os
import json
from typing import Dict, Any
from phishing_analyzer.scoring.engine import AnalysisResult

# Import reportlab components
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

def export_json_report(result: AnalysisResult, file_path: str) -> None:
    """
    Exports the analysis result to a JSON file.
    """
    # Create directory if it doesn't exist
    dir_name = os.path.dirname(file_path)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(dir_name, exist_ok=True)

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=4)


def export_pdf_report(result: AnalysisResult, file_path: str) -> None:
    """
    Exports the analysis result to a PDF report using ReportLab.
    """
    # Create directory if it doesn't exist
    dir_name = os.path.dirname(file_path)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(dir_name, exist_ok=True)

    # Setup colors based on risk level
    risk_colors = {
        "Safe": colors.HexColor("#2e7d32"),       # Green
        "Low": colors.HexColor("#7cb342"),        # Light Green
        "Medium": colors.HexColor("#f57c00"),     # Orange
        "High": colors.HexColor("#d32f2f"),       # Red
        "Very High": colors.HexColor("#c62828")   # Dark Red
    }
    
    theme_color = risk_colors.get(result.risk_level, colors.HexColor("#37474f"))
    neutral_dark = colors.HexColor("#263238")
    neutral_light = colors.HexColor("#f5f7f8")
    border_color = colors.HexColor("#cfd8dc")

    # Document template setup
    doc = SimpleDocTemplate(
        file_path,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()
    
    # Custom Paragraph Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=neutral_dark,
        spaceAfter=12
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#78909c"),
        spaceAfter=20
    )

    h1_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=neutral_dark,
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )

    meta_label_style = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=neutral_dark
    )

    meta_val_style = ParagraphStyle(
        'MetaVal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#37474f")
    )

    body_style = ParagraphStyle(
        'ReportBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#455a64")
    )

    finding_title_style = ParagraphStyle(
        'FindingTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=theme_color
    )

    story = []

    # 1. Header
    story.append(Paragraph("Phishing Email Analyzer", title_style))
    story.append(Paragraph(f"Security Assessment Report &bull; Generated: {result.timestamp}", subtitle_style))
    story.append(Spacer(1, 10))

    # 2. Executive Summary Table (Metadata & Risk Level)
    risk_text = f"<font size='14' color='white'><b>{result.risk_level.upper()}</b></font><br/><font size='9' color='white'>Score: {result.final_score}/100</font>"
    
    meta_data = [
        [
            Paragraph("<b>Subject:</b>", meta_label_style),
            Paragraph(result.subject if result.subject else "(No Subject)", meta_val_style),
            Paragraph(risk_text, ParagraphStyle('RiskBadge', parent=styles['Normal'], alignment=1))
        ],
        [
            Paragraph("<b>Analyzed At:</b>", meta_label_style),
            Paragraph(result.timestamp, meta_val_style),
            ""
        ],
        [
            Paragraph("<b>Total Indicators:</b>", meta_label_style),
            Paragraph(str(len(result.matches)), meta_val_style),
            ""
        ]
    ]

    meta_table = Table(meta_data, colWidths=[1.2*inch, 4.0*inch, 1.8*inch])
    meta_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('SPAN', (2,0), (2,2)),  # Span the risk badge cell vertically
        ('BACKGROUND', (2,0), (2,2), theme_color),
        ('ALIGN', (2,0), (2,2), 'CENTER'),
        ('VALIGN', (2,0), (2,2), 'MIDDLE'),
        ('BOTTOMPADDING', (2,0), (2,2), 12),
        ('TOPPADDING', (2,0), (2,2), 12),
        ('LINEBELOW', (0,0), (1,-1), 0.5, colors.HexColor("#e0e0e0")),
        ('TOPPADDING', (0,0), (1,-1), 6),
        ('BOTTOMPADDING', (0,0), (1,-1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 20))

    # 3. Email Source Preview
    story.append(Paragraph("Email Preview", h1_style))
    # Truncate preview if very long
    preview_body = result.body
    if len(preview_body) > 600:
        preview_body = preview_body[:600] + "\n\n[... content truncated in report preview ...]"
        
    preview_text = f"<b>Subject:</b> {result.subject if result.subject else '(No Subject)'}\n\n{preview_body}"
    preview_paragraph = Paragraph(preview_text.replace("\n", "<br/>"), ParagraphStyle('Preview', parent=styles['Normal'], fontName='Courier', fontSize=9, leading=12, textColor=colors.HexColor("#546e7a")))
    
    preview_table = Table([[preview_paragraph]], colWidths=[7.0*inch])
    preview_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), neutral_light),
        ('BOX', (0,0), (-1,-1), 1, border_color),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(preview_table)
    story.append(Spacer(1, 20))

    # 4. Indicators Found
    story.append(Paragraph("Analysis Findings", h1_style))
    if not result.matches:
        story.append(Paragraph("No phishing indicators were detected in this email.", body_style))
    else:
        # Table of matches
        findings_data = [[
            Paragraph("<b>Category</b>", meta_label_style),
            Paragraph("<b>Found In</b>", meta_label_style),
            Paragraph("<b>Matched Text / Detail</b>", meta_label_style)
        ]]
        
        for match in result.matches:
            category_display = match.category.replace("_", " ").title()
            findings_data.append([
                Paragraph(f"<b>{category_display}</b>", finding_title_style),
                Paragraph(match.location.upper(), meta_val_style),
                Paragraph(f"Snippet: \"<b>{match.matched_text}</b>\"<br/><i>Reason: {match.explanation}</i>", body_style)
            ])

        findings_table = Table(findings_data, colWidths=[1.8*inch, 0.9*inch, 4.3*inch])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#eceff1")),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ]))
        story.append(findings_table)

    story.append(Spacer(1, 20))

    # 5. Risk Assessment Explanation
    story.append(Paragraph("Risk Level Assessment", h1_style))
    explanation_map = {
        "Safe": "No indicators of phishing were identified. The email is highly likely to be legitimate. However, always exercise caution when opening links or attachments from outside sources.",
        "Low": "A few minor indicators were found, but the overall score remains low. The email is likely safe, but proceed with caution if it requests unusual actions.",
        "Medium": "Several indicators commonly associated with phishing were identified. The email exhibits suspicious characteristics. Verify the sender's identity through out-of-band communication before interacting.",
        "High": "Critical phishing indicators, such as urgent language combined with credentials requests or suspicious URLs, were identified. There is a high probability that this is a phishing email. DO NOT click links, open attachments, or reply.",
        "Very High": "Multiple severe indicators, direct credentials requests, and suspicious links were detected. This email is almost certainly a malicious phishing attempt. Report it to your security operations team immediately."
    }
    story.append(Paragraph(explanation_map.get(result.risk_level, ""), body_style))
    
    # 6. Disclaimer
    story.append(Spacer(1, 30))
    disclaimer_style = ParagraphStyle(
        'Disclaimer',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#90a4ae")
    )
    story.append(Paragraph(
        "<b>Disclaimer:</b> This report is generated by a rule-based automated engine. It is intended for educational "
        "and investigative support purposes only. Rule-based detection may produce false positives or false negatives. "
        "Always follow your organization's official security guidelines when handling suspicious emails.",
        disclaimer_style
    ))

    # Build Document
    def add_page_number(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor("#78909c"))
        canvas.drawRightString(letter[0] - 54, 36, f"Page {doc.page}")
        canvas.drawString(54, 36, "CONFIDENTIAL - Phishing Analysis Report")
        canvas.restoreState()

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
