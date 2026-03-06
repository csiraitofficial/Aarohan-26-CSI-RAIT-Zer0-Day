"""
ThreatSense — PDF Incident Report Generator
============================================
Member 4's deliverable.  One function, one file.

Usage by Member 1's backend:
    from pdf_generator import generate_pdf_report
    pdf_bytes = generate_pdf_report(incident_dict)

Returns bytes of a professional PDF incident report.
Never crashes — returns a minimal error PDF on failure.
"""

from io import BytesIO
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    PageBreak,
)
from reportlab.pdfbase import pdfmetrics


# ---------------------------------------------------------------------------
#  Colour palette — matches frontend severity colours exactly
# ---------------------------------------------------------------------------
SEVERITY_COLORS = {
    "CRITICAL": HexColor("#dc2626"),
    "HIGH":     HexColor("#ea580c"),
    "MEDIUM":   HexColor("#d97706"),
    "LOW":      HexColor("#16a34a"),
    "BENIGN":   HexColor("#2563eb"),
    "UNKNOWN":  HexColor("#6b7280"),
}

# Accent / structural colours
COLOR_HEADER_BG     = HexColor("#2d3748")
COLOR_LABEL_BG      = HexColor("#f0f0f0")
COLOR_ALT_ROW       = HexColor("#f9f9f9")
COLOR_EXEC_BG       = HexColor("#f5f5f5")
COLOR_CORR_WARN     = HexColor("#fff3cd")
COLOR_CORR_CAMPAIGN = HexColor("#f8d7da")
COLOR_MUTED         = HexColor("#6b7280")
COLOR_DARK          = HexColor("#1a202c")
COLOR_ACCENT_LINE   = HexColor("#e2e8f0")

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm
CONTENT_W = PAGE_W - 2 * MARGIN


# ---------------------------------------------------------------------------
#  Reusable paragraph styles
# ---------------------------------------------------------------------------
def _styles():
    """Return a dict of named ParagraphStyle objects."""
    base = getSampleStyleSheet()
    s = {}

    s["title"] = ParagraphStyle(
        "title",
        parent=base["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=COLOR_DARK,
        alignment=TA_LEFT,
        spaceAfter=4,
    )
    s["subtitle"] = ParagraphStyle(
        "subtitle",
        fontName="Helvetica",
        fontSize=13,
        leading=16,
        textColor=COLOR_MUTED,
        alignment=TA_LEFT,
        spaceAfter=2,
    )
    s["section"] = ParagraphStyle(
        "section",
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=COLOR_DARK,
        spaceBefore=14,
        spaceAfter=6,
    )
    s["body"] = ParagraphStyle(
        "body",
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=black,
        alignment=TA_JUSTIFY,
    )
    s["body_small"] = ParagraphStyle(
        "body_small",
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=black,
    )
    s["mono"] = ParagraphStyle(
        "mono",
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=black,
    )
    s["mono_small"] = ParagraphStyle(
        "mono_small",
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=black,
    )
    s["label"] = ParagraphStyle(
        "label",
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=HexColor("#374151"),
    )
    s["italic"] = ParagraphStyle(
        "italic",
        fontName="Helvetica-Oblique",
        fontSize=10,
        leading=14,
        textColor=COLOR_MUTED,
        alignment=TA_JUSTIFY,
    )
    s["badge"] = ParagraphStyle(
        "badge",
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=white,
        alignment=TA_CENTER,
    )
    s["bullet"] = ParagraphStyle(
        "bullet",
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=black,
        leftIndent=12,
        bulletIndent=0,
    )
    s["corr_title"] = ParagraphStyle(
        "corr_title",
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=HexColor("#856404"),
        alignment=TA_LEFT,
    )
    s["corr_body"] = ParagraphStyle(
        "corr_body",
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=HexColor("#856404"),
    )
    s["footer"] = ParagraphStyle(
        "footer",
        fontName="Helvetica",
        fontSize=7,
        leading=9,
        textColor=COLOR_MUTED,
    )
    return s


# ---------------------------------------------------------------------------
#  Safe helpers
# ---------------------------------------------------------------------------
def _safe(val, default="N/A"):
    """Return *val* if truthy, else *default*."""
    if val is None:
        return default
    if isinstance(val, str) and val.strip() == "":
        return default
    return val


def _safe_list(val):
    """Guarantee a list."""
    if isinstance(val, list):
        return val
    return []


def _safe_dict(val):
    """Guarantee a dict."""
    if isinstance(val, dict):
        return val
    return {}


def _sev_color(severity: str) -> HexColor:
    return SEVERITY_COLORS.get(str(severity).upper(), SEVERITY_COLORS["UNKNOWN"])


def _esc(text) -> str:
    """Escape XML entities so ReportLab Paragraph doesn't choke."""
    t = str(text)
    t = t.replace("&", "&amp;")
    t = t.replace("<", "&lt;")
    t = t.replace(">", "&gt;")
    return t


# ---------------------------------------------------------------------------
#  Page header / footer drawn on every page
# ---------------------------------------------------------------------------
def _header_footer(canvas_obj, doc):
    canvas_obj.saveState()

    # — header text
    canvas_obj.setFont("Helvetica", 7)
    canvas_obj.setFillColor(COLOR_MUTED)
    canvas_obj.drawString(MARGIN, PAGE_H - 14 * mm, "ThreatSense Platform")
    canvas_obj.drawRightString(
        PAGE_W - MARGIN, PAGE_H - 14 * mm, "CONFIDENTIAL — INCIDENT REPORT"
    )
    # thin header line
    canvas_obj.setStrokeColor(COLOR_ACCENT_LINE)
    canvas_obj.setLineWidth(0.5)
    canvas_obj.line(MARGIN, PAGE_H - 16 * mm, PAGE_W - MARGIN, PAGE_H - 16 * mm)

    # — footer
    canvas_obj.setFont("Helvetica", 7)
    canvas_obj.setFillColor(COLOR_MUTED)
    canvas_obj.drawString(
        MARGIN,
        10 * mm,
        f"Generated by ThreatSense — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    )
    canvas_obj.drawRightString(
        PAGE_W - MARGIN, 10 * mm, f"Page {doc.page}"
    )
    canvas_obj.restoreState()


# ---------------------------------------------------------------------------
#  Section builders — each returns list[Flowable]
# ---------------------------------------------------------------------------
def _build_title_block(inc, sty):
    """Title, filename, severity badge, timestamp."""
    elements = []
    sev = str(_safe(inc.get("severity"), "UNKNOWN")).upper()
    sev_col = _sev_color(sev)

    elements.append(Paragraph("INCIDENT ANALYSIS REPORT", sty["title"]))
    elements.append(
        Paragraph(f"File: <b>{_esc(inc.get('filename', 'Unknown'))}</b>", sty["subtitle"])
    )
    elements.append(Spacer(1, 6))

    # severity badge — full-width coloured bar
    badge_text = Paragraph(
        f"SEVERITY: {sev}", sty["badge"]
    )
    badge_table = Table(
        [[badge_text]],
        colWidths=[CONTENT_W],
        rowHeights=[28],
    )
    badge_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), sev_col),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("ROUNDEDCORNERS", [4, 4, 4, 4]),
            ]
        )
    )
    elements.append(badge_table)
    elements.append(Spacer(1, 6))

    # timestamp & incident id
    ts = _safe(inc.get("timestamp"), datetime.now().isoformat())
    inc_id = inc.get("incident_id", inc.get("id", "—"))
    elements.append(
        Paragraph(
            f"Analysis Date: {_esc(ts)}&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;"
            f"Incident ID: {_esc(inc_id)}",
            sty["body_small"],
        )
    )
    elements.append(Spacer(1, 4))

    # accent HR matching severity colour
    elements.append(
        HRFlowable(
            width="100%", thickness=2, color=sev_col, spaceAfter=8, spaceBefore=2
        )
    )
    return elements


def _build_correlation_section(inc, sty):
    """Correlation warning banner — only called when matches exist."""
    corr = _safe_dict(inc.get("correlation"))
    if not corr.get("matches_found"):
        return []

    elements = []
    campaign = corr.get("campaign_flag", False)
    bg = COLOR_CORR_CAMPAIGN if campaign else COLOR_CORR_WARN
    title_text = (
        "\u26a0  POSSIBLE ATTACK CAMPAIGN DETECTED"
        if campaign
        else "\u26a0  RELATED INCIDENTS DETECTED"
    )

    match_count = corr.get("match_count", 0)
    matched_iocs = _safe_list(corr.get("matched_iocs"))
    related = _safe_list(corr.get("related_incidents"))

    body_parts = []
    if match_count:
        body_parts.append(f"{match_count} shared IOC(s) found across {len(related)} related incident(s).")
    if matched_iocs:
        body_parts.append(f"Shared indicators: {', '.join(str(i) for i in matched_iocs[:8])}")
    if campaign:
        msg = corr.get("campaign_message", "")
        if msg:
            body_parts.append(str(msg))

    # Related incidents detail
    for ri in related[:5]:
        ri = _safe_dict(ri)
        ri_id = ri.get("incident_id", "?")
        ri_file = ri.get("filename", "unknown")
        ri_ts = ri.get("timestamp", "")
        shared = _safe_list(ri.get("shared_iocs"))
        body_parts.append(
            f"• Incident #{ri_id} ({_esc(ri_file)}, {ri_ts}) — "
            f"{ri.get('shared_count', len(shared))} shared IOC(s)"
        )

    title_p = Paragraph(title_text, sty["corr_title"])
    body_p = Paragraph("<br/>".join(_esc(p) for p in body_parts), sty["corr_body"])

    inner = Table(
        [[title_p], [body_p]],
        colWidths=[CONTENT_W - 16],
    )
    inner.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (0, 0), 8),
                ("BOTTOMPADDING", (-1, -1), (-1, -1), 8),
                ("ROUNDEDCORNERS", [4, 4, 4, 4]),
            ]
        )
    )
    elements.append(inner)
    elements.append(Spacer(1, 10))
    return elements


def _build_metadata_table(inc, sty):
    """Two-column label/value metadata table."""
    elements = []
    elements.append(Paragraph("FILE METADATA", sty["section"]))

    llm = _safe_dict(inc.get("llm_report"))
    vt = _safe_dict(inc.get("vt_result"))

    # VT summary string
    if vt.get("available"):
        if vt.get("known"):
            vt_str = f"{vt.get('malicious', 0)} / {vt.get('total', 0)} engines detected threat"
        else:
            vt_str = "Hash not found in VirusTotal database"
    else:
        vt_str = "VirusTotal lookup unavailable"

    # Entropy string
    entropy_val = inc.get("entropy")
    entropy_verdict = _safe(inc.get("entropy_verdict"), "")
    if entropy_val is not None:
        entropy_str = f"{entropy_val:.4f}   —   {entropy_verdict}"
    else:
        entropy_str = "N/A"

    raw_rows = [
        ("Filename",            _esc(inc.get("filename", "N/A"))),
        ("Analysis Date/Time",  _esc(_safe(inc.get("timestamp")))),
        ("File Type",           _esc(_safe(inc.get("file_type", inc.get("input_type"))))),
        ("Input Category",      "Binary Analysis" if inc.get("input_type") == "binary" else "Script Analysis"),
        ("MD5 Hash",            None),   # special mono
        ("SHA256 Hash",         None),   # special mono
        ("Entropy Score",       _esc(entropy_str)),
        ("VirusTotal Result",   _esc(vt_str)),
        ("Threat Classification", _esc(_safe(inc.get("threat_class", llm.get("threat_classification"))))),
        ("Confidence Level",    f"{llm.get('confidence', 'N/A')}%"
                                 if isinstance(llm.get("confidence"), (int, float))
                                 else _esc(str(llm.get("confidence", "N/A")))),
    ]

    label_w = 55 * mm
    value_w = CONTENT_W - label_w

    table_data = []
    for label, value in raw_rows:
        label_p = Paragraph(f"<b>{label}</b>", sty["label"])
        if label == "MD5 Hash":
            value_p = Paragraph(_esc(_safe(inc.get("md5"))), sty["mono"])
        elif label == "SHA256 Hash":
            value_p = Paragraph(_esc(_safe(inc.get("sha256"))), sty["mono_small"])
        else:
            value_p = Paragraph(str(value), sty["body_small"])
        table_data.append([label_p, value_p])

    tbl = Table(table_data, colWidths=[label_w, value_w])
    tbl.setStyle(
        TableStyle(
            [
                # label column background
                ("BACKGROUND", (0, 0), (0, -1), COLOR_LABEL_BG),
                # borders
                ("GRID", (0, 0), (-1, -1), 0.4, HexColor("#d1d5db")),
                # padding
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    elements.append(tbl)
    elements.append(Spacer(1, 10))
    return elements


def _build_executive_summary(inc, sty):
    """Executive summary in a highlighted box."""
    elements = []
    llm = _safe_dict(inc.get("llm_report"))
    text = _safe(llm.get("executive_summary"), "No executive summary available.")

    elements.append(Paragraph("EXECUTIVE SUMMARY", sty["section"]))

    box_p = Paragraph(_esc(text), sty["body"])
    box_table = Table([[box_p]], colWidths=[CONTENT_W - 16])
    box_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), COLOR_EXEC_BG),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("ROUNDEDCORNERS", [3, 3, 3, 3]),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_ACCENT_LINE),
            ]
        )
    )
    elements.append(box_table)
    elements.append(Spacer(1, 10))
    return elements


def _build_technical_analysis(inc, sty):
    """Behavioral / technical analysis section."""
    elements = []
    llm = _safe_dict(inc.get("llm_report"))
    text = _safe(llm.get("behavioral_summary"), "No technical analysis available.")

    elements.append(Paragraph("TECHNICAL BEHAVIORAL ANALYSIS", sty["section"]))
    elements.append(Paragraph(_esc(text), sty["body"]))
    elements.append(Spacer(1, 10))
    return elements


def _build_ioc_table(inc, sty):
    """IOC table with alternating row colours."""
    elements = []
    elements.append(Paragraph("INDICATORS OF COMPROMISE (IOCs)", sty["section"]))

    iocs = _safe_dict(inc.get("iocs"))
    rows = []

    type_map = [
        ("ips", "IP Address"),
        ("domains", "Domain"),
        ("urls", "URL"),
        ("registry_keys", "Registry Key"),
        ("file_paths", "File Path"),
    ]

    for key, label in type_map:
        for item in _safe_list(iocs.get(key)):
            rows.append((label, str(item)))

    if not rows:
        elements.append(
            Paragraph("<i>No indicators of compromise extracted.</i>", sty["body_small"])
        )
        elements.append(Spacer(1, 10))
        return elements

    # header row
    header = [
        Paragraph("<b>Type</b>", ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=white)),
        Paragraph("<b>Indicator</b>", ParagraphStyle("th2", fontName="Helvetica-Bold", fontSize=9, textColor=white)),
    ]
    table_data = [header]

    for ioc_type, ioc_val in rows:
        table_data.append(
            [
                Paragraph(ioc_type, sty["body_small"]),
                Paragraph(_esc(ioc_val), sty["mono"]),
            ]
        )

    type_w = 30 * mm
    val_w = CONTENT_W - type_w
    tbl = Table(table_data, colWidths=[type_w, val_w], repeatRows=1)

    style_cmds = [
        # header
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), white),
        # grid
        ("GRID", (0, 0), (-1, -1), 0.3, HexColor("#d1d5db")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    # alternating row colours
    for i in range(1, len(table_data)):
        if i % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), COLOR_ALT_ROW))

    tbl.setStyle(TableStyle(style_cmds))
    elements.append(tbl)
    elements.append(Spacer(1, 10))
    return elements


def _build_mitre_section(inc, sty):
    """MITRE ATT&CK technique bullet list."""
    elements = []
    llm = _safe_dict(inc.get("llm_report"))
    techniques = _safe_list(llm.get("attack_techniques"))

    elements.append(Paragraph("MITRE ATT&amp;CK TECHNIQUES IDENTIFIED", sty["section"]))

    if not techniques:
        elements.append(
            Paragraph("<i>No specific MITRE techniques mapped.</i>", sty["body_small"])
        )
    else:
        for tech in techniques:
            # attempt to bold the technique ID (e.g. T1055)
            t = str(tech)
            if t.startswith("T") and " " in t:
                parts = t.split(" ", 1)
                formatted = f"<b>{_esc(parts[0])}</b> {_esc(parts[1])}"
            elif t.startswith("T") and "-" in t:
                parts = t.split("-", 1)
                formatted = f"<b>{_esc(parts[0].strip())}</b> — {_esc(parts[1].strip())}"
            else:
                formatted = _esc(t)
            elements.append(Paragraph(f"\u2022  {formatted}", sty["bullet"]))

    elements.append(Spacer(1, 10))
    return elements


def _build_remediation(inc, sty):
    """Numbered remediation steps."""
    elements = []
    llm = _safe_dict(inc.get("llm_report"))
    steps = _safe_list(llm.get("remediation"))

    elements.append(Paragraph("REMEDIATION STEPS", sty["section"]))

    if not steps:
        elements.append(
            Paragraph("<i>No remediation steps provided.</i>", sty["body_small"])
        )
    else:
        for idx, step in enumerate(steps, 1):
            elements.append(
                Paragraph(f"<b>{idx}.</b>&nbsp;&nbsp;{_esc(step)}", sty["bullet"])
            )

    elements.append(Spacer(1, 10))
    return elements


def _build_vt_section(inc, sty):
    """VirusTotal threat intelligence details."""
    elements = []
    vt = _safe_dict(inc.get("vt_result"))

    elements.append(Paragraph("VIRUSTOTAL THREAT INTELLIGENCE", sty["section"]))

    if not vt.get("available"):
        elements.append(
            Paragraph(
                "VirusTotal lookup was unavailable during this analysis.",
                sty["body"],
            )
        )
    elif vt.get("known"):
        malicious = vt.get("malicious", 0)
        total = vt.get("total", 0)
        names = _safe_list(vt.get("threat_names"))

        if malicious > 0:
            elements.append(
                Paragraph(
                    f"<b>Detection Rate:</b> {malicious} / {total} engines flagged as malicious.",
                    sty["body"],
                )
            )
            if names:
                elements.append(
                    Paragraph(
                        f"<b>Threat names identified:</b> {_esc(', '.join(str(n) for n in names))}",
                        sty["body"],
                    )
                )
        else:
            elements.append(
                Paragraph(
                    f"<b>Detection Rate:</b> 0 / {total} — no engines flagged this hash.",
                    sty["body"],
                )
            )
            elements.append(
                Paragraph(
                    "<i>Note: Absence of VirusTotal detection does not confirm the file is safe "
                    "— novel or targeted malware may not yet be in the signature database.</i>",
                    sty["italic"],
                )
            )
    else:
        elements.append(
            Paragraph(
                "Hash was not found in the VirusTotal database. This file has not been "
                "previously submitted to any of the 70+ scanning engines.",
                sty["body"],
            )
        )
        elements.append(
            Paragraph(
                "<i>Note: An unknown hash may indicate a novel, custom-built, or targeted implant. "
                "Do not dismiss — proceed with sandbox analysis.</i>",
                sty["italic"],
            )
        )

    elements.append(Spacer(1, 10))
    return elements


def _build_analyst_notes(inc, sty):
    """Analyst notes in italic style."""
    elements = []
    llm = _safe_dict(inc.get("llm_report"))
    notes = _safe(llm.get("analyst_notes"), "")

    if not notes or notes == "N/A":
        return []

    elements.append(Paragraph("ANALYST NOTES", sty["section"]))

    box_p = Paragraph(f"<i>{_esc(notes)}</i>", sty["italic"])
    box_table = Table([[box_p]], colWidths=[CONTENT_W - 16])
    box_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), COLOR_EXEC_BG),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("ROUNDEDCORNERS", [3, 3, 3, 3]),
            ]
        )
    )
    elements.append(box_table)
    elements.append(Spacer(1, 10))
    return elements


def _build_signature_block(sty):
    """Three-column signature block for official sign-off."""
    elements = []
    elements.append(Spacer(1, 18))
    elements.append(
        HRFlowable(width="100%", thickness=0.5, color=COLOR_ACCENT_LINE, spaceAfter=12)
    )

    sig_style = ParagraphStyle(
        "sig",
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=COLOR_DARK,
        alignment=TA_CENTER,
    )

    col_w = CONTENT_W / 3

    sig_data = [
        [
            Paragraph("Analyst Signature<br/><br/>___________________", sig_style),
            Paragraph("Date Reviewed<br/><br/>___________________", sig_style),
            Paragraph("Approved By<br/><br/>___________________", sig_style),
        ]
    ]
    sig_table = Table(sig_data, colWidths=[col_w, col_w, col_w])
    sig_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ]
        )
    )
    elements.append(sig_table)
    return elements


# ---------------------------------------------------------------------------
#  IOC highlights (bonus section — shows top IOCs called out by LLM)
# ---------------------------------------------------------------------------
def _build_ioc_highlights(inc, sty):
    """Short list of the most critical IOCs as called out by the LLM."""
    llm = _safe_dict(inc.get("llm_report"))
    highlights = _safe_list(llm.get("ioc_highlights"))
    if not highlights:
        return []

    elements = []
    elements.append(Paragraph("CRITICAL IOC HIGHLIGHTS", sty["section"]))
    for h in highlights:
        elements.append(
            Paragraph(f"\u2022  <font face='Courier'>{_esc(h)}</font>", sty["bullet"])
        )
    elements.append(Spacer(1, 10))
    return elements


# ---------------------------------------------------------------------------
#  PUBLIC API — the single function Member 1 calls
# ---------------------------------------------------------------------------
def generate_pdf_report(incident: dict) -> bytes:
    """
    Generate a professional PDF incident report and return it as bytes.

    Parameters
    ----------
    incident : dict
        Full incident dictionary as stored/retrieved from the ThreatSense database.
        See the project spec for the exact schema.

    Returns
    -------
    bytes
        Raw PDF file content, ready to be written to disk or streamed as an
        HTTP response.
    """
    try:
        buf = BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            topMargin=20 * mm,
            bottomMargin=18 * mm,
            leftMargin=MARGIN,
            rightMargin=MARGIN,
            title="ThreatSense Incident Report",
            author="ThreatSense Platform",
        )

        sty = _styles()
        story = []

        # 1 — Title block with severity badge
        story.extend(_build_title_block(incident, sty))

        # 2 — Correlation warning (conditional)
        story.extend(_build_correlation_section(incident, sty))

        # 3 — File metadata table
        story.extend(_build_metadata_table(incident, sty))

        # 4 — Executive summary
        story.extend(_build_executive_summary(incident, sty))

        # 5 — Technical behavioral analysis
        story.extend(_build_technical_analysis(incident, sty))

        # 6 — IOC highlights (top IOCs from LLM)
        story.extend(_build_ioc_highlights(incident, sty))

        # 7 — Full IOC table
        story.extend(_build_ioc_table(incident, sty))

        # 8 — MITRE ATT&CK techniques
        story.extend(_build_mitre_section(incident, sty))

        # 9 — Remediation steps
        story.extend(_build_remediation(incident, sty))

        # 10 — VirusTotal details
        story.extend(_build_vt_section(incident, sty))

        # 11 — Analyst notes
        story.extend(_build_analyst_notes(incident, sty))

        # 12 — Signature block
        story.extend(_build_signature_block(sty))

        doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
        return buf.getvalue()

    except Exception as exc:
        # ---- NEVER CRASH — produce a minimal error PDF instead ----
        return _error_pdf(str(exc))


def _error_pdf(error_msg: str) -> bytes:
    """Return a minimal valid PDF containing only the error message."""
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    sty = _styles()
    story = [
        Paragraph("ThreatSense — PDF Generation Error", sty["title"]),
        Spacer(1, 20),
        Paragraph(
            f"An error occurred while generating the incident report:<br/><br/>"
            f"<font face='Courier' color='red'>{_esc(error_msg)}</font>",
            sty["body"],
        ),
        Spacer(1, 20),
        Paragraph(
            "Please review the raw incident data in the dashboard or contact Member 4.",
            sty["body"],
        ),
    ]
    doc.build(story)
    return buf.getvalue()


# ---------------------------------------------------------------------------
#  Standalone test harness — run `python pdf_generator.py` directly
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    fake_incident = {
        "incident_id": 7,
        "filename": "suspicious_payload.exe",
        "timestamp": "2026-03-05T14:32:11",
        "file_type": "Windows PE Executable",
        "input_type": "binary",
        "md5": "a1b2c3d4e5f67890a1b2c3d4e5f67890",
        "sha1": "aabbccdd11223344556677889900aabbccdd1122",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "size_bytes": 245760,
        "entropy": 7.82,
        "entropy_verdict": "Critical — almost certainly encrypted / packed payload",
        "risk_score": 92,
        "severity": "CRITICAL",
        "threat_class": "Trojan.Injector",
        "llm_report": {
            "threat_classification": "Trojan.Injector",
            "severity": "CRITICAL",
            "confidence": 87,
            "attack_techniques": [
                "T1055 - Process Injection",
                "T1140 - Deobfuscate/Decode Files or Information",
                "T1071 - Application Layer Protocol",
            ],
            "behavioral_summary": (
                "Static analysis reveals the binary imports CreateRemoteThread, "
                "VirtualAllocEx, and WriteProcessMemory — the classic triad for "
                "process injection. The file also resolves network APIs (WSAStartup, "
                "connect) suggesting outbound C2 communication. Entropy of 7.82 "
                "indicates the majority of the payload is encrypted or packed, which "
                "is consistent with evasion-focused malware. Strings analysis revealed "
                "a hardcoded IP address used as a command-and-control endpoint."
            ),
            "executive_summary": (
                "This executable displays characteristics consistent with a process "
                "injection trojan designed to evade endpoint detection. It imports "
                "Windows APIs commonly used to inject code into legitimate processes, "
                "contains encrypted payload sections, and communicates with an external "
                "command-and-control server. Immediate isolation of the affected system "
                "and firewall blocking of the identified C2 IP are recommended."
            ),
            "ioc_highlights": [
                "193.42.11.23 (C2 server)",
                "evil-domain.ru (payload host)",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Update (persistence)",
            ],
            "remediation": [
                "Isolate the affected machine from the network immediately.",
                "Block IP 193.42.11.23 at the perimeter firewall.",
                "Block domain evil-domain.ru in DNS filtering.",
                "Scan all machines on the same subnet for the identified IOCs.",
                "Check the registry run key for unauthorized persistence entries.",
                "Submit the sample to a sandbox (e.g. Any.run) for dynamic analysis.",
                "Engage incident response team for forensic imaging if warranted.",
            ],
            "analyst_notes": (
                "Zero VirusTotal detections despite high-confidence malicious indicators "
                "suggests a custom-built, targeted sample. This may be part of a larger "
                "campaign — cross-reference with past incidents recommended. Do not "
                "dismiss based solely on the lack of AV signatures."
            ),
        },
        "iocs": {
            "ips": ["193.42.11.23", "10.0.0.5"],
            "domains": ["evil-domain.ru"],
            "urls": ["http://193.42.11.23/stage2.ps1"],
            "registry_keys": [
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Update"
            ],
            "file_paths": ["C:\\Windows\\Temp\\svchost_update.dll"],
        },
        "vt_result": {
            "available": True,
            "known": True,
            "malicious": 0,
            "total": 70,
            "threat_names": [],
        },
        "correlation": {
            "matches_found": True,
            "match_count": 2,
            "matched_iocs": ["193.42.11.23"],
            "related_incidents": [
                {
                    "incident_id": 3,
                    "filename": "suspicious_update.ps1",
                    "timestamp": "2026-03-05T13:10:44",
                    "shared_iocs": ["193.42.11.23"],
                    "shared_count": 1,
                },
                {
                    "incident_id": 5,
                    "filename": "firewall_log.txt",
                    "timestamp": "2026-03-05T13:45:22",
                    "shared_iocs": ["193.42.11.23"],
                    "shared_count": 1,
                },
            ],
            "campaign_flag": True,
            "campaign_message": (
                "Multiple incidents share C2 infrastructure — likely coordinated attack campaign."
            ),
        },
    }

    pdf_bytes = generate_pdf_report(fake_incident)
    out_path = "test_output.pdf"
    with open(out_path, "wb") as f:
        f.write(pdf_bytes)
    print(f"PDF generated successfully: {len(pdf_bytes):,} bytes → {out_path}")
    print("Open the file to verify layout, severity badge, IOC table, and correlation banner.")
