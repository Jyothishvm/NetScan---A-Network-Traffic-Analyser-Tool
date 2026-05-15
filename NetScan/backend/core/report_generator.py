import os
import json
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf_report(case_id: str, report_data: dict) -> str:
    """
    Takes the structured report data from the backend and generates a PDF file.
    Returns the absolute path to the generated PDF.
    """
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    pdf_path = os.path.join(reports_dir, f"{case_id}.pdf")
    
    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = styles["Title"]
    heading_style = styles["Heading2"]
    normal_style = styles["Normal"]
    
    warn_style = ParagraphStyle(
        name="WarnLabel",
        parent=styles["Normal"],
        textColor=colors.whitesmoke,
        backColor=colors.firebrick,
        borderPadding=4,
        fontSize=10,
        leading=14,
        spaceAfter=10
    )

    story = []
    
    # --- Title Page ---
    story.append(Paragraph(f"NetScan Intelligence Report", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Case ID: {case_id}", normal_style))
    story.append(Spacer(1, 24))
    
    # --- Executive Summary ---
    total_score = report_data.get("total_score", 0)
    story.append(Paragraph("Executive Summary", heading_style))
    story.append(Paragraph(f"Total Threat Score: {total_score}/100", normal_style))
    story.append(Spacer(1, 12))
    
    if total_score > 75:
        story.append(Paragraph("CRITICAL ALERT: SEVERE COMPROMISE DETECTED", warn_style))
    elif total_score > 40:
        story.append(Paragraph("WARNING: SUSPICIOUS ACTIVITY DETECTED", warn_style))
        
    story.append(Spacer(1, 12))
    
    # Inject AI Summary
    ai_summary = report_data.get("ai_summary")
    if ai_summary:
        story.append(Paragraph("<b>AI Analysis:</b> " + str(ai_summary).replace("\n", "<br/>\n"), normal_style))
        story.append(Spacer(1, 24))

    engines_data = report_data.get("engines", {})

    # --- Victim Identification ---
    victim_data = engines_data.get("victim", {})
    if victim_data:
        story.append(Paragraph("Primary Victim Profile", heading_style))
        v_table_data = [
            ["Primary IP", victim_data.get("most_compromised_host", "Unknown")],
            ["Confidence", f"{victim_data.get('confidence_score', 0)}/100"],
            ["Indicators", ", ".join(victim_data.get("indicators", []))]
        ]
        t = Table(v_table_data, colWidths=[120, 300])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(t)
        story.append(Spacer(1, 24))

    # --- Detection Engines Summary ---
    story.append(Paragraph("Detection Engine Results", heading_style))
    detectors = [
        ("DNS Anomalies", "dns"),
        ("C2 Beacons", "c2"),
        ("TLS Fingerprinting", "tls"),
        ("Data Exfiltration", "exfil"),
        ("Lateral Movement", "lateral"),
        ("HTTP/SQLi DPI", "http"),
        ("ICMP Overflows", "icmp"),
        ("Port Scanning", "port_scan"),
        ("Cleartext Credentials", "credentials"),
        ("VPN / Tor Nodes", "vpn_tor")
    ]
    
    for title, key in detectors:
        engine = engines_data.get(key, {})
        alerts = engine.get("findings", [])
        if alerts:
            story.append(Paragraph(f"{title} ({len(alerts)} alerts)", styles["Heading3"]))
            
            for alert in alerts[:15]: # Cap at 15 per category so PDF doesn't explode
                desc = alert.get("description", str(alert))
                story.append(Paragraph(f"• {desc}", normal_style))
            if len(alerts) > 15:
                story.append(Paragraph(f"• ... and {len(alerts) - 15} more.", normal_style))
                
            story.append(Spacer(1, 12))

    # --- Timelines --- 
    timeline = engines_data.get("timeline", [])
    if timeline:
        story.append(Paragraph("Timeline of Events", heading_style))
        for event in timeline[:30]:
            time = event.get("time", "Unknown Time")
            stage = event.get("stage", "Unknown")
            desc = event.get("description", "")
            story.append(Paragraph(f"<b>[{time}] {stage}:</b> {desc}", normal_style))
        story.append(Spacer(1, 12))

    doc.build(story)
    return pdf_path

if __name__ == "__main__":
    # Test
    print("Testing Report Generator...")
