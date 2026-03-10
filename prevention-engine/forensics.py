"""
prevention-engine/forensics.py
Forensic Evidence Collector — PCAP capture via tcpdump + PDF report via reportlab.

Captures network traffic during an attack event, analyses packets with dpkt,
and generates a PDF forensic report detailing attack statistics and defense actions.
"""

import os
import subprocess
import time
import logging
import yaml
from datetime import datetime

# ── Config ──
_CFG_PATH = os.path.join(os.path.dirname(__file__), "config.yml")

def _load_config():
    try:
        with open(_CFG_PATH) as f:
            return yaml.safe_load(f)
    except Exception:
        return {}

_cfg = _load_config()
_net = _cfg.get("network", {})
_forensics = _cfg.get("forensics", {})

INTERFACE     = _net.get("interface", "wlan1")
CAPTURE_DIR   = _forensics.get("capture_dir", "/var/log/wifi_defense/attacks")
REPORT_DIR    = _forensics.get("report_dir", "/var/log/wifi_defense/reports")
PACKET_COUNT  = _forensics.get("packet_count", 600)
CAPTURE_TIMEOUT = _forensics.get("capture_timeout", 60)

# Ensure directories exist (may need sudo at runtime)
try:
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)
except PermissionError:
    pass  # will be created when engine runs as sudo

# ── Logger ──
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
forensics_log = logging.getLogger("forensics")
forensics_log.setLevel(logging.DEBUG)
if not forensics_log.handlers:
    fh = logging.FileHandler(os.path.join(LOG_DIR, "forensics.log"))
    fh.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
    forensics_log.addHandler(fh)


# ── PCAP Capture ─────────────────────────────────────────────────────────────
def capture_packets(event_id: str, duration: int = 10) -> str:
    """Capture packets to a PCAP file. Returns path to PCAP or empty string."""
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(CAPTURE_DIR, f"attack_{event_id}_{timestamp}.pcap")

    try:
        proc = subprocess.run(
            ["sudo", "tcpdump", "-i", INTERFACE, "-c", str(PACKET_COUNT),
             "-w", pcap_file, "-G", str(duration), "-W", "1"],
            capture_output=True, text=True, timeout=duration + 5
        )
        if os.path.isfile(pcap_file):
            forensics_log.info(f"PCAP captured: {pcap_file} ({os.path.getsize(pcap_file)} bytes)")
            return pcap_file
    except subprocess.TimeoutExpired:
        if os.path.isfile(pcap_file):
            forensics_log.info(f"PCAP captured (timeout): {pcap_file}")
            return pcap_file
    except Exception as e:
        forensics_log.error(f"PCAP capture failed: {e}")

    return ""


# ── PCAP Analysis ────────────────────────────────────────────────────────────
def analyse_pcap(pcap_path: str) -> dict:
    """Analyse a PCAP file with dpkt and return statistics."""
    stats = {
        "total_packets": 0,
        "deauth_frames": 0,
        "disassoc_frames": 0,
        "management_frames": 0,
        "data_frames": 0,
        "unique_sources": set(),
        "unique_destinations": set(),
    }

    if not pcap_path or not os.path.isfile(pcap_path):
        return stats

    try:
        import dpkt
        with open(pcap_path, "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                stats["total_packets"] += 1
                try:
                    tap = dpkt.radiotap.Radiotap(buf)
                    frame = tap.data
                    if hasattr(frame, "type"):
                        if frame.type == 0:  # Management
                            stats["management_frames"] += 1
                            if hasattr(frame, "subtype"):
                                if frame.subtype == 12:  # Deauthentication
                                    stats["deauth_frames"] += 1
                                elif frame.subtype == 10:  # Disassociation
                                    stats["disassoc_frames"] += 1
                        elif frame.type == 2:  # Data
                            stats["data_frames"] += 1
                    # Track MACs
                    if hasattr(frame, "mgmt") and hasattr(frame.mgmt, "src"):
                        stats["unique_sources"].add(frame.mgmt.src.hex())
                    if hasattr(frame, "mgmt") and hasattr(frame.mgmt, "dst"):
                        stats["unique_destinations"].add(frame.mgmt.dst.hex())
                except Exception:
                    pass
    except Exception as e:
        forensics_log.error(f"PCAP analysis failed: {e}")

    # Convert sets to counts for JSON serialisation
    stats["unique_sources"] = len(stats["unique_sources"])
    stats["unique_destinations"] = len(stats["unique_destinations"])
    return stats


# ── PDF Report Generation ────────────────────────────────────────────────────
LOGO_PATH = os.path.join(os.path.dirname(__file__), "assets", "wifi_shield_logo.png")

def generate_report(event_data: dict, pcap_stats: dict = None) -> str:
    """Generate a branded PDF forensic report. Returns path to PDF."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    event_id = event_data.get("event_id", "unknown")
    pdf_path = os.path.join(REPORT_DIR, f"forensic_report_{event_id}_{timestamp}.pdf")

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm, mm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                         Table, TableStyle, Image, PageBreak)
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor, Color
        from reportlab.lib.enums import TA_CENTER, TA_RIGHT
        from reportlab.platypus.frames import Frame
        from reportlab.platypus.doctemplate import PageTemplate
        from reportlab.pdfgen import canvas as pdf_canvas

        # ── Brand colours ──
        NAVY   = HexColor("#1a1a2e")
        BLUE   = HexColor("#2563eb")
        DARK   = HexColor("#0f172a")
        GRAY   = HexColor("#64748b")
        LIGHT  = HexColor("#f1f5f9")
        WHITE  = HexColor("#ffffff")
        RED    = HexColor("#dc2626")
        GREEN  = HexColor("#16a34a")
        ORANGE = HexColor("#ea580c")

        page_w, page_h = A4

        # ── Watermark + Header/Footer callback ──
        def _draw_page(c, doc):
            c.saveState()
            # Watermark
            c.setFont("Helvetica-Bold", 60)
            c.setFillColor(Color(0.9, 0.9, 0.9, alpha=0.3))
            c.translate(page_w / 2, page_h / 2)
            c.rotate(45)
            c.drawCentredString(0, 0, "CONFIDENTIAL")
            c.restoreState()

            # Footer
            c.saveState()
            c.setFont("Helvetica", 8)
            c.setFillColor(GRAY)
            c.drawString(2 * cm, 1.2 * cm, f"WiFi Shield — Forensic Report #{event_id}")
            c.drawRightString(page_w - 2 * cm, 1.2 * cm,
                              f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Page {doc.page}")
            c.line(2 * cm, 1.5 * cm, page_w - 2 * cm, 1.5 * cm)
            c.restoreState()

        doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                                topMargin=2.5 * cm, bottomMargin=2.5 * cm,
                                leftMargin=2 * cm, rightMargin=2 * cm)
        # Attach callback
        frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="normal")
        template = PageTemplate(id="branded", frames=frame, onPage=_draw_page)
        doc.addPageTemplates([template])

        styles = getSampleStyleSheet()
        story = []

        # ── Custom styles ──
        title_style = ParagraphStyle("BrandTitle", parent=styles["Title"],
                                      textColor=NAVY, fontSize=22, spaceAfter=4)
        subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"],
                                         textColor=GRAY, fontSize=11, spaceAfter=12)
        heading_style = ParagraphStyle("SectionHead", parent=styles["Heading2"],
                                        textColor=NAVY, fontSize=14, spaceBefore=16, spaceAfter=8,
                                        borderWidth=0, borderPadding=0)
        normal = ParagraphStyle("Body", parent=styles["Normal"],
                                 textColor=DARK, fontSize=10, leading=14)
        small_gray = ParagraphStyle("SmallGray", parent=styles["Normal"],
                                     textColor=GRAY, fontSize=9)

        # ── Logo + Header ──
        if os.path.isfile(LOGO_PATH):
            try:
                logo = Image(LOGO_PATH, width=3.5 * cm, height=3.5 * cm)
                logo.hAlign = "CENTER"
                story.append(logo)
                story.append(Spacer(1, 4 * mm))
            except Exception:
                pass

        story.append(Paragraph("WiFi Shield — Forensic Evidence Report", title_style))
        story.append(Paragraph(
            f"Report ID: <b>{event_id}</b>  •  Classification: <font color='#dc2626'>CONFIDENTIAL</font>",
            subtitle_style))
        story.append(Spacer(1, 6 * mm))

        # ── Executive Summary ──
        confidence = event_data.get("confidence", 0)
        severity = "Critical" if confidence >= 85 else ("High" if confidence >= 60 else "Moderate")
        sev_color = "#dc2626" if confidence >= 85 else ("#ea580c" if confidence >= 60 else "#2563eb")

        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Paragraph(
            f"A deauthentication attack with <b><font color='{sev_color}'>{confidence:.1f}%</font></b> "
            f"confidence ({severity} severity) was detected targeting SSID "
            f"<b>{event_data.get('ssid', 'N/A')}</b> on channel {event_data.get('channel', 'N/A')}. "
            f"Automated defenses were activated, and this report documents the forensic evidence collected.",
            normal))
        story.append(Spacer(1, 6 * mm))

        # ── Event Details Table ──
        story.append(Paragraph("Attack Details", heading_style))
        details_data = [
            ["Field", "Value"],
            ["Event ID", str(event_id)],
            ["Timestamp", str(event_data.get("timestamp", "N/A"))],
            ["Confidence", f"{confidence:.1f}% ({severity})"],
            ["Attacker MAC", str(event_data.get("attacker_mac", "N/A"))],
            ["Victim MAC", str(event_data.get("victim_mac", "N/A"))],
            ["SSID", str(event_data.get("ssid", "N/A"))],
            ["Channel", str(event_data.get("channel", "N/A"))],
        ]
        details_table = Table(details_data, colWidths=[6 * cm, 10 * cm])
        details_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("BACKGROUND", (0, 1), (0, -1), LIGHT),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            # Alternating row colours
            *[("BACKGROUND", (1, i), (1, i), WHITE if i % 2 == 1 else HexColor("#f8fafc"))
              for i in range(1, len(details_data))],
        ]))
        story.append(details_table)
        story.append(Spacer(1, 8 * mm))

        # ── Defense Response ──
        story.append(Paragraph("Defense Response", heading_style))
        levels = []
        if event_data.get("level1_fired"): levels.append(("L1", "Fast Reconnection", GREEN))
        if event_data.get("level2_fired"): levels.append(("L2", "Application Resilience", BLUE))
        if event_data.get("level3_fired"): levels.append(("L3", "UX Optimization", ORANGE))

        if levels:
            defense_data = [["Level", "Action", "Status"]]
            for tag, name, _color in levels:
                defense_data.append([tag, name, "ACTIVATED"])
            if event_data.get("honeypot_active"):
                defense_data.append(["HP", "Honeypot (150 Fake APs)", "ACTIVE"])

            defense_table = Table(defense_data, colWidths=[3 * cm, 9 * cm, 4 * cm])
            defense_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                *[("BACKGROUND", (0, i), (-1, i), WHITE if i % 2 == 1 else HexColor("#f8fafc"))
                  for i in range(1, len(defense_data))],
                ("TEXTCOLOR", (-1, 1), (-1, -1), GREEN),
                ("FONTNAME", (-1, 1), (-1, -1), "Helvetica-Bold"),
            ]))
            story.append(defense_table)
        else:
            story.append(Paragraph("No defense levels were activated for this event.", normal))
        story.append(Spacer(1, 8 * mm))

        # ── Latency Measurements ──
        baseline = event_data.get("baseline_ms")
        optimized = event_data.get("optimized_ms")
        improvement = event_data.get("improvement_pct")

        if baseline is not None or optimized is not None:
            story.append(Paragraph("Latency Measurements", heading_style))
            lat_data = [
                ["Metric", "Value"],
                ["Baseline RTT", f"{baseline:.1f} ms" if baseline else "N/A"],
                ["Optimized RTT", f"{optimized:.1f} ms" if optimized else "N/A"],
                ["Improvement", f"{improvement:.1f}%" if improvement else "N/A"],
            ]
            lat_table = Table(lat_data, colWidths=[8 * cm, 8 * cm])
            lat_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                *[("BACKGROUND", (0, i), (-1, i), WHITE if i % 2 == 1 else HexColor("#f8fafc"))
                  for i in range(1, len(lat_data))],
            ]))
            story.append(lat_table)
            story.append(Spacer(1, 8 * mm))

        # ── PCAP Analysis ──
        if pcap_stats and pcap_stats.get("total_packets", 0) > 0:
            story.append(Paragraph("Packet Capture Analysis", heading_style))
            pcap_data = [
                ["Metric", "Count"],
                ["Total Packets", str(pcap_stats.get("total_packets", 0))],
                ["Deauth Frames", str(pcap_stats.get("deauth_frames", 0))],
                ["Disassoc Frames", str(pcap_stats.get("disassoc_frames", 0))],
                ["Management Frames", str(pcap_stats.get("management_frames", 0))],
                ["Data Frames", str(pcap_stats.get("data_frames", 0))],
                ["Unique Sources", str(pcap_stats.get("unique_sources", 0))],
                ["Unique Destinations", str(pcap_stats.get("unique_destinations", 0))],
            ]
            pcap_table = Table(pcap_data, colWidths=[8 * cm, 8 * cm])
            pcap_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                *[("BACKGROUND", (0, i), (-1, i), WHITE if i % 2 == 1 else HexColor("#f8fafc"))
                  for i in range(1, len(pcap_data))],
            ]))
            story.append(pcap_table)

        doc.build(story)
        forensics_log.info(f"Branded report generated: {pdf_path}")
        return pdf_path

    except Exception as e:
        forensics_log.error(f"Report generation failed: {e}")
        return ""


# ── Full pipeline ────────────────────────────────────────────────────────────
def collect_evidence(event_data: dict) -> dict:
    """Full pipeline: capture → analyse → report. Returns result dict."""
    event_id = event_data.get("event_id", "unknown")
    forensics_log.info(f"Collecting evidence for event {event_id}")

    # Capture (short)
    pcap_path = capture_packets(event_id, duration=5)
    pcap_stats = analyse_pcap(pcap_path) if pcap_path else {}

    # Report
    report_path = generate_report(event_data, pcap_stats)

    return {
        "event_id": event_id,
        "pcap_file": pcap_path,
        "report_file": report_path,
        "pcap_stats": pcap_stats,
    }


def list_reports():
    """Return list of available forensic reports and PCAPs."""
    reports = []
    if os.path.isdir(REPORT_DIR):
        for f in sorted(os.listdir(REPORT_DIR), reverse=True):
            reports.append({
                "filename": f,
                "path": os.path.join(REPORT_DIR, f),
                "size": os.path.getsize(os.path.join(REPORT_DIR, f)),
                "type": "pdf" if f.endswith(".pdf") else "pcap",
            })
    pcaps = []
    if os.path.isdir(CAPTURE_DIR):
        for f in sorted(os.listdir(CAPTURE_DIR), reverse=True):
            pcaps.append({
                "filename": f,
                "path": os.path.join(CAPTURE_DIR, f),
                "size": os.path.getsize(os.path.join(CAPTURE_DIR, f)),
                "type": "pcap",
            })
    return {"reports": reports, "pcaps": pcaps}
