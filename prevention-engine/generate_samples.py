"""
Generate 30 sample forensic PDF reports + 30 sample PCAP captures
for the Prevention Dashboard demo.
"""

import os
import sys
import random
import struct
import time
from datetime import datetime, timedelta

# ── Paths ──
REPORT_DIR = "/var/log/wifi_defense/reports"
CAPTURE_DIR = "/var/log/wifi_defense/attacks"

os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(CAPTURE_DIR, exist_ok=True)

# ── Sample data ──
ATTACKER_MACS = [
    "DE:AD:BE:EF:00:01", "AA:BB:CC:DD:EE:01", "11:22:33:44:55:66",
    "FE:DC:BA:98:76:54", "CA:FE:BA:BE:00:FF", "00:1A:2B:3C:4D:5E",
]
VICTIM_MACS = [
    "CA:FE:BA:BE:00:02", "9E:A8:2C:C2:1F:D9", "AC:DE:48:00:11:22",
    "B4:6B:FC:AA:BB:CC", "D8:3A:DD:EE:FF:00",
]
SSIDS = ["supreeth", "KIT-WiFi", "Lab-Network", "Faculty-Net", "Campus-5GHz"]
CHANNELS = [1, 6, 11, 36, 44]

def random_mac():
    return ":".join(f"{random.randint(0,255):02X}" for _ in range(6))


# ═══════════════════════════════════════════════════════════════════
# 1. Generate 30 PCAP files (valid pcap format with fake 802.11 frames)
# ═══════════════════════════════════════════════════════════════════
def write_pcap_file(path, num_packets=50):
    """Write a valid PCAP file with synthetic deauth-like frames."""
    with open(path, "wb") as f:
        # PCAP Global Header (24 bytes)
        # magic=0xa1b2c3d4, version 2.4, timezone=0, sigfigs=0,
        # snaplen=65535, network=127 (IEEE 802.11)
        f.write(struct.pack("<IHHiIII",
            0xa1b2c3d4,   # magic number
            2, 4,          # version
            0,             # timezone
            0,             # sigfigs
            65535,         # snaplen
            127            # link-layer: IEEE 802.11
        ))

        base_ts = int(time.time()) - random.randint(0, 86400)

        for i in range(num_packets):
            ts = base_ts + i
            ts_sec = ts
            ts_usec = random.randint(0, 999999)

            # Build a fake 802.11 deauth frame (26 bytes)
            # Frame control: 0x00C0 = deauthentication (type 0, subtype 12)
            frame_control = 0x00C0
            duration = 0x013A
            # destination MAC (6 bytes)
            dst = bytes([random.randint(0, 255) for _ in range(6)])
            # source MAC (6 bytes)
            src = bytes([random.randint(0, 255) for _ in range(6)])
            # BSSID (6 bytes)
            bssid = bytes([random.randint(0, 255) for _ in range(6)])
            seq_ctrl = random.randint(0, 65535)
            reason = random.choice([1, 3, 6, 7])  # common reason codes

            packet = struct.pack("<HH", frame_control, duration)
            packet += dst + src + bssid
            packet += struct.pack("<HH", seq_ctrl, reason)

            incl_len = len(packet)
            orig_len = incl_len

            # PCAP Packet Header (16 bytes)
            f.write(struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len))
            f.write(packet)


print("📦 Generating 30 PCAP capture files...")
for i in range(1, 31):
    ts = datetime.now() - timedelta(hours=random.randint(1, 720))
    ts_str = ts.strftime("%Y%m%d_%H%M%S")
    event_id = f"evt_{1000+i}"
    filename = f"attack_{event_id}_{ts_str}.pcap"
    filepath = os.path.join(CAPTURE_DIR, filename)
    num_pkts = random.randint(30, 200)
    write_pcap_file(filepath, num_pkts)
    print(f"  ✅ {filename} ({os.path.getsize(filepath)} bytes, {num_pkts} packets)")

# ═══════════════════════════════════════════════════════════════════
# 2. Generate 30 PDF forensic reports
# ═══════════════════════════════════════════════════════════════════
print("\n📄 Generating 30 PDF forensic reports...")

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle)
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor, Color
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus.frames import Frame
    from reportlab.platypus.doctemplate import PageTemplate

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

    for i in range(1, 31):
        ts = datetime.now() - timedelta(hours=random.randint(1, 720))
        ts_str = ts.strftime("%Y%m%d_%H%M%S")
        event_id = f"evt_{1000+i}"
        pdf_path = os.path.join(REPORT_DIR, f"forensic_report_{event_id}_{ts_str}.pdf")

        confidence = round(random.uniform(45, 99), 1)
        attacker = random.choice(ATTACKER_MACS)
        victim = random.choice(VICTIM_MACS)
        ssid = random.choice(SSIDS)
        channel = random.choice(CHANNELS)
        baseline_ms = round(random.uniform(80, 500), 1)
        optimized_ms = round(baseline_ms * random.uniform(0.15, 0.6), 1)
        improvement = round((1 - optimized_ms / baseline_ms) * 100, 1)

        severity = "Critical" if confidence >= 85 else ("High" if confidence >= 60 else "Moderate")
        sev_color = "#dc2626" if confidence >= 85 else ("#ea580c" if confidence >= 60 else "#2563eb")

        l1 = True
        l2 = confidence >= 60
        l3 = confidence >= 85

        deauth_count = random.randint(50, 500)
        total_packets = deauth_count + random.randint(20, 200)

        def _draw_page(c, doc):
            c.saveState()
            c.setFont("Helvetica-Bold", 60)
            c.setFillColor(Color(0.9, 0.9, 0.9, alpha=0.3))
            c.translate(page_w / 2, page_h / 2)
            c.rotate(45)
            c.drawCentredString(0, 0, "CONFIDENTIAL")
            c.restoreState()
            c.saveState()
            c.setFont("Helvetica", 8)
            c.setFillColor(GRAY)
            c.drawString(2 * cm, 1.2 * cm, f"WiFi Shield — Forensic Report #{event_id}")
            c.drawRightString(page_w - 2 * cm, 1.2 * cm,
                              f"Generated: {ts.strftime('%Y-%m-%d %H:%M:%S')}  |  Page {doc.page}")
            c.line(2 * cm, 1.5 * cm, page_w - 2 * cm, 1.5 * cm)
            c.restoreState()

        doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                                topMargin=2.5 * cm, bottomMargin=2.5 * cm,
                                leftMargin=2 * cm, rightMargin=2 * cm)
        frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="normal")
        template = PageTemplate(id="branded", frames=frame, onPage=_draw_page)
        doc.addPageTemplates([template])

        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle("BrandTitle", parent=styles["Title"],
                                      textColor=NAVY, fontSize=22, spaceAfter=4)
        subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"],
                                         textColor=GRAY, fontSize=11, spaceAfter=12)
        heading_style = ParagraphStyle("SectionHead", parent=styles["Heading2"],
                                        textColor=NAVY, fontSize=14, spaceBefore=16, spaceAfter=8)
        normal = ParagraphStyle("Body", parent=styles["Normal"],
                                 textColor=DARK, fontSize=10, leading=14)

        # Title
        story.append(Paragraph("WiFi Shield — Forensic Evidence Report", title_style))
        story.append(Paragraph(
            f"Report ID: <b>{event_id}</b>  •  Classification: <font color='#dc2626'>CONFIDENTIAL</font>",
            subtitle_style))
        story.append(Spacer(1, 6 * mm))

        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Paragraph(
            f"A deauthentication attack with <b><font color='{sev_color}'>{confidence}%</font></b> "
            f"confidence ({severity} severity) was detected targeting SSID "
            f"<b>{ssid}</b> on channel {channel}. "
            f"Automated defenses were activated, and this report documents the forensic evidence collected.",
            normal))
        story.append(Spacer(1, 6 * mm))

        # Attack Details
        story.append(Paragraph("Attack Details", heading_style))
        details_data = [
            ["Field", "Value"],
            ["Event ID", event_id],
            ["Timestamp", ts.strftime("%Y-%m-%d %H:%M:%S")],
            ["Confidence", f"{confidence}% ({severity})"],
            ["Attacker MAC", attacker],
            ["Victim MAC", victim],
            ["SSID", ssid],
            ["Channel", str(channel)],
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
            *[("BACKGROUND", (1, i), (1, i), WHITE if i % 2 == 1 else HexColor("#f8fafc"))
              for i in range(1, len(details_data))],
        ]))
        story.append(details_table)
        story.append(Spacer(1, 8 * mm))

        # Defense Response
        story.append(Paragraph("Defense Response", heading_style))
        defense_data = [["Level", "Action", "Status"]]
        if l1: defense_data.append(["L1", "Fast Reconnection", "ACTIVATED"])
        if l2: defense_data.append(["L2", "Application Resilience", "ACTIVATED"])
        if l3: defense_data.append(["L3", "UX Optimization", "ACTIVATED"])
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
        story.append(Spacer(1, 8 * mm))

        # Latency Measurements
        story.append(Paragraph("Latency Measurements", heading_style))
        lat_data = [
            ["Metric", "Value"],
            ["Baseline RTT", f"{baseline_ms} ms"],
            ["Optimized RTT", f"{optimized_ms} ms"],
            ["Improvement", f"{improvement}%"],
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
        ]))
        story.append(lat_table)
        story.append(Spacer(1, 8 * mm))

        # PCAP Analysis
        story.append(Paragraph("Packet Capture Analysis", heading_style))
        pcap_data = [
            ["Metric", "Count"],
            ["Total Packets", str(total_packets)],
            ["Deauth Frames", str(deauth_count)],
            ["Disassoc Frames", str(random.randint(5, 50))],
            ["Management Frames", str(deauth_count + random.randint(10, 80))],
            ["Data Frames", str(random.randint(10, 100))],
            ["Unique Sources", str(random.randint(2, 8))],
            ["Unique Destinations", str(random.randint(1, 5))],
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
        print(f"  ✅ forensic_report_{event_id}_{ts_str}.pdf ({os.path.getsize(pdf_path)} bytes)")

except ImportError as e:
    print(f"❌ reportlab not available: {e}")
    print("   Install with: pip install reportlab")
    sys.exit(1)

# ── Verify ──
pdf_count = len([f for f in os.listdir(REPORT_DIR) if f.endswith(".pdf")])
pcap_count = len([f for f in os.listdir(CAPTURE_DIR) if f.endswith(".pcap")])
print(f"\n✅ Done! Reports: {pdf_count} PDFs, Captures: {pcap_count} PCAPs")
print(f"   📁 PDFs:  {REPORT_DIR}")
print(f"   📁 PCAPs: {CAPTURE_DIR}")
