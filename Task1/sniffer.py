#!/usr/bin/env python3
"""Basic network packet sniffer with PDF reporting. Use only on authorized networks."""
import argparse
import os
import sys
from collections import Counter
from datetime import datetime

try:
    from scapy.all import sniff, get_if_list, Ether, ARP, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw
except ImportError:
    print("Missing dependency: scapy. Install with: python -m pip install -r requirements.txt")
    raise SystemExit(2)

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
except ImportError:
    print("Missing dependency: reportlab. Install with: python -m pip install -r requirements.txt")
    raise SystemExit(2)

DEFAULT_OUTPUT = "network_sniffer_report.pdf"
MAX_PREVIEW_BYTES = 40
captured_packets = []


def escape_pdf(value):
    """Escape text before inserting it into a ReportLab Paragraph."""
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def printable_preview(packet, enabled=False, limit=MAX_PREVIEW_BYTES):
    """Show payload bytes only when explicitly requested."""
    if not enabled:
        return "Disabled (use --show-payload-preview to opt in)"
    if Raw not in packet:
        return "No undecoded payload"
    raw = bytes(packet[Raw].load)
    preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw[:limit])
    if len(raw) > limit:
        preview += "…"
    return preview or "(empty payload)"


def get_timestamp(packet):
    try:
        return datetime.fromtimestamp(float(packet.time)).astimezone().isoformat(timespec="seconds")
    except (AttributeError, TypeError, ValueError, OSError):
        return datetime.now().astimezone().isoformat(timespec="seconds")


def protocol_name(packet):
    for layer, name in ((DNS, "DNS"), (ARP, "ARP"), (ICMP, "ICMP"), (TCP, "TCP"),
                        (UDP, "UDP"), (IPv6, "IPv6"), (IP, "IPv4"), (Ether, "Ethernet")):
        if layer in packet:
            return name
    return "Other"


def packet_addresses(packet):
    src_mac = packet[Ether].src if Ether in packet else "N/A"
    dst_mac = packet[Ether].dst if Ether in packet else "N/A"
    src_ip = dst_ip = "N/A"
    if IP in packet:
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        src_ip, dst_ip = packet[IPv6].src, packet[IPv6].dst
    elif ARP in packet:
        src_ip, dst_ip = packet[ARP].psrc, packet[ARP].pdst
    src_port = str(packet[TCP].sport) if TCP in packet else (str(packet[UDP].sport) if UDP in packet else "N/A")
    dst_port = str(packet[TCP].dport) if TCP in packet else (str(packet[UDP].dport) if UDP in packet else "N/A")
    return src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port


def explain_packet(packet):
    notes = []
    if Ether in packet:
        notes.append("Ethernet frame: carries data across the local network link.")
    if ARP in packet:
        arp = packet[ARP]
        if int(arp.op) == 1:
            notes.append(f"ARP request: asks which device owns IPv4 address {arp.pdst}.")
        elif int(arp.op) == 2:
            notes.append(f"ARP reply: reports a hardware-address mapping for {arp.psrc}.")
        else:
            notes.append(f"ARP message with operation code {arp.op}.")
    if IP in packet:
        notes.append(f"IPv4 packet from {packet[IP].src} to {packet[IP].dst}.")
    elif IPv6 in packet:
        notes.append(f"IPv6 packet from {packet[IPv6].src} to {packet[IPv6].dst}; IPv6 uses 128-bit addresses.")
    if TCP in packet:
        tcp = packet[TCP]
        meanings = {"S": "SYN (connection start)", "A": "ACK (acknowledgement)",
                    "F": "FIN (connection close)", "R": "RST (reset)",
                    "P": "PSH (push data)", "U": "URG (urgent data)"}
        flags = str(tcp.flags)
        flag_text = ", ".join(text for flag, text in meanings.items() if flag in flags)
        msg = f"TCP segment from port {tcp.sport} to port {tcp.dport}; TCP supports ordered delivery and retransmission."
        if flag_text:
            msg += " Flags: " + flag_text + "."
        notes.append(msg)
    if UDP in packet:
        udp = packet[UDP]
        notes.append(f"UDP datagram from port {udp.sport} to port {udp.dport}; UDP does not itself guarantee delivery or ordering.")
    if ICMP in packet:
        icmp = packet[ICMP]
        meanings = {0: "Echo Reply (ping response)", 3: "Destination Unreachable",
                    8: "Echo Request (ping)", 11: "Time Exceeded"}
        notes.append(f"ICMP control/diagnostic message: {meanings.get(int(icmp.type), 'ICMP type ' + str(icmp.type))}.")
    if DNS in packet:
        dns = packet[DNS]
        if int(dns.qr) == 0:
            qname = ""
            if DNSQR in packet and packet[DNSQR].qname:
                raw_name = packet[DNSQR].qname
                qname = (raw_name.decode("utf-8", "replace") if isinstance(raw_name, bytes) else str(raw_name)).rstrip(".")
            notes.append("DNS query: requests information about a domain name." + (f" Queried name: {qname}." if qname else ""))
        else:
            notes.append(f"DNS response: resolver reply; reported answer-record count: {getattr(dns, 'ancount', 0) or 0}.")
    if Raw in packet:
        notes.append(f"Undecoded payload present; preview is limited to {MAX_PREVIEW_BYTES} bytes and opt-in.")
    return " ".join(notes) if notes else "No recognized protocol explanation was available for this packet."


def inspect_packet(packet, number, show_payload_preview=False):
    layers = [layer.__name__ for layer in packet.layers()]
    src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port = packet_addresses(packet)
    return {"number": number, "timestamp": get_timestamp(packet),
            "layers": " > ".join(layers) if layers else "Unknown",
            "src_mac": src_mac, "dst_mac": dst_mac, "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": src_port, "dst_port": dst_port, "protocol": protocol_name(packet),
            "length": len(packet), "explanation": explain_packet(packet),
            "preview": printable_preview(packet, enabled=show_payload_preview)}


def on_packet(packet, show_payload_preview=False):
    details = inspect_packet(packet, len(captured_packets) + 1, show_payload_preview)
    captured_packets.append(details)
    print(f"#{details['number']:03d}  {details['protocol']:<9} {details['src_ip']}:{details['src_port']} -> "
          f"{details['dst_ip']}:{details['dst_port']} ({details['length']} bytes)")


def build_pdf(output_path, interface, requested_count, started_at, stopped_at, capture_error=None):
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontSize=19, leading=23,
                               alignment=TA_CENTER, textColor=colors.HexColor("#163A52"), spaceAfter=8))
    styles.add(ParagraphStyle(name="SectionTitle", parent=styles["Heading1"], fontSize=13, leading=16,
                              textColor=colors.HexColor("#163A52"), spaceBefore=10, spaceAfter=6))
    styles.add(ParagraphStyle(name="PacketTitle", parent=styles["Heading2"], fontSize=10, leading=13,
                              textColor=colors.HexColor("#176B87"), spaceBefore=7, spaceAfter=4))
    styles.add(ParagraphStyle(name="SmallBody", parent=styles["BodyText"], fontSize=8.5, leading=11, spaceAfter=4))
    styles.add(ParagraphStyle(name="TinyBody", parent=styles["BodyText"], fontSize=7.2, leading=9))
    doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=16*mm, leftMargin=16*mm,
                            topMargin=15*mm, bottomMargin=18*mm,
                            title="Basic Network Sniffer Report", author="CodeAlpha Cyber Security Internship Project")
    story = [Spacer(1, 8*mm), Paragraph("BASIC NETWORK SNIFFER", styles["ReportTitle"]),
             Paragraph("Packet Capture and Protocol Analysis Report", styles["Heading2"]), Spacer(1, 3*mm),
             Paragraph(f"<b>Generated:</b> {escape_pdf(datetime.now().astimezone().isoformat(timespec='seconds'))}", styles["SmallBody"]),
             Paragraph(f"<b>Interface:</b> {escape_pdf(interface or 'System default')}", styles["SmallBody"]),
             Paragraph(f"<b>Requested packet limit:</b> {requested_count}", styles["SmallBody"]),
             Paragraph(f"<b>Packets recorded:</b> {len(captured_packets)}", styles["SmallBody"]),
             Paragraph(f"<b>Capture started:</b> {escape_pdf(started_at)}", styles["SmallBody"]),
             Paragraph(f"<b>Capture ended:</b> {escape_pdf(stopped_at)}", styles["SmallBody"]),
             Paragraph("Scope note: this report reflects only packets visible to the selected interface during this capture. "
                       "Use packet capture only on networks and devices you own or are authorized to inspect.", styles["SmallBody"])]
    if capture_error:
        story.append(Paragraph(f"<b>Capture note:</b> {escape_pdf(capture_error)}", styles["SmallBody"]))
    story.append(Paragraph("1. Protocol Summary", styles["SectionTitle"]))
    counts = Counter(item["protocol"] for item in captured_packets)
    summary_rows = [["Protocol", "Packet count"]] + [[escape_pdf(proto), str(n)] for proto, n in sorted(counts.items())]
    if not counts:
        summary_rows.append(["No packets recorded", "0"])
    summary = Table(summary_rows, colWidths=[100*mm, 35*mm], repeatRows=1)
    summary.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCEAF2")),
                                 ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#B8C7CF")),
                                 ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.extend([summary, Paragraph("2. Packet-by-Packet Analysis", styles["SectionTitle"])])
    if not captured_packets:
        story.append(Paragraph("No packets were recorded. Check the interface name, permissions, and capture driver.", styles["SmallBody"]))
    for item in captured_packets:
        rows = [["Timestamp", item["timestamp"]], ["Detected layers", item["layers"]],
                ["Source MAC", item["src_mac"]], ["Destination MAC", item["dst_mac"]],
                ["Source IP / ARP address", item["src_ip"]], ["Destination IP / ARP address", item["dst_ip"]],
                ["Source port", item["src_port"]], ["Destination port", item["dst_port"]],
                ["Packet length", f'{item["length"]} bytes'], ["Explanation", item["explanation"]],
                ["Payload preview", item["preview"]]]
        packet_rows = [[Paragraph(f"<b>{escape_pdf(k)}</b>", styles["TinyBody"]),
                        Paragraph(escape_pdf(v), styles["TinyBody"])] for k, v in rows]
        table = Table(packet_rows, colWidths=[42*mm, 126*mm], hAlign="LEFT")
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F0F4F6")),
                                   ("GRID", (0, 0), (-1, -1), .3, colors.HexColor("#D0D9DE")),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(KeepTogether([Paragraph(f'Packet #{item["number"]} — {escape_pdf(item["protocol"])}', styles["PacketTitle"]),
                                   table, Spacer(1, 3*mm)]))
    story.append(Paragraph("3. Protocol Guide", styles["SectionTitle"]))
    for name, desc in [("Ethernet", "Link-layer frame format carrying data across a local network."),
                       ("ARP", "Maps a local IPv4 address to a hardware address."),
                       ("IPv4 / IPv6", "Network-layer protocols carrying source and destination IP addresses."),
                       ("TCP", "Connection-oriented transport with ordered delivery and retransmission."),
                       ("UDP", "Low-overhead datagram transport without TCP-style delivery guarantees."),
                       ("ICMP", "Network diagnostic and error messages; ping commonly uses echo messages."),
                       ("DNS", "Domain Name System messages request or return domain-name records.")]:
        story.append(Paragraph(f"<b>{name}:</b> {desc}", styles["SmallBody"]))
    story.extend([Paragraph("4. Limitations and Privacy", styles["SectionTitle"]),
                  Paragraph("The sniffer sees only traffic exposed to the selected interface. Permissions, capture drivers, "
                            "Wi-Fi configuration, and network hardware affect results. HTTPS content is generally encrypted "
                            "and is not decrypted by this tool. Metadata and payload previews can be sensitive; review the report "
                            "before sharing it.", styles["SmallBody"]),
                  Paragraph("5. Project Notes", styles["SectionTitle"]),
                  Paragraph("This report is generated from packets observed during the current run. Do not claim successful capture "
                            "unless you have run and checked the program on your own machine.", styles["SmallBody"])])
    def footer(canvas, _doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#CCD7DD"))
        canvas.line(16*mm, 13*mm, 194*mm, 13*mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#586A73"))
        canvas.drawString(16*mm, 8*mm, "CodeAlpha Basic Network Sniffer")
        canvas.drawRightString(194*mm, 8*mm, f"Page {_doc.page}")
        canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def main():
    parser = argparse.ArgumentParser(description="Capture authorized network packets and create a PDF report.")
    parser.add_argument("-c", "--count", type=int, default=30, help="Maximum packets to capture (default: 30)")
    parser.add_argument("-i", "--interface", default=None, help="Capture interface name")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help="PDF output path")
    parser.add_argument("--timeout", type=float, default=30.0, help="Maximum capture duration in seconds")
    parser.add_argument("--show-payload-preview", action="store_true", help="Include up to 40 printable payload bytes; may expose sensitive data")
    parser.add_argument("--list-interfaces", action="store_true", help="List available interfaces and exit")
    args = parser.parse_args()
    if args.list_interfaces:
        try:
            print("\n".join(get_if_list()))
        except Exception as exc:
            print(f"Could not list interfaces: {exc}", file=sys.stderr)
            raise SystemExit(1)
        return
    if args.count < 1:
        parser.error("--count must be at least 1")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    if not args.output.lower().endswith(".pdf"):
        parser.error("--output must end with .pdf")
    print("CodeAlpha Basic Network Sniffer")
    print(f"Packet limit: {args.count}\nInterface: {args.interface or 'system default'}")
    print(f"Capture timeout: {args.timeout:g} seconds")
    print(f"Payload preview: {'enabled' if args.show_payload_preview else 'disabled (privacy-safe default)'}")
    print("Capture only traffic you are authorized to inspect.\n")
    started = datetime.now().astimezone().isoformat(timespec="seconds")
    capture_error = None
    try:
        sniff(iface=args.interface, prn=lambda p: on_packet(p, args.show_payload_preview),
              count=args.count, timeout=args.timeout, store=False)
    except KeyboardInterrupt:
        capture_error = "Capture stopped by user (Ctrl+C)."
        print("\nCapture stopped by user.")
    except PermissionError:
        capture_error = "Permission denied. Use an appropriately elevated terminal if authorized."
        print(f"\n{capture_error}", file=sys.stderr)
    except Exception as exc:
        capture_error = f"{type(exc).__name__}: {exc}"
        print(f"\nCapture error: {capture_error}", file=sys.stderr)
        print("Check interface name, capture permissions, and Npcap/libpcap installation.", file=sys.stderr)
    stopped = datetime.now().astimezone().isoformat(timespec="seconds")
    try:
        build_pdf(args.output, args.interface, args.count, started, stopped, capture_error)
        print(f"\nPDF report saved to: {os.path.abspath(args.output)}")
        print(f"Packets recorded: {len(captured_packets)}")
    except Exception as exc:
        print(f"\nPDF generation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if capture_error and not captured_packets:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
