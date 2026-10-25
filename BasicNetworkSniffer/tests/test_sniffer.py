"""Offline unit tests for packet interpretation and PDF generation."""
import os
import tempfile
import unittest
from datetime import datetime, timezone

from scapy.all import ARP, DNS, DNSQR, Ether, IP, TCP, UDP, Raw

import sniffer


class PacketAnalysisTests(unittest.TestCase):
    def test_tcp_packet_metadata(self):
        packet = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(
            src="192.0.2.10", dst="198.51.100.20"
        ) / TCP(sport=12345, dport=443, flags="S")
        details = sniffer.inspect_packet(packet, 1)
        self.assertEqual(details["protocol"], "TCP")
        self.assertEqual(details["src_ip"], "192.0.2.10")
        self.assertEqual(details["dst_ip"], "198.51.100.20")
        self.assertEqual(details["src_port"], "12345")
        self.assertIn("SYN", details["explanation"])
        self.assertIn("Disabled", details["preview"])

    def test_dns_query_recognized(self):
        packet = Ether() / IP(src="192.0.2.2", dst="192.0.2.53") / UDP(sport=53000, dport=53) / DNS(
            rd=1, qd=DNSQR(qname="example.com")
        )
        details = sniffer.inspect_packet(packet, 1)
        self.assertEqual(details["protocol"], "DNS")
        self.assertIn("example.com", details["explanation"])

    def test_arp_addresses(self):
        packet = Ether() / ARP(op=1, psrc="192.0.2.10", pdst="192.0.2.1")
        details = sniffer.inspect_packet(packet, 1)
        self.assertEqual(details["protocol"], "ARP")
        self.assertEqual(details["src_ip"], "192.0.2.10")
        self.assertEqual(details["dst_ip"], "192.0.2.1")

    def test_payload_preview_is_opt_in_and_limited(self):
        packet = Ether() / IP() / TCP() / Raw(load=b"HELLO" + b"X" * 100)
        self.assertIn("Disabled", sniffer.printable_preview(packet))
        preview = sniffer.printable_preview(packet, enabled=True)
        self.assertTrue(preview.startswith("HELLO"))
        self.assertLessEqual(len(preview), sniffer.MAX_PREVIEW_BYTES + 1)
        self.assertTrue(preview.endswith("…"))

    def test_pdf_created_for_empty_capture(self):
        previous = sniffer.captured_packets[:]
        sniffer.captured_packets.clear()
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = os.path.join(directory, "empty-report.pdf")
                now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
                sniffer.build_pdf(path, None, 5, now, now)
                self.assertTrue(os.path.isfile(path))
                with open(path, "rb") as report:
                    self.assertTrue(report.read(5).startswith(b"%PDF-"))
        finally:
            sniffer.captured_packets[:] = previous

    def test_pdf_created_with_packet_details(self):
        previous = sniffer.captured_packets[:]
        packet = Ether() / IP(src="192.0.2.5", dst="198.51.100.5") / TCP(sport=50000, dport=443)
        sniffer.captured_packets[:] = [sniffer.inspect_packet(packet, 1)]
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = os.path.join(directory, "packet-report.pdf")
                now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
                sniffer.build_pdf(path, "test0", 1, now, now)
                self.assertTrue(os.path.isfile(path))
                self.assertGreater(os.path.getsize(path), 1000)
        finally:
            sniffer.captured_packets[:] = previous


if __name__ == "__main__":
    unittest.main()
