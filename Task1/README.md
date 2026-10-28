# CodeAlpha Basic Network Sniffer

A Python network packet sniffer for the CodeAlpha Cyber Security Internship Task 1. It captures packets visible to a selected network interface, summarizes protocols, explains recognized packet layers, and creates a PDF report.

## Features

- Capture a chosen number of packets with Scapy.
- Show source/destination IP addresses, MAC addresses, ports, protocol, packet length, and detected layers.
- Explain common protocols: Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, and DNS.
- Export a PDF report with protocol counts and packet-by-packet analysis.
- Keep payload previews disabled by default; optionally show only a short printable excerpt.
- List available interfaces.
- Include capture notes and privacy limitations in the report.

## Requirements

- Python 3.10 or newer recommended.
- Scapy.
- ReportLab.
- A packet capture driver/library: Windows: Npcap; Linux: libpcap support.
- Appropriate capture permissions.

## Setup

```bash
python -m venv .venv
```

Activate on Windows PowerShell with `\.venv\Scripts\Activate.ps1`, Windows CMD with `.venv\Scripts\activate.bat`, or Linux/Kali with `source .venv/bin/activate`.

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

List interfaces:

```bash
python sniffer.py --list-interfaces
```

Capture up to 30 packets, stopping after 30 seconds if the limit is not reached:

```bash
python sniffer.py --count 30 --timeout 30
```

Enable a short payload preview only when necessary (payloads can contain private information):

```bash
python sniffer.py --count 30 --show-payload-preview
```

Choose an interface or output path with `--interface "Wi-Fi"` and `--output my_packet_report.pdf`.

## Offline unit tests

Run from this folder:

```bash
python -m unittest discover -s tests -v
```

These tests use synthetic packets and temporary PDF files; they do not sniff live traffic. Live capture must be verified separately on your own authorized system.

## Output

The default report is `network_sniffer_report.pdf` in the current working directory. It contains capture metadata, protocol summary, packet-by-packet details, a protocol guide, and privacy notes.

## Safety and privacy

Use this tool only on your own device/network or with explicit permission. Do not capture or share other people's traffic without authorization. HTTPS application content is generally encrypted and this tool does not decrypt it. Metadata and payload previews can still be sensitive, so inspect the report before publishing it.

## Internship submission checklist

- [ ] Run the offline tests and verify they pass.
- [ ] Run the tool on an authorized interface.
- [ ] Verify the PDF report is created and inspect it for sensitive information.
- [ ] Add screenshots of your actual successful run if requested.
- [ ] Follow the latest official CodeAlpha submission form/instructions for any additional deliverables.

Do not claim a successful capture until you have run and verified it on your own computer.
