# CodeAlpha Cyber Security Internship Projects

This repository contains two separate projects completed for the CodeAlpha Cyber Security Internship.

## Task 1 — Basic Network Sniffer

Folder: [`BasicNetworkSniffer/`](./BasicNetworkSniffer/)

A Python packet sniffer built with Scapy that summarizes visible packet metadata and generates a PDF report. See [Task 1 README](./BasicNetworkSniffer/README.md) for setup, usage, tests, and safety notes.

## Task 2 — Network Intrusion Detection System (NIDS)

Folder: [`NIDS/`](./NIDS/)

A Suricata-based learning project with a custom ICMP Echo Request alert rule, configuration notes, test report, and a helper script for summarizing `fast.log`. See [NIDS README](./NIDS/README.md).

## Repository layout

```text
.
├── BasicNetworkSniffer/  # Task 1: Python packet sniffer and PDF reporting
├── NIDS/                 # Task 2: Suricata-based NIDS demonstration
├── .github/workflows/    # Repository CI checks
├── .gitignore
└── LICENSE
```

## Safety

Use network tools only on devices and networks you own or have explicit permission to monitor. Review generated logs, reports, and captures for sensitive information before sharing.
