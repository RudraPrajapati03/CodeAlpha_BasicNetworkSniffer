# NIDS Test Report

**Test date shown in local screenshots:** 25 October 2026  
**Engine:** Suricata 8.0.7  
**Platform:** Windows with Npcap

## Results recorded

| Test | Observed result | Status |
|---|---|---|
| Suricata version | Suricata 8.0.7 RELEASE displayed | PASS (as recorded) |
| Configuration validation | `Configuration provided was successfully loaded. Exiting.` | PASS (as recorded) |
| Live capture startup | `Engine started.` displayed | PASS (as recorded) |
| Local gateway ping | Three replies received with 0% packet loss in the shown test | PASS (as recorded) |
| Custom ICMP rule | `NIDS TEST - ICMP traffic detected` entries appeared in `fast.log` after ping | PASS (as recorded) |
| HTTPS connectivity | `curl.exe -I` returned `HTTP/1.1 200 OK` for tested sites | PASS (connectivity only) |
| CSV summary | 26 matching entries exported from the existing log at the time of the test | PASS (as recorded) |

## Interpretation

These are results recorded from the project's local test evidence; they have not been independently rerun as part of this repository edit. They indicate that Suricata was reported to start, accept the configuration, capture traffic on the selected interface, and log alerts matching the custom ICMP Echo Request rule.

The HTTPS request is a connectivity/control test. It does not demonstrate comprehensive TLS inspection or broad attack-detection coverage. The exported CSV count may include alerts from earlier tests and should not be interpreted as alerts from one ping.

## Remaining verification

- Re-run the tests after moving the folder to `Task4` and verify the actual paths on your machine.
- Verify the helper script against a fresh local `fast.log`.
- Review generated logs and CSV for environment-specific details before sharing.
- Follow the official internship submission instructions.
