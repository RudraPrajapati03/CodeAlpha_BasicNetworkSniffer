# Project notes

## What the program does
The sniffer captures packets visible on the selected interface and uses Scapy's decoded layers to extract basic metadata. It keeps payload previews disabled by default. If explicitly enabled, it records at most 40 printable payload bytes per packet and writes the analysis to a PDF.

## Known limitations
- Capture visibility depends on interface, OS permissions, drivers, Wi-Fi mode, and network setup.
- Protocol identification is based on recognized layers and is not a guarantee about the application using a port.
- The program does not decrypt HTTPS traffic.
- Packet metadata and payload previews may contain sensitive information; previews are opt-in.
- Test results should be collected on the user's own authorized environment before submission.

## Verification status

- Python syntax compilation was checked locally.
- Run the unit tests with `python -m unittest discover -s tests -v` after installing `requirements.txt`.
- Live packet capture should be tested on the target computer with an authorized interface and appropriate capture driver/permissions.
