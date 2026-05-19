# CodeAlpha Task 1 - Basic Network Sniffer

This project is a Python-based **Basic Network Sniffer** with a modern GUI built using **Tkinter** and packet capturing powered by **Scapy**.

## Features

- Live packet capture from the selected network interface
- Displays:
  - Source IP / MAC
  - Destination IP / MAC
  - Protocol
  - Packet length
  - Summary information
  - Payload preview
- Protocol filters: ALL, TCP, UDP, ICMP, ARP, HTTP-like
- Search by IP address or port
- Detailed packet inspection panel
- Export packet summary to CSV
- Export captured packets to PCAP
- Simple protocol distribution chart

## Tech Stack

- Python 3.10+
- Scapy
- Tkinter

## Installation

```bash
pip install -r requirements.txt
```

## Run

### Windows
Run Command Prompt or PowerShell as **Administrator**:

```bash
python app.py
```

### Linux / macOS
Run terminal with elevated permissions if needed:

```bash
sudo python3 app.py
```

## Project Structure

```text
codealpha_sniffer/
├── app.py
├── requirements.txt
└── README.md
```

## How It Works

1. The app reads available network interfaces from Scapy.
2. When you click **Start Capture**, it begins sniffing traffic on the selected interface.
3. Each packet is parsed to extract source, destination, protocol, ports, and raw payload preview.
4. Packets are shown in a table and can be clicked for detailed inspection.
5. Results can be exported to **CSV** or **PCAP**.

## Important Note

Use this tool only on networks and devices you own or are authorized to test. Packet sniffing on unauthorized networks may violate laws, policies, or privacy rules.

## Suggested GitHub Repository Name

```text
CodeAlpha_BasicNetworkSniffer
```

## Suggested LinkedIn Demo Points

- What packet sniffing is
- How TCP, UDP, ICMP, and ARP packets differ
- How the GUI helps inspect packet details
- Why admin/root permissions are required
- How CSV and PCAP export can support analysis
