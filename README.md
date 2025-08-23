# Suspicious Connection Detector – Real-Time Network Monitor

This is a Python-based tool designed to monitor all outgoing TCP connections from your system in real time. It flags connections made to foreign or untrusted countries and logs them for later review. The tool is especially helpful for students, cybersecurity learners, and anyone interested in understanding what their system is connecting to.

---

## Features

- Displays all real-time outgoing TCP connections
- Shows process name, PID, local and remote IPs with ports
- Uses `ipapi.co` to get country information of remote IPs
- Flags connections that are not from trusted countries
- Logs suspicious connections to a text file
- Clean terminal interface using `rich`

---

## Setup

### Requirements

Install the following Python packages before running the tool:

```bash
pip install psutil requests rich
