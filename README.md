# Suspicious Connection Detector – Real-Time Network Monitor

This is a Python-based tool designed to monitor all outgoing TCP connections from your system in real time. It flags connections made to foreign or untrusted countries and logs them for later review. The tool is especially helpful for students, cybersecurity learners, and anyone interested in understanding what their system is connecting to.

---

## Features

- Displays all outgoing TCP connections in real time
- Shows process name, PID, local and remote IP addresses with ports
- Integrates with `ipapi.co` to fetch country information for remote IPs
- Flags connections originating from untrusted or foreign countries
- Logs suspicious connection details to a text file for later review
- Provides a clean and user-friendly terminal interface using  `rich`

---

## Setup

### Requirements

Install the following Python packages before running the tool:

```bash
pip install psutil requests rich
