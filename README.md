# Cyber-security---Task-1

## Overview

This project demonstrates network reconnaissance by scanning a local network for open ports. It's an educational tool to understand network security and port scanning.

**⚠️ IMPORTANT:** Only scan networks you own or have explicit permission to scan.

## Tools Used

- **Nmap** - Network scanning tool
- **Python 3** - For automation
- **Wireshark** (optional) - Packet analysis

## Installation

**Install Nmap:**
- macOS: `brew install nmap`
- Linux: `sudo apt-get install nmap`
- Windows: Download from [nmap.org](https://nmap.org/download.html)

## Usage

### Method 1: Python Script (Recommended)

```bash
python3 network_scanner.py
```

Follow the prompts to enter your IP range (e.g., 192.168.1.0/24) and select scan type.

### Method 2: Direct Nmap Commands

```bash
# Basic scan
nmap 192.168.1.0/24

# TCP SYN scan (requires sudo)
sudo nmap -sS 192.168.1.0/24

# Save results
sudo nmap -sS -T4 192.168.1.0/24 -oN scan_results.txt
```

## Finding Your IP Range

```bash
# macOS/Linux
ifconfig | grep inet

# Windows
ipconfig
```

Look for your local IP (usually `192.168.1.x` or `10.0.0.x`). Your network range is typically `192.168.1.0/24`.

## Understanding Results

**Port States:**
- **Open** - Service is accepting connections
- **Closed** - No service listening
- **Filtered** - Firewall blocking access

**Common Ports:**
- Port 22: SSH
- Port 80: HTTP
- Port 443: HTTPS
- Port 3306: MySQL
- Port 3389: RDP

## Key Concepts

- **Port Scanning** - Discovering open ports on network hosts
- **TCP SYN Scan** - Stealthy half-open scanning technique
- **Network Reconnaissance** - Information gathering for security assessment

## Security Insights

**Risks of Open Ports:**
- Unauthorized access points
- Vulnerable services can be exploited
- Information disclosure

**Best Practices:**
- Close unnecessary ports
- Use firewalls
- Keep services updated
- Use strong authentication
- Regular monitoring

**High-Risk Ports:**
- Port 21 (FTP) - Use SFTP instead
- Port 23 (Telnet) - Use SSH instead
- Port 3389 (RDP) - Ensure strong auth

## Files Included

- `network_scanner.py` - Interactive Python scanner
- `scan.sh` - Bash script alternative
- `INTERVIEW_QUESTIONS.md` - Detailed answers to all questions
- `SETUP.md` - Installation guide
- `results/` - Scan outputs saved here

## Ethical Use

This tool is for **educational purposes only**:
- Only scan networks you own or have permission to test
- Do not exploit vulnerabilities you find
- Comply with all applicable laws

---

**Use responsibly!** 🛡️
