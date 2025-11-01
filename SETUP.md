# Setup Guide - Network Port Scanner

This guide provides detailed installation instructions for all required tools.

## Table of Contents

1. [Nmap Installation](#nmap-installation)
2. [Python Setup](#python-setup)
3. [Wireshark Installation](#wireshark-installation-optional)
4. [Finding Your Local IP Range](#finding-your-local-ip-range)
5. [Testing Your Setup](#testing-your-setup)
6. [Troubleshooting](#troubleshooting)

---

## Nmap Installation

### macOS

#### Option 1: Homebrew (Recommended)

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Nmap
brew install nmap

# Verify installation
nmap --version
```

#### Option 2: Official Installer

1. Download from [nmap.org](https://nmap.org/download.html)
2. Download the `.dmg` file for macOS
3. Open the `.dmg` file and drag Nmap to Applications
4. Open Terminal and verify: `nmap --version`

### Linux

#### Ubuntu/Debian

```bash
# Update package list
sudo apt update

# Install Nmap
sudo apt install nmap -y

# Verify installation
nmap --version
```

#### Fedora/RHEL/CentOS

```bash
# Install Nmap
sudo dnf install nmap -y
# or for older versions:
sudo yum install nmap -y

# Verify installation
nmap --version
```

#### Arch Linux

```bash
# Install Nmap
sudo pacman -S nmap

# Verify installation
nmap --version
```

### Windows

#### Option 1: Official Installer (Recommended)

1. Visit [nmap.org/download.html](https://nmap.org/download.html)
2. Download the latest Windows installer (`.exe`)
3. Run the installer with administrator privileges
4. Follow the installation wizard
5. Optional: Install Npcap (packet capture library) when prompted
6. Add Nmap to PATH during installation

#### Option 2: Chocolatey

```powershell
# Install Chocolatey if not already installed
# Run PowerShell as Administrator

# Install Nmap
choco install nmap -y

# Verify installation
nmap --version
```

#### Verify Windows Installation

Open Command Prompt or PowerShell:
```cmd
nmap --version
```

If command not found, add to PATH:
1. Search "Environment Variables" in Windows
2. Edit System PATH
3. Add: `C:\Program Files (x86)\Nmap`

---

## Python Setup

The Python scanner requires Python 3.7 or higher.

### Check Current Python Version

```bash
python3 --version
```

### macOS

Python 3 is usually pre-installed on modern macOS:

```bash
# Check if Python 3 is installed
python3 --version

# If not installed, use Homebrew
brew install python3

# Verify
python3 --version
```

### Linux

#### Ubuntu/Debian

```bash
# Python 3 is usually pre-installed
python3 --version

# If not installed:
sudo apt update
sudo apt install python3 python3-pip -y
```

#### Fedora/RHEL

```bash
sudo dnf install python3 python3-pip -y
```

### Windows

1. Download from [python.org](https://www.python.org/downloads/)
2. Run installer
3. **Important**: Check "Add Python to PATH" during installation
4. Verify in Command Prompt:
```cmd
python --version
```

---

## Wireshark Installation (Optional)

Wireshark is optional but recommended for deep packet analysis.

### macOS

#### Option 1: Homebrew

```bash
brew install --cask wireshark

# You may need to install ChmodBPF for packet capture
sudo /Library/Application\ Support/Wireshark/ChmodBPF/ChmodBPF
```

#### Option 2: Official Installer

1. Download from [wireshark.org](https://www.wireshark.org/download.html)
2. Install the `.dmg` package
3. Follow installation instructions

### Linux

#### Ubuntu/Debian

```bash
sudo apt update
sudo apt install wireshark -y

# Add your user to wireshark group for non-root capture
sudo usermod -aG wireshark $USER

# Log out and log back in for changes to take effect
```

During installation, select "Yes" when asked if non-superusers should be able to capture packets.

#### Fedora/RHEL

```bash
sudo dnf install wireshark wireshark-qt -y

# Add user to wireshark group
sudo usermod -aG wireshark $USER
```

### Windows

1. Download from [wireshark.org/download.html](https://www.wireshark.org/download.html)
2. Download Windows installer (`.exe`)
3. Run with administrator privileges
4. Install Npcap when prompted (required for packet capture)
5. Follow installation wizard

---

## Finding Your Local IP Range

### macOS

```bash
# Method 1: Using ifconfig
ifconfig | grep "inet "

# Method 2: System Preferences
# System Preferences → Network → Select Active Connection
# Your IP will be shown (e.g., 192.168.1.5)

# Method 3: Using networksetup
networksetup -getinfo "Wi-Fi"
```

**Example Output:**
```
inet 192.168.1.5 netmask 0xffffff00
```

This means:
- Your IP: `192.168.1.5`
- Netmask: `255.255.255.0` (the /24)
- Your network range: `192.168.1.0/24`

### Linux

```bash
# Method 1: Using ip command (modern)
ip addr show

# Method 2: Using ifconfig (older)
ifconfig

# Method 3: Using hostname
hostname -I

# Method 4: Show routing table
ip route | grep default
```

**Example Output:**
```
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 192.168.1.10/24 brd 192.168.1.255
```

Your network range: `192.168.1.0/24`

### Windows

```cmd
# Method 1: Using ipconfig
ipconfig

# Method 2: PowerShell
Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4"}
```

**Example Output:**
```
IPv4 Address. . . . . . . . . . : 192.168.1.15
Subnet Mask . . . . . . . . . . : 255.255.255.0
```

Your network range: `192.168.1.0/24`

### Understanding CIDR Notation

| Subnet Mask     | CIDR | IP Range              | Total IPs |
|----------------|------|-----------------------|-----------|
| 255.255.255.0  | /24  | 192.168.1.0-255      | 256       |
| 255.255.0.0    | /16  | 192.168.0.0-255.255  | 65,536    |
| 255.255.255.128| /25  | 192.168.1.0-127      | 128       |

**Most common for home networks:** `/24` (192.168.1.0/24 or 10.0.0.0/24)

---

## Testing Your Setup

### Test 1: Verify Nmap Installation

```bash
nmap --version
```

**Expected Output:**
```
Nmap version 7.94 ( https://nmap.org )
```

### Test 2: Basic Nmap Scan

Scan your own machine (always safe and legal):

```bash
# Scan localhost
nmap localhost

# Or
nmap 127.0.0.1
```

**Expected Output:**
```
Starting Nmap 7.94
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00010s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
```

### Test 3: Python Script

```bash
# Navigate to project directory
cd /path/to/network-port-scanner-task

# Make script executable (macOS/Linux)
chmod +x network_scanner.py

# Run the script
python3 network_scanner.py

# Follow prompts - test with 127.0.0.1 (localhost)
```

### Test 4: Bash Script (macOS/Linux only)

```bash
# Make script executable
chmod +x scan.sh

# Run the script
./scan.sh

# Test with localhost: 127.0.0.1
```

### Test 5: Wireshark (Optional)

1. Open Wireshark
2. Select your network interface (e.g., Wi-Fi, Ethernet)
3. Click "Start" to begin capture
4. Run a simple ping: `ping google.com`
5. Stop capture after a few seconds
6. You should see ICMP packets in Wireshark

---

## Project Setup

### Clone or Download Project

```bash
# Option 1: If using Git
git clone https://github.com/yourusername/network-port-scanner-task.git
cd network-port-scanner-task

# Option 2: Download ZIP
# Extract to your desired location
cd /path/to/extracted/folder
```

### Make Scripts Executable (macOS/Linux)

```bash
chmod +x network_scanner.py
chmod +x scan.sh
```

### Create Results Directory

The scripts create this automatically, but you can pre-create it:

```bash
mkdir -p results
mkdir -p screenshots  # Optional, for storing scan screenshots
```

---

## Troubleshooting

### Issue: "nmap: command not found"

**Solution:**
- Verify installation: Follow installation steps again
- Check PATH:
  - macOS/Linux: `which nmap`
  - Windows: `where nmap`
- Restart terminal/command prompt after installation

### Issue: "Permission denied" when running SYN scan

**Problem:** SYN scans require root/administrator privileges

**Solution:**

```bash
# macOS/Linux: Use sudo
sudo nmap -sS 192.168.1.0/24

# Or use the Python script which prompts for sudo automatically
python3 network_scanner.py
# Choose option 2 (SYN scan)
```

### Issue: "python3: command not found" (Windows)

**Solution:**
- Try `python` instead of `python3`
- Reinstall Python with "Add to PATH" option checked
- Manually add Python to PATH

### Issue: Nmap scan is very slow

**Possible Causes & Solutions:**

1. **Scanning too many hosts:**
   - Solution: Reduce range (e.g., scan /26 instead of /24)

2. **Slow timing template:**
   - Solution: Use `-T4` flag for faster scanning
   ```bash
   nmap -T4 192.168.1.0/24
   ```

3. **Firewall blocking:**
   - Solution: Check firewall settings

4. **Network congestion:**
   - Solution: Scan during off-peak hours

### Issue: "Unable to find interface" (Wireshark)

**Solution:**
- Run Wireshark with administrator/root privileges
- macOS: Install ChmodBPF
  ```bash
  sudo /Library/Application\ Support/Wireshark/ChmodBPF/ChmodBPF
  ```
- Linux: Add user to wireshark group
  ```bash
  sudo usermod -aG wireshark $USER
  ```
- Restart Wireshark

### Issue: No open ports found on network

**Possible Reasons:**

1. **Incorrect IP range:**
   - Verify your network range (see "Finding Your Local IP Range")

2. **Devices have firewalls:**
   - This is normal; many devices block scans

3. **No other devices on network:**
   - Try scanning your own machine first (localhost)

### Issue: "Socket error" or "Cannot assign requested address"

**Solution:**
- Check your network connection
- Verify you're scanning the correct network range
- Try scanning a single host first:
  ```bash
  nmap 192.168.1.1
  ```

### Issue: Script won't run on Windows

**Solution for Python Script:**
```cmd
# Use python instead of python3
python network_scanner.py
```

**Solution for Bash Script:**
- Bash scripts don't run natively on Windows
- Options:
  1. Use Python script instead
  2. Install Git Bash or WSL (Windows Subsystem for Linux)
  3. Use PowerShell alternative or Nmap directly

### Getting Help

If you encounter issues:

1. Check Nmap documentation: [nmap.org/docs.html](https://nmap.org/docs.html)
2. Wireshark wiki: [wiki.wireshark.org](https://wiki.wireshark.org/)
3. Stack Overflow: Search for specific error messages
4. Reddit communities: r/netsec, r/AskNetsec

---

## Security Reminder

⚠️ **IMPORTANT:**
- Only scan networks you own or have explicit written permission to scan
- Unauthorized network scanning may be illegal in your jurisdiction
- Be cautious with aggressive scans on production networks
- Inform network administrators before scanning business networks

---

## Ready to Start!

Once everything is set up:

1. ✅ Nmap installed and working
2. ✅ Python 3 installed (for Python script)
3. ✅ Scripts are executable
4. ✅ Know your local IP range
5. ✅ Optional: Wireshark installed

You're ready to proceed with the [README.md](README.md) instructions!

---

## Quick Start Command

```bash
# Test everything with a localhost scan
python3 network_scanner.py
# When prompted, enter: 127.0.0.1
# Choose scan type: 1 (basic scan)
```

Good luck with your network security learning journey! 🚀🛡️
