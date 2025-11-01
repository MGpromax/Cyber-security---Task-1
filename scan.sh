#!/bin/bash
# Simple Network Scanner Script
# Educational tool for learning port scanning

echo "============================================"
echo "Network Port Scanner - Educational Tool"
echo "============================================"
echo ""
echo "IMPORTANT: Only scan networks you own!"
echo ""

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "[!] ERROR: nmap is not installed!"
    echo ""
    echo "To install:"
    echo "  macOS: brew install nmap"
    echo "  Linux: sudo apt-get install nmap"
    exit 1
fi

echo "[+] nmap is installed!"

# Create results directory
mkdir -p results

# Get local network info
echo ""
echo "[*] Your network interfaces:"
ifconfig | grep -E "inet |flags" | head -20

# Get target from user
echo ""
read -p "Enter target IP range (e.g., 192.168.1.0/24): " TARGET

if [ -z "$TARGET" ]; then
    echo "[!] No target specified. Exiting."
    exit 1
fi

# Create timestamp for filename
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="results/scan_${TIMESTAMP}"

echo ""
echo "[*] Starting scan on $TARGET..."
echo "[*] This may take a few minutes..."
echo ""

# Run nmap scan
# -sS: TCP SYN scan (requires sudo)
# -T4: Timing template (faster)
# -oN: Normal output format
# -oX: XML output format

sudo nmap -sS -T4 "$TARGET" -oN "${OUTPUT_FILE}.txt" -oX "${OUTPUT_FILE}.xml"

echo ""
echo "[+] Scan complete!"
echo "[+] Results saved to: ${OUTPUT_FILE}.txt"

# Try to create HTML output if xsltproc is available
if command -v xsltproc &> /dev/null; then
    xsltproc "${OUTPUT_FILE}.xml" -o "${OUTPUT_FILE}.html" 2>/dev/null
    if [ -f "${OUTPUT_FILE}.html" ]; then
        echo "[+] HTML report: ${OUTPUT_FILE}.html"
    fi
fi

# Show quick summary
echo ""
echo "--- Quick Summary ---"
grep "Nmap scan report for" "${OUTPUT_FILE}.txt"
grep "Host is up" "${OUTPUT_FILE}.txt"
echo ""
grep "open" "${OUTPUT_FILE}.txt" | grep -v "Scanning"

echo ""
echo "[+] Check the results directory for detailed output!"
echo ""
echo "Security Reminders:"
echo "- Close unnecessary open ports"
echo "- Keep services updated"
echo "- Use firewalls to restrict access"
echo "- Monitor your network regularly"
