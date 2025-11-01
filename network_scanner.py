#!/usr/bin/env python3
"""
Network Port Scanner
Educational tool for learning network reconnaissance and port scanning
"""

import subprocess
import sys
import os
from datetime import datetime
import json


def check_nmap_installed():
    """Check if nmap is installed on the system"""
    try:
        result = subprocess.run(['nmap', '--version'],
                              capture_output=True,
                              text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def get_local_ip_info():
    """Get local IP information"""
    print("\n[*] Getting local network information...")
    try:
        # For macOS/Linux
        result = subprocess.run(['ifconfig'],
                              capture_output=True,
                              text=True)
        print("\n--- Network Interface Information ---")
        print(result.stdout[:500])  # Print first 500 chars
        print("\nLook for your local IP (usually starts with 192.168.x.x or 10.x.x.x)")
    except Exception as e:
        print(f"Error getting IP info: {e}")


def run_nmap_scan(target, scan_type='basic'):
    """
    Run nmap scan on target network

    Args:
        target: IP range to scan (e.g., '192.168.1.0/24')
        scan_type: Type of scan - 'basic', 'syn', or 'full'
    """
    print(f"\n[*] Starting {scan_type} scan on {target}")
    print("[*] This may take a few minutes...")

    # Create results directory
    os.makedirs('results', exist_ok=True)

    # Generate output filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f"results/scan_{scan_type}_{timestamp}"

    # Build nmap command based on scan type
    if scan_type == 'syn':
        # TCP SYN scan (requires sudo/root)
        cmd = ['sudo', 'nmap', '-sS', '-T4', target,
               '-oN', f"{output_file}.txt",
               '-oX', f"{output_file}.xml"]
    elif scan_type == 'full':
        # More comprehensive scan
        cmd = ['sudo', 'nmap', '-sS', '-sV', '-T4', '-p-', target,
               '-oN', f"{output_file}.txt",
               '-oX', f"{output_file}.xml"]
    else:
        # Basic scan (no sudo required)
        cmd = ['nmap', '-T4', target,
               '-oN', f"{output_file}.txt",
               '-oX', f"{output_file}.xml"]

    print(f"[*] Running command: {' '.join(cmd)}")
    print(f"[*] Results will be saved to: {output_file}.txt")

    try:
        # Run the scan
        result = subprocess.run(cmd,
                              capture_output=True,
                              text=True,
                              timeout=600)  # 10 minute timeout

        print("\n--- Scan Output ---")
        print(result.stdout)

        if result.stderr:
            print("\n--- Warnings/Errors ---")
            print(result.stderr)

        # Also save to HTML format for better viewing
        subprocess.run(['xsltproc', f"{output_file}.xml",
                       '-o', f"{output_file}.html"],
                      capture_output=True)

        print(f"\n[+] Scan complete! Results saved to:")
        print(f"    - {output_file}.txt (text format)")
        print(f"    - {output_file}.xml (XML format)")
        print(f"    - {output_file}.html (HTML format, if xsltproc available)")

        return output_file

    except subprocess.TimeoutExpired:
        print("[!] Scan timed out after 10 minutes")
        return None
    except Exception as e:
        print(f"[!] Error running scan: {e}")
        return None


def analyze_results(output_file):
    """Provide basic analysis of scan results"""
    print("\n[*] Analyzing results...")

    try:
        with open(f"{output_file}.txt", 'r') as f:
            content = f.read()

        # Count open ports
        open_ports = content.count('open')
        hosts_up = content.count('Host is up')

        print(f"\n--- Quick Analysis ---")
        print(f"Hosts up: {hosts_up}")
        print(f"Open ports found: {open_ports}")

        # Extract some common services
        common_services = ['http', 'https', 'ssh', 'ftp', 'smtp', 'mysql', 'postgresql']
        found_services = [s for s in common_services if s in content.lower()]

        if found_services:
            print(f"Common services detected: {', '.join(found_services)}")

    except Exception as e:
        print(f"[!] Error analyzing results: {e}")


def print_security_tips():
    """Print security tips based on findings"""
    print("\n" + "="*60)
    print("SECURITY TIPS")
    print("="*60)
    print("""
1. Open ports expose services to the network
2. Unnecessary open ports should be closed
3. Critical services should be behind a firewall
4. Keep all services updated to latest versions
5. Use strong authentication for all network services
6. Monitor your network regularly for changes
7. Common risky ports:
   - 21 (FTP) - Use SFTP instead
   - 23 (Telnet) - Use SSH instead
   - 3389 (RDP) - Ensure strong passwords/VPN access
   - 3306 (MySQL) - Should not be exposed externally
   - 5432 (PostgreSQL) - Should not be exposed externally
    """)


def main():
    """Main function"""
    print("="*60)
    print("NETWORK PORT SCANNER - Educational Tool")
    print("="*60)
    print("\nIMPORTANT: Only scan networks you own or have permission to scan!")
    print("Unauthorized scanning may be illegal.\n")

    # Check if nmap is installed
    if not check_nmap_installed():
        print("[!] ERROR: nmap is not installed!")
        print("\nTo install nmap:")
        print("  - macOS: brew install nmap")
        print("  - Ubuntu/Debian: sudo apt-get install nmap")
        print("  - Windows: Download from https://nmap.org/download.html")
        sys.exit(1)

    print("[+] nmap is installed!")

    # Show network info
    get_local_ip_info()

    # Get user input
    print("\n" + "="*60)
    target = input("\nEnter target IP range (e.g., 192.168.1.0/24): ").strip()

    if not target:
        print("[!] No target specified. Exiting.")
        sys.exit(1)

    print("\nScan Types:")
    print("1. Basic scan (no sudo required, faster)")
    print("2. TCP SYN scan (requires sudo, recommended)")
    print("3. Full scan (requires sudo, slower but comprehensive)")

    choice = input("\nSelect scan type (1-3) [default: 1]: ").strip()

    scan_types = {'1': 'basic', '2': 'syn', '3': 'full'}
    scan_type = scan_types.get(choice, 'basic')

    # Run the scan
    output_file = run_nmap_scan(target, scan_type)

    if output_file:
        # Analyze results
        analyze_results(output_file)

        # Print security tips
        print_security_tips()

        print("\n[+] Task complete! Check the 'results' directory for detailed output.")
        print("[+] You can view the HTML file in a web browser for better visualization.")
    else:
        print("\n[!] Scan failed or was interrupted.")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0)
