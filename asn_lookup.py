#!/usr/bin/env python3
"""
ASN IP Block Lookup Tool

Takes an IP address, finds the BGP ASN that announces it,
retrieves all IP blocks for that ASN, and saves them to a text file.

Uses:
- Team Cymru whois for IP to ASN lookup
- RIPE RIS API for prefix data (primary)
- RADB whois as fallback

Usage:
    python asn_lookup.py <IP_ADDRESS>
    
Example:
    python asn_lookup.py 8.8.8.8
"""

import sys
import os
import json
import socket
import urllib.request
import urllib.error
from datetime import datetime


def get_asn_via_whois(ip: str) -> dict | None:
    """
    Look up ASN using Team Cymru whois service.
    This is the most reliable method for IP to ASN mapping.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("whois.cymru.com", 43))
        # -v flag gives verbose output with AS name
        sock.sendall(f" -v {ip}\n".encode())
        
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        sock.close()
        
        lines = response.decode().strip().split("\n")
        # Skip header line, parse data line
        # Format: AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
        for line in lines[1:]:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 7:
                try:
                    asn = int(parts[0].strip())
                    return {
                        "asn": asn,
                        "ip": parts[1].strip(),
                        "prefix": parts[2].strip(),
                        "country": parts[3].strip(),
                        "registry": parts[4].strip(),
                        "allocated": parts[5].strip(),
                        "name": parts[6].strip()
                    }
                except ValueError:
                    continue
    except (socket.error, socket.timeout) as e:
        print(f"Whois lookup error: {e}")
    
    return None


def get_prefixes_from_ripe(asn: int) -> list[str]:
    """
    Get announced prefixes from RIPE RIS (Routing Information Service).
    This provides real-time BGP announcement data.
    """
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    prefixes = []
    
    try:
        req = urllib.request.Request(
            url, 
            headers={"User-Agent": "ASN-Lookup-Tool/1.0"}
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "ok":
                for prefix_data in data.get("data", {}).get("prefixes", []):
                    prefixes.append(prefix_data["prefix"])
                print(f"  Retrieved {len(prefixes)} prefixes from RIPE RIS")
    except urllib.error.HTTPError as e:
        print(f"RIPE HTTP Error: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        print(f"RIPE URL Error: {e.reason}")
    except (json.JSONDecodeError, KeyError) as e:
        print(f"RIPE parsing error: {e}")
    
    return prefixes


def get_prefixes_from_radb(asn: int) -> list[str]:
    """
    Get prefixes from RADB (Routing Assets Database) via whois.
    This is a fallback that queries the IRR databases.
    """
    prefixes = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect(("whois.radb.net", 43))
        sock.sendall(f"-i origin AS{asn}\n".encode())
        
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        sock.close()
        
        for line in response.decode().strip().split("\n"):
            if line.startswith("route:") or line.startswith("route6:"):
                prefix = line.split(":", 1)[1].strip()
                if "/" in prefix:
                    prefixes.append(prefix)
        
        if prefixes:
            print(f"  Retrieved {len(prefixes)} prefixes from RADB")
    except (socket.error, socket.timeout) as e:
        print(f"RADB lookup error: {e}")
    
    return prefixes


def sort_prefixes(prefixes: list[str], is_ipv6: bool = False) -> list[str]:
    """Sort IP prefixes numerically."""
    def prefix_key(prefix):
        try:
            network, length = prefix.rsplit("/", 1)
            if is_ipv6:
                # For IPv6, just use string sorting
                return (network, int(length))
            else:
                # For IPv4, convert to tuple of integers
                parts = [int(p) for p in network.split(".")]
                return (tuple(parts), int(length))
        except (ValueError, AttributeError):
            return (prefix, 0)
    
    return sorted(set(prefixes), key=prefix_key)


def main():
    if len(sys.argv) != 2:
        print("ASN IP Block Lookup Tool")
        print("-" * 40)
        print("Usage: python asn_lookup.py <IP_ADDRESS>")
        print("")
        print("Examples:")
        print("  python asn_lookup.py 8.8.8.8        # Google DNS")
        print("  python asn_lookup.py 1.1.1.1        # Cloudflare DNS")
        print("  python asn_lookup.py 208.67.222.222 # OpenDNS")
        sys.exit(1)

    ip = sys.argv[1]
    print(f"Looking up ASN for IP: {ip}")
    print("-" * 40)

    # Get ASN info for the IP via Team Cymru whois
    asn_info = get_asn_via_whois(ip)
    if not asn_info:
        print(f"Error: Could not find ASN information for IP: {ip}")
        print("Make sure the IP address is valid and publicly routed.")
        sys.exit(1)

    asn = asn_info["asn"]
    asn_name = asn_info["name"]
    
    print(f"ASN:      AS{asn}")
    print(f"Name:     {asn_name}")
    print(f"Prefix:   {asn_info['prefix']}")
    print(f"Country:  {asn_info['country']}")
    print(f"Registry: {asn_info['registry']}")
    print("-" * 40)

    # Get all prefixes for this ASN
    print(f"Fetching all prefixes for AS{asn}...")
    
    # Try RIPE first (real-time BGP data)
    prefixes = get_prefixes_from_ripe(asn)
    source = "RIPE RIS"
    
    # Fallback to RADB if RIPE fails
    if not prefixes:
        print("RIPE API unavailable, trying RADB...")
        prefixes = get_prefixes_from_radb(asn)
        source = "RADB"

    if not prefixes:
        print("Error: No prefixes found for this ASN.")
        print("The ASN might not be currently announcing any prefixes.")
        sys.exit(1)

    # Separate and sort IPv4/IPv6
    ipv4_prefixes = sort_prefixes([p for p in prefixes if ":" not in p], is_ipv6=False)
    ipv6_prefixes = sort_prefixes([p for p in prefixes if ":" in p], is_ipv6=True)

    total = len(ipv4_prefixes) + len(ipv6_prefixes)
    print("-" * 40)
    print(f"IPv4 prefixes: {len(ipv4_prefixes)}")
    print(f"IPv6 prefixes: {len(ipv6_prefixes)}")
    print(f"Total:         {total}")
    print(f"Data source:   {source}")

    # Create EDL output folder
    output_dir = "EDL"
    os.makedirs(output_dir, exist_ok=True)
    
    # Write to separate files in EDL folder
    ipv4_file = os.path.join(output_dir, f"AS{asn}_ipv4.txt")
    ipv6_file = os.path.join(output_dir, f"AS{asn}_ipv6.txt")
    
    def write_header(f, ip_version, count):
        f.write(f"# {ip_version} Prefixes for AS{asn}\n")
        f.write(f"# Name: {asn_name}\n")
        f.write(f"# Country: {asn_info['country']}\n")
        f.write(f"# Registry: {asn_info['registry']}\n")
        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Source IP: {ip}\n")
        f.write(f"# Data source: {source}\n")
        f.write(f"# Total: {count}\n")
        f.write("#" + "=" * 50 + "\n\n")

    # Write IPv4 file
    with open(ipv4_file, "w") as f:
        write_header(f, "IPv4", len(ipv4_prefixes))
        for prefix in ipv4_prefixes:
            f.write(f"{prefix}\n")

    # Write IPv6 file
    with open(ipv6_file, "w") as f:
        write_header(f, "IPv6", len(ipv6_prefixes))
        for prefix in ipv6_prefixes:
            f.write(f"{prefix}\n")

    print("-" * 40)
    print(f"IPv4 prefixes saved to: {ipv4_file}")
    print(f"IPv6 prefixes saved to: {ipv6_file}")


if __name__ == "__main__":
    main()
