"""
utils.py - Utility functions for the port scanner

CONCEPTS COVERED:
  - DNS resolution (hostname → IP)
  - Banner grabbing (service fingerprinting)
  - Known vulnerability detection by version
"""

import socket
import re


# ─────────────────────────────────────────────────────────────────
# CONCEPT: DNS RESOLUTION
# ─────────────────────────────────────────────────────────────────
# DNS (Domain Name System) = the phonebook of the Internet.
# It translates human-readable names (google.com) into IP addresses
# (142.250.185.46).
#
# RESOLUTION PROCESS:
#   1. Your machine checks its local cache
#   2. Then queries the ISP's DNS resolver (e.g. 8.8.8.8 for Google)
#   3. Which traces back to the root servers if needed
#
# In security, reverse resolution (IP → name) can reveal
# information about the organization that owns the address.

def resolve_hostname(target: str) -> str | None:
    """
    Resolves a hostname to an IPv4 address.
    If the target is already a valid IP, it is returned as-is.

    Args:
        target : Hostname (e.g. "scanme.nmap.org") or IP (e.g. "192.168.1.1")

    Returns:
        IP address as a string, or None if resolution fails
    """
    try:
        # gethostbyname() performs the DNS lookup.
        # If target is already a valid IP, it is returned unchanged.
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror as e:
        # gaierror covers: host not found, no DNS connectivity, etc.
        print(f"  [DNS] Resolution error for '{target}': {e}")
        return None


def reverse_dns_lookup(ip: str) -> str:
    """
    Reverse DNS lookup: finds the hostname associated with an IP address.
    Useful for OSINT (Open Source Intelligence) during an audit.

    Example: 8.8.8.8 → dns.google
    """
    try:
        # gethostbyaddr() returns (hostname, aliases, addresses)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        # herror = host not found in reverse DNS
        return "N/A"


# ─────────────────────────────────────────────────────────────────
# CONCEPT: BANNER GRABBING
# ─────────────────────────────────────────────────────────────────
# When connecting to a service, it often sends a "banner":
# a text string revealing its version and sometimes configuration.
#
# REAL BANNER EXAMPLES:
#   SSH  : "SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2"
#   FTP  : "220 vsftpd 3.0.3"
#   SMTP : "220 mail.example.com ESMTP Postfix"
#   HTTP : Response header "Server: Apache/2.4.51"
#
# IN CYBERSECURITY: If a banner reveals a vulnerable version
# (e.g. OpenSSH < 8.x with a known CVE), it becomes an attack vector.
# This is why the best practice is to HIDE or SUPPRESS banners.

# Probes to send per service to trigger a response
BANNER_PROBES = {
    80:   b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
    21:   b"",        # FTP sends its banner without a probe
    22:   b"",        # SSH sends its banner without a probe
    25:   b"EHLO test\r\n",
    110:  b"",        # POP3 sends its banner without a probe
    143:  b"",        # IMAP sends its banner without a probe
    3306: b"",        # MySQL sends its banner without a probe
    5432: b"",        # PostgreSQL
}


def grab_banner(sock: socket.socket, port: int, max_bytes: int = 1024) -> str:
    """
    Attempts to retrieve the service banner from a connected socket.

    The strategy varies by port:
    - Some services send their banner immediately (SSH, FTP)
    - Others require a request first (HTTP)

    Args:
        sock      : Socket already connected to the service
        port      : Port number (used to select the appropriate probe)
        max_bytes : Maximum banner size to read

    Returns:
        Cleaned banner as a string, or "" if unavailable
    """
    try:
        sock.settimeout(2.0)

        # Send a probe if one is defined for this port
        probe = BANNER_PROBES.get(port)
        if probe is not None and len(probe) > 0:
            sock.send(probe)

        # Receive the response
        banner_bytes = sock.recv(max_bytes)

        if not banner_bytes:
            return ""

        # Decode as UTF-8, replacing invalid bytes.
        # Banners sometimes contain control characters.
        banner = banner_bytes.decode("utf-8", errors="replace")

        # Clean the banner: keep only the first useful line
        banner = banner.strip()
        first_line = banner.split("\n")[0].strip()

        # Remove non-printable characters
        first_line = re.sub(r"[^\x20-\x7E]", "", first_line)

        return first_line[:200]  # Cap the length

    except (socket.timeout, OSError, UnicodeDecodeError):
        return ""


# ─────────────────────────────────────────────────────────────────
# CONCEPT: FINGERPRINTING AND VULNERABILITY DETECTION
# ─────────────────────────────────────────────────────────────────
# Fingerprinting means precisely identifying a software and its
# version from collected information.
#
# CVE (Common Vulnerabilities and Exposures) = a public registry
# of known vulnerabilities. Example: CVE-2021-41773 = Apache flaw.
#
# In a real audit, detected versions would be cross-referenced
# against databases like NVD (National Vulnerability Database)
# or tools like searchsploit.

# Regex patterns to extract versions from banners
VERSION_PATTERNS = {
    "OpenSSH": r"OpenSSH[_\s]([\d.]+\w*)",
    "Apache":  r"Apache/([\d.]+)",
    "nginx":   r"nginx/([\d.]+)",
    "vsftpd":  r"vsftpd\s+([\d.]+)",
    "MySQL":   r"([\d]+\.[\d]+\.[\d]+)-",
    "Postfix": r"Postfix",
    "IIS":     r"Microsoft-IIS/([\d.]+)",
}

# Known vulnerable versions (simplified for educational purposes)
# In production, use a live CVE database feed
KNOWN_VULNERABILITIES = {
    "OpenSSH": {
        "7.2": ["CVE-2016-6210 (user enumeration)"],
        "7.4": ["CVE-2018-15919 (user enumeration)"],
    },
    "Apache": {
        "2.4.49": ["CVE-2021-41773 (path traversal, CRITICAL)"],
        "2.4.50": ["CVE-2021-42013 (path traversal, CRITICAL)"],
    },
    "IIS": {
        "6.0": ["CVE-2017-7269 (buffer overflow, CRITICAL)"],
    },
}


def analyze_banner(banner: str, port: int) -> dict:
    """
    Analyzes a banner to extract the software name, version,
    and identify potential known vulnerabilities.

    Returns:
        dict with keys 'software', 'version', 'cves', 'notes'
    """
    analysis = {
        "software": "Unknown",
        "version": "",
        "cves": [],
        "notes": [],
    }

    if not banner:
        return analysis

    # Search each pattern against the banner
    for software, pattern in VERSION_PATTERNS.items():
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            analysis["software"] = software
            if match.lastindex:
                analysis["version"] = match.group(1)
            break

    # Check against the known vulnerability database
    if analysis["software"] in KNOWN_VULNERABILITIES:
        vulns = KNOWN_VULNERABILITIES[analysis["software"]]
        version = analysis["version"]
        if version in vulns:
            analysis["cves"] = vulns[version]
            analysis["notes"].append("⚠ Potentially vulnerable version detected!")

    # Alerts for unencrypted protocols
    if port == 23:
        analysis["notes"].append("CRITICAL: Telnet transmits all data in plaintext!")
    elif port == 21:
        analysis["notes"].append("WARNING: FTP sends passwords in plaintext over the network!")
    elif port == 80:
        analysis["notes"].append("INFO: Unencrypted HTTP — consider enforcing HTTPS (port 443)")

    return analysis


def get_service_name(port: int, common_ports: dict) -> str:
    """Returns the service name for a given port number."""
    if port in common_ports:
        return common_ports[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def is_valid_ip(ip_string: str) -> bool:
    """
    Validates that a string is a valid IPv4 address.
    Uses socket.inet_aton() which raises OSError on invalid input.
    """
    try:
        socket.inet_aton(ip_string)
        parts = ip_string.split(".")
        return len(parts) == 4
    except OSError:
        return False


def is_private_ip(ip: str) -> bool:
    """
    Checks whether an IP address falls within a private range (RFC 1918).
    Private IPs are not routable on the public Internet.

    Private ranges:
      10.0.0.0/8       → large enterprise networks
      172.16.0.0/12    → medium-sized networks
      192.168.0.0/16   → home / small office networks
      127.0.0.0/8      → loopback (localhost)
    """
    try:
        parts = list(map(int, ip.split(".")))
        if len(parts) != 4:
            return False

        # 10.x.x.x
        if parts[0] == 10:
            return True
        # 172.16.x.x – 172.31.x.x
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        # 192.168.x.x
        if parts[0] == 192 and parts[1] == 168:
            return True
        # 127.x.x.x (loopback)
        if parts[0] == 127:
            return True

        return False
    except (ValueError, AttributeError):
        return False
