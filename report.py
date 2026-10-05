"""
report.py - Scan report generation

CONCEPTS COVERED:
  - JSON serialization (standard format for data exchange)
  - Structured text report generation
  - Timestamping and file naming

In cybersecurity, documenting results is essential:
  - Evidence for audit / pentest reports
  - Traceability of scans performed
  - Communication with non-technical teams
"""

import json
import os
from datetime import datetime
from utils import analyze_banner, reverse_dns_lookup, is_private_ip


class ScanReport:
    """
    Generates and saves a port scan report.

    A professional pentest report typically contains:
      1. Target information (IP, hostname, date)
      2. Executive summary (open ports, overall risk level)
      3. Detail of each open port
      4. Banner analysis and potential vulnerabilities
      5. Recommendations
    """

    RISK_LABELS = {
        "HIGH":   "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW":    "LOW",
    }

    def __init__(
        self,
        target: str,
        ip: str,
        results: list[dict],
        scan_start: datetime | None = None,
        scan_end: datetime | None = None,
    ):
        self.target = target
        self.ip = ip
        self.results = results
        self.scan_start = scan_start or datetime.now()
        self.scan_end = scan_end or datetime.now()
        self.hostname = reverse_dns_lookup(ip)
        self.is_private = is_private_ip(ip)

    def _calculate_risk_summary(self) -> dict:
        """
        Computes a summary of detected risks.
        In pentesting, findings are classified by criticality level.
        """
        summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": len(self.results)}
        for port in self.results:
            risk = port.get("risk", "LOW")
            summary[risk] = summary.get(risk, 0) + 1

        # Overall risk = the highest risk level detected
        if summary["HIGH"] > 0:
            summary["global_risk"] = "HIGH"
        elif summary["MEDIUM"] > 0:
            summary["global_risk"] = "MEDIUM"
        else:
            summary["global_risk"] = "LOW"

        return summary

    def _generate_recommendations(self) -> list[str]:
        """
        Generates recommendations based on open ports.
        This is the most valuable section of an audit report.
        """
        recs = []
        open_port_numbers = {p["port"] for p in self.results}

        if 23 in open_port_numbers:
            recs.append(
                "CRITICAL - Port 23 (Telnet): Disable immediately. "
                "Replace with SSH (port 22) for secure remote access."
            )
        if 21 in open_port_numbers:
            recs.append(
                "HIGH - Port 21 (FTP): Migrate to SFTP or FTPS. "
                "FTP transmits credentials in plaintext over the network."
            )
        if 3389 in open_port_numbers:
            recs.append(
                "HIGH - Port 3389 (RDP): Restrict access via firewall/VPN. "
                "Enable Network Level Authentication (NLA). Frequent attack vector."
            )
        if 445 in open_port_numbers:
            recs.append(
                "HIGH - Port 445 (SMB): Verify the version (SMBv1 = CRITICAL). "
                "WannaCry and NotPetya exploited SMBv1 (CVE-2017-0144)."
            )
        if 6379 in open_port_numbers:
            recs.append(
                "HIGH - Port 6379 (Redis): Redis is often exposed without authentication. "
                "Set a strong password and restrict network access."
            )
        if 27017 in open_port_numbers:
            recs.append(
                "HIGH - Port 27017 (MongoDB): Verify that authentication is enabled. "
                "Many MongoDB instances are publicly exposed with no auth."
            )
        if 80 in open_port_numbers and 443 not in open_port_numbers:
            recs.append(
                "MEDIUM - Port 80 (HTTP) without HTTPS: Implement TLS/SSL. "
                "Data is transmitted in plaintext (passwords, session tokens)."
            )
        if 5900 in open_port_numbers:
            recs.append(
                "MEDIUM - Port 5900 (VNC): Restrict access by IP/VPN. "
                "Verify that strong authentication is enforced."
            )

        if not recs:
            recs.append("No immediate critical vulnerability detected on the open ports.")

        recs.append(
            "GENERAL: Apply the principle of least privilege. "
            "Close every port that is not required for the service to function."
        )

        return recs

    def to_dict(self) -> dict:
        """Serializes the report to a dictionary (for JSON output)."""
        duration = (self.scan_end - self.scan_start).total_seconds()
        risk_summary = self._calculate_risk_summary()

        # Enrich each result with banner analysis
        enriched_results = []
        for port_info in self.results:
            banner_analysis = analyze_banner(port_info.get("banner", ""), port_info["port"])
            enriched_results.append({**port_info, "analysis": banner_analysis})

        return {
            "report_metadata": {
                "tool": "Network Port Scanner v1.0",
                "generated_at": datetime.now().isoformat(),
                "scan_duration_seconds": round(duration, 2),
            },
            "target": {
                "input": self.target,
                "ip": self.ip,
                "hostname": self.hostname,
                "is_private_network": self.is_private,
            },
            "scan_info": {
                "start_time": self.scan_start.isoformat(),
                "end_time": self.scan_end.isoformat(),
                "duration_seconds": round(duration, 2),
            },
            "risk_summary": risk_summary,
            "open_ports": enriched_results,
            "recommendations": self._generate_recommendations(),
        }

    def to_text(self) -> str:
        """Generates a human-readable text report."""
        duration = (self.scan_end - self.scan_start).total_seconds()
        risk_summary = self._calculate_risk_summary()
        recommendations = self._generate_recommendations()

        lines = [
            "=" * 70,
            "   NETWORK PORT SCAN REPORT",
            "   Network Port Scanner v1.0 - Cybersecurity Portfolio",
            "=" * 70,
            "",
            "[ TARGET INFORMATION ]",
            f"  Input target     : {self.target}",
            f"  IP address       : {self.ip}",
            f"  Reverse hostname : {self.hostname}",
            f"  Private network  : {'Yes (local network)' if self.is_private else 'No (Internet)'}",
            "",
            "[ SCAN INFORMATION ]",
            f"  Started   : {self.scan_start.strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Finished  : {self.scan_end.strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Duration  : {duration:.2f} seconds",
            "",
            "[ RISK SUMMARY ]",
            f"  Total open ports : {risk_summary['total']}",
            f"  HIGH risk        : {risk_summary['HIGH']} port(s)",
            f"  MEDIUM risk      : {risk_summary['MEDIUM']} port(s)",
            f"  LOW risk         : {risk_summary['LOW']} port(s)",
            f"  Overall level    : {self.RISK_LABELS.get(risk_summary['global_risk'], 'N/A')}",
            "",
            "[ OPEN PORTS ]",
            f"  {'PORT':<8} {'PROTO':<6} {'SERVICE':<15} {'RISK':<8} BANNER / ANALYSIS",
            "  " + "-" * 65,
        ]

        for port_info in self.results:
            banner = port_info.get("banner", "")
            analysis = analyze_banner(banner, port_info["port"])

            banner_short = banner[:40] + "…" if len(banner) > 40 else banner
            risk = port_info.get("risk", "LOW")

            lines.append(
                f"  {port_info['port']:<8} {port_info['protocol']:<6} "
                f"{port_info['service']:<15} {risk:<8} {banner_short}"
            )

            if analysis["software"] != "Unknown":
                lines.append(
                    f"  {'':>8}   └─ Software: {analysis['software']} {analysis['version']}"
                )
            for cve in analysis["cves"]:
                lines.append(f"  {'':>8}      ⚠ CVE: {cve}")
            for note in analysis["notes"]:
                lines.append(f"  {'':>8}      ℹ {note}")

        lines += [
            "",
            "[ RECOMMENDATIONS ]",
        ]
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"  {i}. {rec}")

        lines += [
            "",
            "[ LEGAL DISCLAIMER ]",
            "  This scan was performed within a legal and ethical context.",
            "  Scanning a system without authorization is illegal.",
            "  (JP: 不正アクセス禁止法 / FR: Art. 323-1 Code Pénal / US: CFAA)",
            "",
            "=" * 70,
            f"  Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 70,
        ]

        return "\n".join(lines)

    def save(self, fmt: str = "txt") -> str:
        """
        Saves the report to a file.

        Naming convention: scan_<IP>_<timestamp>.<ext>
        Example: scan_192.168.1.1_20240601_143022.txt
        """
        # Create the 'reports' directory if it does not exist
        os.makedirs("reports", exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_ip = self.ip.replace(".", "_")
        filename = f"reports/scan_{safe_ip}_{timestamp}.{fmt}"

        if fmt == "json":
            with open(filename, "w", encoding="utf-8") as f:
                # indent=2 makes the JSON human-readable
                json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
        else:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(self.to_text())

        return filename
