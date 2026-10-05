"""
╔══════════════════════════════════════════════════════════════════╗
║           NETWORK PORT SCANNER - Cybersecurity Portfolio         ║
║                                                                  ║
║  Educational objective:                                          ║
║  This program illustrates the core concepts used by              ║
║  professional tools like Nmap. It demonstrates how               ║
║  attackers (and defenders!) map services exposed on a network.   ║
╚══════════════════════════════════════════════════════════════════╝

KEY CONCEPTS COVERED:
  1. TCP/UDP Sockets        - Low-level network connections
  2. Threading              - Parallel scanning for performance
  3. Queue                  - Work distribution between threads
  4. Banner Grabbing        - Service identification
  5. Timeout & error handling - Program robustness

LEGAL DISCLAIMER:
  Only scan machines you are authorized to test!
  Scanning a network without permission is illegal in most countries
  (including Japan: 不正アクセス禁止法 - Unauthorized Computer Access Law).
"""

import argparse
import socket
import sys
import threading
from queue import Queue
from datetime import datetime
from utils import resolve_hostname, grab_banner, get_service_name
from report import ScanReport


# ─────────────────────────────────────────────────────────────────
# CONCEPT 1: PORTS
# ─────────────────────────────────────────────────────────────────
# A port is a numerical entry point (0-65535) on a machine.
# Each network service "listens" on a specific port:
#   - Port 22   → SSH (secure remote shell access)
#   - Port 80   → HTTP (unencrypted web)
#   - Port 443  → HTTPS (encrypted web)
#   - Port 3306 → MySQL (database)
# An "open" port means an active service is responding there.
# This is valuable information when assessing a system's attack surface.

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Ports considered risky when open (high attack surface)
RISKY_PORTS = {23, 21, 135, 139, 445, 3389, 5900, 6379, 27017}


# ─────────────────────────────────────────────────────────────────
# CONCEPT 2: TCP SCANNING WITH SOCKETS
# ─────────────────────────────────────────────────────────────────
# TCP uses a "3-way handshake" to establish connections:
#   1. Client sends SYN   →  "I want to connect"
#   2. Server replies SYN-ACK  →  "OK, I'm available" (port OPEN)
#      or RST             →  "No"                     (port CLOSED)
#      or nothing         →  timeout                  (port FILTERED by firewall)
#   3. Client sends ACK   →  "Connection established"
#
# socket.connect_ex() attempts this full handshake.
# A return code of 0 means the port is open.

def scan_tcp_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """
    Attempts a TCP connection to host:port.

    Returns:
        dict with keys:
          - 'port'     : port number
          - 'state'    : 'open', 'closed', or 'filtered'
          - 'service'  : known service name
          - 'banner'   : grabbed banner (if available)
          - 'risk'     : risk level ('HIGH', 'MEDIUM', 'LOW')
    """
    result = {
        "port": port,
        "protocol": "TCP",
        "state": "closed",
        "service": get_service_name(port, COMMON_PORTS),
        "banner": "",
        "risk": "LOW",
    }

    try:
        # AF_INET     = IPv4 addresses (e.g. 192.168.1.1)
        # SOCK_STREAM = TCP protocol (connection-oriented, reliable)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Timeout prevents waiting indefinitely for a filtered port.
        # 1 second is a good balance between speed and reliability.
        sock.settimeout(timeout)

        # connect_ex() returns 0 on success (port open).
        # Unlike connect(), it does not raise an exception on failure.
        connection_result = sock.connect_ex((host, port))

        if connection_result == 0:
            result["state"] = "open"
            result["risk"] = "HIGH" if port in RISKY_PORTS else "MEDIUM"

            # Attempt to grab the service banner.
            # Some services automatically send their version string on connect.
            result["banner"] = grab_banner(sock, port)

        sock.close()

    except socket.gaierror:
        # gaierror = "getaddrinfo error" → host not found
        result["state"] = "error"
    except socket.timeout:
        # No response within the timeout → port is likely filtered by a firewall
        result["state"] = "filtered"
    except OSError:
        result["state"] = "closed"

    return result


# ─────────────────────────────────────────────────────────────────
# CONCEPT 3: UDP SCANNING
# ─────────────────────────────────────────────────────────────────
# UDP differs from TCP: there is no established connection.
# We send a packet and wait:
#   - A UDP response        →  port OPEN
#   - ICMP "port unreachable" → port CLOSED
#   - Nothing (timeout)     →  open|filtered (cannot distinguish without root)
#
# UDP scanning is harder and less precise than TCP.
# Important UDP ports: 53 (DNS), 67 (DHCP), 161 (SNMP), 123 (NTP)

def scan_udp_port(host: str, port: int, timeout: float = 2.0) -> dict:
    """Attempts a basic UDP probe on host:port."""
    result = {
        "port": port,
        "protocol": "UDP",
        "state": "open|filtered",
        "service": get_service_name(port, COMMON_PORTS),
        "banner": "",
        "risk": "LOW",
    }

    try:
        # SOCK_DGRAM = UDP protocol (connectionless, fast but unreliable)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Send an empty packet to probe the port
        sock.sendto(b"\x00", (host, port))

        data, _ = sock.recvfrom(1024)
        if data:
            result["state"] = "open"
            result["banner"] = data.decode(errors="replace").strip()

        sock.close()

    except socket.timeout:
        # Timeout = no ICMP "closed" response received → likely open or filtered
        result["state"] = "open|filtered"
    except ConnectionResetError:
        # ICMP "Port Unreachable" received → port is closed
        result["state"] = "closed"
    except OSError:
        result["state"] = "closed"

    return result


# ─────────────────────────────────────────────────────────────────
# CONCEPT 4: THREADING AND QUEUE FOR PARALLEL SCANNING
# ─────────────────────────────────────────────────────────────────
# Scanning 65535 ports sequentially would take hours.
# With N threads working in parallel, the time is divided by N.
#
# DESIGN PATTERN — "Worker Pool":
#   - A Queue holds all ports to scan
#   - N worker threads pull ports from the queue
#   - Each worker scans a port, stores the result, moves to the next
#   - When the queue is empty, all workers stop
#
#   Queue: [80, 443, 22, 3306, 8080, ...]
#               ↓       ↓       ↓
#           Thread1  Thread2  Thread3   (parallel work)

class PortScanner:
    """
    Multi-threaded port scanner.

    Attributes:
        host        : Target IP address or hostname
        open_ports  : List of results for open ports
        _lock       : Threading lock for thread-safe writes
    """

    def __init__(self, host: str, threads: int = 100, timeout: float = 1.0):
        self.host = host
        self.threads = threads
        self.timeout = timeout
        self.open_ports: list[dict] = []
        self.scan_start: datetime | None = None
        self.scan_end: datetime | None = None

        # Lock to protect open_ports from concurrent access.
        # Without a lock, two threads could write simultaneously
        # and corrupt the list — this is called a "race condition".
        self._lock = threading.Lock()

        # Thread-safe queue provided by Python's standard library
        self._queue: Queue = Queue()

    def _worker(self, protocol: str):
        """
        Function executed by each worker thread.
        Loops as long as the queue contains ports to process.
        """
        while True:
            try:
                # get() extracts a port from the queue.
                # block=False raises an exception immediately if the queue is empty.
                port = self._queue.get(block=False)
            except Exception:
                # Queue is empty → this worker has finished its job
                break

            # Choose the scan function based on the protocol
            if protocol == "TCP":
                result = scan_tcp_port(self.host, port, self.timeout)
            else:
                result = scan_udp_port(self.host, port, self.timeout)

            # Store only open ports (or open|filtered for UDP)
            if result["state"] in ("open", "open|filtered"):
                with self._lock:  # Protect against race conditions
                    self.open_ports.append(result)

            # Signal to the queue that this task is done
            self._queue.task_done()

    def scan(
        self,
        port_range: tuple[int, int] = (1, 1024),
        protocol: str = "TCP",
        custom_ports: list[int] | None = None,
    ) -> list[dict]:
        """
        Launches a scan over a port range or a custom list.

        Args:
            port_range   : Tuple (start, end) of the port range
            protocol     : 'TCP' or 'UDP'
            custom_ports : Specific list of ports to scan

        Returns:
            Sorted list of open ports with their details
        """
        self.open_ports = []
        self.scan_start = datetime.now()

        # Fill the queue with ports to scan
        ports = custom_ports if custom_ports else range(port_range[0], port_range[1] + 1)
        for port in ports:
            self._queue.put(port)

        total_ports = self._queue.qsize()

        print(f"\n{'='*60}")
        print(f"  Target    : {self.host}")
        print(f"  Protocol  : {protocol}")
        print(f"  Ports     : {total_ports} ports to scan")
        print(f"  Threads   : {self.threads} parallel workers")
        print(f"  Started   : {self.scan_start.strftime('%H:%M:%S')}")
        print(f"{'='*60}\n")

        # Create and start worker threads
        thread_list = []
        for _ in range(min(self.threads, total_ports)):
            t = threading.Thread(target=self._worker, args=(protocol,))
            t.daemon = True  # Thread stops if the main program exits
            t.start()
            thread_list.append(t)

        # Wait for ALL threads to finish
        for t in thread_list:
            t.join()

        self.scan_end = datetime.now()
        duration = (self.scan_end - self.scan_start).total_seconds()

        # Sort results by port number
        self.open_ports.sort(key=lambda x: x["port"])

        print(f"\n  Scan completed in {duration:.2f} seconds")
        print(f"  {len(self.open_ports)} open port(s) found\n")

        return self.open_ports

    def scan_common_ports(self, protocol: str = "TCP") -> list[dict]:
        """
        Quick scan targeting only the most common ports.
        Useful for fast initial reconnaissance.
        """
        return self.scan(custom_ports=list(COMMON_PORTS.keys()), protocol=protocol)

    def print_results(self):
        """Displays results in the terminal with readable formatting."""
        if not self.open_ports:
            print("  No open ports found.")
            return

        print(f"{'PORT':<8} {'PROTO':<6} {'STATE':<12} {'SERVICE':<15} {'RISK':<8} BANNER")
        print("-" * 75)

        risk_symbols = {"HIGH": "[HIGH]", "MEDIUM": "[MED]", "LOW": "[LOW]"}

        for p in self.open_ports:
            risk_display = f"{risk_symbols.get(p['risk'], '[UNK]')} {p['risk']}"
            banner_short = (p["banner"][:30] + "...") if len(p["banner"]) > 30 else p["banner"]
            print(
                f"{p['port']:<8} {p['protocol']:<6} {p['state']:<12} "
                f"{p['service']:<15} {risk_display:<12} {banner_short}"
            )


# ─────────────────────────────────────────────────────────────────
# CONCEPT 5: ARGPARSE — PROFESSIONAL CLI INTERFACE
# ─────────────────────────────────────────────────────────────────
# argparse is Python's standard library for building command-line
# interfaces. It handles:
#   - Argument parsing and type validation
#   - Automatic --help generation
#   - Default values and required/optional arguments
#
# A proper CLI makes the tool scriptable and pipeline-friendly,
# which is expected in professional security tooling.
#
# USAGE EXAMPLES:
#   python scanner.py --target 192.168.1.1
#   python scanner.py -t scanme.nmap.org --ports 1-1024 --threads 100
#   python scanner.py -t 10.0.0.1 --ports 80,443,8080 --output json
#   python scanner.py -t 10.0.0.1 --ports all --protocol TCP --timeout 0.5
#   python scanner.py  (no arguments → interactive mode)

BANNER = """
+==============================================+
|     Network Port Scanner v1.0                |
|     Cybersecurity Portfolio - Japan          |
+==============================================+
"""


def build_parser() -> argparse.ArgumentParser:
    """
    Defines the CLI interface using argparse.

    Each add_argument() call registers one flag:
      - positional args have no leading dashes
      - optional args use - (short) and -- (long) prefixes
      - 'type' enforces automatic type conversion
      - 'default' sets the value when the flag is omitted
      - 'help' appears in --help output
    """
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="Network Port Scanner - Cybersecurity Portfolio",
        epilog=(
            "Examples:\n"
            "  python scanner.py -t scanme.nmap.org\n"
            "  python scanner.py -t 192.168.1.1 --ports 1-1024 --threads 100\n"
            "  python scanner.py -t 10.0.0.1 --ports 80,443,8080 --output json\n"
            "  python scanner.py -t 10.0.0.1 --ports all --protocol UDP\n"
            "\nLegal targets for practice:\n"
            "  scanme.nmap.org  (official Nmap test server)\n"
            "  127.0.0.1        (your own machine)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Target ────────────────────────────────────────────────────
    parser.add_argument(
        "-t", "--target",
        metavar="HOST",
        help="Target IP address or hostname (e.g. 192.168.1.1, scanme.nmap.org)",
    )

    # ── Port specification ─────────────────────────────────────────
    # Accepts four formats:
    #   "common"       → predefined list of ~20 well-known ports
    #   "all"          → full range 1-65535
    #   "1-1024"       → arbitrary range (dash-separated)
    #   "80,443,8080"  → arbitrary list (comma-separated)
    parser.add_argument(
        "-p", "--ports",
        metavar="PORTS",
        default="common",
        help=(
            "Ports to scan. Formats:\n"
            "  common        - well-known ports only (default)\n"
            "  all           - full range 1-65535\n"
            "  1-1024        - port range\n"
            "  80,443,8080   - specific ports"
        ),
    )

    # ── Protocol ──────────────────────────────────────────────────
    parser.add_argument(
        "--protocol",
        choices=["TCP", "UDP"],
        default="TCP",
        help="Transport protocol to use (default: TCP)",
    )

    # ── Performance ───────────────────────────────────────────────
    parser.add_argument(
        "--threads",
        type=int,
        default=200,
        metavar="N",
        help="Number of parallel worker threads (default: 200)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.8,
        metavar="SEC",
        help="Socket timeout in seconds per port (default: 0.8)",
    )

    # ── Output ────────────────────────────────────────────────────
    parser.add_argument(
        "-o", "--output",
        choices=["txt", "json"],
        metavar="FORMAT",
        help="Save report automatically in this format: txt or json",
    )
    parser.add_argument(
        "--output-file",
        metavar="PATH",
        help="Custom file path for the report (overrides auto-naming)",
    )

    # ── Behaviour flags ───────────────────────────────────────────
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip banner grabbing (faster, less noisy on the network)",
    )
    parser.add_argument(
        "--open-only",
        action="store_true",
        default=True,
        help="Display only open ports in results (default: true)",
    )

    return parser


def parse_ports(ports_arg: str) -> tuple[tuple[int, int] | None, list[int] | None]:
    """
    Parses the --ports argument into a usable form.

    Returns a tuple of (port_range, custom_ports):
      - port_range   : tuple (start, end) for a range scan, or None
      - custom_ports : list of ints for a specific-port scan, or None

    Supported formats:
      "common"      → (None, None)  — caller uses scan_common_ports()
      "all"         → ((1, 65535), None)
      "1-1024"      → ((1, 1024), None)
      "80,443,8080" → (None, [80, 443, 8080])

    Raises SystemExit with an error message on invalid input.
    """
    arg = ports_arg.strip().lower()

    if arg == "common":
        return None, None

    if arg == "all":
        return (1, 65535), None

    # Range format: "start-end"
    if "-" in arg and "," not in arg:
        parts = arg.split("-")
        if len(parts) == 2:
            try:
                start, end = int(parts[0]), int(parts[1])
                if not (1 <= start <= end <= 65535):
                    raise ValueError
                return (start, end), None
            except ValueError:
                print(f"  Error: invalid port range '{ports_arg}'. Use format: 1-1024")
                sys.exit(1)

    # List format: "80,443,8080"
    if "," in arg:
        try:
            port_list = [int(p.strip()) for p in arg.split(",")]
            invalid = [p for p in port_list if not (1 <= p <= 65535)]
            if invalid:
                print(f"  Error: port(s) out of range: {invalid}")
                sys.exit(1)
            return None, port_list
        except ValueError:
            print(f"  Error: invalid port list '{ports_arg}'. Use format: 80,443,8080")
            sys.exit(1)

    # Single port
    try:
        port = int(arg)
        if not (1 <= port <= 65535):
            raise ValueError
        return None, [port]
    except ValueError:
        print(f"  Error: unrecognized port specification '{ports_arg}'.")
        print("  Valid formats: common, all, 1-1024, 80,443,8080")
        sys.exit(1)


def run_scan(target: str, args: argparse.Namespace) -> None:
    """
    Resolves the target, runs the scan with the given args,
    prints results, and optionally saves a report.
    This function is shared by both CLI mode and interactive mode.
    """
    ip = resolve_hostname(target)
    if not ip:
        print(f"  Error: cannot resolve '{target}'")
        sys.exit(1)

    if ip != target:
        print(f"\n  Resolved : {target} → {ip}")

    # Warn when scanning a full range in interactive mode without --output
    port_range, custom_ports = parse_ports(args.ports)
    if args.ports == "all" and not hasattr(args, "_confirmed"):
        confirm = input("\n  ⚠ Full scan (65535 ports) takes a long time. Confirm? (yes/no): ")
        if confirm.strip().lower() != "yes":
            print("  Scan cancelled.")
            return

    scanner = PortScanner(host=ip, threads=args.threads, timeout=args.timeout)

    if args.ports == "common":
        results = scanner.scan_common_ports(protocol=args.protocol)
    elif port_range:
        results = scanner.scan(port_range=port_range, protocol=args.protocol)
    else:
        results = scanner.scan(custom_ports=custom_ports, protocol=args.protocol)

    scanner.print_results()

    # ── Report saving ─────────────────────────────────────────────
    if args.output:
        report = ScanReport(
            target=target,
            ip=ip,
            results=results,
            scan_start=scanner.scan_start,
            scan_end=scanner.scan_end,
        )
        filename = report.save(args.output)
        print(f"\n  Report saved: {filename}")
    elif results:
        # In interactive mode, prompt the user
        if not sys.argv[1:]:
            save = input("\n  Save report? (yes/no): ").strip().lower()
            if save == "yes":
                fmt = input("  Format [txt/json]: ").strip().lower()
                report = ScanReport(
                    target=target,
                    ip=ip,
                    results=results,
                    scan_start=scanner.scan_start,
                    scan_end=scanner.scan_end,
                )
                filename = report.save(fmt if fmt in ("txt", "json") else "txt")
                print(f"\n  Report saved: {filename}")


def interactive_mode(args: argparse.Namespace) -> None:
    """
    Guides the user through a scan interactively when no --target is given.
    Populates a mutable args namespace so run_scan() can be reused.
    """
    # Legal practice targets:
    # - "scanme.nmap.org"  → official Nmap test machine
    # - "127.0.0.1"        → your own machine (localhost)
    # - "192.168.x.x"      → your local network (with permission)

    target = input("  Enter target IP address or hostname: ").strip()
    if not target:
        print("  Error: no target specified.")
        sys.exit(1)

    print("\n  Scan type:")
    print("   [1] Common ports only  (fast, ~20 ports)   -> --ports common")
    print("   [2] Ports 1-1024       (standard)          -> --ports 1-1024")
    print("   [3] Ports 1-65535      (full scan, slow)   -> --ports all")
    print("   [4] Custom ports                           -> --ports 80,443,8080")

    choice = input("\n  Your choice [1-4]: ").strip()

    port_map = {"1": "common", "2": "1-1024", "3": "all", "4": None}
    chosen = port_map.get(choice)

    if chosen is None and choice == "4":
        chosen = input("  Enter ports (e.g. 80,443,8080 or 8000-9000): ").strip()
    elif chosen is None:
        print("  Invalid choice, defaulting to common ports.")
        chosen = "common"

    args.ports = chosen
    run_scan(target, args)


def main() -> None:
    print(BANNER)

    parser = build_parser()

    # ── Route: interactive mode when called with no arguments ──────
    # This lets beginners learn step-by-step while still supporting
    # the full CLI for scripting and automation use-cases.
    if not sys.argv[1:]:
        args = parser.parse_args([])   # populate defaults
        interactive_mode(args)
        return

    # ── Route: CLI mode ────────────────────────────────────────────
    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        print("\n  Error: --target is required in CLI mode.")
        sys.exit(1)

    # Validate thread count and timeout
    if not (1 <= args.threads <= 1000):
        print("  Error: --threads must be between 1 and 1000.")
        sys.exit(1)
    if not (0.1 <= args.timeout <= 30.0):
        print("  Error: --timeout must be between 0.1 and 30.0 seconds.")
        sys.exit(1)

    run_scan(args.target, args)


if __name__ == "__main__":
    main()
