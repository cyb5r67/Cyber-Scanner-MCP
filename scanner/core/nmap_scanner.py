"""Module 4: Nmap Scanner.

Wraps Nmap for port scanning, service/version detection, and vulnerability
scanning via NSE scripts.  Uses the ``python-nmap`` library to interface with
the system nmap binary.

All public functions return JSON-serializable dicts and are decorated with
@audit for automatic logging.
"""

import re
import time
from typing import Optional

from scanner.core.logging_audit import audit

# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------
_TARGET_RE = re.compile(r"^[a-zA-Z0-9.\-:/]+$")
_PORTS_RE = re.compile(r"^[0-9,\-]+$")


def _validate_target(target: str) -> str:
    """Validate and return *target*, or raise ValueError.

    Only alphanumeric characters, dots, slashes, colons, and hyphens are
    permitted (whitelist approach to prevent command injection).
    """
    target = target.strip()
    if not target:
        raise ValueError("Target must not be empty.")
    if not _TARGET_RE.match(target):
        raise ValueError(
            f"Invalid target '{target}'. Only alphanumeric characters, "
            "dots, slashes, colons, and hyphens are allowed."
        )
    return target


def _validate_ports(ports: Optional[str]) -> Optional[str]:
    """Validate and return *ports* string, or raise ValueError.

    Only digits, commas, and hyphens are permitted.
    """
    if ports is None:
        return None
    ports = ports.strip()
    if not ports:
        return None
    if not _PORTS_RE.match(ports):
        raise ValueError(
            f"Invalid ports '{ports}'. Only digits, commas, and hyphens "
            "are allowed (e.g. '22,80,443' or '1-1024')."
        )
    return ports


# ---------------------------------------------------------------------------
# Lazy nmap import helper
# ---------------------------------------------------------------------------
def _get_nmap_scanner():
    """Return a ``nmap.PortScanner`` instance.

    Raises a RuntimeError with a helpful message when either ``python-nmap``
    or the system ``nmap`` binary is unavailable.
    """
    try:
        import nmap  # noqa: F811
    except ImportError:
        raise RuntimeError(
            "python-nmap is not installed. "
            "Install it with: pip install python-nmap"
        )

    try:
        scanner = nmap.PortScanner()
    except nmap.PortScannerError:
        raise RuntimeError(
            "nmap binary not found on this system. "
            "Please install nmap: https://nmap.org/download.html"
        )

    return scanner


# ---------------------------------------------------------------------------
# Scan-type argument mapping
# ---------------------------------------------------------------------------
_SCAN_TYPE_ARGS = {
    "quick": "--top-ports 100",
    "basic": "--top-ports 1000",
    "full": "-p-",
}


# ---------------------------------------------------------------------------
# Tool functions
# ---------------------------------------------------------------------------
@audit(tool_name="nmap_scan")
def nmap_scan(
    target: str,
    ports: Optional[str] = None,
    scan_type: str = "basic",
) -> dict:
    """Port-scan a host or network range using Nmap.

    Args:
        target: Hostname, IP address, or CIDR range to scan.
        ports: Explicit port specification (e.g. ``"22,80,443"`` or
            ``"1-1024"``).  Overrides *scan_type* when provided.
        scan_type: One of ``"quick"`` (top 100 ports), ``"basic"``
            (top 1000 ports, default), or ``"full"`` (all 65535 ports).

    Returns:
        Dict with keys: ``target``, ``scan_type``, ``open_ports``,
        ``total_open``, ``scan_time``.
    """
    try:
        target = _validate_target(target)
        ports = _validate_ports(ports)
    except ValueError as exc:
        return {"error": str(exc)}

    if scan_type not in _SCAN_TYPE_ARGS:
        return {
            "error": (
                f"Invalid scan_type '{scan_type}'. "
                "Must be one of: quick, basic, full."
            )
        }

    try:
        nm = _get_nmap_scanner()
    except RuntimeError as exc:
        return {"error": str(exc)}

    # Build arguments
    if ports:
        arguments = f"-p {ports}"
    else:
        arguments = _SCAN_TYPE_ARGS[scan_type]

    try:
        start = time.time()
        nm.scan(hosts=target, arguments=arguments)
        elapsed = round(time.time() - start, 3)
    except Exception as exc:
        return {"error": f"Nmap scan failed: {exc}"}

    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports_list = sorted(nm[host][proto].keys())
            for port in ports_list:
                info = nm[host][proto][port]
                if info.get("state") == "open":
                    open_ports.append({
                        "port": port,
                        "protocol": proto,
                        "state": info.get("state", ""),
                        "service": info.get("name", ""),
                    })

    return {
        "target": target,
        "scan_type": scan_type,
        "open_ports": open_ports,
        "total_open": len(open_ports),
        "scan_time": elapsed,
    }


@audit(tool_name="nmap_service_detect")
def nmap_service_detect(
    target: str,
    ports: Optional[str] = None,
) -> dict:
    """Run Nmap service/version detection (-sV) against a target.

    Args:
        target: Hostname, IP address, or CIDR range to scan.
        ports: Explicit port specification (e.g. ``"22,80,443"``).
            When omitted, Nmap scans its default top ports.

    Returns:
        Dict with keys: ``target``, ``services`` (list of dicts with
        ``port``, ``protocol``, ``service``, ``version``, ``product``,
        ``extra_info``).
    """
    try:
        target = _validate_target(target)
        ports = _validate_ports(ports)
    except ValueError as exc:
        return {"error": str(exc)}

    try:
        nm = _get_nmap_scanner()
    except RuntimeError as exc:
        return {"error": str(exc)}

    arguments = "-sV"
    if ports:
        arguments += f" -p {ports}"

    try:
        nm.scan(hosts=target, arguments=arguments)
    except Exception as exc:
        return {"error": f"Nmap service detection failed: {exc}"}

    services = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                info = nm[host][proto][port]
                services.append({
                    "port": port,
                    "protocol": proto,
                    "service": info.get("name", ""),
                    "version": info.get("version", ""),
                    "product": info.get("product", ""),
                    "extra_info": info.get("extrainfo", ""),
                })

    return {
        "target": target,
        "services": services,
    }


@audit(tool_name="nmap_vuln_scan")
def nmap_vuln_scan(
    target: str,
    ports: Optional[str] = None,
) -> dict:
    """Run Nmap NSE vulnerability scripts (--script vuln) against a target.

    Args:
        target: Hostname, IP address, or CIDR range to scan.
        ports: Explicit port specification (e.g. ``"22,80,443"``).
            When omitted, Nmap scans its default top ports.

    Returns:
        Dict with keys: ``target``, ``vulnerabilities`` (list of dicts
        with ``port``, ``script_id``, ``output``, ``severity_estimate``).
    """
    try:
        target = _validate_target(target)
        ports = _validate_ports(ports)
    except ValueError as exc:
        return {"error": str(exc)}

    try:
        nm = _get_nmap_scanner()
    except RuntimeError as exc:
        return {"error": str(exc)}

    arguments = "--script vuln"
    if ports:
        arguments += f" -p {ports}"

    try:
        nm.scan(hosts=target, arguments=arguments)
    except Exception as exc:
        return {"error": f"Nmap vuln scan failed: {exc}"}

    vulnerabilities = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                info = nm[host][proto][port]
                scripts = info.get("script", {})
                for script_id, output in scripts.items():
                    severity = _estimate_severity(script_id, output)
                    vulnerabilities.append({
                        "port": port,
                        "script_id": script_id,
                        "output": output,
                        "severity_estimate": severity,
                    })

    return {
        "target": target,
        "vulnerabilities": vulnerabilities,
    }


def _estimate_severity(script_id: str, output: str) -> str:
    """Heuristically estimate severity from NSE script output.

    Returns one of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``,
    or ``"info"``.
    """
    output_lower = output.lower()
    script_lower = script_id.lower()

    # Critical indicators
    if any(kw in output_lower for kw in (
        "remote code execution", "rce", "critical",
        "unauthenticated", "overflow",
    )):
        return "critical"

    # High indicators
    if any(kw in output_lower for kw in (
        "vulnerable", "exploit", "cve-", "high",
    )):
        return "high"

    # Medium indicators
    if any(kw in output_lower for kw in (
        "medium", "weak", "deprecated", "ssl-",
    )) or "ssl" in script_lower:
        return "medium"

    # Low indicators
    if any(kw in output_lower for kw in (
        "low", "info", "disclosure",
    )):
        return "low"

    return "info"


# ---------------------------------------------------------------------------
# MCP registration
# ---------------------------------------------------------------------------
def register(mcp) -> None:
    """Register all Nmap scanner tools with the MCP server."""
    mcp.tool()(nmap_scan)
    mcp.tool()(nmap_service_detect)
    mcp.tool()(nmap_vuln_scan)
