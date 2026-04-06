"""OB1 Open-Brain integration — capture scan summaries as thoughts.

Posts scan results to OB1's MCP endpoint so they become part of the
persistent AI memory and are searchable via semantic search.

Silently fails if OB1 is not available — the scanner must never break
because the memory system is down.
"""

import json
import os
import urllib.request
from typing import Any


_OB1_MCP_URL = os.environ.get("OB1_MCP_URL", "http://ob1-mcp:3000")
_OB1_MCP_KEY = os.environ.get("OB1_MCP_KEY", "")


def _build_thought_content(
    tool_name: str,
    parameters: dict | None,
    results_summary: dict | None,
    duration: float | None,
    status: str,
) -> str:
    """Build a human-readable thought string from scan results."""
    parts = [f"Security scan: {tool_name}"]

    # Add key parameters
    if parameters:
        param_parts = []
        for key in ("host", "target", "file_path", "directory", "search_terms", "file_pattern", "package_name"):
            val = parameters.get(key)
            if val:
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val[:3])
                param_parts.append(f"{key}={val}")
        if param_parts:
            parts.append(f"({', '.join(param_parts)})")

    parts.append("—")

    # Add results
    if status == "error":
        error = (results_summary or {}).get("error", "unknown error")
        parts.append(f"FAILED: {error}")
    elif results_summary:
        summary_parts = []
        for key, val in results_summary.items():
            if key == "error":
                continue
            if isinstance(val, (int, float)):
                summary_parts.append(f"{key}: {val}")
            elif isinstance(val, str) and len(val) < 100:
                summary_parts.append(f"{key}: {val}")
        if summary_parts:
            parts.append(", ".join(summary_parts))
        else:
            parts.append("completed successfully")
    else:
        parts.append("completed")

    if duration:
        parts.append(f"({duration:.1f}s)")

    return " ".join(parts)


def _extract_topics(tool_name: str, results_summary: dict | None) -> list[str]:
    """Extract topic tags from the scan results."""
    topics = [tool_name]

    # Map tool names to broader categories
    category_map = {
        "scan_files": "file_scanning",
        "check_file": "file_scanning",
        "check_tls": "tls_certificate",
        "check_ssl_versions": "tls_protocol",
        "scan_certificates": "tls_certificate",
        "check_cert_chain": "tls_certificate",
        "nmap_scan": "network_scanning",
        "nmap_service_detect": "network_scanning",
        "nmap_vuln_scan": "vulnerability_scanning",
        "hash_file": "file_integrity",
        "hash_directory": "file_integrity",
        "compare_baseline": "file_integrity",
        "verify_integrity": "file_integrity",
        "check_vulnerability": "vulnerability_scanning",
        "analyze_package_json": "dependency_analysis",
        "scan_dependencies": "dependency_analysis",
        "generate_sbom": "sbom",
        "generate_oscal_assessment": "compliance",
    }
    cat = category_map.get(tool_name)
    if cat and cat not in topics:
        topics.append(cat)

    # Add severity-based topics
    if results_summary:
        status = results_summary.get("status")
        if status in ("fail", "critical", "error"):
            topics.append("critical_finding")
        elif status in ("warn", "warning"):
            topics.append("warning")

    return topics


def _extract_action_items(tool_name: str, results_summary: dict | None, status: str) -> list[str]:
    """Extract action items if there are critical findings."""
    items = []
    if status == "error":
        items.append(f"Investigate failed {tool_name} scan")

    if results_summary:
        rs = results_summary
        if rs.get("status") in ("fail", "critical"):
            items.append(f"Review critical findings from {tool_name}")
        if rs.get("expired"):
            items.append("Renew expired TLS certificate")
        if rs.get("hits") and rs["hits"] > 0:
            items.append(f"Review {rs['hits']} matches found by {tool_name}")

    return items


def capture_scan_thought(
    tool_name: str,
    parameters: dict | None = None,
    results_summary: dict | None = None,
    duration: float | None = None,
    status: str = "completed",
) -> bool:
    """Post a scan summary to OB1 as a thought for semantic search.

    Returns True if the thought was captured, False otherwise.
    Never raises — fails silently.
    """
    if not _OB1_MCP_KEY:
        return False

    try:
        content = _build_thought_content(tool_name, parameters, results_summary, duration, status)

        # Build the MCP tool call request
        mcp_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "capture_thought",
                "arguments": {
                    "content": content,
                },
            },
        }

        data = json.dumps(mcp_request).encode("utf-8")
        req = urllib.request.Request(
            _OB1_MCP_URL,
            data=data,
            headers={
                "Content-Type": "application/json",
                "x-brain-key": _OB1_MCP_KEY,
            },
            method="POST",
        )

        urllib.request.urlopen(req, timeout=5)
        return True

    except Exception:
        # Silent failure — scanner must never break because OB1 is down
        return False
