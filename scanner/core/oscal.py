"""Module 8: OSCAL Compliance.

Generates OSCAL (Open Security Controls Assessment Language) documents from
scan results.  Supports Assessment Results, Component Definitions, control
mapping across multiple frameworks, and JSON/XML export.
"""

import json
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.core.logging_audit import audit, scan_history

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_OSCAL_DIR = _BASE_DIR / "data" / "oscal"
_SBOM_DIR = _BASE_DIR / "data" / "sboms"

# ---------------------------------------------------------------------------
# Control mappings
# ---------------------------------------------------------------------------
CONTROL_MAPPINGS: dict[str, dict[str, dict[str, str]]] = {
    "nist-800-53": {
        "malicious_code": {"id": "SI-3", "name": "Malicious Code Protection", "family": "System and Information Integrity"},
        "weak_tls": {"id": "SC-8", "name": "Transmission Confidentiality and Integrity", "family": "System and Communications Protection"},
        "open_ports": {"id": "SC-7", "name": "Boundary Protection", "family": "System and Communications Protection"},
        "integrity_violation": {"id": "SI-7", "name": "Software, Firmware, and Information Integrity", "family": "System and Information Integrity"},
        "component_inventory": {"id": "CM-8", "name": "System Component Inventory", "family": "Configuration Management"},
        "known_vulnerability": {"id": "RA-5", "name": "Vulnerability Monitoring and Scanning", "family": "Risk Assessment"},
        "audit_logging": {"id": "AU-2", "name": "Event Logging", "family": "Audit and Accountability"},
    },
    "fedramp": {
        # Same control IDs, FedRAMP uses NIST 800-53 controls
        "malicious_code": {"id": "SI-3", "name": "Malicious Code Protection", "family": "System and Information Integrity"},
        "weak_tls": {"id": "SC-8", "name": "Transmission Confidentiality and Integrity", "family": "System and Communications Protection"},
        "open_ports": {"id": "SC-7", "name": "Boundary Protection", "family": "System and Communications Protection"},
        "integrity_violation": {"id": "SI-7", "name": "Software, Firmware, and Information Integrity", "family": "System and Information Integrity"},
        "component_inventory": {"id": "CM-8", "name": "System Component Inventory", "family": "Configuration Management"},
        "known_vulnerability": {"id": "RA-5", "name": "Vulnerability Monitoring and Scanning", "family": "Risk Assessment"},
        "audit_logging": {"id": "AU-2", "name": "Event Logging", "family": "Audit and Accountability"},
    },
    "nist-csf": {
        "malicious_code": {"id": "DE.CM-4", "name": "Malicious Code Detection", "family": "Detect"},
        "weak_tls": {"id": "PR.DS-2", "name": "Data-in-Transit Protection", "family": "Protect"},
        "open_ports": {"id": "PR.AC-5", "name": "Network Integrity Protection", "family": "Protect"},
        "integrity_violation": {"id": "PR.DS-6", "name": "Integrity Checking", "family": "Protect"},
        "component_inventory": {"id": "ID.AM-1", "name": "Physical Devices and Systems Inventory", "family": "Identify"},
        "known_vulnerability": {"id": "ID.RA-1", "name": "Asset Vulnerabilities Identified", "family": "Identify"},
        "audit_logging": {"id": "DE.AE-3", "name": "Event Data Aggregation", "family": "Detect"},
    },
    "iso-27001": {
        "malicious_code": {"id": "A.12.2.1", "name": "Controls Against Malware", "family": "Operations Security"},
        "weak_tls": {"id": "A.14.1.2", "name": "Securing Application Services", "family": "System Acquisition"},
        "open_ports": {"id": "A.13.1.1", "name": "Network Controls", "family": "Communications Security"},
        "integrity_violation": {"id": "A.14.1.3", "name": "Protecting Application Transactions", "family": "System Acquisition"},
        "component_inventory": {"id": "A.8.1.1", "name": "Inventory of Assets", "family": "Asset Management"},
        "known_vulnerability": {"id": "A.12.6.1", "name": "Management of Technical Vulnerabilities", "family": "Operations Security"},
        "audit_logging": {"id": "A.12.4.1", "name": "Event Logging", "family": "Operations Security"},
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _new_uuid() -> str:
    """Generate a new UUID-4 string."""
    return str(uuid.uuid4())


def _ensure_oscal_dir() -> Path:
    """Create the OSCAL output directory if it does not exist."""
    _OSCAL_DIR.mkdir(parents=True, exist_ok=True)
    return _OSCAL_DIR


def _save_document(document: dict, document_id: str) -> Path:
    """Persist an OSCAL document as JSON and return the file path."""
    oscal_dir = _ensure_oscal_dir()
    file_path = oscal_dir / f"{document_id}.json"
    file_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return file_path


def _dict_to_xml(tag: str, data: Any) -> ET.Element:
    """Recursively convert a dict/list/scalar to an XML ElementTree element."""
    elem = ET.Element(tag)
    if isinstance(data, dict):
        for key, value in data.items():
            child = _dict_to_xml(key, value)
            elem.append(child)
    elif isinstance(data, list):
        for item in data:
            child = _dict_to_xml("item", item)
            elem.append(child)
    else:
        elem.text = str(data) if data is not None else ""
    return elem


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

@audit(tool_name="generate_oscal_assessment")
def generate_oscal_assessment(
    scan_ids: list[str] | None = None,
    framework: str = "nist-800-53",
) -> dict:
    """Gather results from past scans and produce an OSCAL Assessment Results document.

    Reads scan history from the audit database, maps findings to security
    controls for the requested framework, and saves the OSCAL document to
    ``data/oscal/``.

    Args:
        scan_ids: Optional list of scan IDs to include.  When ``None`` the
            most recent 100 scan records are used.
        framework: Compliance framework for control mapping.  One of
            ``nist-800-53``, ``fedramp``, ``nist-csf``, ``iso-27001``.

    Returns:
        Dict with ``document_id``, ``framework``, ``findings_count``,
        ``controls_mapped``, and ``file_path``.
    """
    if framework not in CONTROL_MAPPINGS:
        return {
            "error": f"Unsupported framework: {framework}. "
                     f"Supported: {', '.join(CONTROL_MAPPINGS.keys())}",
        }

    # Fetch scan history --------------------------------------------------
    history = scan_history(limit=100)
    records = history.get("records", [])

    # If specific scan_ids requested, filter
    if scan_ids:
        id_set = set(scan_ids)
        records = [r for r in records if str(r.get("id")) in id_set]

    # Build findings from scan records ------------------------------------
    findings: list[dict[str, Any]] = []
    for record in records:
        # Derive a finding type from the tool name recorded in audit
        tool = record.get("tool_name", "")
        finding_type = _tool_to_finding_type(tool)
        if finding_type is None:
            continue

        status = record.get("status", "completed")
        if status == "error":
            findings.append({
                "type": finding_type,
                "title": f"Finding from {tool}",
                "description": record.get("results_summary", f"Error during {tool}"),
            })
        elif record.get("results_summary"):
            findings.append({
                "type": finding_type,
                "title": f"Finding from {tool}",
                "description": str(record.get("results_summary", "")),
            })

    # Map findings to controls --------------------------------------------
    control_result = map_to_controls(findings, framework=framework)
    mappings = control_result.get("mappings", [])

    # Build OSCAL Assessment Results document -----------------------------
    document_id = _new_uuid()
    now = _now_iso()

    oscal_findings = []
    for i, finding in enumerate(findings):
        mapping = mappings[i] if i < len(mappings) else {}
        control_id = mapping.get("control_id", "UNKNOWN")
        oscal_findings.append({
            "uuid": _new_uuid(),
            "title": finding.get("title", "Untitled Finding"),
            "description": finding.get("description", ""),
            "target": {
                "type": "objective-id",
                "target-id": control_id,
                "status": {"state": "not-satisfied"},
            },
            "related-observations": [],
        })

    document = {
        "assessment-results": {
            "uuid": document_id,
            "metadata": {
                "title": "Cybersecurity Scanner Assessment",
                "last-modified": now,
                "version": "1.0.0",
                "oscal-version": "1.1.2",
            },
            "results": [
                {
                    "uuid": _new_uuid(),
                    "title": "Automated Scan Results",
                    "start": now,
                    "findings": oscal_findings,
                }
            ],
        }
    }

    file_path = _save_document(document, document_id)

    controls_mapped = len({m.get("control_id") for m in mappings if m.get("control_id")})

    return {
        "document_id": document_id,
        "framework": framework,
        "findings_count": len(oscal_findings),
        "controls_mapped": controls_mapped,
        "file_path": str(file_path),
    }


def _tool_to_finding_type(tool_name: str) -> str | None:
    """Map an audit tool name to a finding type known by CONTROL_MAPPINGS.

    Returns ``None`` when no meaningful mapping exists.
    """
    mapping: dict[str, str] = {
        "scan_files": "malicious_code",
        "check_file": "malicious_code",
        "find_suspicious_files": "malicious_code",
        "check_tls": "weak_tls",
        "check_ssl_versions": "weak_tls",
        "scan_certificates": "weak_tls",
        "check_cert_chain": "weak_tls",
        "nmap_scan": "open_ports",
        "nmap_service_detect": "open_ports",
        "nmap_vuln_scan": "known_vulnerability",
        "compare_baseline": "integrity_violation",
        "verify_integrity": "integrity_violation",
        "hash_file": "integrity_violation",
        "hash_directory": "integrity_violation",
        "analyze_package_json": "component_inventory",
        "scan_dependencies": "known_vulnerability",
        "check_vulnerability": "known_vulnerability",
        "scan_history": "audit_logging",
        "get_scan_stats": "audit_logging",
    }
    return mapping.get(tool_name)


@audit(tool_name="generate_oscal_component")
def generate_oscal_component(sbom_id: str) -> dict:
    """Read an SBOM from ``data/sboms/`` and convert to an OSCAL Component Definition.

    Args:
        sbom_id: Identifier (filename stem) of the SBOM JSON file to read.

    Returns:
        Dict with ``document_id``, ``components_count``, and ``file_path``.
    """
    sbom_file = _SBOM_DIR / f"{sbom_id}.json"
    if not sbom_file.exists():
        return {"error": f"SBOM file not found: {sbom_file}"}

    try:
        sbom_data = json.loads(sbom_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {"error": f"Invalid JSON in SBOM file: {exc}"}

    # Extract packages from SBOM (supports CycloneDX and SPDX-like layouts)
    packages = _extract_packages(sbom_data)

    document_id = _new_uuid()
    now = _now_iso()

    components = []
    for pkg in packages:
        components.append({
            "uuid": _new_uuid(),
            "type": "software",
            "title": pkg.get("name", "unknown"),
            "description": f"{pkg.get('ecosystem', 'unknown')} package version {pkg.get('version', 'unknown')}",
            "props": [{"name": "version", "value": pkg.get("version", "unknown")}],
        })

    document = {
        "component-definition": {
            "uuid": document_id,
            "metadata": {
                "title": "System Component Inventory",
                "last-modified": now,
                "version": "1.0.0",
                "oscal-version": "1.1.2",
            },
            "components": components,
        }
    }

    file_path = _save_document(document, document_id)

    return {
        "document_id": document_id,
        "components_count": len(components),
        "file_path": str(file_path),
    }


def _extract_packages(sbom_data: dict) -> list[dict[str, str]]:
    """Extract a flat list of packages from various SBOM formats."""
    packages: list[dict[str, str]] = []

    # CycloneDX format
    if "components" in sbom_data:
        for comp in sbom_data["components"]:
            packages.append({
                "name": comp.get("name", "unknown"),
                "version": comp.get("version", "unknown"),
                "ecosystem": comp.get("type", comp.get("purl", "").split("/")[0] if comp.get("purl") else "unknown"),
            })

    # SPDX format
    elif "packages" in sbom_data:
        for pkg in sbom_data["packages"]:
            packages.append({
                "name": pkg.get("name", "unknown"),
                "version": pkg.get("versionInfo", "unknown"),
                "ecosystem": pkg.get("externalRefs", [{}])[0].get("referenceType", "unknown")
                if pkg.get("externalRefs") else "unknown",
            })

    # Simple flat list of dependencies (scanner-generated SBOMs)
    elif "dependencies" in sbom_data:
        ecosystem = sbom_data.get("ecosystem", "unknown")
        for dep in sbom_data["dependencies"]:
            if isinstance(dep, dict):
                packages.append({
                    "name": dep.get("name", "unknown"),
                    "version": dep.get("version", "unknown"),
                    "ecosystem": dep.get("ecosystem", ecosystem),
                })
            elif isinstance(dep, str):
                parts = dep.rsplit("@", 1)
                packages.append({
                    "name": parts[0],
                    "version": parts[1] if len(parts) > 1 else "unknown",
                    "ecosystem": ecosystem,
                })

    return packages


@audit(tool_name="map_to_controls")
def map_to_controls(
    findings: list[dict[str, Any]],
    framework: str = "nist-800-53",
) -> dict:
    """Map a list of finding dicts to security controls for the given framework.

    Each finding dict should contain a ``type`` field whose value matches a key
    in :data:`CONTROL_MAPPINGS` (e.g. ``"malicious_code"``, ``"weak_tls"``).

    Args:
        findings: List of finding dicts, each with at least a ``type`` key.
        framework: Compliance framework identifier.

    Returns:
        Dict with a ``mappings`` list.  Each entry contains ``finding_type``,
        ``control_id``, ``control_name``, and ``control_family``.
    """
    if framework not in CONTROL_MAPPINGS:
        return {
            "error": f"Unsupported framework: {framework}. "
                     f"Supported: {', '.join(CONTROL_MAPPINGS.keys())}",
            "mappings": [],
        }

    framework_controls = CONTROL_MAPPINGS[framework]
    mappings: list[dict[str, str]] = []

    for finding in findings:
        finding_type = finding.get("type", "unknown")
        control = framework_controls.get(finding_type)

        if control:
            mappings.append({
                "finding_type": finding_type,
                "control_id": control["id"],
                "control_name": control["name"],
                "control_family": control["family"],
            })
        else:
            mappings.append({
                "finding_type": finding_type,
                "control_id": "UNMAPPED",
                "control_name": "No mapping available",
                "control_family": "Unknown",
            })

    return {"mappings": mappings}


@audit(tool_name="export_oscal")
def export_oscal(document_id: str, format: str = "json") -> dict:
    """Export an OSCAL document in the requested format.

    Args:
        document_id: UUID of the document (filename stem in ``data/oscal/``).
        format: Output format -- ``"json"`` or ``"xml"``.

    Returns:
        Dict with ``document_id``, ``format``, and ``file_path``.
    """
    if format not in ("json", "xml"):
        return {"error": f"Unsupported format: {format}. Supported: json, xml"}

    source_file = _OSCAL_DIR / f"{document_id}.json"
    if not source_file.exists():
        return {"error": f"OSCAL document not found: {source_file}"}

    if format == "json":
        # Already stored as JSON
        return {
            "document_id": document_id,
            "format": "json",
            "file_path": str(source_file),
        }

    # XML export -----------------------------------------------------------
    try:
        doc_data = json.loads(source_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {"error": f"Invalid JSON in OSCAL document: {exc}"}

    # Determine the root element name from the top-level key
    root_tag = next(iter(doc_data), "oscal-document")
    root_element = _dict_to_xml(root_tag, doc_data[root_tag])

    tree = ET.ElementTree(root_element)
    xml_path = _OSCAL_DIR / f"{document_id}.xml"
    ET.indent(tree, space="  ")
    tree.write(str(xml_path), encoding="unicode", xml_declaration=True)

    return {
        "document_id": document_id,
        "format": "xml",
        "file_path": str(xml_path),
    }


@audit(tool_name="list_oscal_documents")
def list_oscal_documents() -> dict:
    """List all generated OSCAL documents stored in ``data/oscal/``.

    Returns:
        Dict with a ``documents`` list.  Each entry contains ``document_id``,
        ``file_path``, ``size_bytes``, and ``modified``.
    """
    _ensure_oscal_dir()
    documents: list[dict[str, Any]] = []

    for path in sorted(_OSCAL_DIR.glob("*.json")):
        stat = path.stat()
        documents.append({
            "document_id": path.stem,
            "file_path": str(path),
            "size_bytes": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        })

    return {"documents": documents}


# ---------------------------------------------------------------------------
# MCP registration
# ---------------------------------------------------------------------------

def register(mcp) -> None:
    """Register OSCAL compliance tools with the MCP server."""
    mcp.tool()(generate_oscal_assessment)
    mcp.tool()(generate_oscal_component)
    mcp.tool()(map_to_controls)
    mcp.tool()(export_oscal)
    mcp.tool()(list_oscal_documents)
