"""Cybersecurity Scanner CLI.

Provides command-line access to all scanner modules.
Subcommands mirror the MCP tools. Use --json for structured output.
"""

import argparse
import json
import sys
from typing import Any


def _output(result: Any, as_json: bool = False) -> None:
    """Print result as JSON or human-readable text."""
    if as_json:
        print(json.dumps(result, indent=2, default=str))
        return

    if isinstance(result, dict):
        for key, value in result.items():
            if isinstance(value, list) and len(value) > 0:
                print(f"\n{key}:")
                for item in value:
                    if isinstance(item, dict):
                        print(f"  - {item}")
                    else:
                        print(f"  - {item}")
            elif isinstance(value, dict):
                print(f"\n{key}:")
                for k, v in value.items():
                    print(f"  {k}: {v}")
            else:
                print(f"{key}: {value}")
    else:
        print(result)


def _import_module(name: str):
    """Lazily import a scanner module, returning None if unavailable."""
    try:
        if name == "file_scanner":
            from scanner.core import file_scanner
            return file_scanner
        elif name == "integrity":
            from scanner.core import integrity
            return integrity
        elif name == "tls_checker":
            from scanner.core import tls_checker
            return tls_checker
        elif name == "dependency":
            from scanner.core import dependency
            return dependency
        elif name == "nmap_scanner":
            from scanner.core import nmap_scanner
            return nmap_scanner
        elif name == "sbom":
            from scanner.core import sbom
            return sbom
        elif name == "oscal":
            from scanner.core import oscal
            return oscal
        elif name == "logging_audit":
            from scanner.core import logging_audit
            return logging_audit
    except ImportError as e:
        print(f"Error: Module '{name}' is not available: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------
def cmd_scan(args):
    mod = _import_module("file_scanner")
    result = mod.scan_files(
        search_terms=args.terms,
        file_pattern=args.pattern,
        search_paths=args.paths,
        max_results=args.max_results,
    )
    _output(result, args.json)


def cmd_check_file(args):
    mod = _import_module("file_scanner")
    result = mod.check_file(args.file, args.terms)
    _output(result, args.json)


def cmd_list_drives(args):
    mod = _import_module("file_scanner")
    result = mod.list_drives()
    _output(result, args.json)


def cmd_find_suspicious(args):
    mod = _import_module("file_scanner")
    result = mod.find_suspicious_files(
        search_paths=args.paths,
        patterns=args.patterns,
    )
    _output(result, args.json)


def cmd_check_tls(args):
    mod = _import_module("tls_checker")
    result = mod.check_tls(args.host, port=args.port)
    _output(result, args.json)


def cmd_check_ssl_versions(args):
    mod = _import_module("tls_checker")
    result = mod.check_ssl_versions(args.host, port=args.port)
    _output(result, args.json)


def cmd_scan_certificates(args):
    mod = _import_module("tls_checker")
    result = mod.scan_certificates(args.hosts)
    _output(result, args.json)


def cmd_check_cert_chain(args):
    mod = _import_module("tls_checker")
    result = mod.check_cert_chain(args.host, port=args.port)
    _output(result, args.json)


def cmd_nmap(args):
    mod = _import_module("nmap_scanner")
    result = mod.nmap_scan(args.target, ports=args.ports, scan_type=args.type)
    _output(result, args.json)


def cmd_nmap_services(args):
    mod = _import_module("nmap_scanner")
    result = mod.nmap_service_detect(args.target, ports=args.ports)
    _output(result, args.json)


def cmd_nmap_vuln(args):
    mod = _import_module("nmap_scanner")
    result = mod.nmap_vuln_scan(args.target, ports=args.ports)
    _output(result, args.json)


def cmd_hash_file(args):
    mod = _import_module("integrity")
    result = mod.hash_file(args.file, algorithm=args.algorithm)
    _output(result, args.json)


def cmd_hash_dir(args):
    mod = _import_module("integrity")
    result = mod.hash_directory(
        args.directory,
        pattern=args.pattern,
        algorithm=args.algorithm,
        baseline_name=args.save_baseline,
    )
    _output(result, args.json)


def cmd_compare_baseline(args):
    mod = _import_module("integrity")
    result = mod.compare_baseline(args.directory, args.baseline)
    _output(result, args.json)


def cmd_verify_integrity(args):
    mod = _import_module("integrity")
    result = mod.verify_integrity(args.baseline)
    _output(result, args.json)


def cmd_analyze_package(args):
    mod = _import_module("dependency")
    result = mod.analyze_package_json(args.file)
    _output(result, args.json)


def cmd_scan_deps(args):
    mod = _import_module("dependency")
    result = mod.scan_dependencies(search_paths=args.paths, file_types=args.file_types)
    _output(result, args.json)


def cmd_check_vuln(args):
    mod = _import_module("dependency")
    result = mod.check_vulnerability(args.package, args.version, ecosystem=args.ecosystem)
    _output(result, args.json)


def cmd_generate_sbom(args):
    mod = _import_module("sbom")
    result = mod.generate_sbom(
        search_paths=args.paths,
        format=args.format,
        file_types=args.file_types,
    )
    _output(result, args.json)


def cmd_list_sboms(args):
    mod = _import_module("sbom")
    result = mod.list_sboms()
    _output(result, args.json)


def cmd_export_sbom(args):
    mod = _import_module("sbom")
    result = mod.export_sbom(args.sbom_id, format=args.format)
    _output(result, args.json)


def cmd_generate_oscal(args):
    mod = _import_module("oscal")
    result = mod.generate_oscal_assessment(
        scan_ids=args.scan_ids,
        framework=args.framework,
    )
    _output(result, args.json)


def cmd_generate_oscal_component(args):
    mod = _import_module("oscal")
    result = mod.generate_oscal_component(args.sbom_id)
    _output(result, args.json)


def cmd_map_controls(args):
    mod = _import_module("oscal")
    findings = [{"type": f} for f in args.finding_types]
    result = mod.map_to_controls(findings, framework=args.framework)
    _output(result, args.json)


def cmd_list_oscal(args):
    mod = _import_module("oscal")
    result = mod.list_oscal_documents()
    _output(result, args.json)


def cmd_export_oscal(args):
    mod = _import_module("oscal")
    result = mod.export_oscal(args.document_id, format=args.format)
    _output(result, args.json)


def cmd_history(args):
    mod = _import_module("logging_audit")
    result = mod.scan_history(
        limit=args.limit,
        tool_name=args.tool,
        date_from=args.date_from,
    )
    _output(result, args.json)


def cmd_stats(args):
    mod = _import_module("logging_audit")
    result = mod.get_scan_stats(days=args.days)
    _output(result, args.json)


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Cyber-Scanner-MCP — pluggable security toolkit",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # -- File Scanner --
    p = sub.add_parser("scan", help="Scan files for suspicious content")
    p.add_argument("--terms", nargs="+", required=True, help="Search terms")
    p.add_argument("--pattern", default="package.json", help="File pattern to search for")
    p.add_argument("--paths", nargs="+", help="Directories to search")
    p.add_argument("--max-results", type=int, default=1000)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("check-file", help="Check a single file for terms")
    p.add_argument("file", help="Path to file")
    p.add_argument("--terms", nargs="+", required=True)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_check_file)

    p = sub.add_parser("list-drives", help="List available drives/filesystems")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_list_drives)

    p = sub.add_parser("find-suspicious", help="Find files with suspicious names")
    p.add_argument("--paths", nargs="+", help="Directories to search")
    p.add_argument("--patterns", nargs="+", help="Suspicious patterns to look for")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_find_suspicious)

    # -- TLS/SSL --
    p = sub.add_parser("check-tls", help="Check TLS certificate of a host")
    p.add_argument("host", help="Hostname to check")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_check_tls)

    p = sub.add_parser("check-ssl-versions", help="Test accepted SSL/TLS versions")
    p.add_argument("host", help="Hostname to check")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_check_ssl_versions)

    p = sub.add_parser("scan-certs", help="Batch scan certificates for multiple hosts")
    p.add_argument("hosts", nargs="+", help="Hostnames to scan")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_scan_certificates)

    p = sub.add_parser("check-cert-chain", help="Validate certificate chain")
    p.add_argument("host", help="Hostname to check")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_check_cert_chain)

    # -- Nmap --
    p = sub.add_parser("nmap", help="Port scan a target")
    p.add_argument("target", help="Host or network range")
    p.add_argument("--ports", help="Port range (e.g. 80,443 or 1-1000)")
    p.add_argument("--type", choices=["quick", "basic", "full"], default="basic")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_nmap)

    p = sub.add_parser("nmap-services", help="Detect services on a target")
    p.add_argument("target", help="Host or network range")
    p.add_argument("--ports", help="Port range")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_nmap_services)

    p = sub.add_parser("nmap-vuln", help="Run vulnerability scan on a target")
    p.add_argument("target", help="Host or network range")
    p.add_argument("--ports", help="Port range")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_nmap_vuln)

    # -- File Integrity --
    p = sub.add_parser("hash-file", help="Hash a single file")
    p.add_argument("file", help="Path to file")
    p.add_argument("--algorithm", choices=["sha256", "sha512", "md5"], default="sha256")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_hash_file)

    p = sub.add_parser("hash-dir", help="Hash all files in a directory")
    p.add_argument("directory", help="Directory to hash")
    p.add_argument("--pattern", default="*", help="Glob pattern")
    p.add_argument("--algorithm", choices=["sha256", "sha512", "md5"], default="sha256")
    p.add_argument("--save-baseline", help="Save as named baseline")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_hash_dir)

    p = sub.add_parser("compare-baseline", help="Compare directory against baseline")
    p.add_argument("directory", help="Directory to compare")
    p.add_argument("baseline", help="Baseline name")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_compare_baseline)

    p = sub.add_parser("verify-integrity", help="Verify files against baseline")
    p.add_argument("baseline", help="Baseline name")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify_integrity)

    # -- Dependency Checker --
    p = sub.add_parser("analyze-package", help="Analyze a package.json file")
    p.add_argument("file", help="Path to package.json")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_analyze_package)

    p = sub.add_parser("scan-deps", help="Scan for all dependency files")
    p.add_argument("--paths", nargs="+", help="Directories to search")
    p.add_argument("--file-types", nargs="+", help="File types to look for")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_scan_deps)

    p = sub.add_parser("check-vuln", help="Check a package for known vulnerabilities")
    p.add_argument("package", help="Package name")
    p.add_argument("version", help="Package version")
    p.add_argument("--ecosystem", default="npm", help="Package ecosystem")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_check_vuln)

    # -- SBOM --
    p = sub.add_parser("generate-sbom", help="Generate an SBOM")
    p.add_argument("--paths", nargs="+", help="Directories to scan")
    p.add_argument("--format", choices=["cyclonedx", "spdx"], default="cyclonedx")
    p.add_argument("--file-types", nargs="+", help="Dependency file types")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_generate_sbom)

    p = sub.add_parser("list-sboms", help="List generated SBOMs")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_list_sboms)

    p = sub.add_parser("export-sbom", help="Export an SBOM in a different format")
    p.add_argument("sbom_id", help="SBOM ID")
    p.add_argument("--format", choices=["cyclonedx", "spdx"], default="cyclonedx")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_export_sbom)

    # -- OSCAL --
    p = sub.add_parser("generate-oscal-assessment", help="Generate OSCAL assessment from scan results")
    p.add_argument("--scan-ids", nargs="+", type=int, help="Specific scan log IDs")
    p.add_argument("--framework", default="nist-800-53",
                   choices=["nist-800-53", "fedramp", "nist-csf", "iso-27001"])
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_generate_oscal)

    p = sub.add_parser("generate-oscal-component", help="Convert SBOM to OSCAL component definition")
    p.add_argument("sbom_id", help="SBOM ID to convert")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_generate_oscal_component)

    p = sub.add_parser("map-controls", help="Map finding types to security controls")
    p.add_argument("finding_types", nargs="+", help="Finding types to map")
    p.add_argument("--framework", default="nist-800-53",
                   choices=["nist-800-53", "fedramp", "nist-csf", "iso-27001"])
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_map_controls)

    p = sub.add_parser("list-oscal", help="List generated OSCAL documents")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_list_oscal)

    p = sub.add_parser("export-oscal", help="Export OSCAL document")
    p.add_argument("document_id", help="OSCAL document ID")
    p.add_argument("--format", choices=["json", "xml"], default="json")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_export_oscal)

    # -- Audit --
    p = sub.add_parser("history", help="View scan history")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--tool", help="Filter by tool name")
    p.add_argument("--date-from", help="Filter after this date (ISO format)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("stats", help="View scan statistics")
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_stats)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
