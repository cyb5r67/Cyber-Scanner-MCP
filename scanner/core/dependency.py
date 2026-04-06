"""Module 2: Dependency Checker.

Analyzes package dependency files (package.json, requirements.txt, Gemfile,
pom.xml, go.mod) across the filesystem, extracts package information, and
checks for known vulnerabilities via the OSV.dev API.
"""

import json
import os
import re
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Optional

from scanner.core.logging_audit import audit

# ---------------------------------------------------------------------------
# Default dependency file names to search for
# ---------------------------------------------------------------------------
_DEFAULT_FILE_TYPES = [
    "package.json",
    "requirements.txt",
    "Gemfile",
    "pom.xml",
    "go.mod",
]

_OSV_API_URL = "https://api.osv.dev/v1/query"

# Suspicious script keys that may indicate supply-chain attacks
_SUSPICIOUS_SCRIPTS = {"preinstall", "postinstall", "install"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _detect_search_roots() -> list[str]:
    """Auto-detect filesystem roots based on the current platform."""
    roots: list[str] = []
    if os.name == "nt":
        # Windows: check common drive letters
        for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = f"{letter}:\\"
            if os.path.isdir(drive):
                roots.append(drive)
    else:
        roots.append("/")
    return roots or ["/"]


def _parse_requirements_txt(file_path: str) -> list[dict[str, str]]:
    """Parse a requirements.txt file into a list of {name, version} dicts."""
    packages: list[dict[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                # Skip blanks, comments, options, and -r includes
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Handle version specifiers: ==, >=, <=, ~=, !=, >, <
                match = re.match(r"^([A-Za-z0-9_][A-Za-z0-9._-]*)\s*([><=!~]+.*)?", line)
                if match:
                    name = match.group(1).strip()
                    version_spec = match.group(2).strip() if match.group(2) else "*"
                    packages.append({"name": name, "version": version_spec})
    except Exception:
        pass
    return packages


def _parse_gemfile(file_path: str) -> list[dict[str, str]]:
    """Parse a Gemfile for gem names and optional version constraints."""
    packages: list[dict[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                # Match: gem 'name', '~> 1.0'  or  gem "name"
                match = re.match(
                    r"""gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*)['"]\s*)?""",
                    line,
                )
                if match:
                    name = match.group(1)
                    version = match.group(2) if match.group(2) else "*"
                    packages.append({"name": name, "version": version})
    except Exception:
        pass
    return packages


def _parse_pom_xml(file_path: str) -> list[dict[str, str]]:
    """Parse a pom.xml for <dependency> groupId:artifactId and version."""
    packages: list[dict[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        # Simple regex extraction — not a full XML parser but sufficient
        dep_pattern = re.compile(
            r"<dependency>\s*"
            r"<groupId>([^<]+)</groupId>\s*"
            r"<artifactId>([^<]+)</artifactId>\s*"
            r"(?:<version>([^<]*)</version>)?",
            re.DOTALL,
        )
        for m in dep_pattern.finditer(content):
            group_id = m.group(1).strip()
            artifact_id = m.group(2).strip()
            version = m.group(3).strip() if m.group(3) else "*"
            packages.append({
                "name": f"{group_id}:{artifact_id}",
                "version": version,
            })
    except Exception:
        pass
    return packages


def _parse_go_mod(file_path: str) -> list[dict[str, str]]:
    """Parse a go.mod file for require directives."""
    packages: list[dict[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        # Single-line requires: require module/path v1.2.3
        for m in re.finditer(r"require\s+(\S+)\s+(v\S+)", content):
            packages.append({"name": m.group(1), "version": m.group(2)})
        # Block requires
        block_match = re.search(r"require\s*\((.*?)\)", content, re.DOTALL)
        if block_match:
            for line in block_match.group(1).splitlines():
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    packages.append({"name": parts[0], "version": parts[1]})
    except Exception:
        pass
    return packages


def _ecosystem_for_file(filename: str) -> str:
    """Map a dependency filename to its ecosystem identifier."""
    mapping = {
        "package.json": "npm",
        "requirements.txt": "PyPI",
        "Gemfile": "RubyGems",
        "pom.xml": "Maven",
        "go.mod": "Go",
    }
    return mapping.get(filename, "unknown")


# ---------------------------------------------------------------------------
# Tool 1: analyze_package_json
# ---------------------------------------------------------------------------
@audit(tool_name="analyze_package_json")
def analyze_package_json(file_path: str) -> dict[str, Any]:
    """Deep inspection of a single package.json file.

    Parses and reports all dependency groups, suspicious install scripts,
    unusual registry settings, and total dependency count.

    Args:
        file_path: Absolute path to a package.json file.

    Returns:
        Dict with keys: path, dependencies, warnings, scripts,
        total_dependency_count, and raw metadata.
    """
    result: dict[str, Any] = {
        "path": file_path,
        "dependencies": {},
        "warnings": [],
        "scripts": {},
        "total_dependency_count": 0,
    }

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        result["warnings"].append(f"Invalid JSON: {exc}")
        return result
    except FileNotFoundError:
        result["warnings"].append(f"File not found: {file_path}")
        return result
    except Exception as exc:
        result["warnings"].append(f"Error reading file: {exc}")
        return result

    # --- Collect dependency groups ---
    dep_groups = ["dependencies", "devDependencies", "peerDependencies"]
    total = 0
    for group in dep_groups:
        deps = data.get(group, {})
        if isinstance(deps, dict):
            result["dependencies"][group] = deps
            total += len(deps)
    result["total_dependency_count"] = total

    # --- Scripts inspection ---
    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        result["scripts"] = scripts
        for key in _SUSPICIOUS_SCRIPTS:
            if key in scripts:
                result["warnings"].append(
                    f"Suspicious install script detected: '{key}' -> "
                    f"'{scripts[key][:200]}'"
                )

    # --- Registry / publishConfig anomalies ---
    publish_config = data.get("publishConfig", {})
    if isinstance(publish_config, dict):
        registry = publish_config.get("registry", "")
        if registry and "registry.npmjs.org" not in registry:
            result["warnings"].append(
                f"Unusual publish registry: {registry}"
            )

    # Check top-level for custom registry fields
    for key in ("registry", "publishConfig"):
        val = data.get(key)
        if isinstance(val, str) and val and "registry.npmjs.org" not in val:
            result["warnings"].append(
                f"Unusual top-level '{key}' value: {val}"
            )

    # --- Name / version anomalies ---
    pkg_name = data.get("name", "")
    if pkg_name and pkg_name.startswith("@") and "/" not in pkg_name:
        result["warnings"].append(
            f"Malformed scoped package name: {pkg_name}"
        )

    return result


# ---------------------------------------------------------------------------
# Tool 2: scan_dependencies
# ---------------------------------------------------------------------------
@audit(tool_name="scan_dependencies")
def scan_dependencies(
    search_paths: Optional[list[str]] = None,
    file_types: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Find and parse all dependency files across the filesystem.

    Walks the given search paths (or auto-detected drives) looking for
    dependency manifests and extracts package names and versions.

    Args:
        search_paths: Directories to search. Auto-detects drives if None.
        file_types: Filenames to look for (default: package.json,
                    requirements.txt, Gemfile, pom.xml, go.mod).

    Returns:
        Dict with files_found (int), total_packages (int), and packages
        list (each entry: name, version, ecosystem, source_file).
    """
    targets = file_types or _DEFAULT_FILE_TYPES
    roots = search_paths or _detect_search_roots()
    target_set = set(targets)

    found_files: list[str] = []
    packages: list[dict[str, str]] = []

    # Directories to skip for performance
    skip_dirs = {
        "node_modules", ".git", "__pycache__", ".tox", ".venv",
        "venv", "env", ".eggs", "dist", "build",
    }

    for root_path in roots:
        if not os.path.isdir(root_path):
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
                # Prune uninteresting directories in-place
                dirnames[:] = [
                    d for d in dirnames
                    if d not in skip_dirs and not d.startswith(".")
                ]
                for fname in filenames:
                    if fname not in target_set:
                        continue
                    full_path = os.path.join(dirpath, fname)
                    found_files.append(full_path)
                    ecosystem = _ecosystem_for_file(fname)

                    try:
                        if fname == "package.json":
                            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                                data = json.load(fh)
                            for group in ("dependencies", "devDependencies", "peerDependencies"):
                                deps = data.get(group, {})
                                if isinstance(deps, dict):
                                    for name, version in deps.items():
                                        packages.append({
                                            "name": name,
                                            "version": str(version),
                                            "ecosystem": ecosystem,
                                            "source_file": full_path,
                                        })
                        elif fname == "requirements.txt":
                            for pkg in _parse_requirements_txt(full_path):
                                packages.append({
                                    **pkg,
                                    "ecosystem": ecosystem,
                                    "source_file": full_path,
                                })
                        elif fname == "Gemfile":
                            for pkg in _parse_gemfile(full_path):
                                packages.append({
                                    **pkg,
                                    "ecosystem": ecosystem,
                                    "source_file": full_path,
                                })
                        elif fname == "pom.xml":
                            for pkg in _parse_pom_xml(full_path):
                                packages.append({
                                    **pkg,
                                    "ecosystem": ecosystem,
                                    "source_file": full_path,
                                })
                        elif fname == "go.mod":
                            for pkg in _parse_go_mod(full_path):
                                packages.append({
                                    **pkg,
                                    "ecosystem": ecosystem,
                                    "source_file": full_path,
                                })
                    except Exception:
                        # Skip files that cannot be parsed
                        continue
        except PermissionError:
            continue

    return {
        "files_found": len(found_files),
        "total_packages": len(packages),
        "packages": packages,
    }


# ---------------------------------------------------------------------------
# Tool 3: check_vulnerability
# ---------------------------------------------------------------------------
@audit(tool_name="check_vulnerability")
def check_vulnerability(
    package_name: str,
    version: str,
    ecosystem: str = "npm",
) -> dict[str, Any]:
    """Query the OSV.dev API for known vulnerabilities in a package.

    Args:
        package_name: The package name (e.g. 'lodash').
        version: The exact version string (e.g. '4.17.20').
        ecosystem: Package ecosystem — npm, PyPI, RubyGems, Maven, Go, etc.

    Returns:
        Dict with package, version, vulnerable (bool), and vulnerabilities
        list (each entry: id, summary, severity, references).
    """
    result: dict[str, Any] = {
        "package": package_name,
        "version": version,
        "ecosystem": ecosystem,
        "vulnerable": False,
        "vulnerabilities": [],
    }

    payload = json.dumps({
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        },
        "version": version,
    }).encode("utf-8")

    req = urllib.request.Request(
        _OSV_API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        result["error"] = f"HTTP {exc.code}: {exc.reason}"
        return result
    except urllib.error.URLError as exc:
        result["error"] = f"Connection error: {exc.reason}"
        return result
    except Exception as exc:
        result["error"] = f"Request failed: {exc}"
        return result

    vulns_raw = body.get("vulns", [])
    if not vulns_raw:
        return result

    result["vulnerable"] = True
    for vuln in vulns_raw:
        # Extract severity — OSV uses database_specific or severity list
        severity = "UNKNOWN"
        severity_list = vuln.get("severity", [])
        if severity_list and isinstance(severity_list, list):
            severity = severity_list[0].get("score", severity_list[0].get("type", "UNKNOWN"))
        elif vuln.get("database_specific", {}).get("severity"):
            severity = vuln["database_specific"]["severity"]

        references = [
            ref.get("url", "")
            for ref in vuln.get("references", [])
            if ref.get("url")
        ]

        result["vulnerabilities"].append({
            "id": vuln.get("id", "UNKNOWN"),
            "summary": vuln.get("summary", vuln.get("details", "No summary available"))[:500],
            "severity": severity,
            "references": references[:5],  # Limit to first 5 references
        })

    return result


# ---------------------------------------------------------------------------
# Module registration for pluggable loader
# ---------------------------------------------------------------------------
def register(mcp) -> None:
    """Register dependency-checker tools with the MCP server."""
    mcp.tool()(analyze_package_json)
    mcp.tool()(scan_dependencies)
    mcp.tool()(check_vulnerability)
