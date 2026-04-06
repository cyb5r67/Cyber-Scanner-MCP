"""Module 7: SBOM Generation.

Generates Software Bill of Materials (SBOM) documents in CycloneDX 1.5 and
SPDX 2.3 formats.  Dependency files are discovered automatically across the
filesystem (or within explicit search paths), parsed locally, and assembled
into standards-compliant JSON documents.

All public functions return JSON-serializable dicts and are registered as MCP
tools via the ``register()`` entry point.
"""

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from scanner.core.logging_audit import audit

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_SBOM_DIR = _BASE_DIR / "data" / "sboms"

_DEFAULT_FILE_TYPES = [
    "package.json",
    "requirements.txt",
    "Gemfile",
    "pom.xml",
    "go.mod",
]

_SUPPORTED_FORMATS = ("cyclonedx", "spdx")

# Ecosystem mapping used for CycloneDX purl generation.
_ECOSYSTEM_MAP = {
    "package.json": "npm",
    "requirements.txt": "pypi",
    "Gemfile": "gem",
    "pom.xml": "maven",
    "go.mod": "golang",
}


# ---------------------------------------------------------------------------
# Internal helpers -- file discovery
# ---------------------------------------------------------------------------

def _discover_search_paths() -> list[Path]:
    """Return a reasonable default set of search paths for the current OS."""
    cwd = Path.cwd()
    return [cwd]


def _find_dependency_files(
    search_paths: list[Path],
    file_types: list[str],
) -> list[Path]:
    """Walk *search_paths* and return every file whose name matches one of
    *file_types*.
    """
    results: list[Path] = []
    seen: set[str] = set()

    for root_path in search_paths:
        root_path = Path(root_path)
        if not root_path.exists():
            continue
        for dirpath, _dirnames, filenames in os.walk(root_path):
            # Skip common vendored / generated directories.
            dir_lower = Path(dirpath).name.lower()
            if dir_lower in {"node_modules", ".git", "__pycache__", "vendor", ".tox", ".venv", "venv"}:
                _dirnames.clear()
                continue
            for fname in filenames:
                if fname in file_types:
                    full = Path(dirpath) / fname
                    resolved = str(full.resolve())
                    if resolved not in seen:
                        seen.add(resolved)
                        results.append(full)
    return results


# ---------------------------------------------------------------------------
# Internal helpers -- dependency parsers
# ---------------------------------------------------------------------------

def _parse_package_json(path: Path) -> list[dict[str, str]]:
    """Extract packages from a Node.js package.json file."""
    components: list[dict[str, str]] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return components

    for section in ("dependencies", "devDependencies"):
        deps = data.get(section, {})
        if isinstance(deps, dict):
            for name, version in deps.items():
                # Strip leading version constraint characters.
                ver = re.sub(r"^[\^~>=<! ]+", "", str(version))
                components.append({"name": name, "version": ver, "ecosystem": "npm"})
    return components


def _parse_requirements_txt(path: Path) -> list[dict[str, str]]:
    """Extract packages from a Python requirements.txt file."""
    components: list[dict[str, str]] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return components

    for raw_line in lines:
        line = raw_line.strip()
        # Skip blanks, comments, and options.
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle inline comments.
        line = line.split("#")[0].strip()
        # Split on version specifiers.
        match = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*([=<>!~]+.+)?$", line)
        if match:
            name = re.sub(r"\[.*\]", "", match.group(1))
            ver_part = match.group(2) or ""
            version = re.sub(r"^[=<>!~]+", "", ver_part).strip()
            components.append({
                "name": name,
                "version": version if version else "unknown",
                "ecosystem": "pypi",
            })
    return components


def _parse_gemfile(path: Path) -> list[dict[str, str]]:
    """Extract packages from a Ruby Gemfile."""
    components: list[dict[str, str]] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return components

    for raw_line in lines:
        line = raw_line.strip()
        match = re.match(r"""^gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*)['"]\s*)?""", line)
        if match:
            name = match.group(1)
            version = match.group(2) or "unknown"
            version = re.sub(r"^[~>=<! ]+", "", version)
            components.append({"name": name, "version": version, "ecosystem": "gem"})
    return components


def _parse_pom_xml(path: Path) -> list[dict[str, str]]:
    """Extract packages from a Maven pom.xml file (simple regex approach)."""
    components: list[dict[str, str]] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except OSError:
        return components

    # Find <dependency> blocks.
    dep_pattern = re.compile(
        r"<dependency>\s*"
        r"<groupId>([^<]+)</groupId>\s*"
        r"<artifactId>([^<]+)</artifactId>\s*"
        r"(?:<version>([^<]+)</version>)?",
        re.DOTALL,
    )
    for m in dep_pattern.finditer(content):
        group_id = m.group(1).strip()
        artifact_id = m.group(2).strip()
        version = (m.group(3) or "unknown").strip()
        components.append({
            "name": f"{group_id}/{artifact_id}",
            "version": version,
            "ecosystem": "maven",
        })
    return components


def _parse_go_mod(path: Path) -> list[dict[str, str]]:
    """Extract packages from a Go go.mod file."""
    components: list[dict[str, str]] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return components

    in_require = False
    for raw_line in lines:
        line = raw_line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue

        if in_require:
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1].lstrip("v")
                components.append({"name": name, "version": version, "ecosystem": "golang"})
        elif line.startswith("require "):
            parts = line.split()
            if len(parts) >= 3:
                name = parts[1]
                version = parts[2].lstrip("v")
                components.append({"name": name, "version": version, "ecosystem": "golang"})
    return components


_PARSERS = {
    "package.json": _parse_package_json,
    "requirements.txt": _parse_requirements_txt,
    "Gemfile": _parse_gemfile,
    "pom.xml": _parse_pom_xml,
    "go.mod": _parse_go_mod,
}


def _parse_dependency_file(path: Path) -> list[dict[str, str]]:
    """Dispatch to the correct parser based on the file name."""
    parser = _PARSERS.get(path.name)
    if parser is None:
        return []
    return parser(path)


# ---------------------------------------------------------------------------
# Internal helpers -- SBOM document builders
# ---------------------------------------------------------------------------

def _build_cyclonedx(components: list[dict[str, str]], serial: str, timestamp: str) -> dict[str, Any]:
    """Build a CycloneDX 1.5 SBOM document as a plain dict."""
    cdx_components = []
    for comp in components:
        ecosystem = comp.get("ecosystem", "generic")
        name = comp["name"]
        version = comp["version"]
        purl = f"pkg:{ecosystem}/{name}@{version}"
        cdx_components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "cyber-scanner-mcp",
                    "name": "sbom-generator",
                    "version": "1.0.0",
                }
            ],
        },
        "components": cdx_components,
    }


def _build_spdx(components: list[dict[str, str]], serial: str, timestamp: str) -> dict[str, Any]:
    """Build an SPDX 2.3 SBOM document as a plain dict."""
    packages = []
    for idx, comp in enumerate(components, start=1):
        packages.append({
            "SPDXID": f"SPDXRef-Package-{idx}",
            "name": comp["name"],
            "versionInfo": comp["version"],
            "downloadLocation": "NOASSERTION",
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "cyber-scanner-mcp-scan",
        "documentNamespace": f"https://spdx.org/spdxdocs/{serial}",
        "creationInfo": {
            "created": timestamp,
            "creators": ["Tool: cyber-scanner-mcp-1.0.0"],
        },
        "packages": packages,
    }


_BUILDERS = {
    "cyclonedx": _build_cyclonedx,
    "spdx": _build_spdx,
}


# ---------------------------------------------------------------------------
# Internal helpers -- persistence
# ---------------------------------------------------------------------------

def _ensure_sbom_dir() -> Path:
    """Create the SBOM storage directory if it does not exist."""
    _SBOM_DIR.mkdir(parents=True, exist_ok=True)
    return _SBOM_DIR


def _save_sbom(sbom_id: str, fmt: str, document: dict[str, Any]) -> Path:
    """Persist an SBOM document to disk and return the file path."""
    _ensure_sbom_dir()
    filename = f"{sbom_id}_{fmt}.json"
    file_path = _SBOM_DIR / filename
    with open(file_path, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2)
    return file_path


def _load_sbom(file_path: Path) -> dict[str, Any]:
    """Load and return an SBOM JSON document from disk."""
    with open(file_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _extract_component_count(document: dict[str, Any]) -> int:
    """Return the number of components/packages in an SBOM document."""
    if "components" in document:
        return len(document["components"])
    if "packages" in document:
        return len(document["packages"])
    return 0


def _detect_format(document: dict[str, Any]) -> str:
    """Detect whether a loaded SBOM document is CycloneDX or SPDX."""
    if document.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if "spdxVersion" in document:
        return "spdx"
    return "unknown"


def _extract_components_from_document(document: dict[str, Any]) -> list[dict[str, str]]:
    """Extract a normalised component list from a stored SBOM document."""
    components: list[dict[str, str]] = []
    if "components" in document:
        # CycloneDX
        for comp in document["components"]:
            ecosystem = "generic"
            purl = comp.get("purl", "")
            if purl.startswith("pkg:"):
                ecosystem = purl.split(":")[1].split("/")[0]
            components.append({
                "name": comp.get("name", ""),
                "version": comp.get("version", "unknown"),
                "ecosystem": ecosystem,
            })
    elif "packages" in document:
        # SPDX
        for pkg in document["packages"]:
            components.append({
                "name": pkg.get("name", ""),
                "version": pkg.get("versionInfo", "unknown"),
                "ecosystem": "generic",
            })
    return components


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@audit("generate_sbom")
def generate_sbom(
    search_paths: Optional[list[str]] = None,
    format: str = "cyclonedx",
    file_types: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Discover dependency files, parse them, and produce an SBOM document.

    Parameters
    ----------
    search_paths:
        Directories to scan for dependency files.  When ``None``, the
        current working directory is used.
    format:
        Output format -- ``"cyclonedx"`` (default) or ``"spdx"``.
    file_types:
        File names to look for (e.g. ``["package.json", "requirements.txt"]``).
        Defaults to the standard set of dependency manifests.

    Returns
    -------
    dict
        ``sbom_id``, ``format``, ``component_count``, ``file_path``, and
        ``timestamp``.
    """
    fmt = format.lower()
    if fmt not in _SUPPORTED_FORMATS:
        raise ValueError(
            f"Unsupported SBOM format '{format}'. "
            f"Supported: {', '.join(_SUPPORTED_FORMATS)}"
        )

    if file_types is None:
        file_types = list(_DEFAULT_FILE_TYPES)

    paths = [Path(p) for p in search_paths] if search_paths else _discover_search_paths()

    # Discover and parse.
    dep_files = _find_dependency_files(paths, file_types)
    all_components: list[dict[str, str]] = []
    for dep_file in dep_files:
        all_components.extend(_parse_dependency_file(dep_file))

    # Build identifiers.
    now = datetime.now(timezone.utc)
    timestamp = now.isoformat()
    serial = str(uuid.uuid4())
    sbom_id = now.strftime("%Y%m%dT%H%M%SZ") + "_" + serial[:8]

    # Build document.
    builder = _BUILDERS[fmt]
    document = builder(all_components, serial, timestamp)

    # Persist.
    file_path = _save_sbom(sbom_id, fmt, document)

    return {
        "sbom_id": sbom_id,
        "format": fmt,
        "component_count": len(all_components),
        "file_path": str(file_path),
        "timestamp": timestamp,
    }


@audit("export_sbom")
def export_sbom(
    sbom_id: str,
    format: str = "cyclonedx",
) -> dict[str, Any]:
    """Re-export a previously generated SBOM in a different format.

    Parameters
    ----------
    sbom_id:
        The identifier of the original SBOM (returned by ``generate_sbom``).
    format:
        Target format -- ``"cyclonedx"`` or ``"spdx"``.

    Returns
    -------
    dict
        ``sbom_id``, ``format``, ``file_path``.
    """
    fmt = format.lower()
    if fmt not in _SUPPORTED_FORMATS:
        raise ValueError(
            f"Unsupported SBOM format '{format}'. "
            f"Supported: {', '.join(_SUPPORTED_FORMATS)}"
        )

    _ensure_sbom_dir()

    # Find any existing file for this sbom_id.
    source_path: Optional[Path] = None
    for candidate in _SBOM_DIR.iterdir():
        if candidate.stem.startswith(sbom_id) and candidate.suffix == ".json":
            source_path = candidate
            break

    if source_path is None:
        raise FileNotFoundError(
            f"No SBOM found with id '{sbom_id}' in {_SBOM_DIR}"
        )

    # Load original, extract components, rebuild in new format.
    source_doc = _load_sbom(source_path)
    components = _extract_components_from_document(source_doc)

    now = datetime.now(timezone.utc)
    timestamp = now.isoformat()
    serial = str(uuid.uuid4())

    builder = _BUILDERS[fmt]
    document = builder(components, serial, timestamp)

    file_path = _save_sbom(sbom_id, fmt, document)

    return {
        "sbom_id": sbom_id,
        "format": fmt,
        "file_path": str(file_path),
    }


@audit("list_sboms")
def list_sboms() -> dict[str, Any]:
    """List all previously generated SBOMs stored in the data/sboms/ directory.

    Returns
    -------
    dict
        ``sboms`` -- a list of dicts, each containing ``id``, ``format``,
        ``component_count``, ``timestamp``, and ``file_path``.
    """
    _ensure_sbom_dir()

    sboms: list[dict[str, Any]] = []
    for entry in sorted(_SBOM_DIR.iterdir()):
        if entry.suffix != ".json":
            continue
        try:
            document = _load_sbom(entry)
        except (json.JSONDecodeError, OSError):
            continue

        detected_format = _detect_format(document)
        component_count = _extract_component_count(document)

        # Extract timestamp from the document metadata.
        timestamp = ""
        if detected_format == "cyclonedx":
            timestamp = document.get("metadata", {}).get("timestamp", "")
        elif detected_format == "spdx":
            timestamp = document.get("creationInfo", {}).get("created", "")

        # Derive the sbom_id from the filename (strip the _<format>.json suffix).
        stem = entry.stem
        for fmt_suffix in _SUPPORTED_FORMATS:
            if stem.endswith(f"_{fmt_suffix}"):
                sbom_id = stem[: -(len(fmt_suffix) + 1)]
                break
        else:
            sbom_id = stem

        sboms.append({
            "id": sbom_id,
            "format": detected_format,
            "component_count": component_count,
            "timestamp": timestamp,
            "file_path": str(entry),
        })

    return {"sboms": sboms}


# ---------------------------------------------------------------------------
# MCP registration
# ---------------------------------------------------------------------------

def register(mcp) -> None:
    """Register SBOM generation tools with the MCP server."""
    mcp.tool()(generate_sbom)
    mcp.tool()(export_sbom)
    mcp.tool()(list_sboms)
