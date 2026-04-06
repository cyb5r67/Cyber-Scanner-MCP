"""Cybersecurity Scanner — FastMCP Server with pluggable module loading.

Automatically discovers and registers available scanner modules at startup.
Missing modules are skipped with a warning — the server runs with whatever is installed.
"""

import importlib
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    name="Cybersecurity Scanner",
    instructions=(
        "A pluggable cybersecurity toolkit. Available capabilities depend on which "
        "modules are installed. Use list_modules to see what's available. Modules "
        "include: file scanning, dependency analysis, TLS/SSL checking, Nmap "
        "vulnerability scanning, file integrity monitoring, SBOM generation, "
        "OSCAL compliance reporting, and audit logging."
    ),
)

# ---------------------------------------------------------------------------
# Module registry — add new modules here
# ---------------------------------------------------------------------------
_MODULES = [
    ("scanner.core.logging_audit", "Logging & Audit"),
    ("scanner.core.file_scanner", "File Scanner"),
    ("scanner.core.integrity", "File Integrity"),
    ("scanner.core.tls_checker", "TLS/SSL Checker"),
    ("scanner.core.dependency", "Dependency Checker"),
    ("scanner.core.nmap_scanner", "Nmap Scanner"),
    ("scanner.core.sbom", "SBOM Generation"),
    ("scanner.core.oscal", "OSCAL Compliance"),
]

_loaded_modules: dict[str, str] = {}
_failed_modules: dict[str, str] = {}


def _load_modules() -> None:
    """Discover and register all available scanner modules."""
    for module_path, display_name in _MODULES:
        try:
            mod = importlib.import_module(module_path)
            if hasattr(mod, "register"):
                mod.register(mcp)
                _loaded_modules[module_path] = display_name
            else:
                _failed_modules[module_path] = "No register() function found"
        except ImportError as e:
            _failed_modules[module_path] = f"Import error: {e}"
        except Exception as e:
            _failed_modules[module_path] = f"Load error: {e}"


# ---------------------------------------------------------------------------
# Built-in server tools
# ---------------------------------------------------------------------------
@mcp.tool()
def list_modules() -> dict:
    """List all available and unavailable scanner modules.

    Returns:
        Dict with 'loaded' modules and 'unavailable' modules with error reasons.
    """
    return {
        "loaded": _loaded_modules,
        "unavailable": _failed_modules,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
_load_modules()

if __name__ == "__main__":
    print(f"Loaded modules: {list(_loaded_modules.values())}", file=sys.stderr)
    if _failed_modules:
        print(f"Unavailable: {_failed_modules}", file=sys.stderr)
    mcp.run()
