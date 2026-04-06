"""Module 1: File Scanner.

Ports the shell-based package.json scanning logic into Python with
cross-platform drive detection, concurrent file scanning, and suspicious
file detection.  All public functions return JSON-serializable dicts and
are registered as MCP tools via the ``register()`` entry point.
"""

import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from scanner.core.logging_audit import audit

# ---------------------------------------------------------------------------
# Default suspicious-file patterns
# ---------------------------------------------------------------------------
_DEFAULT_SUSPICIOUS_PATTERNS: list[dict[str, str]] = [
    {
        "regex": r"\.\w+\.(exe|scr|bat|cmd|com|pif|vbs|js|wsh|wsf|ps1)$",
        "reason": "Double extension masquerading as benign file",
    },
    {
        "regex": r"^\.",
        "reason": "Hidden file with executable extension",
        "extra_check": r"\.(exe|bat|cmd|com|scr|pif|vbs|js|wsh|wsf|ps1|sh)$",
    },
    {
        "regex": r"\.(exe|dll|scr|com|pif)$",
        "reason": "Executable in unexpected location",
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_file_text(path: str) -> Optional[str]:
    """Read a file as UTF-8 text, returning None on failure."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except (OSError, PermissionError):
        return None


def _match_terms(content: str, search_terms: list[str]) -> list[str]:
    """Return the subset of *search_terms* found in *content*."""
    return [term for term in search_terms if term in content]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@audit()
def scan_files(
    search_terms: list[str],
    file_pattern: str = "package.json",
    search_paths: Optional[list[str]] = None,
    max_results: int = 1000,
) -> dict[str, Any]:
    """Full filesystem scan for files matching a pattern whose content contains search terms.

    Uses ``os.walk()`` to traverse all detected drives/mounts (or the
    supplied *search_paths*), then checks each matching file's content for
    every term in *search_terms* using a thread pool for parallelism.

    Args:
        search_terms: List of literal strings to search for inside each file.
        file_pattern: Filename glob to match (default ``"package.json"``).
            Supports simple names or shell-style globs via :func:`fnmatch`.
        search_paths: Explicit root directories to search.  When ``None``,
            :func:`list_drives` is called to auto-detect them.
        max_results: Stop collecting matches after this many hits.

    Returns:
        A dict with keys:

        - ``scan_summary`` — metadata about the scan (files found, scanned,
          hits, duration, search_paths used, etc.).
        - ``matches`` — list of match dicts, each with ``path``,
          ``matched_terms``, and ``size_bytes``.
    """
    import fnmatch

    start = time.time()

    if search_paths is None:
        search_paths = list_drives()

    # Phase 1: discover candidate files
    candidates: list[str] = []
    for root_path in search_paths:
        try:
            for dirpath, _dirnames, filenames in os.walk(root_path, followlinks=False):
                for fname in filenames:
                    if fnmatch.fnmatch(fname, file_pattern):
                        candidates.append(os.path.join(dirpath, fname))
        except (OSError, PermissionError):
            continue

    # Phase 2: scan candidates concurrently
    matches: list[dict[str, Any]] = []
    files_scanned = 0
    errors = 0
    workers = min(32, (os.cpu_count() or 1) + 4)

    def _scan_one(filepath: str) -> Optional[dict[str, Any]]:
        content = _read_file_text(filepath)
        if content is None:
            return None
        found = _match_terms(content, search_terms)
        if found:
            try:
                size = os.path.getsize(filepath)
            except OSError:
                size = -1
            return {
                "path": filepath,
                "matched_terms": found,
                "size_bytes": size,
            }
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_scan_one, fp): fp for fp in candidates}
        for future in as_completed(futures):
            files_scanned += 1
            try:
                result = future.result()
            except Exception:
                errors += 1
                continue
            if result is not None:
                matches.append(result)
                if len(matches) >= max_results:
                    break

    duration = round(time.time() - start, 3)

    return {
        "scan_summary": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "search_terms": search_terms,
            "file_pattern": file_pattern,
            "search_paths": search_paths,
            "files_found": len(candidates),
            "files_scanned": files_scanned,
            "hits": len(matches),
            "errors": errors,
            "duration_seconds": duration,
            "max_results": max_results,
            "truncated": len(matches) >= max_results,
        },
        "matches": matches,
    }


@audit()
def check_file(
    file_path: str,
    search_terms: list[str],
) -> dict[str, Any]:
    """Check a single file for the presence of search terms.

    Args:
        file_path: Absolute or relative path to the file to inspect.
        search_terms: List of literal strings to look for.

    Returns:
        A dict with:

        - ``path`` — the resolved file path.
        - ``matched_terms`` — list of terms found (may be empty).
        - ``status`` — ``"match"``, ``"clean"``, or ``"error"``.
    """
    resolved = os.path.abspath(file_path)
    if not os.path.isfile(resolved):
        return {
            "path": resolved,
            "matched_terms": [],
            "status": "error",
            "detail": "File not found",
        }

    content = _read_file_text(resolved)
    if content is None:
        return {
            "path": resolved,
            "matched_terms": [],
            "status": "error",
            "detail": "Unable to read file",
        }

    found = _match_terms(content, search_terms)
    return {
        "path": resolved,
        "matched_terms": found,
        "status": "match" if found else "clean",
    }


@audit()
def list_drives() -> list[str]:
    """Auto-detect available drives / mount points.

    On Windows (``sys.platform == "win32"``): checks each letter ``A``-``Z``
    followed by ``:\\`` for existence.

    On Linux / other POSIX: parses ``/proc/mounts`` for real filesystem
    mount targets, falling back to ``["/"]`` if the file is unavailable.

    Returns:
        Sorted list of root paths that exist and are accessible.
    """
    paths: list[str] = []

    if sys.platform == "win32":
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                paths.append(drive)
    else:
        # Linux / macOS: parse /proc/mounts
        _REAL_FS_TYPES = {
            "ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "ntfs",
            "fuseblk", "zfs", "apfs", "hfs", "hfsplus", "tmpfs",
            "overlay", "nfs", "nfs4", "cifs", "smb",
        }
        try:
            with open("/proc/mounts", "r") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 3:
                        mount_point = parts[1]
                        fs_type = parts[2]
                        if fs_type in _REAL_FS_TYPES and os.path.isdir(mount_point):
                            paths.append(mount_point)
        except (OSError, FileNotFoundError):
            pass

        if not paths:
            paths = ["/"]

    return sorted(set(paths))


@audit()
def find_suspicious_files(
    search_paths: list[str],
    patterns: Optional[list[dict[str, str]]] = None,
) -> list[dict[str, Any]]:
    """Find files with suspicious names or extensions.

    Walks each directory in *search_paths* and flags files that match
    heuristic patterns such as double extensions (e.g. ``.pdf.exe``),
    hidden executables, or binaries in unusual locations.

    Args:
        search_paths: Root directories to walk.
        patterns: Optional list of pattern dicts, each with ``regex``
            (applied to the filename) and ``reason`` (human-readable
            explanation).  Defaults to a built-in set of heuristics.

    Returns:
        List of dicts, each containing:

        - ``path`` — full path to the suspicious file.
        - ``reason`` — why the file was flagged.
    """
    if patterns is None:
        patterns = _DEFAULT_SUSPICIOUS_PATTERNS

    compiled: list[tuple[re.Pattern, str, Optional[re.Pattern]]] = []
    for pat in patterns:
        main = re.compile(pat["regex"], re.IGNORECASE)
        extra = None
        if "extra_check" in pat:
            extra = re.compile(pat["extra_check"], re.IGNORECASE)
        compiled.append((main, pat["reason"], extra))

    results: list[dict[str, Any]] = []

    for root_path in search_paths:
        try:
            for dirpath, _dirnames, filenames in os.walk(root_path, followlinks=False):
                for fname in filenames:
                    for regex, reason, extra in compiled:
                        if regex.search(fname):
                            # If there is an extra_check, both must match
                            if extra is not None and not extra.search(fname):
                                continue
                            results.append({
                                "path": os.path.join(dirpath, fname),
                                "reason": reason,
                            })
                            break  # one reason per file is sufficient
        except (OSError, PermissionError):
            continue

    return results


# ---------------------------------------------------------------------------
# MCP registration
# ---------------------------------------------------------------------------

def register(mcp) -> None:
    """Register all file-scanner tools with the MCP server."""
    mcp.tool()(scan_files)
    mcp.tool()(check_file)
    mcp.tool()(list_drives)
    mcp.tool()(find_suspicious_files)
