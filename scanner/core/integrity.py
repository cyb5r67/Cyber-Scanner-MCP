"""Module 5: File Integrity Monitor.

Provides hash-based file integrity monitoring. Files can be hashed individually
or as a directory, and their hashes saved as named baselines for later
comparison and verification.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.core.logging_audit import audit

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_BASELINES_DIR = _BASE_DIR / "data" / "baselines"

_SUPPORTED_ALGORITHMS = ("sha256", "sha512", "md5")
_DEFAULT_ALGORITHM = "sha256"
_CHUNK_SIZE = 8192


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _validate_algorithm(algorithm: str) -> str:
    """Return the normalised algorithm name or raise ValueError."""
    algo = algorithm.lower()
    if algo not in _SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Supported: {', '.join(_SUPPORTED_ALGORITHMS)}"
        )
    return algo


def _compute_hash(file_path: Path, algorithm: str) -> str:
    """Compute the hex digest of a file using the given algorithm."""
    h = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(_CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _baseline_path(baseline_name: str) -> Path:
    """Return the full path to a baseline JSON file."""
    name = baseline_name if baseline_name.endswith(".json") else f"{baseline_name}.json"
    return _BASELINES_DIR / name


def _load_baseline(baseline_name: str) -> dict[str, Any]:
    """Load a baseline JSON file and return its contents."""
    path = _baseline_path(baseline_name)
    if not path.exists():
        raise FileNotFoundError(f"Baseline '{baseline_name}' not found at {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_baseline(baseline_name: str, data: dict[str, Any]) -> Path:
    """Save baseline data as a JSON file and return the path."""
    _BASELINES_DIR.mkdir(parents=True, exist_ok=True)
    path = _baseline_path(baseline_name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path


# ---------------------------------------------------------------------------
# Public tool functions
# ---------------------------------------------------------------------------
@audit(tool_name="hash_file")
def hash_file(file_path: str, algorithm: str = _DEFAULT_ALGORITHM) -> dict:
    """Hash a single file using the specified algorithm.

    Args:
        file_path: Absolute or relative path to the file to hash.
        algorithm: Hash algorithm to use. Supported: sha256, sha512, md5.

    Returns:
        Dict with path, algorithm, hash, and size_bytes.
    """
    algo = _validate_algorithm(algorithm)
    p = Path(file_path).resolve()

    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    if not p.is_file():
        raise ValueError(f"Path is not a file: {p}")

    file_hash = _compute_hash(p, algo)
    size_bytes = p.stat().st_size

    return {
        "path": str(p),
        "algorithm": algo,
        "hash": file_hash,
        "size_bytes": size_bytes,
    }


@audit(tool_name="hash_directory")
def hash_directory(
    directory: str,
    pattern: str = "*",
    algorithm: str = _DEFAULT_ALGORITHM,
    baseline_name: str | None = None,
) -> dict:
    """Generate hashes for all files in a directory matching a glob pattern.

    Args:
        directory: Path to the directory to scan.
        pattern: Glob pattern for file matching (default: '*').
        algorithm: Hash algorithm to use. Supported: sha256, sha512, md5.
        baseline_name: If provided, save the results as a named baseline
            JSON file in data/baselines/.

    Returns:
        Dict with directory, file_count, algorithm, baseline_name (if saved),
        and a files list containing path, relative_path, hash, and size_bytes
        for each matched file.
    """
    algo = _validate_algorithm(algorithm)
    dir_path = Path(directory).resolve()

    if not dir_path.exists():
        raise FileNotFoundError(f"Directory not found: {dir_path}")
    if not dir_path.is_dir():
        raise ValueError(f"Path is not a directory: {dir_path}")

    files_list: list[dict[str, Any]] = []
    for file_path in sorted(dir_path.rglob(pattern)):
        if not file_path.is_file():
            continue
        rel = file_path.relative_to(dir_path)
        file_hash = _compute_hash(file_path, algo)
        size_bytes = file_path.stat().st_size
        files_list.append({
            "path": str(file_path),
            "relative_path": str(rel),
            "hash": file_hash,
            "size_bytes": size_bytes,
        })

    result: dict[str, Any] = {
        "directory": str(dir_path),
        "file_count": len(files_list),
        "algorithm": algo,
        "files": files_list,
    }

    if baseline_name:
        baseline_data = {
            "name": baseline_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "algorithm": algo,
            "directory": str(dir_path),
            "files": {entry["relative_path"]: entry["hash"] for entry in files_list},
        }
        _save_baseline(baseline_name, baseline_data)
        result["baseline_name"] = baseline_name

    return result


@audit(tool_name="compare_baseline")
def compare_baseline(directory: str, baseline_name: str) -> dict:
    """Compare the current state of a directory against a saved baseline.

    Args:
        directory: Path to the directory to compare.
        baseline_name: Name of the baseline to compare against.

    Returns:
        Dict with added, removed, and modified file lists, plus
        unchanged_count.
    """
    baseline = _load_baseline(baseline_name)
    algo = baseline.get("algorithm", _DEFAULT_ALGORITHM)
    baseline_files: dict[str, str] = baseline.get("files", {})

    dir_path = Path(directory).resolve()
    if not dir_path.exists():
        raise FileNotFoundError(f"Directory not found: {dir_path}")
    if not dir_path.is_dir():
        raise ValueError(f"Path is not a directory: {dir_path}")

    # Build current file hash map
    current_files: dict[str, str] = {}
    for file_path in sorted(dir_path.rglob("*")):
        if not file_path.is_file():
            continue
        rel = str(file_path.relative_to(dir_path))
        current_files[rel] = _compute_hash(file_path, algo)

    baseline_keys = set(baseline_files.keys())
    current_keys = set(current_files.keys())

    added = sorted(current_keys - baseline_keys)
    removed = sorted(baseline_keys - current_keys)
    common = baseline_keys & current_keys

    modified = sorted(
        rel for rel in common if current_files[rel] != baseline_files[rel]
    )
    unchanged_count = len(common) - len(modified)

    return {
        "baseline_name": baseline_name,
        "directory": str(dir_path),
        "algorithm": algo,
        "added": added,
        "removed": removed,
        "modified": modified,
        "unchanged_count": unchanged_count,
    }


@audit(tool_name="verify_integrity")
def verify_integrity(baseline_name: str) -> dict:
    """Check all files in a baseline still match their recorded hashes.

    Args:
        baseline_name: Name of the baseline to verify.

    Returns:
        Dict with total file count, passed count, and lists of failed
        and missing files.
    """
    baseline = _load_baseline(baseline_name)
    algo = baseline.get("algorithm", _DEFAULT_ALGORITHM)
    directory = Path(baseline.get("directory", "")).resolve()
    baseline_files: dict[str, str] = baseline.get("files", {})

    passed = 0
    failed: list[dict[str, str]] = []
    missing: list[str] = []

    for rel_path, expected_hash in sorted(baseline_files.items()):
        full_path = directory / rel_path
        if not full_path.exists():
            missing.append(rel_path)
            continue
        current_hash = _compute_hash(full_path, algo)
        if current_hash == expected_hash:
            passed += 1
        else:
            failed.append({
                "path": rel_path,
                "expected": expected_hash,
                "actual": current_hash,
            })

    return {
        "baseline_name": baseline_name,
        "directory": str(directory),
        "algorithm": algo,
        "total": len(baseline_files),
        "passed": passed,
        "failed": failed,
        "missing": missing,
    }


# ---------------------------------------------------------------------------
# Module registration for pluggable loader
# ---------------------------------------------------------------------------
def register(mcp) -> None:
    """Register file integrity monitoring tools with the MCP server."""
    mcp.tool()(hash_file)
    mcp.tool()(hash_directory)
    mcp.tool()(compare_baseline)
    mcp.tool()(verify_integrity)
