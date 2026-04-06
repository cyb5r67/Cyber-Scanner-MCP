"""Module 6: Logging & Audit System.

Provides automatic logging of all tool calls to file, API, and database.
Uses db_backend for storage (PostgreSQL via OB1, or SQLite fallback).
Optionally captures scan summaries as OB1 thoughts for semantic search.
"""

import functools
import json
import logging
import time
import urllib.request
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_LOG_DIR = _BASE_DIR / "logs"
_LOG_FILE = _LOG_DIR / "scanner.log"

# ---------------------------------------------------------------------------
# Configuration (mutable at runtime via configure_logging)
# ---------------------------------------------------------------------------
_config: dict[str, Any] = {
    "file_enabled": True,
    "database_enabled": True,
    "api_url": None,
    "api_key": None,
    "ob1_thoughts_enabled": True,
    "log_max_bytes": 10 * 1024 * 1024,  # 10 MB
    "log_backup_count": 5,
}


# ---------------------------------------------------------------------------
# File logger
# ---------------------------------------------------------------------------
def _get_file_logger() -> logging.Logger:
    logger = logging.getLogger("scanner.audit")
    if not logger.handlers:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            _LOG_FILE,
            maxBytes=_config["log_max_bytes"],
            backupCount=_config["log_backup_count"],
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


# ---------------------------------------------------------------------------
# API logger
# ---------------------------------------------------------------------------
def _log_to_api(record: dict[str, Any]) -> None:
    url = _config.get("api_url")
    if not url:
        return
    try:
        data = json.dumps(record).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if _config.get("api_key"):
            req.add_header("Authorization", f"Bearer {_config['api_key']}")
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Core logging function
# ---------------------------------------------------------------------------
def log_operation(
    tool_name: str,
    parameters: dict | None = None,
    scope: dict | None = None,
    results_summary: dict | None = None,
    duration_seconds: float | None = None,
    trigger_source: str = "unknown",
    status: str = "completed",
    details: list[dict] | None = None,
) -> str | int | None:
    """Log a tool operation to all enabled backends.

    Returns the scan_log_id from the database (or None if DB is disabled).
    """
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_name": tool_name,
        "parameters": parameters,
        "scope": scope,
        "results_summary": results_summary,
        "duration_seconds": duration_seconds,
        "trigger_source": trigger_source,
        "status": status,
    }

    # File backend
    if _config["file_enabled"]:
        _get_file_logger().info(json.dumps(record))

    # Database backend (PostgreSQL or SQLite via db_backend)
    scan_log_id = None
    if _config["database_enabled"]:
        try:
            from scanner.core.db_backend import get_backend

            backend = get_backend()
            scan_log_id = backend.log_scan(record)
            if details and scan_log_id is not None:
                for detail in details:
                    backend.log_detail(
                        scan_log_id,
                        detail.get("type", "result"),
                        detail.get("data"),
                    )
        except Exception:
            pass

    # API backend
    if _config.get("api_url"):
        _log_to_api(record)

    # OB1 thought capture
    if _config["ob1_thoughts_enabled"]:
        try:
            from scanner.core.ob1_integration import capture_scan_thought

            capture_scan_thought(
                tool_name=tool_name,
                parameters=parameters,
                results_summary=results_summary,
                duration=duration_seconds,
                status=status,
            )
        except Exception:
            pass

    return scan_log_id


# ---------------------------------------------------------------------------
# Audit decorator — apply to any tool function for automatic logging
# ---------------------------------------------------------------------------
def audit(tool_name: str | None = None, trigger_source: str = "mcp"):
    """Decorator that automatically logs tool execution with timing."""

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            name = tool_name or func.__name__
            start = time.time()
            status = "completed"
            result = None
            error_msg = None
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                status = "error"
                error_msg = str(e)
                raise
            finally:
                duration = time.time() - start
                summary = None
                if isinstance(result, dict):
                    summary = {
                        k: v
                        for k, v in result.items()
                        if k in ("count", "total", "matches", "status", "hits", "files_scanned")
                    }
                if error_msg:
                    summary = summary or {}
                    summary["error"] = error_msg
                log_operation(
                    tool_name=name,
                    parameters=_safe_params(args, kwargs),
                    duration_seconds=duration,
                    trigger_source=trigger_source,
                    status=status,
                    results_summary=summary,
                )

        return wrapper

    return decorator


def _safe_params(args: tuple, kwargs: dict) -> dict:
    """Extract serializable parameters for logging."""
    params = {}
    if kwargs:
        for k, v in kwargs.items():
            try:
                json.dumps(v)
                params[k] = v
            except (TypeError, ValueError):
                params[k] = str(v)
    if args:
        safe_args = []
        for a in args:
            try:
                json.dumps(a)
                safe_args.append(a)
            except (TypeError, ValueError):
                safe_args.append(str(a))
        params["_args"] = safe_args
    return params


# ---------------------------------------------------------------------------
# Tools exposed via MCP
# ---------------------------------------------------------------------------
def scan_history(
    limit: int = 50,
    tool_name: str | None = None,
    date_from: str | None = None,
) -> dict:
    """Query past scan operations from the audit database.

    Args:
        limit: Maximum number of records to return.
        tool_name: Filter by tool name (optional).
        date_from: Filter records after this ISO date (optional).

    Returns:
        Dict with 'records' list and 'total' count.
    """
    from scanner.core.db_backend import get_backend

    rows = get_backend().query_scan_history(limit, tool_name, date_from)
    return {"records": rows, "total": len(rows)}


def get_scan_stats(days: int = 30) -> dict:
    """Get summary statistics for scan operations over a period.

    Args:
        days: Number of days to look back.

    Returns:
        Dict with total_scans, total_errors, scans_by_tool, and avg_duration.
    """
    from scanner.core.db_backend import get_backend

    return get_backend().get_scan_stats(days)


def configure_logging(
    file: bool | None = None,
    database: bool | None = None,
    api_url: str | None = None,
    api_key: str | None = None,
    ob1_thoughts: bool | None = None,
) -> dict:
    """Enable or disable logging backends.

    Args:
        file: Enable/disable file logging.
        database: Enable/disable database logging.
        api_url: Set API webhook URL (None to disable).
        api_key: Set API authentication key.
        ob1_thoughts: Enable/disable OB1 thought capture.

    Returns:
        Current logging configuration.
    """
    if file is not None:
        _config["file_enabled"] = file
    if database is not None:
        _config["database_enabled"] = database
    if api_url is not None:
        _config["api_url"] = api_url
    if api_key is not None:
        _config["api_key"] = api_key
    if ob1_thoughts is not None:
        _config["ob1_thoughts_enabled"] = ob1_thoughts

    from scanner.core.db_backend import get_backend_type

    return {
        "file_enabled": _config["file_enabled"],
        "database_enabled": _config["database_enabled"],
        "database_backend": get_backend_type(),
        "api_url": _config["api_url"],
        "api_key": "***" if _config["api_key"] else None,
        "ob1_thoughts_enabled": _config["ob1_thoughts_enabled"],
    }


# ---------------------------------------------------------------------------
# Module registration for pluggable loader
# ---------------------------------------------------------------------------
def register(mcp) -> None:
    """Register logging/audit tools with the MCP server."""
    mcp.tool()(scan_history)
    mcp.tool()(get_scan_stats)
    mcp.tool()(configure_logging)
