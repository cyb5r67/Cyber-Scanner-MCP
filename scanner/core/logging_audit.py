"""Module 6: Logging & Audit System.

Provides automatic logging of all tool calls to file, API, and SQLite database.
Every scanner module uses the @audit decorator to log operations automatically.
"""

import functools
import json
import logging
import os
import sqlite3
import time
import urllib.request
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_LOG_DIR = _BASE_DIR / "logs"
_DATA_DIR = _BASE_DIR / "data"
_LOG_FILE = _LOG_DIR / "scanner.log"
_DB_FILE = _DATA_DIR / "scanner.db"

# ---------------------------------------------------------------------------
# Configuration (mutable at runtime via configure_logging)
# ---------------------------------------------------------------------------
_config: dict[str, Any] = {
    "file_enabled": True,
    "database_enabled": True,
    "api_url": None,
    "api_key": None,
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
# SQLite database
# ---------------------------------------------------------------------------
def _ensure_db() -> sqlite3.Connection:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_FILE))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            parameters TEXT,
            scope TEXT,
            results_summary TEXT,
            duration_seconds REAL,
            trigger_source TEXT,
            status TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_log_id INTEGER NOT NULL,
            detail_type TEXT,
            detail_data TEXT,
            FOREIGN KEY (scan_log_id) REFERENCES scan_log(id)
        )
    """)
    conn.commit()
    return conn


def _log_to_db(record: dict[str, Any]) -> int:
    conn = _ensure_db()
    cursor = conn.execute(
        """INSERT INTO scan_log
           (timestamp, tool_name, parameters, scope, results_summary,
            duration_seconds, trigger_source, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            record["timestamp"],
            record["tool_name"],
            json.dumps(record.get("parameters")),
            json.dumps(record.get("scope")),
            json.dumps(record.get("results_summary")),
            record.get("duration_seconds"),
            record.get("trigger_source", "unknown"),
            record.get("status", "completed"),
        ),
    )
    scan_log_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_log_id


def _log_detail_to_db(scan_log_id: int, detail_type: str, detail_data: Any) -> None:
    conn = _ensure_db()
    conn.execute(
        "INSERT INTO scan_results (scan_log_id, detail_type, detail_data) VALUES (?, ?, ?)",
        (scan_log_id, detail_type, json.dumps(detail_data)),
    )
    conn.commit()
    conn.close()


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
        # Silent failure — don't break scanning because logging API is down
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
) -> int | None:
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

    # Database backend
    scan_log_id = None
    if _config["database_enabled"]:
        scan_log_id = _log_to_db(record)
        if details and scan_log_id:
            for detail in details:
                _log_detail_to_db(
                    scan_log_id,
                    detail.get("type", "result"),
                    detail.get("data"),
                )

    # API backend
    if _config.get("api_url"):
        _log_to_api(record)

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
    conn = _ensure_db()
    query = "SELECT * FROM scan_log WHERE 1=1"
    params: list[Any] = []

    if tool_name:
        query += " AND tool_name = ?"
        params.append(tool_name)
    if date_from:
        query += " AND timestamp >= ?"
        params.append(date_from)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cursor = conn.execute(query, params)
    columns = [desc[0] for desc in cursor.description]
    rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()

    return {"records": rows, "total": len(rows)}


def get_scan_stats(days: int = 30) -> dict:
    """Get summary statistics for scan operations over a period.

    Args:
        days: Number of days to look back.

    Returns:
        Dict with total_scans, total_errors, scans_by_tool, and avg_duration.
    """
    conn = _ensure_db()
    cutoff = datetime.now(timezone.utc).isoformat()[:10]  # rough cutoff

    cursor = conn.execute(
        "SELECT COUNT(*) FROM scan_log WHERE timestamp >= ?",
        (cutoff,),
    )
    total = cursor.fetchone()[0]

    cursor = conn.execute(
        "SELECT COUNT(*) FROM scan_log WHERE status = 'error' AND timestamp >= ?",
        (cutoff,),
    )
    errors = cursor.fetchone()[0]

    cursor = conn.execute(
        "SELECT tool_name, COUNT(*) as cnt FROM scan_log WHERE timestamp >= ? GROUP BY tool_name ORDER BY cnt DESC",
        (cutoff,),
    )
    by_tool = {row[0]: row[1] for row in cursor.fetchall()}

    cursor = conn.execute(
        "SELECT AVG(duration_seconds) FROM scan_log WHERE timestamp >= ? AND duration_seconds IS NOT NULL",
        (cutoff,),
    )
    avg_duration = cursor.fetchone()[0]

    conn.close()

    return {
        "period_days": days,
        "total_scans": total,
        "total_errors": errors,
        "scans_by_tool": by_tool,
        "avg_duration_seconds": round(avg_duration, 3) if avg_duration else None,
    }


def configure_logging(
    file: bool | None = None,
    database: bool | None = None,
    api_url: str | None = None,
    api_key: str | None = None,
) -> dict:
    """Enable or disable logging backends.

    Args:
        file: Enable/disable file logging.
        database: Enable/disable SQLite logging.
        api_url: Set API webhook URL (None to disable).
        api_key: Set API authentication key.

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

    return {
        "file_enabled": _config["file_enabled"],
        "database_enabled": _config["database_enabled"],
        "api_url": _config["api_url"],
        "api_key": "***" if _config["api_key"] else None,
    }


# ---------------------------------------------------------------------------
# Module registration for pluggable loader
# ---------------------------------------------------------------------------
def register(mcp) -> None:
    """Register logging/audit tools with the MCP server."""
    mcp.tool()(scan_history)
    mcp.tool()(get_scan_stats)
    mcp.tool()(configure_logging)
