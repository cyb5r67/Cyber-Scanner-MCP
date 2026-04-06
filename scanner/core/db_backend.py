"""Database abstraction layer with PostgreSQL and SQLite backends.

Automatically selects PostgreSQL (OB1 integration) if OB1_DATABASE_URL is set
and the connection succeeds. Falls back to SQLite otherwise.
"""

import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_DATA_DIR = _BASE_DIR / "data"
_DB_FILE = _DATA_DIR / "scanner.db"
_BASELINES_DIR = _DATA_DIR / "baselines"


# ---------------------------------------------------------------------------
# Protocol — interface both backends implement
# ---------------------------------------------------------------------------
class DatabaseBackend(Protocol):
    def log_scan(self, record: dict[str, Any]) -> str | int: ...
    def log_detail(self, scan_log_id: str | int, detail_type: str, detail_data: Any) -> None: ...
    def query_scan_history(self, limit: int, tool_name: str | None, date_from: str | None) -> list[dict]: ...
    def get_scan_stats(self, days: int) -> dict: ...
    def save_baseline(self, name: str, data: dict) -> None: ...
    def load_baseline(self, name: str) -> dict | None: ...
    def list_baselines(self) -> list[str]: ...
    def cache_vulnerability(self, package_name: str, version: str, ecosystem: str, cve_data: list[dict]) -> None: ...
    def get_cached_vulnerability(self, package_name: str, version: str, ecosystem: str) -> list[dict] | None: ...
    def create_alert(self, scan_log_id: str | int | None, severity: str, alert_type: str, message: str, details: dict | None) -> None: ...


# ---------------------------------------------------------------------------
# PostgreSQL Backend
# ---------------------------------------------------------------------------
class PostgresBackend:
    """Stores data in OB1's PostgreSQL database under the security schema."""

    def __init__(self, dsn: str, pool_min: int = 2, pool_max: int = 10):
        import psycopg2
        import psycopg2.pool
        import psycopg2.extras

        self._pool = psycopg2.pool.ThreadedConnectionPool(pool_min, pool_max, dsn)
        psycopg2.extras.register_uuid()

    def _conn(self):
        return self._pool.getconn()

    def _put(self, conn):
        self._pool.putconn(conn)

    def log_scan(self, record: dict[str, Any]) -> str:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute(
                """INSERT INTO security.scan_log
                   (timestamp, tool_name, parameters, scope, results_summary,
                    duration_seconds, trigger_source, status)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING id""",
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
            row_id = str(cur.fetchone()[0])
            conn.commit()
            return row_id
        finally:
            self._put(conn)

    def log_detail(self, scan_log_id: str | int, detail_type: str, detail_data: Any) -> None:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO security.scan_results (scan_log_id, detail_type, detail_data) VALUES (%s, %s, %s)",
                (scan_log_id, detail_type, json.dumps(detail_data)),
            )
            conn.commit()
        finally:
            self._put(conn)

    def query_scan_history(self, limit: int, tool_name: str | None, date_from: str | None) -> list[dict]:
        conn = self._conn()
        try:
            cur = conn.cursor()
            query = "SELECT id, timestamp, tool_name, parameters, scope, results_summary, duration_seconds, trigger_source, status FROM security.scan_log WHERE 1=1"
            params: list[Any] = []
            if tool_name:
                query += " AND tool_name = %s"
                params.append(tool_name)
            if date_from:
                query += " AND timestamp >= %s"
                params.append(date_from)
            query += " ORDER BY timestamp DESC LIMIT %s"
            params.append(limit)
            cur.execute(query, params)
            columns = [desc[0] for desc in cur.description]
            rows = []
            for row in cur.fetchall():
                d = dict(zip(columns, row))
                d["id"] = str(d["id"])
                if isinstance(d.get("timestamp"), datetime):
                    d["timestamp"] = d["timestamp"].isoformat()
                rows.append(d)
            return rows
        finally:
            self._put(conn)

    def get_scan_stats(self, days: int) -> dict:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cutoff = f"now() - INTERVAL '{days} days'"

            cur.execute(f"SELECT COUNT(*) FROM security.scan_log WHERE timestamp >= {cutoff}")
            total = cur.fetchone()[0]

            cur.execute(f"SELECT COUNT(*) FROM security.scan_log WHERE status = 'error' AND timestamp >= {cutoff}")
            errors = cur.fetchone()[0]

            cur.execute(f"SELECT tool_name, COUNT(*) FROM security.scan_log WHERE timestamp >= {cutoff} GROUP BY tool_name ORDER BY COUNT(*) DESC")
            by_tool = {row[0]: row[1] for row in cur.fetchall()}

            cur.execute(f"SELECT AVG(duration_seconds) FROM security.scan_log WHERE timestamp >= {cutoff} AND duration_seconds IS NOT NULL")
            avg_dur = cur.fetchone()[0]

            return {
                "period_days": days,
                "total_scans": total,
                "total_errors": errors,
                "scans_by_tool": by_tool,
                "avg_duration_seconds": round(avg_dur, 3) if avg_dur else None,
            }
        finally:
            self._put(conn)

    def save_baseline(self, name: str, data: dict) -> None:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute(
                """INSERT INTO security.integrity_baselines (name, algorithm, directory, files)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (name) DO UPDATE
                   SET algorithm = EXCLUDED.algorithm,
                       directory = EXCLUDED.directory,
                       files = EXCLUDED.files,
                       updated_at = now()""",
                (name, data.get("algorithm", "sha256"), data.get("directory", ""), json.dumps(data.get("files", {}))),
            )
            conn.commit()
        finally:
            self._put(conn)

    def load_baseline(self, name: str) -> dict | None:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT name, algorithm, directory, files, created_at, updated_at FROM security.integrity_baselines WHERE name = %s",
                (name,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "name": row[0],
                "algorithm": row[1],
                "directory": row[2],
                "files": row[3] if isinstance(row[3], dict) else json.loads(row[3]),
                "created_at": row[4].isoformat() if isinstance(row[4], datetime) else str(row[4]),
                "updated_at": row[5].isoformat() if isinstance(row[5], datetime) else str(row[5]),
            }
        finally:
            self._put(conn)

    def list_baselines(self) -> list[str]:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT name FROM security.integrity_baselines ORDER BY name")
            return [row[0] for row in cur.fetchall()]
        finally:
            self._put(conn)

    def cache_vulnerability(self, package_name: str, version: str, ecosystem: str, cve_data: list[dict]) -> None:
        conn = self._conn()
        try:
            cur = conn.cursor()
            for cve in cve_data:
                cur.execute(
                    """INSERT INTO security.vulnerability_cache
                       (package_name, package_version, ecosystem, cve_id, severity, summary, details)
                       VALUES (%s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (package_name, package_version, ecosystem, cve_id) DO UPDATE
                       SET severity = EXCLUDED.severity,
                           summary = EXCLUDED.summary,
                           details = EXCLUDED.details,
                           fetched_at = now(),
                           expires_at = now() + INTERVAL '24 hours'""",
                    (
                        package_name, version, ecosystem,
                        cve.get("id", "unknown"),
                        cve.get("severity", "unknown"),
                        cve.get("summary", ""),
                        json.dumps(cve),
                    ),
                )
            conn.commit()
        finally:
            self._put(conn)

    def get_cached_vulnerability(self, package_name: str, version: str, ecosystem: str) -> list[dict] | None:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute(
                """SELECT cve_id, severity, summary, details FROM security.vulnerability_cache
                   WHERE package_name = %s AND package_version = %s AND ecosystem = %s
                   AND expires_at > now()""",
                (package_name, version, ecosystem),
            )
            rows = cur.fetchall()
            if not rows:
                return None
            return [
                {"id": r[0], "severity": r[1], "summary": r[2], **(json.loads(r[3]) if isinstance(r[3], str) else r[3] or {})}
                for r in rows
            ]
        finally:
            self._put(conn)

    def create_alert(self, scan_log_id, severity, alert_type, message, details=None):
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute(
                """INSERT INTO security.scan_alerts
                   (scan_log_id, severity, alert_type, message, details)
                   VALUES (%s, %s, %s, %s, %s)""",
                (scan_log_id, severity, alert_type, message, json.dumps(details) if details else None),
            )
            conn.commit()
        finally:
            self._put(conn)


# ---------------------------------------------------------------------------
# SQLite Backend (existing behavior, refactored)
# ---------------------------------------------------------------------------
class SqliteBackend:
    """Stores data in local SQLite database and JSON files."""

    def __init__(self):
        self._ensure_db()

    def _ensure_db(self) -> sqlite3.Connection:
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

    def log_scan(self, record: dict[str, Any]) -> int:
        conn = self._ensure_db()
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

    def log_detail(self, scan_log_id, detail_type, detail_data):
        conn = self._ensure_db()
        conn.execute(
            "INSERT INTO scan_results (scan_log_id, detail_type, detail_data) VALUES (?, ?, ?)",
            (scan_log_id, detail_type, json.dumps(detail_data)),
        )
        conn.commit()
        conn.close()

    def query_scan_history(self, limit, tool_name=None, date_from=None):
        conn = self._ensure_db()
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
        return rows

    def get_scan_stats(self, days):
        conn = self._ensure_db()
        cutoff = datetime.now(timezone.utc).isoformat()[:10]

        total = conn.execute("SELECT COUNT(*) FROM scan_log WHERE timestamp >= ?", (cutoff,)).fetchone()[0]
        errors = conn.execute("SELECT COUNT(*) FROM scan_log WHERE status = 'error' AND timestamp >= ?", (cutoff,)).fetchone()[0]
        by_tool = {r[0]: r[1] for r in conn.execute("SELECT tool_name, COUNT(*) FROM scan_log WHERE timestamp >= ? GROUP BY tool_name ORDER BY COUNT(*) DESC", (cutoff,)).fetchall()}
        avg_dur = conn.execute("SELECT AVG(duration_seconds) FROM scan_log WHERE timestamp >= ? AND duration_seconds IS NOT NULL", (cutoff,)).fetchone()[0]
        conn.close()

        return {
            "period_days": days,
            "total_scans": total,
            "total_errors": errors,
            "scans_by_tool": by_tool,
            "avg_duration_seconds": round(avg_dur, 3) if avg_dur else None,
        }

    def save_baseline(self, name: str, data: dict) -> None:
        _BASELINES_DIR.mkdir(parents=True, exist_ok=True)
        path = _BASELINES_DIR / f"{name}.json"
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def load_baseline(self, name: str) -> dict | None:
        path = _BASELINES_DIR / f"{name}.json"
        if not path.exists():
            return None
        with open(path) as f:
            return json.load(f)

    def list_baselines(self) -> list[str]:
        _BASELINES_DIR.mkdir(parents=True, exist_ok=True)
        return [p.stem for p in _BASELINES_DIR.glob("*.json")]

    def cache_vulnerability(self, package_name, version, ecosystem, cve_data):
        pass  # No-op for SQLite — vulnerabilities fetched fresh each time

    def get_cached_vulnerability(self, package_name, version, ecosystem):
        return None  # No cache in SQLite mode

    def create_alert(self, scan_log_id, severity, alert_type, message, details=None):
        pass  # No-op for SQLite


# ---------------------------------------------------------------------------
# Backend singleton
# ---------------------------------------------------------------------------
_backend: DatabaseBackend | None = None


def get_backend() -> DatabaseBackend:
    """Get the active database backend. Tries PostgreSQL first, falls back to SQLite."""
    global _backend
    if _backend is not None:
        return _backend

    dsn = os.environ.get("OB1_DATABASE_URL")
    if dsn:
        try:
            pool_min = int(os.environ.get("OB1_DB_POOL_MIN", "2"))
            pool_max = int(os.environ.get("OB1_DB_POOL_MAX", "10"))
            _backend = PostgresBackend(dsn, pool_min, pool_max)
            print("[scanner] Connected to OB1 PostgreSQL", file=sys.stderr)
            return _backend
        except Exception as e:
            print(f"[scanner] PostgreSQL unavailable ({e}), falling back to SQLite", file=sys.stderr)

    _backend = SqliteBackend()
    return _backend


def get_backend_type() -> str:
    """Return 'postgres' or 'sqlite' based on active backend."""
    backend = get_backend()
    return "postgres" if isinstance(backend, PostgresBackend) else "sqlite"
