-- Cyber-Scanner-MCP — PostgreSQL Schema for OB1 Integration
-- Creates a 'security' schema in the openbrain database.
-- Safe to re-run (idempotent).

CREATE SCHEMA IF NOT EXISTS security;

-- Scan audit log
CREATE TABLE IF NOT EXISTS security.scan_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL,
    tool_name TEXT NOT NULL,
    parameters JSONB,
    scope JSONB,
    results_summary JSONB,
    duration_seconds REAL,
    trigger_source TEXT DEFAULT 'unknown',
    status TEXT DEFAULT 'completed',
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scan_log_tool_name ON security.scan_log (tool_name);
CREATE INDEX IF NOT EXISTS idx_scan_log_timestamp ON security.scan_log (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_scan_log_status ON security.scan_log (status);

-- Detailed scan findings
CREATE TABLE IF NOT EXISTS security.scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_log_id UUID NOT NULL REFERENCES security.scan_log(id) ON DELETE CASCADE,
    detail_type TEXT,
    detail_data JSONB
);

CREATE INDEX IF NOT EXISTS idx_scan_results_log_id ON security.scan_results (scan_log_id);

-- CVE lookup cache (TTL-based)
CREATE TABLE IF NOT EXISTS security.vulnerability_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    package_name TEXT NOT NULL,
    package_version TEXT,
    ecosystem TEXT,
    cve_id TEXT,
    severity TEXT,
    summary TEXT,
    details JSONB,
    fetched_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ DEFAULT (now() + INTERVAL '24 hours')
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_cache_unique
    ON security.vulnerability_cache (package_name, package_version, ecosystem, cve_id);
CREATE INDEX IF NOT EXISTS idx_vuln_cache_lookup
    ON security.vulnerability_cache (package_name, package_version, ecosystem);

-- File integrity baselines
CREATE TABLE IF NOT EXISTS security.integrity_baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT UNIQUE NOT NULL,
    algorithm TEXT NOT NULL,
    directory TEXT NOT NULL,
    files JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Auto-update updated_at on modify
CREATE OR REPLACE FUNCTION security.update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_baselines_updated ON security.integrity_baselines;
CREATE TRIGGER trg_baselines_updated
    BEFORE UPDATE ON security.integrity_baselines
    FOR EACH ROW EXECUTE FUNCTION security.update_timestamp();

-- Scan alerts
CREATE TABLE IF NOT EXISTS security.scan_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_log_id UUID REFERENCES security.scan_log(id),
    severity TEXT CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    alert_type TEXT NOT NULL,
    message TEXT NOT NULL,
    details JSONB,
    acknowledged BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security.scan_alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_unacked ON security.scan_alerts (acknowledged) WHERE NOT acknowledged;
