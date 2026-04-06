# Cyber-Scanner-MCP — Module Documentation

Detailed usage guide for all 8 scanner modules. Each module can be used via the CLI, MCP server, or agent integration.

---

## Table of Contents

1. [File Scanner](#1-file-scanner)
2. [TLS/SSL Checker](#2-tlsssl-checker)
3. [Nmap Scanner](#3-nmap-scanner)
4. [File Integrity Monitor](#4-file-integrity-monitor)
5. [Dependency Checker](#5-dependency-checker)
6. [SBOM Generator](#6-sbom-generator)
7. [OSCAL Compliance](#7-oscal-compliance)
8. [Logging & Audit](#8-logging--audit)

---

## 1. File Scanner

Search files across all drives and filesystems for suspicious content strings. Originally built to detect compromised npm packages, but works with any file type and search terms.

### scan_files

Scan entire filesystems for files containing specific text. Uses multithreaded parallel scanning for performance.

**CLI:**
```bash
# Search all package.json files for compromised axios
scanner scan --terms '"axios": "0.30.4"' '"axios": "1.14.1"' --json

# Search Python files in a specific directory
scanner scan --terms "eval(" "exec(" --pattern "*.py" --paths /home/projects --json

# Limit results
scanner scan --terms "password" --pattern "*.env" --paths /home --max-results 50 --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `search_terms` | list of strings | (required) | Literal strings to search for inside each file |
| `file_pattern` | string | `"package.json"` | Filename pattern to match (supports shell globs like `*.py`) |
| `search_paths` | list of strings | auto-detect | Directories to search. If omitted, scans all detected drives |
| `max_results` | integer | `1000` | Stop after this many matches |

**Output:**
```json
{
  "scan_summary": {
    "timestamp": "2026-04-06T02:30:00+00:00",
    "search_terms": ["\"axios\": \"0.30.4\""],
    "file_pattern": "package.json",
    "search_paths": ["/"],
    "files_found": 9916,
    "files_scanned": 9916,
    "hits": 2,
    "duration_seconds": 12.5,
    "truncated": false
  },
  "matches": [
    {
      "path": "/home/project/package.json",
      "matched_terms": ["\"axios\": \"0.30.4\""],
      "size_bytes": 1234
    }
  ]
}
```

### check_file

Check a single file for specific search terms. Useful for targeted checks without a full filesystem scan.

**CLI:**
```bash
scanner check-file /path/to/package.json --terms '"axios": "0.30.4"' --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | (required) | Path to the file to inspect |
| `search_terms` | list of strings | (required) | Literal strings to search for |

**Output:**
```json
{
  "path": "/path/to/package.json",
  "matched_terms": ["\"axios\": \"0.30.4\""],
  "status": "match"
}
```

Status values: `"match"` (terms found), `"clean"` (no matches), `"error"` (file unreadable).

### list_drives

Auto-detect all available drives and filesystems on the system.

**CLI:**
```bash
scanner list-drives --json
```

**Output:**
- **Windows:** `["C:\\", "D:\\", "E:\\"]`
- **Linux:** `["/", "/home", "/mnt/data"]`
- **Docker:** `["/", "/host"]` (host filesystem mounted at `/host`)

### find_suspicious_files

Find files with suspicious names or extensions that may indicate malware or social engineering attacks.

**CLI:**
```bash
scanner find-suspicious --paths /home/downloads /tmp --json
```

**Default detection patterns:**
- Double extensions (e.g., `invoice.pdf.exe`, `report.doc.scr`)
- Hidden files with executable extensions (e.g., `.hidden.exe`)
- Executables in unexpected locations

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `search_paths` | list of strings | (required) | Directories to scan |
| `patterns` | list of dicts | built-in | Custom patterns with `regex` and `reason` fields |

---

## 2. TLS/SSL Checker

Validate TLS certificates, test protocol versions, and audit certificate chains. Uses Python's built-in `ssl` module — no external dependencies.

### check_tls

Connect to a host and report TLS version, cipher suite, and full certificate details.

**CLI:**
```bash
scanner check-tls example.com --json
scanner check-tls api.example.com --port 8443 --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | string | (required) | Hostname to connect to |
| `port` | integer | `443` | TCP port |

**Output:**
```json
{
  "host": "example.com",
  "port": 443,
  "tls_version": "TLSv1.3",
  "cipher_suite": {
    "name": "TLS_AES_256_GCM_SHA384",
    "protocol": "TLSv1.3",
    "bits": 256
  },
  "certificate": {
    "issuer": {"organizationName": "Let's Encrypt", "commonName": "R3"},
    "subject": {"commonName": "example.com"},
    "not_before": "2026-01-01T00:00:00+00:00",
    "expires": "2026-04-01T00:00:00+00:00",
    "days_remaining": 90,
    "expired": false,
    "expiring_soon": false,
    "serial_number": "ABC123...",
    "key_size": 2048,
    "weak_key": false,
    "warnings": []
  },
  "status": "ok"
}
```

**Status values:**
- `"ok"` — Certificate valid, no issues
- `"warning"` — Minor issues (expiring soon, weak key)
- `"error"` — Connection failed or certificate invalid

**Warning thresholds:**
- Expiring soon: fewer than 30 days remaining
- Weak key: RSA key smaller than 2048 bits (note: 256-bit ECDSA keys are flagged but are actually secure)

### check_ssl_versions

Test which SSL/TLS protocol versions a host accepts. Critical for identifying servers that still support deprecated protocols.

**CLI:**
```bash
scanner check-ssl-versions example.com --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | string | (required) | Hostname to test |
| `port` | integer | `443` | TCP port |

**Output:**
```json
{
  "host": "example.com",
  "port": 443,
  "protocols": {
    "SSLv3": "rejected",
    "TLSv1.0": "rejected",
    "TLSv1.1": "rejected",
    "TLSv1.2": "accepted",
    "TLSv1.3": "accepted"
  },
  "accepted": ["TLSv1.2", "TLSv1.3"],
  "status": "pass"
}
```

**Status values:**
- `"pass"` — Only TLS 1.2 and/or TLS 1.3 accepted
- `"warn"` — TLS 1.1 accepted (deprecated)
- `"fail"` — SSLv3 or TLS 1.0 accepted (insecure)

### scan_certificates

Batch scan certificates for multiple hosts at once. Produces a summary with counts of expired, expiring, and weak certificates.

**CLI:**
```bash
scanner scan-certs example.com api.example.com mail.example.com:587 --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hosts` | list of strings | (required) | Hostnames to scan (supports `host:port` format) |

**Output includes a summary:**
```json
{
  "summary": {
    "total": 3,
    "expired": 0,
    "expiring_soon": 1,
    "weak_key": 0,
    "errors": 0
  }
}
```

### check_cert_chain

Validate the full certificate chain from leaf to root. Detects issues like self-signed certificates, expired intermediates, and missing chain links.

**CLI:**
```bash
scanner check-cert-chain example.com --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | string | (required) | Hostname to connect to |
| `port` | integer | `443` | TCP port |

**Output:**
```json
{
  "chain": [
    {"position": "leaf", "subject": "example.com", "issuer": "R3", ...},
    {"position": "intermediate", "subject": "R3", "issuer": "ISRG Root X1", ...}
  ],
  "chain_length": 2,
  "issues": [],
  "valid": true
}
```

---

## 3. Nmap Scanner

Port scanning, service detection, and vulnerability scanning using Nmap. Requires `nmap` to be installed on the system (included in the Docker image).

**Important:** Input is validated to prevent command injection — only alphanumeric characters, dots, hyphens, colons, and slashes are allowed in target strings.

### nmap_scan

Port scan a host or network range.

**CLI:**
```bash
# Quick scan (top 100 ports)
scanner nmap 192.168.1.1 --type quick --json

# Basic scan (top 1000 ports, default)
scanner nmap 192.168.1.0/24 --json

# Full scan (all 65535 ports)
scanner nmap 10.0.0.1 --type full --json

# Specific ports
scanner nmap example.com --ports 22,80,443,8080 --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | string | (required) | Host, IP, or CIDR range (e.g., `192.168.1.0/24`) |
| `ports` | string | auto | Port specification (e.g., `"22,80,443"` or `"1-1024"`) |
| `scan_type` | string | `"basic"` | `"quick"` (top 100), `"basic"` (top 1000), `"full"` (all 65535) |

**Output:**
```json
{
  "target": "192.168.1.1",
  "scan_type": "basic",
  "open_ports": [
    {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
    {"port": 443, "protocol": "tcp", "state": "open", "service": "https"}
  ],
  "total_open": 3,
  "scan_time": 4.2
}
```

### nmap_service_detect

Identify services and their versions running on open ports. Uses Nmap's `-sV` flag.

**CLI:**
```bash
scanner nmap-services 192.168.1.1 --ports 22,80,443 --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | string | (required) | Host or IP to scan |
| `ports` | string | auto | Port specification |

**Output:**
```json
{
  "target": "192.168.1.1",
  "services": [
    {
      "port": 22,
      "protocol": "tcp",
      "service": "ssh",
      "version": "8.9p1",
      "product": "OpenSSH",
      "extra_info": "Ubuntu Linux"
    }
  ]
}
```

### nmap_vuln_scan

Run Nmap's NSE vulnerability scripts against a target. Identifies known vulnerabilities in running services.

**CLI:**
```bash
scanner nmap-vuln 192.168.1.1 --ports 80,443 --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | string | (required) | Host or IP to scan |
| `ports` | string | auto | Port specification |

**Output:**
```json
{
  "target": "192.168.1.1",
  "vulnerabilities": [
    {
      "port": 443,
      "script_id": "ssl-heartbleed",
      "output": "VULNERABLE: The Heartbleed Bug...",
      "severity_estimate": "critical"
    }
  ]
}
```

**Severity levels:** `"critical"`, `"high"`, `"medium"`, `"low"`, `"info"` (estimated from script output keywords).

---

## 4. File Integrity Monitor

Monitor files for unauthorized changes using cryptographic hashes. Create baselines of known-good states and compare against them later.

### hash_file

Generate a cryptographic hash of a single file.

**CLI:**
```bash
scanner hash-file /etc/passwd --json
scanner hash-file /path/to/binary --algorithm sha512 --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | (required) | Path to the file |
| `algorithm` | string | `"sha256"` | Hash algorithm: `sha256`, `sha512`, or `md5` |

**Output:**
```json
{
  "path": "/etc/passwd",
  "algorithm": "sha256",
  "hash": "a1b2c3d4e5f6...",
  "size_bytes": 2847
}
```

### hash_directory

Hash all files in a directory and optionally save as a named baseline for future comparison.

**CLI:**
```bash
# Hash and display
scanner hash-dir /etc/nginx --json

# Hash and save as baseline
scanner hash-dir /etc/nginx --save-baseline nginx-config --json

# Hash only Python files
scanner hash-dir /home/project --pattern "*.py" --save-baseline project-py --json

# Use SHA-512
scanner hash-dir /usr/bin --algorithm sha512 --save-baseline system-bins --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `directory` | string | (required) | Directory to hash |
| `pattern` | string | `"*"` | Glob pattern for file matching (recursive) |
| `algorithm` | string | `"sha256"` | Hash algorithm: `sha256`, `sha512`, `md5` |
| `save_baseline` | string | none | Save results as a named baseline |

**Output:**
```json
{
  "directory": "/etc/nginx",
  "file_count": 12,
  "algorithm": "sha256",
  "baseline_name": "nginx-config",
  "files": [
    {"path": "/etc/nginx/nginx.conf", "relative_path": "nginx.conf", "hash": "abc123...", "size_bytes": 2048}
  ]
}
```

**Storage:** Baselines are saved to PostgreSQL (if OB1 is connected) and as JSON files in `data/baselines/`.

### compare_baseline

Compare the current state of a directory against a saved baseline. Identifies added, removed, and modified files.

**CLI:**
```bash
scanner compare-baseline /etc/nginx nginx-config --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `directory` | string | (required) | Directory to compare |
| `baseline_name` | string | (required) | Name of the saved baseline |

**Output:**
```json
{
  "baseline_name": "nginx-config",
  "directory": "/etc/nginx",
  "algorithm": "sha256",
  "added": ["sites-enabled/new-site.conf"],
  "removed": [],
  "modified": [
    {
      "path": "nginx.conf",
      "old_hash": "abc123...",
      "new_hash": "def456..."
    }
  ],
  "unchanged_count": 10
}
```

### verify_integrity

Verify that all files in a baseline still match their recorded hashes, without needing to specify the directory.

**CLI:**
```bash
scanner verify-integrity nginx-config --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `baseline_name` | string | (required) | Name of the baseline to verify |

**Output:**
```json
{
  "baseline_name": "nginx-config",
  "directory": "/etc/nginx",
  "algorithm": "sha256",
  "total": 12,
  "passed": 11,
  "failed": [
    {"path": "nginx.conf", "expected": "abc123...", "actual": "def456..."}
  ],
  "missing": []
}
```

---

## 5. Dependency Checker

Analyze package dependency files and check for known vulnerabilities using the OSV.dev database.

### analyze_package_json

Deep inspection of a single `package.json` file for security red flags.

**CLI:**
```bash
scanner analyze-package /path/to/package.json --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | (required) | Path to the package.json file |

**What it checks:**
- All dependency groups (dependencies, devDependencies, peerDependencies)
- Suspicious install scripts (preinstall, postinstall, install)
- Unusual registry configurations
- Malformed scoped package names

**Output:**
```json
{
  "path": "/project/package.json",
  "dependencies": {
    "dependencies": {"axios": "^1.6.0", "express": "^4.18.0"},
    "devDependencies": {"jest": "^29.0.0"}
  },
  "warnings": [
    "Suspicious postinstall script detected: node scripts/install.js..."
  ],
  "scripts": {"postinstall": "node scripts/install.js"},
  "total_dependency_count": 3
}
```

### scan_dependencies

Find and parse all dependency files across the filesystem. Supports multiple package ecosystems.

**CLI:**
```bash
# Scan everything
scanner scan-deps --json

# Scan specific directories
scanner scan-deps --paths /home/projects /opt/apps --json

# Scan only specific file types
scanner scan-deps --file-types package.json requirements.txt --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `search_paths` | list of strings | auto-detect | Directories to search |
| `file_types` | list of strings | all supported | File types to look for |

**Supported dependency files:**

| File | Ecosystem | Parsing |
|------|-----------|---------|
| `package.json` | npm | JSON parsing |
| `requirements.txt` | PyPI | Line-by-line with version specifiers |
| `Gemfile` | RubyGems | Regex extraction |
| `pom.xml` | Maven | XML/regex extraction |
| `go.mod` | Go | Regex extraction |

**Output:**
```json
{
  "files_found": 15,
  "total_packages": 234,
  "packages": [
    {"name": "axios", "version": "1.6.0", "ecosystem": "npm", "source_file": "/project/package.json"},
    {"name": "flask", "version": "3.0.0", "ecosystem": "PyPI", "source_file": "/api/requirements.txt"}
  ]
}
```

**Performance:** Automatically skips `node_modules`, `.git`, `__pycache__`, `.venv`, `vendor`, `dist`, and `build` directories.

### check_vulnerability

Check a specific package version for known CVEs using the OSV.dev API.

**CLI:**
```bash
scanner check-vuln axios 0.21.1 --json
scanner check-vuln lodash 4.17.15 --ecosystem npm --json
scanner check-vuln flask 2.0.0 --ecosystem PyPI --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `package_name` | string | (required) | Package name (e.g., `lodash`) |
| `version` | string | (required) | Exact version string (e.g., `4.17.15`) |
| `ecosystem` | string | `"npm"` | Package ecosystem: `npm`, `PyPI`, `RubyGems`, `Maven`, `Go`, etc. |

**Output:**
```json
{
  "package": "axios",
  "version": "0.21.1",
  "ecosystem": "npm",
  "vulnerable": true,
  "source": "osv.dev",
  "vulnerabilities": [
    {
      "id": "GHSA-42xw-2xvc-qx8m",
      "summary": "Axios Cross-Site Request Forgery Vulnerability",
      "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
      "references": ["https://github.com/advisories/GHSA-42xw-2xvc-qx8m"]
    }
  ]
}
```

**Caching:** Results are cached in PostgreSQL (when OB1 is connected) with a 24-hour TTL to reduce API calls. The `source` field shows `"cache"` or `"osv.dev"`.

---

## 6. SBOM Generator

Generate Software Bill of Materials documents in industry-standard formats.

### generate_sbom

Discover all dependency files and produce an SBOM document.

**CLI:**
```bash
# CycloneDX format (default)
scanner generate-sbom --paths /home/projects --json

# SPDX format
scanner generate-sbom --paths /home/projects --format spdx --json

# Specific file types only
scanner generate-sbom --paths /opt/app --file-types package.json requirements.txt --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `search_paths` | list of strings | current directory | Directories to scan |
| `format` | string | `"cyclonedx"` | Output format: `"cyclonedx"` or `"spdx"` |
| `file_types` | list of strings | all supported | Dependency file types to parse |

**Supported formats:**

| Format | Spec Version | Standard |
|--------|-------------|----------|
| CycloneDX | 1.5 | OWASP — includes Package URLs (purl) |
| SPDX | 2.3 | Linux Foundation — includes SPDX IDs |

**Output:**
```json
{
  "sbom_id": "20260406T023000Z_a1b2c3d4",
  "format": "cyclonedx",
  "component_count": 234,
  "file_path": "/app/data/sboms/20260406T023000Z_a1b2c3d4_cyclonedx.json",
  "timestamp": "2026-04-06T02:30:00+00:00"
}
```

**Generated CycloneDX document structure:**
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "metadata": {"timestamp": "...", "tools": [...]},
  "components": [
    {"type": "library", "name": "axios", "version": "1.6.0", "purl": "pkg:npm/axios@1.6.0"}
  ]
}
```

### export_sbom

Convert an existing SBOM to a different format.

**CLI:**
```bash
scanner export-sbom 20260406T023000Z_a1b2c3d4 --format spdx --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sbom_id` | string | (required) | ID of the SBOM to export |
| `format` | string | `"cyclonedx"` | Target format: `"cyclonedx"` or `"spdx"` |

### list_sboms

List all previously generated SBOMs.

**CLI:**
```bash
scanner list-sboms --json
```

**Output:**
```json
{
  "sboms": [
    {
      "id": "20260406T023000Z_a1b2c3d4",
      "format": "cyclonedx",
      "component_count": 234,
      "timestamp": "2026-04-06T02:30:00+00:00",
      "file_path": "/app/data/sboms/20260406T023000Z_a1b2c3d4_cyclonedx.json"
    }
  ]
}
```

---

## 7. OSCAL Compliance

Generate OSCAL (Open Security Controls Assessment Language) documents that map scan findings to security framework controls. Outputs are importable into GRC tools like Lula, Trestle, and OSCAL Viewer.

### generate_oscal_assessment

Generate an OSCAL Assessment Results document from scan history, mapping findings to security controls.

**CLI:**
```bash
# Use default framework (NIST 800-53) and recent scans
scanner generate-oscal-assessment --json

# Specify framework
scanner generate-oscal-assessment --framework fedramp --json
scanner generate-oscal-assessment --framework nist-csf --json
scanner generate-oscal-assessment --framework iso-27001 --json

# Use specific scan IDs
scanner generate-oscal-assessment --scan-ids 1 2 3 --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_ids` | list of integers | last 100 scans | Specific scan log IDs to include |
| `framework` | string | `"nist-800-53"` | Compliance framework for control mapping |

**Supported frameworks:**

| Framework | Description | Example Controls |
|-----------|-------------|-----------------|
| `nist-800-53` | Federal information systems | SI-3, SC-8, SC-7, RA-5 |
| `fedramp` | Cloud service providers (uses NIST 800-53) | Same as above |
| `nist-csf` | Cybersecurity Framework | DE.CM-4, PR.DS-2, ID.AM-1 |
| `iso-27001` | International information security | A.12.2.1, A.14.1.2, A.8.1.1 |

**Control mappings from scan findings:**

| Finding Type | NIST 800-53 | NIST CSF | ISO 27001 |
|-------------|-------------|----------|-----------|
| Malicious code | SI-3 | DE.CM-4 | A.12.2.1 |
| Weak TLS | SC-8 | PR.DS-2 | A.14.1.2 |
| Open ports | SC-7 | PR.AC-5 | A.13.1.1 |
| Integrity violation | SI-7 | PR.DS-6 | A.14.1.3 |
| Component inventory | CM-8 | ID.AM-1 | A.8.1.1 |
| Known vulnerability | RA-5 | ID.RA-1 | A.12.6.1 |
| Audit logging | AU-2 | DE.AE-3 | A.12.4.1 |

**Output:**
```json
{
  "document_id": "a1b2c3d4-...",
  "framework": "nist-800-53",
  "findings_count": 5,
  "controls_mapped": 3,
  "file_path": "/app/data/oscal/a1b2c3d4-....json"
}
```

### generate_oscal_component

Convert a generated SBOM into an OSCAL Component Definition document.

**CLI:**
```bash
scanner generate-oscal-component 20260406T023000Z_a1b2c3d4 --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sbom_id` | string | (required) | ID of the SBOM to convert |

### map_to_controls

Map finding types to security controls for a given framework. Useful for understanding what controls are affected.

**CLI:**
```bash
scanner map-controls malicious_code weak_tls open_ports --json
scanner map-controls known_vulnerability --framework iso-27001 --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `finding_types` | list of strings | (required) | Finding type identifiers |
| `framework` | string | `"nist-800-53"` | Compliance framework |

**Valid finding types:** `malicious_code`, `weak_tls`, `open_ports`, `integrity_violation`, `component_inventory`, `known_vulnerability`, `audit_logging`

### export_oscal

Export an OSCAL document in JSON or XML format.

**CLI:**
```bash
scanner export-oscal a1b2c3d4-... --format xml --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `document_id` | string | (required) | UUID of the OSCAL document |
| `format` | string | `"json"` | Output format: `"json"` or `"xml"` |

### list_oscal_documents

List all generated OSCAL documents.

**CLI:**
```bash
scanner list-oscal --json
```

---

## 8. Logging & Audit

Every tool call across all modules is automatically logged. The audit system supports four backends that can run simultaneously.

### Backends

| Backend | Storage | Purpose |
|---------|---------|---------|
| **File** | `logs/scanner.log` | JSON Lines format, auto-rotating (10 MB, 5 backups) |
| **SQLite** | `data/scanner.db` | Local database (fallback when OB1 unavailable) |
| **PostgreSQL** | OB1's `security.scan_log` | Persistent storage with JSONB queries |
| **API** | Webhook URL | POST results to external systems |
| **OB1 Thoughts** | OB1's `thoughts` table | Semantic search over security history |

### What gets logged

Every tool execution records:
- **Timestamp** (UTC ISO-8601)
- **Tool name** and input parameters
- **Duration** (seconds)
- **Status** (`completed` or `error`)
- **Results summary** (key metrics from the output)
- **Trigger source** (`mcp`, `cli`, `api_agent`, `sdk_agent`)

### scan_history

Query past scan operations from the audit database.

**CLI:**
```bash
# Last 50 scans
scanner history --json

# Last 10 scans
scanner history --limit 10 --json

# Filter by tool
scanner history --tool check_tls --json

# Filter by date
scanner history --date-from 2026-04-01 --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | `50` | Maximum records to return |
| `tool_name` | string | all | Filter by tool name |
| `date_from` | string | all | ISO date to filter from |

### get_scan_stats

Get summary statistics for scan operations.

**CLI:**
```bash
scanner stats --json
scanner stats --days 7 --json
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | integer | `30` | Number of days to look back |

**Output:**
```json
{
  "period_days": 30,
  "total_scans": 156,
  "total_errors": 3,
  "scans_by_tool": {
    "check_tls": 45,
    "scan_files": 32,
    "hash_file": 28
  },
  "avg_duration_seconds": 1.234
}
```

### configure_logging

Enable or disable logging backends at runtime.

**CLI (via MCP only):**

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file` | boolean | `true` | Enable/disable file logging |
| `database` | boolean | `true` | Enable/disable database logging |
| `api_url` | string | none | Webhook URL for API logging |
| `api_key` | string | none | Bearer token for API authentication |
| `ob1_thoughts` | boolean | `true` | Enable/disable OB1 thought capture |

**Output shows current configuration:**
```json
{
  "file_enabled": true,
  "database_enabled": true,
  "database_backend": "postgres",
  "api_url": null,
  "api_key": null,
  "ob1_thoughts_enabled": true
}
```
