# Cybersecurity Scanner

A pluggable cybersecurity toolkit with 8 scanner modules, a CLI, an MCP server for AI agent integration, and autonomous agent capabilities. Search for compromised files, check TLS certificates, scan for vulnerabilities, monitor file integrity, generate SBOMs, and produce OSCAL compliance reports.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Integration Layers                        │
│                                                             │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐  │
│  │  CLI    │  │MCP Server│  │API Agent │  │  SDK Agent  │  │
│  │         │  │(Claude   │  │(Anthropic│  │(Autonomous  │  │
│  │         │  │Code/     │  │  SDK)    │  │  Service)   │  │
│  │         │  │Desktop)  │  │          │  │             │  │
│  └────┬────┘  └────┬─────┘  └────┬─────┘  └──────┬──────┘  │
│       └─────────┬──┴─────────────┴───────────────┘          │
└─────────────────┼───────────────────────────────────────────┘
                  v
┌─────────────────────────────────────────────────────────────┐
│                   Pluggable Modules                         │
│                                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │   File   │ │   TLS/   │ │  Nmap    │ │  File    │       │
│  │ Scanner  │ │   SSL    │ │ Scanner  │ │Integrity │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                    │
│  │Dependency│ │   SBOM   │ │  OSCAL   │                    │
│  │ Checker  │ │Generator │ │Compliance│                    │
│  └──────────┘ └──────────┘ └──────────┘                    │
└─────────────────────────────────────────────────────────────┘
                  v
┌─────────────────────────────────────────────────────────────┐
│              Logging & Audit (File / API / SQLite)           │
└─────────────────────────────────────────────────────────────┘
```

## Modules

| Module | Description | External Deps |
|--------|-------------|---------------|
| **File Scanner** | Search files across all drives for suspicious content | None |
| **TLS/SSL Checker** | Certificate validation, protocol version testing | None |
| **Nmap Scanner** | Port scanning, service detection, vulnerability scripts | `nmap`, `python-nmap` |
| **File Integrity** | SHA-256 baselines, change detection | None |
| **Dependency Checker** | Package analysis, CVE lookup via OSV.dev | None |
| **SBOM Generator** | CycloneDX and SPDX bill of materials | None |
| **OSCAL Compliance** | NIST 800-53, FedRAMP, CSF, ISO 27001 mappings | None |
| **Logging/Audit** | All operations logged to file, API, and SQLite | None |

Modules are pluggable — add or remove any module and the server adapts automatically.

## Quick Start

### Standalone Scripts (no dependencies)

```powershell
# Windows
.\find_lib.ps1

# Linux/macOS
chmod +x find_lib.sh && ./find_lib.sh
```

### Python CLI

```bash
pip install -e .

# Scan files
scanner scan --terms '"axios": "0.30.4"' --paths /home --json

# Check TLS
scanner check-tls example.com --json

# Hash a directory and save baseline
scanner hash-dir /etc/nginx --save-baseline nginx-config

# Compare against baseline
scanner compare-baseline /etc/nginx nginx-config

# Check for vulnerabilities
scanner check-vuln axios 0.30.4 --ecosystem npm

# Generate SBOM
scanner generate-sbom --paths /home/projects --format cyclonedx

# Generate OSCAL assessment
scanner generate-oscal-assessment --framework nist-800-53

# Nmap scan
scanner nmap 192.168.1.1 --type basic

# View audit history
scanner history --limit 20
```

### MCP Server (Claude Code / Desktop)

```bash
# Project-scoped (auto-discovered via .mcp.json)
cd /path/to/cybersecurity-scanner

# Or register globally
claude mcp add cybersecurity-scanner -- python -m scanner.server
```

Once configured, Claude can use all scanner tools natively in conversation.

### API Agent (Scheduled/Scripted)

```bash
export ANTHROPIC_API_KEY=your-key

# Interactive
python -m agent.api_agent "Check TLS on my production servers and report findings"

# From config file
python -m agent.api_agent --config daily_scan.json
```

### Autonomous Agent

```bash
python -m agent.sdk_agent --task "Perform a full security audit of /home/projects"
```

## Integration Layers

| Layer | Use Case | Requires | Autonomy |
|-------|----------|----------|----------|
| CLI | Manual scanning | Python 3.10+ | Manual |
| MCP Server | Interactive AI chat | Claude Code/Desktop + `fastmcp` | Human-in-the-loop |
| API Agent | Scheduled/scripted | Anthropic API key | Semi-autonomous |
| SDK Agent | Continuous monitoring | Anthropic API key | Fully autonomous |

## Configuration

### Search Terms (standalone scripts)

Edit at the top of `find_lib.ps1` or `find_lib.sh`:

```powershell
$SearchStrings = @(
    '"axios": "0.30.4"'
    '"axios": "1.14.1"'
)
```

### Logging

All operations are automatically logged to:
- **File**: `logs/scanner.log` (JSON Lines, auto-rotating)
- **Database**: `data/scanner.db` (SQLite, queryable via CLI)
- **API**: Optional webhook (configure via `scanner stats` or `configure_logging` tool)

### OSCAL Frameworks

Supported control mappings:
- NIST 800-53 (default)
- FedRAMP
- NIST Cybersecurity Framework (CSF)
- ISO 27001

## Requirements

- **Python 3.10+** (for CLI, MCP server, and agents)
- **Nmap** (optional, for Module 4 only)
- **Anthropic API key** (optional, for API/SDK agents only)
- **PowerShell 5.1+** or **Bash 4+** (for standalone scripts)

Install Python dependencies:

```bash
pip install -e .
```

## Project Structure

```
├── find_lib.ps1              # Standalone Windows scanner
├── find_lib.sh               # Standalone Linux/macOS scanner
├── scanner/
│   ├── server.py             # FastMCP server (pluggable module loader)
│   ├── cli.py                # CLI interface
│   └── core/
│       ├── file_scanner.py   # File content scanning
│       ├── tls_checker.py    # TLS/SSL certificate checks
│       ├── nmap_scanner.py   # Nmap port/vuln scanning
│       ├── integrity.py      # File hash integrity monitoring
│       ├── dependency.py     # Dependency analysis + CVE lookup
│       ├── sbom.py           # SBOM generation (CycloneDX/SPDX)
│       ├── oscal.py          # OSCAL compliance reporting
│       └── logging_audit.py  # Audit logging system
├── agent/
│   ├── api_agent.py          # Claude API agent
│   └── sdk_agent.py          # Autonomous agent
├── data/                     # Baselines, SBOMs, OSCAL docs, SQLite DB
├── logs/                     # Audit log files
├── pyproject.toml
└── .mcp.json                 # MCP server registration
```

## Version History

| Date | Commit | Description |
|---|---|---|
| 2026-04-05 20:33:26 | `6326bfb2` | Add commit UID to README for version tracking |
| 2026-04-05 20:30:38 | `5508f43d` | Update README with multi-term search description and process diagram |
| 2026-04-05 20:15:07 | `efec3862` | Initial commit: package.json scanner for compromised npm dependencies |

## License

MIT
