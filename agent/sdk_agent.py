"""Integration Layer 4: Agent SDK Autonomous Security Agent.

A deployable, autonomous security agent using the Anthropic Agent SDK.
Can run as a long-lived service, monitor systems continuously, and
make multi-step security decisions.

Usage:
    python -m agent.sdk_agent --task "Perform a full security audit"
    python -m agent.sdk_agent --serve --port 8080
"""

import argparse
import importlib
import json
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Tool discovery — shared with api_agent
# ---------------------------------------------------------------------------
_TOOL_FUNCTIONS: dict[str, Any] = {}

_MODULE_TOOLS = {
    "scanner.core.file_scanner": [
        "scan_files", "check_file", "list_drives", "find_suspicious_files",
    ],
    "scanner.core.tls_checker": [
        "check_tls", "check_ssl_versions", "scan_certificates", "check_cert_chain",
    ],
    "scanner.core.nmap_scanner": [
        "nmap_scan", "nmap_service_detect", "nmap_vuln_scan",
    ],
    "scanner.core.integrity": [
        "hash_file", "hash_directory", "compare_baseline", "verify_integrity",
    ],
    "scanner.core.dependency": [
        "analyze_package_json", "scan_dependencies", "check_vulnerability",
    ],
    "scanner.core.sbom": [
        "generate_sbom", "export_sbom", "list_sboms",
    ],
    "scanner.core.oscal": [
        "generate_oscal_assessment", "generate_oscal_component",
        "map_to_controls", "export_oscal", "list_oscal_documents",
    ],
    "scanner.core.logging_audit": [
        "scan_history", "get_scan_stats", "configure_logging",
    ],
}


def _discover_tools() -> None:
    """Import all available scanner modules and collect their functions."""
    for module_path, func_names in _MODULE_TOOLS.items():
        try:
            mod = importlib.import_module(module_path)
            for name in func_names:
                func = getattr(mod, name, None)
                if func:
                    _TOOL_FUNCTIONS[name] = func
        except ImportError:
            pass


# ---------------------------------------------------------------------------
# Agent implementation
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """\
You are an autonomous cybersecurity agent deployed as a security monitoring service.

Your capabilities include:
- File scanning for malicious content and compromised dependencies
- TLS/SSL certificate validation and protocol testing
- Network port scanning and vulnerability detection (via Nmap)
- File integrity monitoring with baseline comparisons
- Software Bill of Materials (SBOM) generation
- OSCAL compliance report generation (NIST 800-53, FedRAMP, CSF, ISO 27001)
- Complete audit logging of all operations

Operating principles:
1. Be systematic — scan methodically, don't skip steps
2. Correlate findings — connect results across different scan types
3. Prioritize by risk — critical vulnerabilities first
4. Document everything — all actions are logged for audit
5. Suggest remediation — provide actionable next steps
6. Generate compliance artifacts when relevant (SBOM, OSCAL)

When performing a full security audit:
1. Start by listing available drives/filesystems
2. Scan for compromised dependencies
3. Check TLS certificates on known services
4. Run integrity checks if baselines exist
5. Generate an SBOM for component inventory
6. Produce an OSCAL assessment mapping findings to controls
7. Summarize all findings with risk levels and recommendations
"""


def run_task(task: str, model: str = "claude-sonnet-4-6", max_iterations: int = 30) -> str:
    """Run a single security task using the Claude API with tool use.

    This is the core agent loop. For each iteration:
    1. Send the conversation to Claude
    2. If Claude wants to use tools, execute them and feed results back
    3. Repeat until Claude provides a final answer

    Args:
        task: Natural language description of the security task.
        model: Claude model to use.
        max_iterations: Safety limit on tool call rounds.

    Returns:
        Final agent response text.
    """
    try:
        import anthropic
    except ImportError:
        return "Error: anthropic SDK not installed. Run: pip install anthropic"

    _discover_tools()

    if not _TOOL_FUNCTIONS:
        return "Error: No scanner tools available."

    # Build tool definitions from function signatures
    tools = _build_tool_schemas()

    client = anthropic.Anthropic()
    messages = [{"role": "user", "content": task}]

    print(f"[Agent] Starting task with {len(tools)} tools available", file=sys.stderr)

    for i in range(max_iterations):
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=tools,
            messages=messages,
        )

        if response.stop_reason == "end_turn":
            return "".join(
                block.text for block in response.content if hasattr(block, "text")
            )

        # Process tool calls
        messages.append({"role": "assistant", "content": response.content})
        tool_results = []

        for block in response.content:
            if block.type == "tool_use":
                print(f"[Agent] Calling {block.name}...", file=sys.stderr)
                func = _TOOL_FUNCTIONS.get(block.name)
                if func:
                    try:
                        result = func(**block.input)
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": json.dumps(result, default=str),
                        })
                    except Exception as e:
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": json.dumps({"error": str(e)}),
                            "is_error": True,
                        })
                else:
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps({"error": f"Unknown tool: {block.name}"}),
                        "is_error": True,
                    })

        messages.append({"role": "user", "content": tool_results})

    return "Error: Maximum iterations reached."


def _build_tool_schemas() -> list[dict]:
    """Build Claude API tool schemas from discovered functions."""
    schemas = {
        "scan_files": {
            "description": "Scan filesystems for files containing suspicious content",
            "input_schema": {
                "type": "object",
                "properties": {
                    "search_terms": {"type": "array", "items": {"type": "string"}, "description": "Terms to search for"},
                    "file_pattern": {"type": "string", "default": "package.json"},
                    "search_paths": {"type": "array", "items": {"type": "string"}},
                    "max_results": {"type": "integer", "default": 1000},
                },
                "required": ["search_terms"],
            },
        },
        "check_file": {
            "description": "Check a single file for specific search terms",
            "input_schema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "search_terms": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["file_path", "search_terms"],
            },
        },
        "list_drives": {
            "description": "List all available drives and filesystems",
            "input_schema": {"type": "object", "properties": {}},
        },
        "find_suspicious_files": {
            "description": "Find files with suspicious names or extensions",
            "input_schema": {
                "type": "object",
                "properties": {
                    "search_paths": {"type": "array", "items": {"type": "string"}},
                    "patterns": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["search_paths"],
            },
        },
        "check_tls": {
            "description": "Check TLS certificate and connection details for a host",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer", "default": 443},
                },
                "required": ["host"],
            },
        },
        "check_ssl_versions": {
            "description": "Test which SSL/TLS protocol versions a host accepts",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer", "default": 443},
                },
                "required": ["host"],
            },
        },
        "scan_certificates": {
            "description": "Batch scan TLS certificates for multiple hosts",
            "input_schema": {
                "type": "object",
                "properties": {
                    "hosts": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["hosts"],
            },
        },
        "check_cert_chain": {
            "description": "Validate the full certificate chain for a host",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer", "default": 443},
                },
                "required": ["host"],
            },
        },
        "nmap_scan": {
            "description": "Port scan a host or network range",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "ports": {"type": "string"},
                    "scan_type": {"type": "string", "enum": ["quick", "basic", "full"], "default": "basic"},
                },
                "required": ["target"],
            },
        },
        "nmap_service_detect": {
            "description": "Identify services and versions running on open ports",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "ports": {"type": "string"},
                },
                "required": ["target"],
            },
        },
        "nmap_vuln_scan": {
            "description": "Run NSE vulnerability scripts against a target",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "ports": {"type": "string"},
                },
                "required": ["target"],
            },
        },
        "hash_file": {
            "description": "Generate a cryptographic hash of a file",
            "input_schema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "algorithm": {"type": "string", "enum": ["sha256", "sha512", "md5"], "default": "sha256"},
                },
                "required": ["file_path"],
            },
        },
        "hash_directory": {
            "description": "Hash all files in a directory and optionally save as baseline",
            "input_schema": {
                "type": "object",
                "properties": {
                    "directory": {"type": "string"},
                    "pattern": {"type": "string", "default": "*"},
                    "algorithm": {"type": "string", "default": "sha256"},
                    "baseline_name": {"type": "string"},
                },
                "required": ["directory"],
            },
        },
        "compare_baseline": {
            "description": "Compare current directory state against a saved hash baseline",
            "input_schema": {
                "type": "object",
                "properties": {
                    "directory": {"type": "string"},
                    "baseline_name": {"type": "string"},
                },
                "required": ["directory", "baseline_name"],
            },
        },
        "verify_integrity": {
            "description": "Verify all files in a baseline still match their recorded hashes",
            "input_schema": {
                "type": "object",
                "properties": {
                    "baseline_name": {"type": "string"},
                },
                "required": ["baseline_name"],
            },
        },
        "analyze_package_json": {
            "description": "Deep inspection of a package.json for security red flags",
            "input_schema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                },
                "required": ["file_path"],
            },
        },
        "scan_dependencies": {
            "description": "Find and analyze all dependency files across directories",
            "input_schema": {
                "type": "object",
                "properties": {
                    "search_paths": {"type": "array", "items": {"type": "string"}},
                    "file_types": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
        "check_vulnerability": {
            "description": "Check a package version for known CVEs via OSV.dev",
            "input_schema": {
                "type": "object",
                "properties": {
                    "package_name": {"type": "string"},
                    "version": {"type": "string"},
                    "ecosystem": {"type": "string", "default": "npm"},
                },
                "required": ["package_name", "version"],
            },
        },
        "generate_sbom": {
            "description": "Generate a Software Bill of Materials (CycloneDX or SPDX)",
            "input_schema": {
                "type": "object",
                "properties": {
                    "search_paths": {"type": "array", "items": {"type": "string"}},
                    "format": {"type": "string", "enum": ["cyclonedx", "spdx"], "default": "cyclonedx"},
                },
            },
        },
        "generate_oscal_assessment": {
            "description": "Generate OSCAL Assessment Results mapping findings to security controls",
            "input_schema": {
                "type": "object",
                "properties": {
                    "scan_ids": {"type": "array", "items": {"type": "integer"}},
                    "framework": {"type": "string", "enum": ["nist-800-53", "fedramp", "nist-csf", "iso-27001"], "default": "nist-800-53"},
                },
            },
        },
        "scan_history": {
            "description": "Query past scan operations from the audit database",
            "input_schema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 50},
                    "tool_name": {"type": "string"},
                    "date_from": {"type": "string"},
                },
            },
        },
        "get_scan_stats": {
            "description": "Get summary statistics for scan operations",
            "input_schema": {
                "type": "object",
                "properties": {
                    "days": {"type": "integer", "default": 30},
                },
            },
        },
    }

    tools = []
    for name, func in _TOOL_FUNCTIONS.items():
        if name in schemas:
            tools.append({"name": name, **schemas[name]})

    return tools


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        prog="sdk-agent",
        description="Cyber-Scanner-MCP — Autonomous Security Agent",
    )
    parser.add_argument("--task", help="Security task to perform")
    parser.add_argument("--model", default="claude-sonnet-4-6", help="Claude model")
    parser.add_argument("--max-iterations", type=int, default=30)
    parser.add_argument("--serve", action="store_true", help="Run as HTTP service (future)")
    parser.add_argument("--port", type=int, default=8080, help="Service port")

    args = parser.parse_args()

    if args.serve:
        print("HTTP service mode is planned for a future release.", file=sys.stderr)
        print("For now, use --task to run single tasks.", file=sys.stderr)
        sys.exit(0)

    if not args.task:
        parser.print_help()
        sys.exit(1)

    result = run_task(args.task, model=args.model, max_iterations=args.max_iterations)
    print(result)


if __name__ == "__main__":
    main()
