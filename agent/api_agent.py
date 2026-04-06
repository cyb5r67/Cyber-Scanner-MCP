"""Integration Layer 3: Custom Claude API Agent.

A standalone security agent using the Anthropic SDK. Can run unattended,
accept natural language instructions, and chain scanner tools autonomously.

Usage:
    python -m agent.api_agent "Check TLS on example.com and report findings"
    python -m agent.api_agent --config daily_scan.json
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

try:
    import anthropic
except ImportError:
    print("Error: anthropic SDK not installed. Run: pip install anthropic", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Tool registry — maps tool names to scanner module functions
# ---------------------------------------------------------------------------
_TOOLS: dict[str, dict] = {}
_TOOL_FUNCTIONS: dict[str, Any] = {}


def _register_tools() -> None:
    """Discover available scanner modules and register their functions as tools."""
    tool_defs = [
        # File Scanner
        {
            "name": "scan_files",
            "module": "scanner.core.file_scanner",
            "description": "Scan filesystems for files containing suspicious content strings",
            "input_schema": {
                "type": "object",
                "properties": {
                    "search_terms": {"type": "array", "items": {"type": "string"}, "description": "Terms to search for"},
                    "file_pattern": {"type": "string", "description": "Filename pattern to match", "default": "package.json"},
                    "search_paths": {"type": "array", "items": {"type": "string"}, "description": "Directories to search (auto-detect if omitted)"},
                    "max_results": {"type": "integer", "description": "Maximum results to return", "default": 1000},
                },
                "required": ["search_terms"],
            },
        },
        {
            "name": "check_file",
            "module": "scanner.core.file_scanner",
            "description": "Check a single file for specific search terms",
            "input_schema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to the file"},
                    "search_terms": {"type": "array", "items": {"type": "string"}, "description": "Terms to search for"},
                },
                "required": ["file_path", "search_terms"],
            },
        },
        {
            "name": "list_drives",
            "module": "scanner.core.file_scanner",
            "description": "List all available drives and filesystems",
            "input_schema": {"type": "object", "properties": {}},
        },
        # TLS/SSL
        {
            "name": "check_tls",
            "module": "scanner.core.tls_checker",
            "description": "Check TLS certificate and connection details for a host",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Hostname to check"},
                    "port": {"type": "integer", "description": "Port number", "default": 443},
                },
                "required": ["host"],
            },
        },
        {
            "name": "check_ssl_versions",
            "module": "scanner.core.tls_checker",
            "description": "Test which SSL/TLS protocol versions a host accepts",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Hostname to check"},
                    "port": {"type": "integer", "description": "Port number", "default": 443},
                },
                "required": ["host"],
            },
        },
        {
            "name": "scan_certificates",
            "module": "scanner.core.tls_checker",
            "description": "Batch scan TLS certificates for multiple hosts",
            "input_schema": {
                "type": "object",
                "properties": {
                    "hosts": {"type": "array", "items": {"type": "string"}, "description": "List of hostnames"},
                },
                "required": ["hosts"],
            },
        },
        # Nmap
        {
            "name": "nmap_scan",
            "module": "scanner.core.nmap_scanner",
            "description": "Port scan a host or network range",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Host or network range"},
                    "ports": {"type": "string", "description": "Port range (e.g. 80,443 or 1-1000)"},
                    "scan_type": {"type": "string", "enum": ["quick", "basic", "full"], "default": "basic"},
                },
                "required": ["target"],
            },
        },
        {
            "name": "nmap_vuln_scan",
            "module": "scanner.core.nmap_scanner",
            "description": "Run vulnerability scanning scripts against a target",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Host or network range"},
                    "ports": {"type": "string", "description": "Port range"},
                },
                "required": ["target"],
            },
        },
        # Integrity
        {
            "name": "hash_file",
            "module": "scanner.core.integrity",
            "description": "Generate a hash of a single file",
            "input_schema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file"},
                    "algorithm": {"type": "string", "enum": ["sha256", "sha512", "md5"], "default": "sha256"},
                },
                "required": ["file_path"],
            },
        },
        {
            "name": "hash_directory",
            "module": "scanner.core.integrity",
            "description": "Hash all files in a directory and optionally save as baseline",
            "input_schema": {
                "type": "object",
                "properties": {
                    "directory": {"type": "string", "description": "Directory path"},
                    "pattern": {"type": "string", "default": "*"},
                    "algorithm": {"type": "string", "enum": ["sha256", "sha512", "md5"], "default": "sha256"},
                    "baseline_name": {"type": "string", "description": "Save as named baseline"},
                },
                "required": ["directory"],
            },
        },
        {
            "name": "compare_baseline",
            "module": "scanner.core.integrity",
            "description": "Compare current directory state against a saved baseline",
            "input_schema": {
                "type": "object",
                "properties": {
                    "directory": {"type": "string", "description": "Directory to compare"},
                    "baseline_name": {"type": "string", "description": "Baseline name"},
                },
                "required": ["directory", "baseline_name"],
            },
        },
        # Dependency
        {
            "name": "check_vulnerability",
            "module": "scanner.core.dependency",
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
        # SBOM
        {
            "name": "generate_sbom",
            "module": "scanner.core.sbom",
            "description": "Generate a Software Bill of Materials (SBOM) in CycloneDX or SPDX format",
            "input_schema": {
                "type": "object",
                "properties": {
                    "search_paths": {"type": "array", "items": {"type": "string"}},
                    "format": {"type": "string", "enum": ["cyclonedx", "spdx"], "default": "cyclonedx"},
                },
            },
        },
        # OSCAL
        {
            "name": "generate_oscal_assessment",
            "module": "scanner.core.oscal",
            "description": "Generate an OSCAL Assessment Results document mapping findings to security controls",
            "input_schema": {
                "type": "object",
                "properties": {
                    "scan_ids": {"type": "array", "items": {"type": "integer"}},
                    "framework": {"type": "string", "enum": ["nist-800-53", "fedramp", "nist-csf", "iso-27001"], "default": "nist-800-53"},
                },
            },
        },
        # Audit
        {
            "name": "scan_history",
            "module": "scanner.core.logging_audit",
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
    ]

    import importlib

    for tool_def in tool_defs:
        module_path = tool_def["module"]
        func_name = tool_def["name"]
        try:
            mod = importlib.import_module(module_path)
            func = getattr(mod, func_name)
            _TOOLS[func_name] = {
                "name": func_name,
                "description": tool_def["description"],
                "input_schema": tool_def["input_schema"],
            }
            _TOOL_FUNCTIONS[func_name] = func
        except (ImportError, AttributeError):
            # Module not available — skip silently
            pass


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are an autonomous cybersecurity agent. You have access to a suite of \
security scanning tools. Your responsibilities:

1. Analyze the user's security request and determine which tools to use
2. Execute scans and analyze results
3. Chain multiple tools together when needed (e.g., scan → analyze → report)
4. Provide clear, actionable findings with severity assessments
5. Suggest remediation steps for any issues found

Be thorough but efficient. Explain what you're doing and why.
Always report findings clearly with risk levels."""


def run_agent(
    instruction: str,
    model: str = "claude-sonnet-4-6",
    max_iterations: int = 20,
    system_prompt: str | None = None,
) -> str:
    """Run the security agent with a natural language instruction.

    Args:
        instruction: What to scan/check/analyze.
        model: Claude model to use.
        max_iterations: Maximum tool call rounds.
        system_prompt: Override the default system prompt.

    Returns:
        Final text response from the agent.
    """
    client = anthropic.Anthropic()
    tools = list(_TOOLS.values())

    if not tools:
        return "Error: No scanner tools available. Check module installation."

    messages = [{"role": "user", "content": instruction}]

    for iteration in range(max_iterations):
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=system_prompt or SYSTEM_PROMPT,
            tools=tools,
            messages=messages,
        )

        # Check if we're done (no more tool calls)
        if response.stop_reason == "end_turn":
            final_text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    final_text += block.text
            return final_text

        # Process tool calls
        assistant_content = response.content
        messages.append({"role": "assistant", "content": assistant_content})

        tool_results = []
        for block in assistant_content:
            if block.type == "tool_use":
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

    return "Error: Maximum iterations reached without completion."


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        prog="api-agent",
        description="Cyber-Scanner-MCP — Claude API Agent",
    )
    parser.add_argument("instruction", nargs="?", help="Natural language instruction")
    parser.add_argument("--config", help="Path to JSON config file with instruction and settings")
    parser.add_argument("--model", default="claude-sonnet-4-6", help="Claude model to use")
    parser.add_argument("--max-iterations", type=int, default=20)

    args = parser.parse_args()

    if args.config:
        with open(args.config) as f:
            config = json.load(f)
        instruction = config.get("instruction", "")
        model = config.get("model", args.model)
        max_iterations = config.get("max_iterations", args.max_iterations)
    elif args.instruction:
        instruction = args.instruction
        model = args.model
        max_iterations = args.max_iterations
    else:
        parser.print_help()
        sys.exit(1)

    _register_tools()
    print(f"Agent initialized with {len(_TOOLS)} tools.", file=sys.stderr)
    print(f"Instruction: {instruction}\n", file=sys.stderr)

    result = run_agent(instruction, model=model, max_iterations=max_iterations)
    print(result)


if __name__ == "__main__":
    main()
