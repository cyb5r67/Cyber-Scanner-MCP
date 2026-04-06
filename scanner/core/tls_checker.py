"""Module 3: TLS/SSL Checker.

Checks TLS certificates and SSL/TLS protocol versions for remote hosts.
Uses only Python's built-in ssl and socket modules.
"""

import hashlib
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any

from scanner.core.logging_audit import audit

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_DEFAULT_TIMEOUT = 10  # seconds
_EXPIRY_SOON_DAYS = 30
_WEAK_KEY_THRESHOLD = 2048

# Map of protocol names to ssl attributes (some may not exist on all builds).
_PROTOCOL_MAP: list[tuple[str, str]] = [
    ("SSLv3", "PROTOCOL_SSLv3"),
    ("TLSv1.0", "PROTOCOL_TLSv1"),
    ("TLSv1.1", "PROTOCOL_TLSv1_1"),
    ("TLSv1.2", "PROTOCOL_TLSv1_2"),
]

# TLS 1.3 is tested differently (via default context with max/min version).
_DEPRECATED_PROTOCOLS = {"SSLv3", "TLSv1.0"}
_WARN_PROTOCOLS = {"TLSv1.1"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _parse_cert_time(cert_time_str: str) -> datetime:
    """Parse an OpenSSL-style time string into a timezone-aware datetime.

    Args:
        cert_time_str: Date string like 'Sep  3 00:00:00 2025 GMT'.

    Returns:
        A timezone-aware datetime in UTC.
    """
    return datetime.strptime(cert_time_str, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc,
    )


def _dn_to_dict(dn_tuple: tuple) -> dict[str, str]:
    """Convert an ssl distinguished-name tuple to a flat dict.

    Args:
        dn_tuple: Nested tuple from ssl.getpeercert() subject/issuer fields.

    Returns:
        Flat dict mapping short names (e.g. 'CN', 'O') to values.
    """
    result: dict[str, str] = {}
    for rdn in dn_tuple:
        for attr_name, attr_value in rdn:
            result[attr_name] = attr_value
    return result


def _parse_host_port(host_str: str, default_port: int = 443) -> tuple[str, int]:
    """Split a 'host' or 'host:port' string.

    Args:
        host_str: Hostname or hostname:port string.
        default_port: Port to use when not specified.

    Returns:
        Tuple of (host, port).
    """
    if ":" in host_str:
        parts = host_str.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except ValueError:
            pass
    return host_str, default_port


def _get_key_size(cert_dict: dict) -> int | None:
    """Extract key bit-length from a peercert dict if available.

    The ssl module does not expose key size directly via getpeercert().
    We retrieve it from the binary DER form via getpeercert(binary_form=True)
    using a helper, but since that requires the live connection we accept
    it as an optional parameter.

    Args:
        cert_dict: Dictionary returned by SSLSocket.getpeercert().

    Returns:
        Key size in bits, or None if unavailable.
    """
    # getpeercert() does not include key size; caller can pass it separately.
    return cert_dict.get("_key_size")


def _extract_cert_info(cert_dict: dict, conn: ssl.SSLSocket | None = None) -> dict[str, Any]:
    """Build a structured summary from a peercert dict.

    Args:
        cert_dict: Dictionary from SSLSocket.getpeercert().
        conn: Optional live SSLSocket to extract cipher/key info.

    Returns:
        Dict with issuer, subject, expires, days_remaining, serial_number,
        key_size, and warning flags.
    """
    now = datetime.now(timezone.utc)
    issuer = _dn_to_dict(cert_dict.get("issuer", ()))
    subject = _dn_to_dict(cert_dict.get("subject", ()))

    not_after_str = cert_dict.get("notAfter", "")
    not_before_str = cert_dict.get("notBefore", "")

    expires = None
    days_remaining = None
    expired = False
    expiring_soon = False

    if not_after_str:
        try:
            expires_dt = _parse_cert_time(not_after_str)
            expires = expires_dt.isoformat()
            days_remaining = (expires_dt - now).days
            expired = days_remaining < 0
            expiring_soon = 0 <= days_remaining < _EXPIRY_SOON_DAYS
        except ValueError:
            expires = not_after_str

    not_before = None
    if not_before_str:
        try:
            not_before = _parse_cert_time(not_before_str).isoformat()
        except ValueError:
            not_before = not_before_str

    serial_number = cert_dict.get("serialNumber", None)

    # Key size — attempt to read from the connection's cipher info
    key_size = None
    weak_key = False
    if conn is not None:
        try:
            cipher_info = conn.cipher()
            if cipher_info and len(cipher_info) >= 3:
                key_size = cipher_info[2]
        except Exception:
            pass
    if key_size is not None and key_size < _WEAK_KEY_THRESHOLD:
        weak_key = True

    warnings: list[str] = []
    if expired:
        warnings.append("Certificate has expired")
    if expiring_soon:
        warnings.append(f"Certificate expires in {days_remaining} days")
    if weak_key:
        warnings.append(f"Weak key size: {key_size} bits (< {_WEAK_KEY_THRESHOLD})")

    return {
        "issuer": issuer,
        "subject": subject,
        "not_before": not_before,
        "expires": expires,
        "days_remaining": days_remaining,
        "expired": expired,
        "expiring_soon": expiring_soon,
        "serial_number": serial_number,
        "key_size": key_size,
        "weak_key": weak_key,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
@audit(tool_name="check_tls")
def check_tls(host: str, port: int = 443) -> dict[str, Any]:
    """Connect to a host and report TLS certificate and connection details.

    Args:
        host: Hostname to connect to.
        port: TCP port (default 443).

    Returns:
        Dict with keys: host, port, tls_version, cipher_suite, certificate
        (issuer, subject, expires, days_remaining, key_size, serial_number,
        warnings), and status.
    """
    result: dict[str, Any] = {"host": host, "port": port}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=_DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["tls_version"] = ssock.version()

                cipher = ssock.cipher()
                result["cipher_suite"] = {
                    "name": cipher[0] if cipher else None,
                    "protocol": cipher[1] if cipher and len(cipher) > 1 else None,
                    "bits": cipher[2] if cipher and len(cipher) > 2 else None,
                }

                cert_dict = ssock.getpeercert()
                if cert_dict:
                    result["certificate"] = _extract_cert_info(cert_dict, conn=ssock)
                else:
                    result["certificate"] = None

                result["status"] = "ok"
                if result.get("certificate") and result["certificate"].get("warnings"):
                    result["status"] = "warning"
    except ssl.SSLCertVerificationError as exc:
        result["status"] = "error"
        result["error"] = f"Certificate verification failed: {exc}"
    except ssl.SSLError as exc:
        result["status"] = "error"
        result["error"] = f"SSL error: {exc}"
    except socket.timeout:
        result["status"] = "error"
        result["error"] = "Connection timed out"
    except OSError as exc:
        result["status"] = "error"
        result["error"] = f"Connection failed: {exc}"
    return result


@audit(tool_name="check_ssl_versions")
def check_ssl_versions(host: str, port: int = 443) -> dict[str, Any]:
    """Test which SSL/TLS protocol versions a host accepts.

    Attempts SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, and TLSv1.3 and reports
    whether each is accepted or rejected.

    Args:
        host: Hostname to test.
        port: TCP port (default 443).

    Returns:
        Dict with 'protocols' mapping (version -> accepted/rejected),
        'accepted' list, and 'status' (pass/warn/fail).
    """
    protocols: dict[str, str] = {}
    accepted: list[str] = []

    # Test legacy protocols via dedicated protocol constants
    for proto_name, proto_attr in _PROTOCOL_MAP:
        proto_const = getattr(ssl, proto_attr, None)
        if proto_const is None:
            # This Python build does not support the protocol at all.
            protocols[proto_name] = "unsupported"
            continue
        try:
            ctx = ssl.SSLContext(proto_const)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Suppress most security restrictions so we can actually probe
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            with socket.create_connection((host, port), timeout=_DEFAULT_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    protocols[proto_name] = "accepted"
                    accepted.append(proto_name)
        except (ssl.SSLError, OSError):
            protocols[proto_name] = "rejected"

    # Test TLS 1.3 (uses min/max version on a default context)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if hasattr(ssl, "TLSVersion"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        with socket.create_connection((host, port), timeout=_DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                negotiated = ssock.version()
                if negotiated and "1.3" in negotiated:
                    protocols["TLSv1.3"] = "accepted"
                    accepted.append("TLSv1.3")
                else:
                    protocols["TLSv1.3"] = "rejected"
    except (ssl.SSLError, OSError):
        protocols["TLSv1.3"] = "rejected"
    except AttributeError:
        protocols["TLSv1.3"] = "unsupported"

    # Determine overall status
    accepted_set = set(accepted)
    if accepted_set & _DEPRECATED_PROTOCOLS:
        status = "fail"
    elif accepted_set & _WARN_PROTOCOLS:
        status = "warn"
    else:
        status = "pass"

    return {
        "host": host,
        "port": port,
        "protocols": protocols,
        "accepted": accepted,
        "status": status,
    }


@audit(tool_name="scan_certificates")
def scan_certificates(hosts: list[str]) -> dict[str, Any]:
    """Batch-scan TLS certificates for a list of hosts.

    Each entry in *hosts* can be a bare hostname or host:port.

    Args:
        hosts: List of host strings (e.g. ['example.com', 'api.example.com:8443']).

    Returns:
        Dict with 'results' list and 'summary' containing total, expired,
        expiring_soon, and weak_key counts.
    """
    results: list[dict[str, Any]] = []
    summary = {
        "total": len(hosts),
        "expired": 0,
        "expiring_soon": 0,
        "weak_key": 0,
        "errors": 0,
    }

    for host_str in hosts:
        host, port = _parse_host_port(host_str)
        tls_info = check_tls.__wrapped__(host, port)  # call unwrapped to avoid double-audit
        entry: dict[str, Any] = {
            "host": host,
            "port": port,
            "status": tls_info.get("status"),
        }

        if tls_info.get("status") == "error":
            entry["error"] = tls_info.get("error")
            summary["errors"] += 1
        else:
            cert = tls_info.get("certificate")
            if cert:
                entry["issuer"] = cert.get("issuer", {}).get("commonName") or cert.get("issuer", {}).get("organizationName")
                entry["subject"] = cert.get("subject", {}).get("commonName")
                entry["expires"] = cert.get("expires")
                entry["days_remaining"] = cert.get("days_remaining")
                entry["key_size"] = cert.get("key_size")
                entry["warnings"] = cert.get("warnings", [])

                if cert.get("expired"):
                    summary["expired"] += 1
                if cert.get("expiring_soon"):
                    summary["expiring_soon"] += 1
                if cert.get("weak_key"):
                    summary["weak_key"] += 1

        results.append(entry)

    return {"results": results, "summary": summary}


@audit(tool_name="check_cert_chain")
def check_cert_chain(host: str, port: int = 443) -> dict[str, Any]:
    """Validate the full certificate chain for a host.

    Connects to the host and retrieves every certificate in the chain
    presented by the server. Reports issuer, subject, and validity for
    each certificate and flags common issues.

    Args:
        host: Hostname to connect to.
        port: TCP port (default 443).

    Returns:
        Dict with 'chain' list (each cert's details), 'chain_length',
        'issues' list, and 'valid' boolean.
    """
    result: dict[str, Any] = {"host": host, "port": port}

    try:
        ctx = ssl.create_default_context()
        # We still verify, but capture the chain
        with socket.create_connection((host, port), timeout=_DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # getpeercert() gives us the leaf certificate
                leaf_cert = ssock.getpeercert()

                # getpeercert(binary_form=True) gives DER of the leaf
                der_cert = ssock.getpeercert(binary_form=True)

                chain_certs: list[dict[str, Any]] = []
                issues: list[str] = []

                if leaf_cert:
                    leaf_info = _extract_cert_info(leaf_cert, conn=ssock)
                    leaf_info["position"] = "leaf"
                    leaf_info["fingerprint_sha256"] = (
                        hashlib.sha256(der_cert).hexdigest() if der_cert else None
                    )
                    chain_certs.append(leaf_info)

                    # Check for self-signed leaf
                    if leaf_info["issuer"] == leaf_info["subject"]:
                        issues.append("Leaf certificate is self-signed")

                    if leaf_info.get("expired"):
                        issues.append("Leaf certificate has expired")
                    if leaf_info.get("expiring_soon"):
                        issues.append(
                            f"Leaf certificate expires in {leaf_info['days_remaining']} days"
                        )
                    if leaf_info.get("weak_key"):
                        issues.append(
                            f"Leaf certificate has weak key: {leaf_info['key_size']} bits"
                        )

                # Try to get the full chain via unverified context
                try:
                    unverified_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    unverified_ctx.check_hostname = False
                    unverified_ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection(
                        (host, port), timeout=_DEFAULT_TIMEOUT
                    ) as raw_sock:
                        with unverified_ctx.wrap_socket(
                            raw_sock, server_hostname=host
                        ) as raw_ssock:
                            # get_unverified_chain available in Python 3.13+
                            if hasattr(raw_ssock, "get_unverified_chain"):
                                raw_chain = raw_ssock.get_unverified_chain()
                                # Skip the leaf (index 0), process intermediates/root
                                for idx, cert_bytes in enumerate(raw_chain[1:], start=1):
                                    try:
                                        parsed = ssl._ssl._test_decode_cert(cert_bytes)  # type: ignore[attr-defined]
                                        info = _extract_cert_info(parsed)
                                        info["position"] = (
                                            "intermediate" if idx < len(raw_chain) - 1 else "root"
                                        )
                                        info["fingerprint_sha256"] = hashlib.sha256(
                                            cert_bytes
                                        ).hexdigest()

                                        if info.get("expired"):
                                            issues.append(
                                                f"{info['position'].title()} certificate has expired: "
                                                f"{info.get('subject', {}).get('commonName', 'unknown')}"
                                            )
                                        if info["issuer"] == info["subject"] and info["position"] != "root":
                                            issues.append(
                                                f"Self-signed certificate in chain at position {idx}"
                                            )
                                        chain_certs.append(info)
                                    except Exception:
                                        chain_certs.append({
                                            "position": f"index_{idx}",
                                            "error": "Could not decode certificate",
                                        })
                except Exception:
                    # Could not retrieve extended chain; leaf-only analysis is fine.
                    pass

                result["chain"] = chain_certs
                result["chain_length"] = len(chain_certs)
                result["issues"] = issues
                result["valid"] = len(issues) == 0

    except ssl.SSLCertVerificationError as exc:
        result["status"] = "error"
        result["error"] = f"Certificate verification failed: {exc}"
        result["chain"] = []
        result["chain_length"] = 0
        result["issues"] = [str(exc)]
        result["valid"] = False
    except ssl.SSLError as exc:
        result["status"] = "error"
        result["error"] = f"SSL error: {exc}"
        result["chain"] = []
        result["chain_length"] = 0
        result["issues"] = [str(exc)]
        result["valid"] = False
    except socket.timeout:
        result["status"] = "error"
        result["error"] = "Connection timed out"
        result["chain"] = []
        result["chain_length"] = 0
        result["issues"] = ["Connection timed out"]
        result["valid"] = False
    except OSError as exc:
        result["status"] = "error"
        result["error"] = f"Connection failed: {exc}"
        result["chain"] = []
        result["chain_length"] = 0
        result["issues"] = [str(exc)]
        result["valid"] = False

    return result


# ---------------------------------------------------------------------------
# Module registration for pluggable loader
# ---------------------------------------------------------------------------
def register(mcp) -> None:
    """Register TLS/SSL checker tools with the MCP server."""
    mcp.tool()(check_tls)
    mcp.tool()(check_ssl_versions)
    mcp.tool()(scan_certificates)
    mcp.tool()(check_cert_chain)
