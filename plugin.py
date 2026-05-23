from __future__ import annotations

"""Network Forensics Cell — packet capture analysis and network intelligence tools.

Built for ForHacker. All tools use pure Python with zero external dependencies
for core functionality. Advanced analysis (pcap parsing) requires optional libs.
"""

import re
import socket
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from forhacker.plugin.base import BasePlugin, Tool


class NetworkForensicsPlugin(BasePlugin):
    name = "network-forensics"
    version = "0.1.0"
    domain = "network"
    risk_levels = {
        "pcap_summary": "LOW",
        "dns_lookup": "LOW",
        "http_header_parse": "LOW",
        "ip_geo_lookup": "MEDIUM",
        "connection_graph": "MEDIUM",
    }

    def register_tools(self) -> list[Tool]:
        return [
            Tool(
                name="pcap_summary",
                description="Summarize a PCAP file — protocol breakdown, top talkers",
                domain="network",
                risk_level="LOW",
                applicable_extensions=(".pcap", ".pcapng", ".cap"),
            ),
            Tool(
                name="dns_lookup",
                description="Resolve hostname to IP addresses (A/AAAA records)",
                domain="network",
                risk_level="LOW",
            ),
            Tool(
                name="http_header_parse",
                description="Parse HTTP request/response headers from raw text",
                domain="network",
                risk_level="LOW",
            ),
            Tool(
                name="ip_geo_lookup",
                description="Reverse DNS and IP classification (GeoIP stub)",
                domain="network",
                risk_level="MEDIUM",
            ),
            Tool(
                name="connection_graph",
                description="Extract TCP/UDP connection pairs from netstat output",
                domain="network",
                risk_level="MEDIUM",
            ),
        ]


# === Tool Implementations ===


def run_pcap_summary(target: str) -> dict[str, Any]:
    """Parse basic PCAP structure — protocol counts, top source/dest IPs."""
    path = Path(target)
    if not path.exists():
        return {"error": f"File not found: {target}"}

    data = path.read_bytes()
    result: dict[str, Any] = {"file": str(path.absolute()), "size": len(data)}

    # PCAP magic number check
    if len(data) < 24:
        result["error"] = "File too small to be PCAP"
        return result

    magic = int.from_bytes(data[:4], "little")
    magic2 = int.from_bytes(data[:4], "big")
    if magic == 0xA1B2C3D4:
        result["format"] = "pcap (little-endian)"
        endian: Literal["little", "big"] = "little"
    elif magic2 == 0xA1B2C3D4:
        result["format"] = "pcap (big-endian)"
        endian = "big"
    elif magic == 0xA1B23C4D:
        result["format"] = "pcap-nanosecond (little-endian)"
        endian = "little"
    elif magic2 == 0xA1B23C4D:
        result["format"] = "pcap-nanosecond (big-endian)"
        endian = "big"
    else:
        result["format"] = "unknown"
        result["note"] = "Raw packet analysis requires scapy. Install: pip install scapy"
        return result

    # Count packets
    packet_count = 0
    offset = 24
    while offset + 16 <= len(data):
        incl_len = int.from_bytes(data[offset + 8 : offset + 12], endian)
        packet_count += 1
        offset += 16 + incl_len
        if offset > len(data):
            break

    result["packet_count"] = packet_count
    result["note"] = "Full protocol breakdown requires scapy. Install: pip install scapy"
    return result


def run_dns_lookup(hostname: str) -> dict[str, Any]:
    """Resolve a hostname to IP addresses using system DNS."""
    if not hostname or not hostname.strip():
        return {"error": "No hostname provided"}
    hostname = hostname.strip()
    result: dict[str, Any] = {"hostname": hostname, "addresses": []}
    try:
        info = socket.getaddrinfo(hostname, None)
        seen = set()
        for _, _, _, _, sockaddr in info:
            addr = sockaddr[0]
            if addr not in seen:
                seen.add(addr)
                result["addresses"].append(addr)
    except socket.gaierror as e:
        result["error"] = f"DNS resolution failed: {e}"
    except Exception as e:
        result["error"] = str(e)
    result["resolved_count"] = len(result["addresses"])
    return result


def run_http_header_parse(text: str) -> dict[str, Any]:
    """Parse HTTP request or response headers from raw text."""
    if not text or not text.strip():
        return {"error": "No input text provided"}

    text = text.strip()
    result: dict[str, Any] = {
        "headers": {},
        "request_line": None,
        "status_line": None,
    }

    # Split headers from body
    parts = text.split("\r\n\r\n", 1)
    if len(parts) == 1:
        parts = text.split("\n\n", 1)
    header_block = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    lines = header_block.split("\r\n") if "\r\n" in header_block else header_block.split("\n")

    # First line
    if lines:
        first = lines[0]
        if first.startswith("HTTP/"):
            result["status_line"] = first
        elif "HTTP/" in first:
            result["request_line"] = first

    # Parse header fields
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            result["headers"][key] = value

    result["header_count"] = len(result["headers"])
    result["body_size"] = len(body)
    return result


def run_ip_geo_lookup(ip_address: str) -> dict[str, Any]:
    """Perform reverse DNS lookup and basic IP validation/classification."""
    if not ip_address or not ip_address.strip():
        return {"error": "No IP address provided"}
    ip = ip_address.strip()

    result: dict[str, Any] = {"ip": ip}

    # Validate IP format
    try:
        socket.inet_pton(socket.AF_INET, ip)
        result["version"] = 4
        result["is_private"] = _is_private_ipv4(ip)
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            result["version"] = 6
            result["is_private"] = ip.startswith("fd") or ip.startswith("fc") or ip == "::1"
        except OSError:
            result["error"] = f"Invalid IP address: {ip}"
            return result

    # Reverse DNS
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        result["reverse_dns"] = hostname
    except (socket.herror, socket.gaierror):
        result["reverse_dns"] = None
    except Exception as e:
        result["reverse_dns_error"] = str(e)

    # Classify IP type
    if result.get("is_private"):
        result["classification"] = "private_rfc1918"
    elif result.get("reverse_dns"):
        rdns = result["reverse_dns"].lower()
        if any(k in rdns for k in ["aws", "amazon", "ec2"]):
            result["classification"] = "cloud_aws"
        elif any(k in rdns for k in ["azure", "cloudapp"]):
            result["classification"] = "cloud_azure"
        elif any(k in rdns for k in ["gcp", "google", "cloud"]):
            result["classification"] = "cloud_gcp"
        elif any(k in rdns for k in ["vpn", "proxy", "tor"]):
            result["classification"] = "vpn_or_proxy"
        elif any(k in rdns for k in ["cdn", "akamai", "cloudflare", "fastly", "cloudfront"]):
            result["classification"] = "cdn"
        elif any(k in rdns for k in ["isp", "broadband", "dsl", "fiber", "cable", "dial"]):
            result["classification"] = "isp_residential"
        else:
            result["classification"] = "external"
    else:
        result["classification"] = "no_ptr_record"

    result["note"] = "For GeoIP location (country/city), install MaxMind GeoLite2 database"
    return result


def _is_private_ipv4(ip: str) -> bool:
    """Check if IPv4 address is in RFC 1918 private ranges."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first = int(parts[0])
        second = int(parts[1])
    except ValueError:
        return False
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if ip == "127.0.0.1" or ip == "0.0.0.0":
        return True
    return False


def run_connection_graph(text: str) -> dict[str, Any]:
    """Extract TCP/UDP connection pairs from netstat or ss output."""
    if not text or not text.strip():
        return {"error": "No netstat/ss output provided"}

    lines = text.strip().split("\n")
    connections: list[dict] = []
    local_counter: Counter = Counter()
    remote_counter: Counter = Counter()

    # Common patterns: "tcp  0  0  192.168.1.1:443  10.0.0.1:52341  ESTABLISHED"
    conn_pattern = re.compile(
        r"(tcp|udp)\S*\s+\d+\s+\d+\s+"
        r"([0-9a-f.:\[\]]+)[:\.](\d+)\s+"
        r"([0-9a-f.:\[\]]+)[:\.](\d+)\s*"
        r"(\S*)",
        re.IGNORECASE,
    )

    for line in lines:
        m = conn_pattern.search(line)
        if m:
            proto, local_ip, local_port, remote_ip, remote_port, state = m.groups()
            conn = {
                "proto": proto.lower(),
                "local": f"{local_ip}:{local_port}",
                "remote": f"{remote_ip}:{remote_port}",
                "state": state or "unknown",
            }
            connections.append(conn)
            local_counter[f"{local_ip}"] += 1
            remote_counter[f"{remote_ip}"] += 1

    return {
        "connection_count": len(connections),
        "connections": connections,
        "top_local_ips": local_counter.most_common(10),
        "top_remote_ips": remote_counter.most_common(10),
    }
