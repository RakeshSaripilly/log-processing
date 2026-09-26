"""
Universal Log Pre-processing Framework (ULPF) - Salvage Extraction Module
Extracts universal security observables (IP, Port, MAC, URL, Email, Hostname, Hashes)
Never makes false semantic guesses (e.g., never assumes random IP is src_endpoint.ip).
Team LunarX - SIH26156 (NTRO)
"""

import re
from typing import Dict, Any, List

IPV4_PATTERN = re.compile(
    r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
MAC_PATTERN = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b")
URL_PATTERN = re.compile(r"https?://[^\s<>\"'{}|\\^`]+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PORT_PATTERN = re.compile(r"\b(?:port|sport|dport|pt)[:=\s]+(\d{1,5})\b", re.IGNORECASE)
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")


def extract_observables(text: str) -> Dict[str, Any]:
    """
    Safely extract ungrounded observables from unknown logs.
    Guarantees zero false semantic mappings: all extracted tokens are returned
    under 'observables' without guessing source vs destination roles.
    """
    observables: Dict[str, Any] = {}

    # Extract IPs
    ips = list(set(IPV4_PATTERN.findall(text)))
    if ips:
        observables["ip_addresses"] = ips

    # Extract MACs
    macs = list(set(MAC_PATTERN.findall(text)))
    if macs:
        observables["mac_addresses"] = macs

    # Extract URLs
    urls = list(set(URL_PATTERN.findall(text)))
    if urls:
        observables["urls"] = urls

    # Extract Emails
    emails = list(set(EMAIL_PATTERN.findall(text)))
    if emails:
        observables["emails"] = emails

    # Extract Ports
    ports = []
    for match in PORT_PATTERN.finditer(text):
        val = int(match.group(1))
        if 1 <= val <= 65535:
            ports.append(val)
    if ports:
        observables["ports"] = sorted(list(set(ports)))

    # Hashes
    sha256s = list(set(SHA256_PATTERN.findall(text)))
    if sha256s:
        observables["hashes_sha256"] = sha256s

    md5s = list(set(MD5_PATTERN.findall(text)))
    if md5s:
        observables["hashes_md5"] = md5s

    return observables
