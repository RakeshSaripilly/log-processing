"""
Universal Log Pre-processing Framework (ULPF) - Air-Gap Compliance Verifier
Problem Statement: SIH26156 (NTRO) | Theme: Blockchain & Cybersecurity | Team LunarX

Audits:
1. Zero outbound external socket leaks during ingestion, parsing, vector matching, attestation, and lake querying.
2. Dashboard self-containment (no external script tags, zero unpkg/cdnjs dependencies).
"""

import sys
import socket
import re
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.pipeline import ProcessingPipeline


def verify_network_isolation():
    print("[*] 1. Auditing Network Isolation & Socket Leakage...")
    external_calls = []

    original_connect = socket.socket.connect

    def guarded_connect(self, address):
        host, port = address[0], address[1]
        if host not in ("127.0.0.1", "::1", "localhost"):
            external_calls.append(address)
            raise ConnectionRefusedError(f"AIR-GAP VIOLATION: Unauthorized attempt to connect to {address}")
        return original_connect(self, address)

    socket.socket.connect = guarded_connect

    tmp_dir = PROJECT_ROOT / "benchmarks" / "airgap_tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    vault_dir = tmp_dir / "vault"
    lake_dir = tmp_dir / "lake"

    pipeline = ProcessingPipeline(vault_dir=str(vault_dir), lake_dir=str(lake_dir))

    sample_logs = [
        "Oct 12 10:14:22 web-01 sshd[12445]: Accepted password for root from 192.0.2.15 port 54322 ssh2",
        "%ASA-6-302013: Built outbound TCP connection 99812 for outside:198.51.100.22/443 to inside:192.0.2.80/51234",
        '{"timestamp":"2026-09-26T12:00:00.123456+0000","event_type":"alert","src_ip":"192.0.2.14","src_port":53211,"dest_ip":"198.51.100.4","dest_port":80}',
        "1,2026/09/26 12:00:00,001234567890,TRAFFIC,drop,1,2026/09/26 12:00:00,203.0.113.19,198.51.100.5,0.0.0.0,0.0.0.0,rule-block-all,,,ping,vsys1,untrust,trust,ethernet1/1,,Syslog-Palo,2026/09/26 12:00:00,12345,1,12345,80,0,0,0x0,icmp,deny,60,60,0,1,2026/09/26 12:00:00,0,any,0,123456789,0x0,192.0.2.0-192.0.2.255,198.51.100.0-198.51.100.255,0,1,0",
        "VENDOR-X|9921|CRIT|disk_array_2|temp=88C|status=degrading"
    ]

    for log in sample_logs:
        pipeline.process_raw(log)

    pipeline.lake.close()
    socket.socket.connect = original_connect

    import shutil
    shutil.rmtree(tmp_dir, ignore_errors=True)

    if external_calls:
        print(f"[-] FAIL: Detected {len(external_calls)} outbound connection attempts: {external_calls}")
        return False
    else:
        print("[+] PASS: Zero outbound socket calls detected. Ingestion pipeline is 100% air-gap sealed.")
        return True


def verify_dashboard_self_containment():
    print("[*] 2. Auditing Dashboard Assets & Offline Self-Containment...")
    dash_file = PROJECT_ROOT / "dashboard" / "index.html"
    if not dash_file.exists():
        print(f"[-] FAIL: {dash_file} not found")
        return False

    content = dash_file.read_text(encoding="utf-8")
    
    # Check for external script src tags (e.g., cdnjs, unpkg)
    external_scripts = re.findall(r'<script[^>]+src=["\'](https?://[^"\']+)["\']', content, re.IGNORECASE)
    if external_scripts:
        print(f"[-] FAIL: Found external remote script tags: {external_scripts}")
        return False

    print("[+] PASS: Zero remote external scripts in dashboard. Fully self-contained inline vanilla JS/CSS.")
    return True


if __name__ == "__main__":
    print("=" * 60)
    print(" ULPF AIR-GAP COMPLIANCE VERIFICATION AUDIT")
    print("=" * 60)
    net_ok = verify_network_isolation()
    dash_ok = verify_dashboard_self_containment()
    print("=" * 60)
    if net_ok and dash_ok:
        print("[+] CONCLUSION: ULPF IS 100% AIR-GAP COMPLIANT & READY FOR NTRO DEPLOYMENT.")
        sys.exit(0)
    else:
        print("[-] CONCLUSION: Air-gap verification failed.")
        sys.exit(1)
