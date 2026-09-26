"""
Air-Gap & Zero Socket Leak Verification Test
Verifies that the entire ULPF ingestion, parsing, vector matching, attestation,
and query execution operates strictly offline with zero external network socket calls.
Team LunarX - SIH26156 (NTRO)
"""

import socket
import pytest
from core.pipeline import ProcessingPipeline


def test_zero_external_socket_calls_during_pipeline_run(monkeypatch, tmp_path):
    external_calls = []

    original_connect = socket.socket.connect

    def guarded_connect(self, address):
        host, port = address[0], address[1]
        # Allow internal localhost loopback only
        if host not in ("127.0.0.1", "::1", "localhost"):
            external_calls.append(address)
            raise ConnectionRefusedError(f"AIR-GAP VIOLATION: Unauthorized attempt to connect to {address}")
        return original_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)

    vault_dir = tmp_path / "vault"
    lake_dir = tmp_path / "lake"
    pipeline = ProcessingPipeline(vault_dir=str(vault_dir), lake_dir=str(lake_dir))

    # Process logs spanning 4 different vendors + unmapped proprietary
    test_logs = [
        "Oct 12 10:14:22 web-01 sshd[12445]: Accepted password for root from 192.0.2.15 port 54322 ssh2",
        "%ASA-6-302013: Built outbound TCP connection 99812 for outside:198.51.100.22/443 to inside:192.0.2.80/51234",
        '{"timestamp":"2026-09-26T12:00:00.123456+0000","event_type":"alert","src_ip":"192.0.2.14","src_port":53211}',
        "VENDOR-X|9921|CRIT|disk_array_2|temp=88C|status=degrading"
    ]

    for log in test_logs:
        pipeline.process_raw(log)

    pipeline.lake.close()

    # Assert exactly 0 external outbound socket connections were attempted
    assert len(external_calls) == 0, f"Air-gap breach detected: {external_calls}"
