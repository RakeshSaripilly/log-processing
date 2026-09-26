"""
Unit tests for ULPF Cryptographic Raw Log Vault
Team LunarX - SIH26156 (NTRO)
"""

import pytest
import shutil
from pathlib import Path
from core.vault import VaultStorage, RawRef


@pytest.fixture
def temp_vault(tmp_path):
    vault_dir = tmp_path / "vault"
    v = VaultStorage(vault_dir=str(vault_dir), max_segment_size=1024 * 1024)
    yield v
    shutil.rmtree(vault_dir, ignore_errors=True)


def test_write_before_parse_and_lossless_retrieval(temp_vault):
    raw_payload = b"Oct 12 10:14:22 web-01 sshd[12445]: Accepted password for root from 192.0.2.15 port 54322 ssh2\n"
    locator = temp_vault.write_raw(raw_payload)

    assert isinstance(locator, RawRef)
    assert locator.to_string().startswith("ulpf:raw:")

    # Read back immediately from in-memory buffer
    retrieved = temp_vault.get_raw(locator)
    assert retrieved == raw_payload

    # Flush to disk and read back from compressed zstd block
    temp_vault.flush()
    retrieved_disk = temp_vault.get_raw(locator)
    assert retrieved_disk == raw_payload


def test_vault_crash_recovery_scan_headers(temp_vault):
    logs = [
        f"test log message number {i} with payload data\n".encode('utf-8')
        for i in range(100)
    ]
    locators = [temp_vault.write_raw(l) for l in logs]
    temp_vault.flush()

    # Reconstruct index by scanning block headers
    recovered_index = temp_vault.recover_index()
    assert len(recovered_index) >= 1
    assert recovered_index[0]["segment_id"] == 0
    assert recovered_index[0]["crc32"].startswith("0x")

    # Verify every locator can be resolved from disk
    for idx, loc in enumerate(locators):
        raw = temp_vault.get_raw(loc)
        assert raw == logs[idx]
