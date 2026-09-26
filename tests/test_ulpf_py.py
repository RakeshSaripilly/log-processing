"""
Unit tests for ULPF-PY Client SDK
Team LunarX - SIH26156 (NTRO)
"""

import shutil
import pytest
from core.pipeline import ProcessingPipeline
from ulpf_py.client import ULPFClient


@pytest.fixture
def populated_env(tmp_path):
    vault_dir = tmp_path / "vault"
    lake_dir = tmp_path / "lake"
    pipeline = ProcessingPipeline(vault_dir=str(vault_dir), lake_dir=str(lake_dir))

    # Ingest 5 sample logs
    sample_logs = [
        "Oct 12 10:14:22 web-01 sshd[12445]: Accepted password for root from 192.0.2.15 port 54322 ssh2",
        "Oct 12 10:14:25 web-01 sshd[12446]: Failed password for invalid user admin from 198.51.100.44 port 43121 ssh2",
        "%ASA-6-302013: Built outbound TCP connection 99812 for outside:198.51.100.22/443 to inside:192.0.2.80/51234",
        '{"timestamp":"2026-09-26T12:00:00.123456+0000","event_type":"alert","src_ip":"192.0.2.14","src_port":53211,"dest_ip":"198.51.100.4","dest_port":80,"proto":"TCP","alert":{"action":"allowed","signature":"ET SCAN Potential SSH Scan"}}',
        "2 123456789012 eni-0123456789abcdef0 198.51.100.12 203.0.113.88 49152 443 6 20 4200 1695730000 1695730060 ACCEPT OK"
    ]
    for log in sample_logs:
        pipeline.process_raw(log)

    pipeline.vault.flush()

    client = ULPFClient(lake_path=str(lake_dir), vault_path=str(vault_dir))
    yield client, pipeline
    client.close()
    pipeline.lake.close()
    shutil.rmtree(tmp_path, ignore_errors=True)


def test_client_query_predicate_and_pandas(populated_env):
    client, _ = populated_env
    # Query with predicate pushdown
    df = client.query(where="src_endpoint.ip='192.0.2.15'").to_pandas()
    assert len(df) == 1
    assert df.iloc[0]["user_name"] == "root"


def test_client_arrow_and_spark(populated_env):
    client, _ = populated_env
    arrow_tbl = client.query().to_arrow()
    assert arrow_tbl.num_rows == 5

    spark_df = client.query().to_spark()
    assert spark_df.count() == 5


def test_client_get_raw_and_lineage(populated_env):
    client, pipeline = populated_env
    rows = client.query().to_pandas()
    first_event_id = rows.iloc[0]["event_id"]

    raw_bytes = client.get_raw(first_event_id)
    assert b"sshd" in raw_bytes

    lineage = client.get_lineage(first_event_id)
    assert "stage_1_raw" in lineage
    assert lineage["stage_6_attestation"]["canonical_scheme"] == "RFC8785_JCS"


def test_client_prove_merkle(populated_env):
    client, _ = populated_env
    proof_result = client.prove(event_seq=0)
    assert proof_result["verified"] is True
    assert len(proof_result["merkle_root"]) == 64


def test_client_to_features(populated_env):
    client, _ = populated_env
    X, feat_names = client.to_features()
    assert X.shape[0] == 5
    assert len(feat_names) == 5
