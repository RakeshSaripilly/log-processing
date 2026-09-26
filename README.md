# Universal Log Pre-processing Framework (ULPF)
### Problem Statement ID: SIH26156 | Theme: Blockchain & Cybersecurity | Organization: NTRO
**Team LunarX** *(Idea 2 for SIH Final Submission — Shortlisted in internal hackathon with SIH26166 ISRO)*

[![Tests](https://img.shields.io/badge/tests-28%20passed-brightgreen.svg)]()
[![Schema](https://img.shields.io/badge/OCSF-1.9.0-blue.svg)]()
[![Air--Gap](https://img.shields.io/badge/Air--Gap-Zero%20Socket%20Leak-purple.svg)]()
[![Integrity](https://img.shields.io/badge/Attestation-RFC8785%20JCS%20%2B%20BLAKE3-orange.svg)]()

---

## 🌟 Architectural Novelty (Vault-First + Vector Matcher + Hash Chain)
ULPF ingests heterogeneous logs from firewalls, IDS/IPS, proxies, web servers, and proprietary devices, normalizes them into **OCSF 1.9**, guarantees **100% lossless raw capture**, and provides blockchain-grade **tamper-evident attestation**.

```
[Raw Bytes Stream] 
        │
        ▼
[1. VAULT APPEND-ONLY] ──► zstd ~1MiB Blocks + CRC-32 + RawRef Locator (WRITE BEFORE PARSE)
        │
        ▼
[2. SOURCE PACK DETECTOR] ──► 8 Active YAML Packs (SSHD, Cisco, Palo Alto, Suricata, AWS, etc.)
        │
        ├── Pack Claimed ──► [3. 10 DECODER CHAIN] ──► Extracted Key-Values
        │                                                     │
        └── No Pack Claimed                                   │
                │                                             │
                ▼                                             │
[3b. SALVAGE & DRAIN3] ──► Observables (IP, Port, URL)        │
                │                                             │
                ▼                                             │
[4. TELEMETRY VECTOR MATCHER] ──► 384-dim Offline Embeddings ──┘
                │
                ├── >0.85 ──────► Auto-Map
                ├── 0.60 - 0.85 ─► Human Review Queue (HITL Promotion)
                └── <0.60 ──────► custom.<vendor>.<field>
                        │
                        ▼
[5. OCSF 1.9 NORMALIZER] ──► Canonical Classes 4001, 3001, 2001, 1001 + 7-Stage Lineage
        │
        ▼
[6. ATTESTATION CHAIN] ──► RFC 8785 JCS + BLAKE3 prev_hash Link
        │
        ├── Every 1000 Events ──► RFC 6962 Merkle Root + Ed25519 Checkpoint Signature
        │
        ▼
[7. LAKE & OUTPUT SINKS] ──► DuckDB + Date Partitioned Parquet + NDJSON + Wazuh UDP Forwarder
```

---

## ⚡ 10 Quickstart Commands

```bash
# 1. Clone & Enter Project Directory
cd c:\College\SIH2026\SIH26156\ULPF

# 2. Run Complete Automated Test Suite (28 Tests)
python -m pytest tests -v

# 3. Execute End-to-End Performance & Throughput Benchmark
python benchmarks/run_benchmark.py

# 4. Start the FastAPI Engine & Modern Web Console
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000

# 5. Open Web Console Dashboard in Browser
# Navigate to: http://localhost:8000

# 6. Ingest Test Batch of 10 Heterogeneous Logs
curl -X POST http://localhost:8000/ingest -H "Content-Type: application/json" -d "{\"logs\": [\"Oct 12 10:14:22 web-01 sshd[12445]: Accepted password for root from 192.0.2.15 port 54322 ssh2\", \"%ASA-6-302013: Built outbound TCP connection 99812 for outside:198.51.100.22/443 to inside:192.0.2.80/51234\"]}"

# 7. Check Cryptographic Chain Integrity
curl http://localhost:8000/verify

# 8. Generate an RFC 6962 Merkle Inclusion Proof for Sequence 0
curl http://localhost:8000/prove/0

# 9. Query Analytical Lake via ULPF-PY Client
python -c "from ulpf_py import ULPFClient; print(ULPFClient().query(where=\"src_endpoint.ip='192.0.2.15'\").to_pandas())"

# 10. Run Tamper Attack Simulation (Instant Mathematical Detection)
curl -X POST http://localhost:8000/tamper-test -H "Content-Type: application/json" -d "{\"sequence\": 0, \"field_to_corrupt\": \"src_ip\", \"tampered_value\": \"198.51.100.99\"}"
```

---

## 🎬 2-Minute Live Evaluation Script

1. **0:00 - 0:30 (Raw Ingest & OCSF 1.9 Output):**  
   Ingest clean JSON and Cisco ASA firewall log. Show instant query in DuckDB table `parsed_logs` normalized to OCSF 1.9 `class_uid: 4001`.
2. **0:30 - 1:00 (Proprietary Log & Telemetry Vector Matcher):**  
   Ingest unmapped proprietary log `VENDOR-X|9921|CRIT|disk_array_2|temp=88C|status=degrading`. Open `/review-queue` in UI, demonstrate confidence score, click **"Approve & Promote"**, and show hot promotion to active configuration without restarting.
3. **1:00 - 1:40 (Byte-Exact Vault Retrieval & Chain Verification):**  
   Call `client.get_raw(event_id)`. Show exact raw payload from zstd block with SHA-256 match. Call `client.verify_chain()`, showing 100% cryptographic integrity.
4. **1:40 - 2:00 (Live Tamper Attack & Zero-Knowledge Merkle Proof):**  
   Trigger `/tamper-test` on sequence 0. Show the console immediately turn red with exact broken sequence number `0`. Generate Merkle proof at sequence 0 with $\lceil \log_2 N \rceil$ sibling hashes verifying event inclusion without exposing vault data.

---

## 🐍 Python SDK (`ulpf-py`) Example

```python
from ulpf_py import ULPFClient

# 1. Initialize Client
client = ULPFClient(lake_path="./lake", vault_path="./storage/raw")

# 2. SQL Query with Predicate Pushdown
df = client.query(where="src_endpoint.ip='192.0.2.15'").to_pandas()
print(df[["event_id", "class_uid", "user_name", "src_ip"]])

# 3. Retrieve Exact Original Raw Payload from Vault via Locator
raw_bytes = client.get_raw(event_id=df.iloc[0]["event_id"])
print(f"Original Raw Bytes: {raw_bytes.decode('utf-8')}")

# 4. Export to PyArrow & Spark
arrow_table = client.query().to_arrow()
spark_df = client.query().to_spark()

# 5. Extract Feature Matrix for Machine Learning (IsolationForest / LSTM)
X, feature_names = client.to_features(window="5min")
print(f"ML Features Matrix Shape: {X.shape}, Features: {feature_names}")

# 6. Verify Blockchain Hash Chain
is_valid, msg, broken_seq = client.verify_chain()
print(f"Chain Verified: {is_valid} ({msg})")

# 7. Generate Zero-Knowledge RFC 6962 Inclusion Proof
proof = client.prove(event_seq=0)
print(f"Merkle Root: {proof['merkle_root']}, Verified: {proof['verified']}")
```

---

## 🏆 Competitive Comparison vs 5 Existing GitHub Repos

| Feature | hunter-x0s | d3v4nshpat3l | printmax99 | thenamang | shivanshumangal007 | **Team LunarX (ULPF)** |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Write-Before-Parse Vault** | ❌ | ✅ | ❌ | ❌ | ❌ | **✅ zstd ~1MB + CRC-32 + RawRef** |
| **Telemetry Vector Matcher** | ❌ | ❌ | ❌ | ❌ | ❌ | **✅ 384-dim sample-aware + FAISS** |
| **Zero Code Gen (Air-Gap Safe)**| ❌ | ✅ | ❌ | ❌ | ❌ | **✅ Deterministic Confidence Routing**|
| **OCSF Schema Version** | None | v1.3 | v1.3 | v1.3 | Custom | **✅ OCSF 1.9.0 (Latest)** |
| **RFC 6962 Merkle Proofs** | ❌ | ✅ | ❌ | ❌ | ❌ | **✅ Inclusion ceil(log2 n) Proof** |
| **Ed25519 Checkpoints** | ❌ | ✅ | ❌ | ❌ | ❌ | **✅ Signs (chain_head + Merkle root)**|
| **Air-Gap Zero-Socket Leak** | ❌ | ✅ | ❌ | ❌ | ❌ | **✅ 100% Offline Verified** |
| **Python Client Library (ulpf-py)**| ❌ | ❌ | ❌ | ❌ | ❌ | **✅ Predicate pushdown + to_spark** |
| **Interactive SOC Console** | ❌ | Basic | React | ❌ | Go/ClickHouse | **✅ Glassmorphism Dark Mode UI** |
