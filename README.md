# Universal Log Pre-processing Framework (ULPF)
### Problem Statement ID: SIH26156 | Theme: Blockchain & Cybersecurity | Organization: NTRO
**Team LunarX** *(Idea 2 for SIH Final Submission — Shortlisted in internal hackathon with SIH26166 ISRO)*

[![Tests](https://img.shields.io/badge/tests-36%20passed-brightgreen.svg)]()
[![Architecture](https://img.shields.io/badge/Architecture-Hybrid%20Python%20%2B%20Rust-blue.svg)]()
[![Throughput](https://img.shields.io/badge/Throughput-%3E8%2C200%20EPS-brightgreen.svg)]()
[![Schema](https://img.shields.io/badge/OCSF-1.9.0-blue.svg)]()
[![Air--Gap](https://img.shields.io/badge/Air--Gap-Zero%20Socket%20Leak-purple.svg)]()
[![Integrity](https://img.shields.io/badge/Attestation-RFC8785%20JCS%20%2B%20BLAKE3-orange.svg)]()

---

## 🌟 Architectural Novelty (Vault-First + Vector Matcher + Hash Chain)
ULPF ingests heterogeneous logs from firewalls, IDS/IPS, proxies, web servers, and proprietary devices, normalizes them into **OCSF 1.9**, guarantees **lossless raw capture with verified byte-exact retrieval**, and provides **cryptographically verifiable tamper-evident attestation**.

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

## 💻 CLI Usage

The ULPF Command Line Interface (`ulpf`) is the primary operational interface to the ULPF Python framework. It provides air-gapped, zero-socket log processing through the complete 7-stage pipeline (Vault Write-Before-Parse, Detection, Parsing, OCSF 1.9 Normalization, Validation, Raw Evidence Preservation, and Cryptographic Attestation).

### Installation
```bash
pip install -e .
```

### Commands

```bash
# 1. View CLI documentation & available options
ulpf --help

# 2. Process a log file with default output directory (output/)
ulpf process samples/Apache.log

# 3. Process with custom output destination
ulpf process samples/Apache.log --output output/

# 4. Machine-readable JSON output mode (ideal for piping to jq/SIEM)
ulpf process samples/Apache.log --output output/ --json
```

#### Terminal Execution Output
```
============================================================
ULPF - Universal Log Pre-processing Framework
============================================================

Input File       : samples/Apache.log
File Size        : 4.90 MB
Format           : HTTP Server
Source           : Apache
Mode             : Offline / Air-Gapped

[1/7] Ingesting raw events................. OK
[2/7] Detecting format..................... OK
[3/7] Parsing events....................... OK (56,482 events)
[4/7] Normalizing to OCSF.................. OK
[5/7] Validating events.................... OK
[6/7] Preserving raw evidence.............. OK
[7/7] Verifying integrity.................. OK

------------------------------------------------------------
RESULT
------------------------------------------------------------
Events Read       : 56,482
Events Parsed     : 56,482
Events Normalized : 56,482
Events Rejected   : 0

Raw Preservation  : PASS
Traceability      : PASS
Integrity         : PASS

Output:
  Normalized JSON : output/normalized.json
  Raw Evidence    : output/raw/
  Metadata        : output/metadata.json

Processing Time   : 6.83 seconds
Throughput        : 8,263 events/sec

============================================================
ULPF PROCESSING COMPLETE
============================================================
```

#### JSON Output Mode (`--json`)
```json
{
  "input_file": "samples/Apache.log",
  "format": "HTTP Server",
  "events_read": 56482,
  "events_parsed": 56482,
  "events_normalized": 56482,
  "events_rejected": 0,
  "raw_preserved": true,
  "traceability_verified": true,
  "integrity_verified": true,
  "processing_time_seconds": 6.83,
  "throughput_events_per_second": 8263,
  "outputs": {
    "normalized": "output/normalized.json",
    "raw": "output/raw/",
    "metadata": "output/metadata.json"
  }
}
```

Optional arguments:
- `--output, -o <dir>`: Custom destination for normalized logs, raw evidence, and metadata.
- `--format, -f <format>`: Explicit log format hint (`cef`, `json`, `syslog`, `cisco_asa`, etc.).
- `--config, -c <config>`: Path to YAML or JSON configuration file.
- `--source, -s <source>`: Vendor or source label (e.g. `Firewall`, `Linux SSHD`, `Suricata`).
- `--no-integrity`: Skip continuous cryptographic hash chain verification.
- `--json`: Output machine-readable JSON only.
- `--verbose`: Enable debug tracebacks on error.

---

## ⚡ 10 Quickstart Commands

```bash
# 1. Clone & Enter Project Directory
cd c:\College\SIH2026\SIH26156\ULPF

# 2. Run Complete Automated Test Suite (36 Tests)
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
4. **1:40 - 2:00 (Live Tamper Attack & RFC 6962 Merkle Inclusion Proof):**  
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

# 6. Verify Continuous Hash Chain (RFC 8785 + BLAKE3)
is_valid, msg, broken_seq = client.verify_chain()
print(f"Chain Verified: {is_valid} ({msg})")

# 7. Generate RFC 6962 Merkle Inclusion Proof
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

---

## 🦀 Hybrid Rust Core (`rust_core/`)

To maximize ingestion and attestation throughput under massive enterprise workloads without altering Python orchestration or declarative YAML parser packs, ULPF incorporates a high-performance native core implemented in Rust under [`rust_core/`](rust_core/).

### Architecture & Engine Boundaries
- **Native Rust Extension (`rust_core/`)**:
  - `vault_append_batch(lines, start_seg, start_block)`: Accelerated ~1MiB block chunking with embedded uncompressed size headers, native `zstd` level 3 compression, and SIMD `crc32fast` checksum computation. Yields deterministic `RawRef` locators (`ulpf:raw:<seg>:<block>:<off>:<len>`).
  - `blake3_hash_chain(prev_hash, canonical_json)`: Deterministic RFC 8785 JSON Canonicalization Scheme (JCS) serializer and BLAKE3 cryptographic hash chain linkage.
  - `merkle_root(hashes)`: RFC 6962 domain-separated Merkle tree root calculation over 1,000-event audit checkpoints.
- **Python Framework Orchestration**:
  - Pipeline execution, active YAML Source Packs ([parsers/active/](parsers/active/)), OCSF 1.9 schema normalization, FastAPI server, and modern CLI remain in high-level Python.
- **Transparent Fallback**:
  - [core/vault.py](core/vault.py) and [core/attestation.py](core/attestation.py) dynamically inspect `ulpf_core_rs`. If the native extension is not compiled, the pipeline automatically falls back to pure Python (`zstandard`, `hashlib`, Python BLAKE3) with 100% cryptographic and byte-level equivalence.
- **Strict Air-Gap Guarantees**:
  - `rust_core` performs pure in-memory computation with zero network socket operations or external dependencies.

### Building the Rust Core
```bash
# Unix / Linux / macOS:
bash scripts/build_rust.sh

# Windows (PowerShell):
.\scripts\build_rust.ps1

# Or directly with maturin CLI:
pip install maturin
maturin develop --release --manifest-path rust_core/Cargo.toml
```

### Verification & Performance Benchmark
Verify the native module is active:
```bash
python -c "import ulpf_core_rs; print('Rust Core Active:', ulpf_core_rs.__file__)"
```

| Pipeline Component | Pure Python Fallback | Hybrid Rust Core (`ulpf_core_rs`) | Speedup |
|---|---|---|:---:|
| **Vault Block Compression (~1MiB chunks)** | 1.84 s | **0.37 s** | **5.0x** |
| **RFC 8785 JCS + BLAKE3 Hash Chaining (56k)** | 4.96 s | **0.14 s** | **35.4x** |
| **RFC 6962 Domain-Separated Merkle Root (1k)** | 12.8 ms | **0.08 ms** | **160.0x** |
| **End-to-End Pipeline Throughput (`Apache.log`)** | 2,510 EPS | **8,263+ EPS** | **3.3x** |
| **Raw Preservation & Traceability** | 100% Byte-Exact | **100% Byte-Exact** | **Identical** |

