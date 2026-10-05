# SIH26156 ULPF — Consolidated Evaluation & Technical Evidence Report
**Universal Log Pre-processing Framework (ULPF)**  
**Problem Statement ID:** SIH26156 | **Theme:** Blockchain & Cybersecurity | **Organization:** NTRO  
**Team:** LunarX *(Shortlisted in Internal Hackathon with SIH26166 ISRO)*  
**Evaluation Date:** 2026-09-28T19:21:49.138751+00:00  

---

## 📌 Executive Audit Summary & Metrics Classification

| Classification | Meaning | Key Metrics in this Report |
|---|---|---|
| **MEASURED** | Directly executed, clocked, and verified in this evaluation run | 28/28 Tests Passed, 100.0% Lossless Retention, 7,750 EPS Throughput, 799.39x Compression, Tamper Detection at Seq #42 |
| **SUPPORTED BY IMPLEMENTATION** | Architecturally enforced and validated by code logic | O(1) RawRef Block Retrieval, RFC 8785 JCS Determinism, Ed25519 Checkpoints, Offline 384-D Matcher, DuckDB Pushdown |
| **DESIGN TARGET** | Target operating envelope under production clustered deployment | Billion-Event/Day scale across distributed ingestion nodes |
| **NOT MEASURED** | Explicitly not measured due to controlled test harness constraints | Cloud egress bandwidth (intentionally 0 for air-gap) |

---

## 🖥️ 1. Environment & Hardware Baseline
- **Git Commit:** `257d12f27e4453616ad90f754e10ebec51bb3262` (modified)
- **Operating System:** `Windows-11-10.0.26200-SP0`
- **Python Version:** `3.13.9` (MSC v.1944 64 bit (AMD64))
- **CPU:** `Intel64 Family 6 Model 154 Stepping 3, GenuineIntel` (12 logical cores)
- **RAM:** `15.7 GB`
- **Crypto Libraries:** BLAKE3: `True`, Ed25519: `True`, Zstandard: `True`

---

## 🧪 2. Automated Test Suite Execution
```text
TESTS
Total:    28
Passed:   28
Failed:   0
Skipped:  0
Duration: 5.11 sec
Pass Rate: 100.0%
```
*Evidence Artifact:* [`evaluation/evidence/01_tests/test_run.txt`](evidence/01_tests/test_run.txt)

---

## 🛡️ 3. Lossless Byte-Exact Preservation (NTRO Core Requirement)
Tested across **10,000 events** spanning 6 distinct categories (Standard Vendor, Multiline Stacktraces, Special Escapes/Nulls, Multilingual Unicode [Hindi, Chinese, Arabic, Russian, Emojis], Unknown Proprietary, and Edge Cases [64KB, Empty, Single-Byte]):
- **Events Tested:** 10,000
- **Events Recovered from Disk:** 10,000
- **SHA-256 Matches:** 10,000
- **Mismatches / Corruptions:** 0
- **Recovery Failures:** 0
- **Measured Retention Success Rate:** **100.0000%**
- **Ingestion Write Rate:** 33,185 events/sec
- **Decompression Retrieval Rate:** 535 events/sec

*Evidence Artifact:* [`evaluation/evidence/02_lossless/lossless_report.txt`](evidence/02_lossless/lossless_report.txt)

---

## 🔄 4. OCSF 1.9 Normalization Validation
- **Corpus Events Tested:** 13
- **Normalized to OCSF 1.9:** 13
- **Valid OCSF Events:** 13
- **Validation Rate:** **100.0%**
- **RawRef Traceability Preservation:** **100.0%**
- **7-Stage Lineage Preservation:** **100.0%**

### Real Compact Ingestion Example (For SIH Presentation):
- **Raw Log:**  
  `Oct 12 10:14:22 web-01 sshd[12445]: Accepted password for root from 192.0.2.15 port 54322 ssh2`
- **Decoded Fields:**  
  `{"user": "root", "src_ip": "192.0.2.15", "src_port": "54322", "app": "sshd", "action": "Accepted"}`
- **OCSF Normalized:**  
  `{"version": "1.9.0", "class_uid": 3001, "class_name": "Authentication (3001)", "actor.user.name": "root", "src_endpoint.ip": "192.0.2.15", "src_endpoint.port": "54322", "fingerprint": "d3d719b176d9afce58926fbd6e94c753e369c20de5b149d33a9778e54e687388", "prev_hash": "genesis"}`
- **RawRef Locator:**  
  `ulpf:raw:0:0:0:94`
- **SHA-256 Digest:**  
  `a3f6d660d88d5f0b7bad67a41bc52977597a62254239169b71a77f715710baef`

*Evidence Artifact:* [`evaluation/evidence/03_ocsf/ocsf_report.txt`](evidence/03_ocsf/ocsf_report.txt)

---

## 🧩 5. Unknown-Vendor & Zero-Code Onboarding Evaluation
- **Input Unknown Log:** `VENDOR-X|9921|CRIT|disk_array_2|temp=88C|status=degrading`
- **Drain3 Clustering Template:** `VENDOR-X|<NUM>|CRIT|disk_array_2|temp=88C|status=degrading`
- **Field Matching Engine:** *Deterministic/offline 384-dimensional telemetry-aware field matching*
- **Measured Confidence Scores:**
  - `status` -> `activity_name` (Confidence: **0.94** -> Decision: `AUTO_MAP`)
  - `temp` -> `custom.vendor_x.temp` (Confidence: **0.2914** -> Decision: `CUSTOM_FALLBACK`)
- **Confidence Routing Bands:**
  - `AUTO_MAP` (>= 0.85): Direct promotion into active normalization pipeline
  - `HUMAN_REVIEW` (0.60 - 0.85): Routed to Human-in-the-Loop review queue
  - `CUSTOM_FALLBACK` (< 0.60): Preserved under `custom.<vendor>.<field>`
- **HITL Hot Promotion:** Approved `client_node` -> `src_endpoint.ip` without restart (`restart_required: False`).

*Evidence Artifact:* [`evaluation/evidence/04_unknown_vendor/unknown_vendor_report.txt`](evidence/04_unknown_vendor/unknown_vendor_report.txt)

---

## 🎯 6. Telemetry Vector Matcher Precision
Evaluated against **30 labeled field mappings**:
- **Top-1 Accuracy:** **86.7%**
- **Top-3 Accuracy:** **86.7%**
- **Mean Confidence:** **0.873**
- **Auto-Map Rate:** 86.7%
- **Human Review Queue Rate:** 0.0%
- **Custom Fallback Rate:** 13.3%

*Evidence Artifact:* [`evaluation/evidence/05_vector_matcher/vector_matcher_report.txt`](evidence/05_vector_matcher/vector_matcher_report.txt)

---

## ⛓️ 7. Cryptographic Integrity & Attestation
- **Events Evaluated:** 2,000
- **Canonical Serialization:** RFC 8785 JSON Canonicalization Scheme (JCS)
- **Hash Chain:** BLAKE3 Continuous Hash Chaining ($H_N = \text{BLAKE3}(JCS(E_N) \parallel H_{N-1})$)
- **Chain Verification Result:** **PASS (Cryptographically Verified)**
- **Chain Verification Speed:** **90,330 checks/sec**
- **Ed25519 Checkpoint Signatures:** **PASS (Valid)**

*Evidence Artifact:* [`evaluation/evidence/06_integrity/integrity_report.txt`](evidence/06_integrity/integrity_report.txt)

---

## 🚨 8. Live Tamper Detection Experiment
```text
BEFORE ATTACK:
  Chain Status: VALID [PASS] (Verified across 100 events)

TAMPER INJECTION:
  Event Modified: Sequence #42
  Field:          src_endpoint.ip (192.0.2.42 -> 198.51.100.99)

AFTER ATTACK:
  Endpoint:       /verify or client.verify_chain()
  Chain Status:   INVALID [TAMPER DETECTED]
  First Broken:   Sequence #42
  Message:        Tamper detected at seq=42: recalculated fingerprint 'ced9218aa478d6c24371098ec815ad2105d39bbf72acbc8281de9c76a48264c3' does not match stored fingerprint 'dca8e5703b8644b41fb2d528e0690db9846ad1253ac6a9163ade07bb53923be4'
```

*Evidence Artifact:* [`evaluation/evidence/07_tamper/tamper_report.txt`](evidence/07_tamper/tamper_report.txt)

---

## 🌳 9. RFC 6962 Merkle Inclusion Proof
- **Standard:** RFC 6962 Certificate Transparency
- **Tree Size:** 1,000 leaves
- **Merkle Root:** `76a730dcb4702f40a7b2f67bf402953d3bf1b315b0693c296fe54c4b976845df`
- **Proof Sibling Hashes:** **10** (Exact $\lceil \log_2(1000) \rceil = 10$)
- **Proof Generation Latency:** 0.014 ms
- **Verification Status:** **PASS (Mathematically Proven)**

*Evidence Artifact:* [`evaluation/evidence/08_merkle/merkle_report.txt`](evidence/08_merkle/merkle_report.txt)

---

## 💥 10. Crash Recovery / Forensic Vault Recovery
- **Events Written to Raw Vault:** 1,500
- **Failure Emulated:** Abrupt process termination / complete memory loss
- **Header Scanned:** 32-byte binary block headers (`ULPF_V1`) + CRC-32 validation
- **Reconstructed Index Blocks:** 1
- **Events Recovered:** **1,500 / 1,500 (100.0%)**
- **Events Lost:** **0**
- **Recovery Time:** 0.004s

*Evidence Artifact:* [`evaluation/evidence/09_crash_recovery/crash_recovery_report.txt`](evidence/09_crash_recovery/crash_recovery_report.txt)

---

## 🔒 11. Air-Gapped Deployment Validation
- **External HTTP Connections:** 0
- **External HTTPS Connections:** 0
- **External API Calls:** 0
- **Socket Leaks:** 0
- **External Dependency Downloads:** 0
- **Result:** **PASS (100% Offline Air-Gapped)**

*Evidence Artifact:* [`evaluation/evidence/10_airgap/airgap_report.txt`](evidence/10_airgap/airgap_report.txt)

---

## ⚡ 12. Multi-Scale Ingestion & Performance Benchmark

| Batch Events | Raw Bytes | Vault Bytes | Compression Ratio | Ingestion (EPS) | Throughput (MB/s) | Chain Verify (eps) | DuckDB Query (ms) | Merkle Proof (ms) |
|---|---|---|---|---|---|---|---|---|
| **1,000** | 167,125 | 877 | **190.56x** | **6,003** | 0.96 | 12,985 | 15.10 | 7.06 |
| **5,000** | 835,625 | 1,050 | **795.83x** | **6,713** | 1.07 | 17,750 | 74.24 | 70.81 |
| **15,000** | 2,506,875 | 3,136 | **799.39x** | **7,750** | 1.24 | 15,984 | 247.27 | 67.75 |
| **30,000** | 5,013,750 | 5,445 | **920.8x** | **6,870** | 1.09 | 15,048 | 59.26 | 132.52 |

### Throughput & Scale Analysis:
- **Measured Single-Instance Peak EPS:** **7,750 Events / sec** (1.24 MB/sec)
- **Theoretical Single-Instance Daily Capacity:** **669,621,959 Events / Day** (Calculated as $\text{measured EPS} \times 86,400$ under benchmark conditions)
- **Billion-Event Statement:** *Architecture designed for billion-event/day scale via horizontal node partitioning.*
- **Measured Compression Ratio:** **799.39x** on heterogeneous test corpus.
- **DuckDB Analytical Query Latency:** **247.27 ms** (with predicate pushdown).
- **RFC 6962 Proof Generation:** **67.75 ms**.

*Evidence Artifacts:*  
- [`evaluation/benchmark_results.csv`](benchmark_results.csv)  
- [`evaluation/benchmark_results.json`](benchmark_results.json)  
- [`evaluation/evidence/11_benchmark/benchmark_report.txt`](evidence/11_benchmark/benchmark_report.txt)

---

## 🛡️ 13. Security & Integrity Validation Matrix

| Security / Integrity Control | Specification & Implementation | Measured Result |
|---|---|---|
| **Raw SHA-256 Verification** | End-to-end payload hash comparison | **PASS** (100.0% match) |
| **CRC-32 Block Validation** | Hardware-accelerated block checksum | **PASS** |
| **Hash-Chain Verification** | RFC 8785 JCS + BLAKE3 continuous chain | **PASS** (90,330 checks/sec) |
| **Merkle Proof Verification** | RFC 6962 audit paths in $\lceil \log_2 N \rceil$ hashes | **PASS** (Midpoint verified) |
| **Ed25519 Checkpoint** | Digital signature over (chain_head + Merkle root) | **PASS** (Signature valid) |
| **Tamper Detection** | Instant chain break flag at exact sequence | **PASS** (Flagged seq #42) |
| **Air-Gap Network Isolation** | Strict zero socket egress guarantee | **PASS** (0 external sockets) |
| **Crash Recovery** | Header scanning without database reliance | **PASS** (100% recovered, 0 lost) |

---

## ⚠️ 14. Measured Facts vs Qualified Claims

| Claim in Prior Literature | Qualified Technical Assessment | Status |
|---|---|---|
| *"1B/day Ready"* | **Qualified:** Architecture designed for billion-event/day scale; measured single-instance capacity is 669,621,959 events/day under benchmark conditions. | **QUALIFIED** |
| *"550x Compression"* | **Measured:** Measured 799.39x compression on repetitive/structured benchmark batches. Variable depending on log entropy. | **MEASURED** |
| *"Zero-Knowledge Proof"* | **Corrected:** Implements **RFC 6962 Merkle inclusion proofs** (not zk-SNARK/zk-STARK). | **CORRECTED** |
| *"100% Lossless"* | **Measured:** 100.0% exact byte retrieval validated over 10,000 events. | **MEASURED** |
| *"Forensic Admissibility"* | **Corrected:** Provides cryptographically verifiable forensic provenance and chain-of-custody integrity. | **CORRECTED** |
| *"90% Parser Reduction"* | **Replaced:** Replaced with implementation facts: declarative YAML source packs hot-reload in 400ms without server restarts. | **REPLACED** |

---
**Report generated automatically by `evaluation/run_evaluation.py`.**
