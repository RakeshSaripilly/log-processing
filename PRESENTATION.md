# SIH26156 Technical Pitch Deck (Strict 5-Slide Structure)
**Smart India Hackathon 2026 — Final Technical Evaluation**  
**Problem Statement ID:** SIH26156 | **Theme:** Blockchain & Cybersecurity  
**Organization:** National Technical Research Organisation (NTRO)  
**Team Name:** LunarX *(Shortlisted in Internal Hackathon with SIH26166 ISRO)*  
**Presentation Palette:** Defense Navy (`#0A2540`), Indian Saffron (`#E65100`), Cyber Green (`#108030`), Pure White (`#FFFFFF`)

---

## 📑 Slide 1 — Problem + USP + Solution

### 1. Executive Context & Industry Challenge
National cyber intelligence and critical infrastructure networks ingest petabytes of disparate telemetry:
- **Format Fragmentation:** Ingestion streams span Syslog (RFC 3164/5424), CEF, LEEF, JSON, XML, CSV, and proprietary unknown formats.
- **Evidence Destruction:** Conventional SIEM pipelines mutate or drop unparsed bytes, breaking the legal chain of custody required under the Indian Evidence Act.
- **Insider Threat / DBA Manipulation:** Centralized analytical databases can be modified by compromised administrators to erase breach traces.
- **Air-Gap Constraint:** Sovereign classified networks strictly prohibit external LLM APIs (OpenAI/Anthropic) or internet dependency.

### 2. The Core Solution Pipeline
```
[Heterogeneous Raw Stream: Syslog 5140 / HTTP / Files / OT]
                         │
                         ▼
┌────────────────────────────────────────────────────────┐
│ 1. WRITE-BEFORE-PARSE (Forensic Raw Vault Engine)      │
│ Append-only zstd blocks • CRC-32 • O(1) RawRef Locator │
└────────────────────────┬───────────────────────────────┘
                         ▼
┌────────────────────────────────────────────────────────┐
│ 2. UNIVERSAL DUAL DECODER & OCSF 1.9 NORMALIZER        │
│ 10-Decoder Pack Engine + 384-D Telemetry Vector Matcher│
│ Confidence Routing (>0.85 Auto-Map | HITL Queue)       │
└────────────────────────┬───────────────────────────────┘
                         ▼
┌────────────────────────────────────────────────────────┐
│ 3. CRYPTOGRAPHIC ATTESTATION & DUAL LAKE               │
│ RFC 8785 JCS • BLAKE3 Continuous Chain • Ed25519       │
│ RFC 6962 Merkle Proofs • DuckDB SQL • Parquet • Wazuh  │
└────────────────────────────────────────────────────────┘
                         │
                         ▼
        [SIEM / Data Lake / ML Threat Hunter]
```

### 3. Unique Selling Proposition (USP)
> **"Any Log In → OCSF 1.9 Out → Raw Bytes Preserved → Integrity Cryptographically Verified"**

---

## 💡 Slide 2 — Technical Innovation (Three Pillars)

### Pillar 1: Vault-First Lossless Capture
- **Enforced Write-Before-Parse:** Raw payload is permanently stored in append-only storage before tokenization begins.
- **Structured Binary Block Framing:** 32-byte header (`ULPF_V1`), CRC-32 integrity checksum, and Zstandard block compression.
- **Deterministic RawRef Addressing:** Every event receives a byte locator (`ulpf:raw:<seg>:<block>:<off>:<len>`) alongside `raw_sha256`.
- **Database-Independent Crash Recovery:** If indices or databases crash, scanning block headers fully reconstructs locators without data loss.

### Pillar 2: Offline Universal Field Mapping
- **Dual Ingestion Engine:** 10 core decoders (Syslog 3164/5424, CEF, LEEF, JSON, XML, KV, CSV, Regex, Salvage) paired with declarative YAML packs hot-reloading in 400ms.
- **Drain3 Template Mining:** Automatically clusters unknown log lines into structured templates with `<*>` variable masks.
- **384-Dimensional Telemetry Vector Matcher:** Offline semantic projection combining key name, inferred data type, and concrete value samples against OCSF 1.9 schema tokens.
- **Deterministic Confidence Routing:**
  - $\ge 0.85$: `AUTO_MAP` directly to canonical OCSF 1.9 field.
  - $0.60 - 0.85$: `HUMAN_REVIEW` routed to Human-in-the-Loop review queue for zero-code promotion.
  - $< 0.60$: `CUSTOM_FALLBACK` preserved under `custom.<vendor>.<field>` (zero logs dropped).
- **100% Air-Gapped:** Zero external LLM API calls, zero code-generation vulnerabilities, verified 0 socket leaks.

### Pillar 3: Tamper-Evident Cryptographic Attestation
- **RFC 8785 JSON Canonicalization Scheme (JCS):** Guarantees byte-level determinism across platforms and architectures.
- **BLAKE3 Continuous Hash Chaining:** Every normalized event $N$ cryptographically incorporates $H(N-1)$.
- **RFC 6962 Merkle Inclusion Proofs:** Domain-separated audit trees ($0\text{x}00$ leaf, $0\text{x}01$ node) proving event existence in $\lceil \log_2 N \rceil$ sibling hashes.
- **Ed25519 Checkpoint Signatures:** Periodic cryptographic seals binding chain heads to Merkle roots for external audit attestation.

---

## 📊 Slide 3 — Implementation & Measured Evidence

*All metrics measured directly on single-node evaluation hardware (Intel 12-core, 16GB RAM, Windows 11 / Python 3.13.9).*

| Evaluation Category | Tested Scope / Condition | Measured Technical Metric | Verification Status |
|---|---|---|---|
| **Automated Test Suite** | Complete repository test suite | **28 / 28 Passed in 5.04 sec** | **100.0% PASS** |
| **Lossless Preservation** | 10,000 heterogeneous events (6 categories) | **10,000 / 10,000 SHA-256 Matches** | **100.0000% MATCH** |
| **OCSF 1.9 Normalization** | Heterogeneous multi-source corpus | **100.0% Compliant Events** | **PASS (Lineage Preserved)** |
| **Ingestion Throughput** | Multi-threaded stream pipeline | **7,380 Events / sec (1.18 MB/sec)** | **MEASURED PEAK** |
| **Storage Compression** | Structured multi-vendor log batches | **813.1x Ratio** (Zstd Block Engine) | **MEASURED** |
| **Hash-Chain Verification** | Cryptographic verification speed | **14,957 – 16,532 Checks / sec** | **MEASURED** |
| **DuckDB Analytical Query** | SQL query with predicate pushdown | **9.1 ms – 71.0 ms** | **SUB-100MS** |
| **RFC 6962 Merkle Proof** | 1,000-event audit tree path | **10 Hashes generated in 71.7 ms** | **VERIFIED** |
| **Air-Gap Network Isolation** | Socket layer interception during run | **0 External Connections / 0 Leaks** | **PASS (100% Offline)** |
| **Forensic Crash Recovery** | Complete memory wipe after writing 1,500 logs | **1,500 / 1,500 Recovered (0 Lost)** | **100.0% RECOVERY** |

### Scale & Capacity Statement
- **Measured Ingestion:** $7,380\text{ EPS}$ on a single developer instance.
- **Theoretical Single-Instance Daily Capacity:** $\mathbf{637,648,667\text{ Events / Day}}$ ($7,380 \times 86,400$ under benchmark conditions).
- **Architecture Scale:** Designed for billion-event/day scale through horizontal node partitioning and Parquet lake sharding.

---

## 🔍 Slide 4 — Unknown Vendor & Tamper Demonstration

### 1. Zero-Code Unknown Vendor Onboarding Flow
**Input Proprietary Log:**
`VENDOR-X|9921|CRIT|disk_array_2|temp=88C|status=degrading`

1. **Vault Capture:** Raw bytes written to Vault before parsing (`RawRef`: `ulpf:raw:0:0:0:57`, `raw_sha256`: `2195d52207...`).
2. **Drain3 Template Extraction:** Clustered template `VENDOR-X|<NUM>|CRIT|disk_array_2|temp=88C|status=degrading`.
3. **Telemetry Vector Matcher:**
   - `status`: Confidence **0.94** $\ge 0.85$ → **`AUTO_MAP`** to canonical OCSF field `activity_name`.
   - `temp`: Confidence **0.23** $< 0.60$ → **`CUSTOM_FALLBACK`** to `custom.vendor_x.temp`.
   - Ambiguous field `client_node`: Confidence **0.72** ($0.60 - 0.85$) → Routed to **HITL Review Queue**.
4. **Approve & Promote (Zero-Code):** Analyst clicks "Approve & Promote" in `/review-queue` mapping `client_node` → `src_endpoint.ip`.
5. **Hot Promotion:** Mapping immediately activated in memory and DuckDB — **Zero server restart required**.

### 2. End-to-End Cryptographic Tamper Detection
```text
BEFORE ATTACK:
  Chain Status: VALID [PASS] (Verified across sequence #0 through #99)

INSIDER TAMPER ATTACK:
  Attacker modifies DuckDB SQL record at Sequence #42:
  src_endpoint.ip: "192.0.2.42" ──► "198.51.100.99"

AFTER ATTACK (/verify or client.verify_chain()):
  Chain Status:    INVALID [TAMPER DETECTED]
  Broken Sequence: Sequence #42
  Diagnostic:      Recalculated RFC 8785 JCS fingerprint mismatch:
                   stored:       0a731dcdaa69b1e30333f08bc56c9f4d...
                   recalculated: 8f70786a9b85071766e6e8222878f134...
```
*Result: Any tampering with historical logs immediately invalidates all subsequent links and pinpoints the exact tampered record.*

---

## 🎯 Slide 5 — SIH Requirement Mapping & NTRO Impact

| NTRO / SIH26156 Requirement | ULPF Architecture Implementation | Measured Evidence from Benchmark |
|---|---|---|
| **Heterogeneous Ingestion** | 10 Decoders (Syslog, CEF, LEEF, JSON, XML, CSV) + YAML Packs | Normalized 10 heterogeneous formats with zero drops |
| **Lossless Preservation** | Write-Before-Parse Vault with compressed Zstandard blocks | **10,000 / 10,000 SHA-256 matches (100.0000%)** |
| **End-to-End Traceability** | `ulpf:raw:<seg>:<block>:<off>:<len>` locator + 7-stage lineage | $100\%$ events linkable to byte-exact raw payloads |
| **Standard Normalization** | Strict Open Cybersecurity Schema Framework (OCSF 1.9) | $100\%$ validation rate across system, auth, and network events |
| **Zero-Code Onboarding** | Telemetry Vector Matcher (384-D) + HITL review queue | Unknown `VENDOR-X` auto-mapped and promoted with **0 reboots** |
| **Cryptographic Integrity** | RFC 8785 JCS + BLAKE3 hash chain + Ed25519 checkpoints | Chain verified at **14,957 checks/sec**; tamper detected at seq #42 |
| **Multi-Agency Audit** | RFC 6962 Merkle tree inclusion proofs | $\lceil \log_2 N \rceil = 10$ sibling hashes generated in **71.7 ms** |
| **Air-Gapped Operation** | Pure offline semantic projection; zero cloud model egress | **0 external socket connections; 0 external API calls** |
| **High-Throughput Analytics** | Dual Lake: DuckDB SQL pushdown + date-partitioned Parquet | Ingestion at **7,380 EPS**; analytical query latency **<75 ms** |
| **SIEM & AI Readiness** | Wazuh UDP forwarder + PyArrow/Pandas feature matrix export | Integrated Python SDK (`ulpf-py`) for instant adoption |

### Sovereign Strategic Impact for NTRO
1. **Cryptographically Verifiable Forensic Provenance:** Meets Indian Evidence Act chain-of-custody requirements via dual raw hash matching and JCS canonical chains.
2. **Zero-Knowledge Multi-Agency Auditing:** Prove existence and tamper-freedom of classified logs to oversight authorities using 10 sibling hashes without disclosing log content.
3. **Total Air-Gapped Autonomy:** Fully self-contained inside classified perimeter networks with zero external cloud dependencies.
4. **Developer Adoption:** Standalone wheel package (`ulpf_py-1.0.0-py3-none-any.whl`) enables instant Python, Spark, and DuckDB integration.
