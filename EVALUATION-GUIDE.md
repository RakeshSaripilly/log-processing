# ULPF Evaluation & Audit Verification Guide
**Universal Log Pre-processing Framework (ULPF)**  
**Problem Statement ID:** SIH26156 | **Theme:** Blockchain & Cybersecurity | **Organization:** NTRO  
**Team:** LunarX (Idea 2 — Shortlisted in Internal Hackathon with SIH26166 ISRO)

---

## 🚀 Quick Verification (3 Steps)

### Step 1: Run Full Automated Verification Suite
```bash
python -m pytest tests -v
```
**Expected Output:** `28 passed in ~4s` (100% pass across Vault, 10 Decoders, Vector Matcher, Attestation, Tamper Detection, Merkle Proofs, ulpf-py, Air-Gap).

### Step 2: Run Master Reproducible Evaluation Suite
```bash
python evaluation/run_evaluation.py
```
**Expected Output:**
- Lossless Byte Retention: **10,000 / 10,000 SHA-256 matches (100.0%)**
- Vault Compression: **Measured >800x ratio** on structured batch corpus
- Chain Verification: **>14,000 checks/sec**
- DuckDB Predicate Pushdown Query: **<75 ms**
- RFC 6962 Merkle Inclusion Proof: **10 hashes (<75 ms)**
- Air-Gap Sockets: **0 External Connections (PASS)**
- Master Report generated at: `evaluation/MASTER_RESULTS.md` and `evaluation/ppt_metrics.json`

### Step 3: Launch Live Interactive Control Console
```bash
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```
Open your browser at `http://localhost:8000`.

---

## 🎯 6 Ways to Try to "Catch Us Out" (And Why We Pass)

### 1. "Can you retrieve the exact raw log bytes without loss?"
- **Test:** Ingest any malformed or unusual log string with weird spacing or trailing characters. Then call `client.get_raw(event_id)`.
- **Why We Pass:** We enforce **Write-Before-Parse**. Raw bytes are written to append-only zstd blocks with CRC-32 checksums before parsing begins. Every event carries a deterministic `ulpf:raw:<seg>:<off>:<len>` locator in `unmapped.ulpf_raw_locator`. The retrieved bytes match the original input byte-for-byte, down to trailing newlines.

### 2. "If the analytical database crashes or index gets corrupted, is raw data lost?"
- **Test:** Delete all database files or indices, leaving only the `.ulpf` segment files in `storage/raw/`.
- **Why We Pass:** Segment index is an optimization, **not** the source of truth. Running `VaultStorage.recover_index()` scans the 32-byte block headers (`ULPF_V1`), validates CRC-32 checksums, and fully reconstructs the segment index in memory.

### 3. "Can an insider or attacker modify an event in the lake without detection?"
- **Test:** Click **"Inject Tamper & Verify Chain"** on the Web Console or call `POST /tamper-test` with `{"sequence": 5, "field_to_corrupt": "src_ip", "tampered_value": "198.51.100.99"}`.
- **Why We Pass:** Events are bound in an RFC 8785 JCS canonical hash chain: Event $N$ includes `prev_hash = Hash(N-1)`. When event 5 is corrupted, recalculating its RFC 8785 canonical fingerprint yields a mismatch (`stored != calculated`), immediately failing verification and reporting the exact sequence `5`.

### 4. "How do you prove an event was logged to an external auditor without leaking all logs?"
- **Test:** Run `client.prove(event_seq=X)` or `GET /prove/{seq}`.
- **Why We Pass:** RFC 6962 Merkle Tree: leaves are $H(\text{0x00} + \text{fp})$, internal nodes are $H(\text{0x01} + L + R)$. The verifier receives $\lceil \log_2 N \rceil$ sibling hashes and computes the root without seeing any other log in the tree.

### 5. "Does your vector matcher require external LLM API calls or leak data over the internet?"
- **Test:** Run `python -m pytest tests/test_airgap.py -v`.
- **Why We Pass:** Our Telemetry-Aware Vector Matcher uses an offline 384-dimensional semantic projection against canonical OCSF 1.9 schema tokens. No external API, no OpenAI keys, no HuggingFace downloads on hot paths, and zero network socket leaks.

### 6. "What happens when a completely unknown proprietary log arrives?"
- **Test:** Ingest `VENDOR-X|9921|CRIT|disk_array_2|temp=88C|status=degrading`.
- **Why We Pass:** Zero logs are ever dropped.
  1. Drain3 clusters the message into `<*>` templates and computes token specificity.
  2. Salvage decodes universal security observables (IPs, ports, URLs, hashes).
  3. The vector matcher assigns confidence: $>0.85$ auto-maps, $0.60 - 0.85$ routes to Human Review Queue, $<0.60$ preserves under `custom.<vendor>.<field>`.
