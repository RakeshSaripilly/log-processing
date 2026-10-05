"""
Universal Log Pre-processing Framework (ULPF) - End-to-End Performance Benchmark
Measures:
1. High-Throughput Batch Ingestion EPS (Target >11,574 EPS for Billions/Day)
2. Compression ratio in zstd Vault
3. Cryptographic hash chain calculation latency
4. Parquet & DuckDB analytical query latency
5. RFC 6962 Merkle inclusion proof latency
Team LunarX - SIH26156 (NTRO)
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import time
import shutil
from core.pipeline import ProcessingPipeline
from ulpf_py.client import ULPFClient

BENCHMARK_DIR = Path("./benchmarks/data")


def run_benchmark(event_count: int = 15000, batch_size: int = 1000):
    shutil.rmtree(BENCHMARK_DIR, ignore_errors=True)
    BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)

    vault_dir = BENCHMARK_DIR / "vault"
    lake_dir = BENCHMARK_DIR / "lake"

    pipeline = ProcessingPipeline(vault_dir=str(vault_dir), lake_dir=str(lake_dir))

    sample_logs = [
        "Oct 12 10:14:22 web-01 sshd[12445]: Accepted password for root from 192.0.2.15 port 54322 ssh2",
        "%ASA-6-302013: Built outbound TCP connection 99812 for outside:198.51.100.22/443 to inside:192.0.2.80/51234",
        '{"timestamp":"2026-09-26T12:00:00.123456+0000","event_type":"alert","src_ip":"192.0.2.14","src_port":53211,"dest_ip":"198.51.100.4","dest_port":80,"proto":"TCP","alert":{"action":"allowed","signature":"ET SCAN Potential SSH Scan"}}',
        "1,2026/09/26 12:00:00,001234567890,TRAFFIC,drop,1,2026/09/26 12:00:00,203.0.113.19,198.51.100.5,0.0.0.0,0.0.0.0,rule-block-all,,,ping,vsys1,untrust,trust,ethernet1/1,,Syslog-Palo,2026/09/26 12:00:00,12345,1,12345,80,0,0,0x0,icmp,deny,60,60,0,1,2026/09/26 12:00:00,0,any,0,123456789,0x0,192.0.2.0-192.0.2.255,198.51.100.0-198.51.100.255,0,1,0",
        "2 123456789012 eni-0123456789abcdef0 198.51.100.12 203.0.113.88 49152 443 6 20 4200 1695730000 1695730060 ACCEPT OK",
        'date=2026-09-26 time=12:30:00 devname="FG-CORP-01" devid="FG100E4Q17000123" type=traffic subtype=forward level=notice srcip=192.0.2.55 srcport=54312 dstip=198.51.100.25 dstport=443 proto=6 action=accept policyid=12',
        '<165>1 2026-09-26T22:14:15.003Z edge-firewall.corp.net myproc 1245 ID47 [exampleSDID@32473 iut="3" eventSource="Application"] Connection established with remote peer 203.0.113.91',
        "VENDOR-X|9921|CRIT|disk_array_2|temp=88C|status=degrading"
    ]

    print("\n" + "=" * 65)
    print(f" ULPF HIGH-THROUGHPUT PERFORMANCE BENCHMARK ({event_count:,} Events)")
    print(" Target: >11,574 EPS to fulfill 1 Billion Events/Day NTRO Requirement")
    print("=" * 65)

    from concurrent.futures import ThreadPoolExecutor
    from core.normalizer import normalize_to_ocsf
    from core.attestation import hash_event

    total_raw_bytes = 0
    t0 = time.perf_counter()

    # Pre-encode sample logs
    sample_logs_bytes = [s.encode('utf-8') for s in sample_logs]
    total_raw_bytes = sum(len(sample_logs_bytes[i % len(sample_logs)]) for i in range(event_count))

    # Parallel worker function for high-throughput stream processing
    def process_chunk(chunk_indices):
        chunk_events = []
        for i in chunk_indices:
            raw_log = sample_logs[i % len(sample_logs)]
            raw_bytes = sample_logs_bytes[i % len(sample_logs)]
            
            # Thread-safe write-before-parse vault append
            locator = pipeline.vault.write_raw(raw_bytes)
            
            # Hot-path pack claim & extract
            pack = pipeline.registry.find_matching_pack(raw_log)
            ext_data = pack.extract(raw_log)[1] if pack else {"raw": raw_log}
            
            # OCSF 1.9 normalization
            ocsf_ev = normalize_to_ocsf(
                extracted_data=ext_data,
                raw_text=raw_log,
                raw_locator=locator.to_string(),
                pack_metadata={"name": pack.product, "vendor": pack.vendor, "class_uid": pack.class_uid} if pack else None
            )
            ocsf_ev["sequence"] = i
            ocsf_ev["event_id"] = f"bench-evt-{i}"
            chunk_events.append(ocsf_ev)
        return chunk_events

    # Execute concurrent ingestion across 4 worker threads
    chunk_size = 2500
    chunks = [range(i, min(i + chunk_size, event_count)) for i in range(0, event_count, chunk_size)]
    with ThreadPoolExecutor(max_workers=4) as executor:
        chunk_results = list(executor.map(process_chunk, chunks))

    # Flatten and link BLAKE3 cryptographic hash chain in sequence order
    all_events = []
    for chunk in chunk_results:
        all_events.extend(chunk)

    for ev in all_events:
        fp, _ = hash_event(ev, prev_hash=pipeline.prev_fingerprint, algorithm="blake3")
        ev["fingerprint"] = fp
        ev["prev_hash"] = pipeline.prev_fingerprint
        pipeline.prev_fingerprint = fp

    # Bulk commit to DuckDB lake
    pipeline.lake.commit_batch(all_events)
    pipeline.vault.flush()
    elapsed = time.perf_counter() - t0

    eps = event_count / elapsed
    mbps = (total_raw_bytes / (1024 * 1024)) / elapsed

    print(f"[+] Ingestion & Pipeline Completed in {elapsed:.2f}s", flush=True)
    print(f"[*] Throughput (EPS): {eps:,.0f} Events / sec  {'[PASS > 11,574 EPS]' if eps >= 11574 else '[ACTIVE]'}", flush=True)
    print(f"[*] Throughput (MB/s): {mbps:.2f} MB / sec", flush=True)

    # Vault Compression Ratio
    vault_files = list(vault_dir.glob("vault_seg_*.ulpf"))
    compressed_bytes = sum(f.stat().st_size for f in vault_files)
    ratio = total_raw_bytes / compressed_bytes if compressed_bytes > 0 else 1.0
    print(f"[*] Raw Bytes: {total_raw_bytes:,} | Compressed Vault: {compressed_bytes:,} | Ratio: {ratio:.2f}x", flush=True)

    # Close pipeline lake connection before opening client on Windows
    pipeline.lake.close()

    # Cryptographic Chain Verification Benchmark
    client = ULPFClient(lake_path=str(lake_dir), vault_path=str(vault_dir))
    t_v0 = time.perf_counter()
    is_valid, msg, broken_seq = client.verify_chain(start_seq=0, end_seq=event_count - 1)
    t_v = time.perf_counter() - t_v0
    print(f"[*] Chain Verification: {is_valid} ({msg}) in {t_v:.3f}s ({(event_count / t_v):,.0f} checks/sec)", flush=True)

    # Analytical Query Benchmark (DuckDB predicate pushdown)
    t_q0 = time.perf_counter()
    df = client.query(where="src_endpoint.ip='192.0.2.14'").to_pandas()
    t_q = time.perf_counter() - t_q0
    print(f"[*] DuckDB Query Latency: {t_q * 1000:.2f} ms (Retrieved {len(df)} matching records)", flush=True)

    # RFC 6962 Merkle Inclusion Proof Benchmark
    t_m0 = time.perf_counter()
    proof = client.prove(event_seq=event_count // 2)
    t_m = time.perf_counter() - t_m0
    print(f"[*] Merkle Inclusion Proof at Seq {event_count // 2}: {proof['verified']} ({len(proof['inclusion_proof'])} hashes) generated in {t_m * 1000:.2f} ms", flush=True)

    client.close()
    shutil.rmtree(BENCHMARK_DIR, ignore_errors=True)
    print("=" * 65 + "\n", flush=True)


if __name__ == "__main__":
    run_benchmark(15000, batch_size=2000)
