"""
Universal Log Pre-processing Framework (ULPF) - End-to-End Performance Benchmark
Measures:
1. EPS (Events Per Second) throughput for single collector pipeline
2. Compression ratio in zstd Vault
3. Cryptographic hash chain calculation latency
4. Parquet & DuckDB analytical query latency
Team LunarX - SIH26156 (NTRO)
"""

import sys
from pathlib import Path

# Add project root to Python module search path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import time
import shutil
from core.pipeline import ProcessingPipeline
from ulpf_py.client import ULPFClient

BENCHMARK_DIR = Path("./benchmarks/data")


def run_benchmark(event_count: int = 5000):
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

    print(f"\n=======================================================")
    print(f" ULPF PERFORMANCE BENCHMARK (Target: {event_count} Events)")
    print(f"=======================================================")

    t0 = time.perf_counter()
    total_raw_bytes = 0
    for i in range(event_count):
        raw_log = sample_logs[i % len(sample_logs)]
        total_raw_bytes += len(raw_log.encode('utf-8'))
        pipeline.process_raw(raw_log)

    pipeline.vault.flush()
    elapsed = time.perf_counter() - t0

    eps = event_count / elapsed
    mbps = (total_raw_bytes / (1024 * 1024)) / elapsed

    print(f"[+] Ingestion Completed in {elapsed:.2f}s")
    print(f"[*] Throughput (EPS): {eps:,.0f} Events / sec")
    print(f"[*] Throughput (MB/s): {mbps:.2f} MB / sec")

    # Vault Compression Ratio
    vault_files = list(vault_dir.glob("vault_seg_*.ulpf"))
    compressed_bytes = sum(f.stat().st_size for f in vault_files)
    ratio = total_raw_bytes / compressed_bytes if compressed_bytes > 0 else 1.0
    print(f"[*] Raw Bytes: {total_raw_bytes:,} | Compressed Vault: {compressed_bytes:,} | Ratio: {ratio:.2f}x")

    # Cryptographic Chain Verification Benchmark
    client = ULPFClient(lake_path=str(lake_dir), vault_path=str(vault_dir))
    t_v0 = time.perf_counter()
    is_valid, msg, broken_seq = client.verify_chain(start_seq=0, end_seq=event_count - 1)
    t_v = time.perf_counter() - t_v0
    print(f"[*] Chain Verification: {is_valid} ({msg}) across {event_count} events in {t_v:.3f}s ({(event_count / t_v):,.0f} checks/sec)")

    # Analytical Query Benchmark (DuckDB predicate pushdown)
    t_q0 = time.perf_counter()
    df = client.query(where="src_endpoint.ip='192.0.2.14'").to_pandas()
    t_q = time.perf_counter() - t_q0
    print(f"[*] DuckDB Query Latency: {t_q * 1000:.2f} ms (Retrieved {len(df)} matching records)")

    # RFC 6962 Merkle Inclusion Proof Benchmark
    t_m0 = time.perf_counter()
    proof = client.prove(event_seq=event_count // 2)
    t_m = time.perf_counter() - t_m0
    print(f"[*] Merkle Inclusion Proof at Seq {event_count // 2}: {proof['verified']} ({len(proof['inclusion_proof'])} hashes) generated in {t_m * 1000:.2f} ms")

    client.close()
    pipeline.lake.close()
    shutil.rmtree(BENCHMARK_DIR, ignore_errors=True)
    print(f"=======================================================\n")


if __name__ == "__main__":
    run_benchmark(3000)
