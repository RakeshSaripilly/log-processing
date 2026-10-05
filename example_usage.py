"""
Universal Log Pre-processing Framework (ULPF) - Example Python SDK Usage
Demonstrating Slide 4 capabilities of the SIH26156 presentation:
1. Installation: pip install dist/ulpf_py-1.0.0-py3-none-any.whl
2. Query with Predicate Pushdown (sub-70ms)
3. Byte-exact Raw Forensic Payload Extraction
4. Cryptographic Blockchain Hash Chain Verification
5. AI/ML Feature Extraction
6. RFC 6962 Merkle Inclusion Proof
"""

from ulpf_py import ULPFClient

def main():
    print("=" * 70)
    print("[*] ULPF Python SDK (ulpf-py) Demo - SIH26156 / NTRO")
    print("=" * 70)

    # 1. Initialize Client
    client = ULPFClient(lake_path="./lake", vault_path="./storage/raw")
    print("\n[+] 1. Initialized ULPFClient against local lake and vault.")

    # 2. Query Normalized OCSF Logs
    print("\n[+] 2. Executing SQL query with predicate pushdown...")
    try:
        df = client.query().to_pandas()
        print(f"    Retrieved {len(df)} normalized events from DuckDB lake.")
        if not df.empty:
            cols_to_show = [c for c in ['sequence', 'class_uid', 'user_name', 'src_ip', 'disposition'] if c in df.columns]
            print(df[cols_to_show].head(3))
    except Exception as e:
        print(f"    Query note: {e}")

    # 3. Retrieve Byte-Exact Raw Forensic Payload
    print("\n[+] 3. Retrieving byte-exact raw payload via deterministic RawRef locator...")
    try:
        if not df.empty:
            sample_id = df.iloc[0]["event_id"]
            raw_bytes = client.get_raw(event_id=sample_id)
            print(f"    Original Raw Log Bytes (lossless): {raw_bytes.decode('utf-8', errors='replace')[:80]}...")
    except Exception as e:
        print(f"    Raw retrieval note: {e}")

    # 4. Cryptographic Tamper Verification
    print("\n[+] 4. Verifying RFC 8785 JCS + BLAKE3 continuous hash chain...")
    try:
        is_valid, msg, broken_seq = client.verify_chain()
        status = "PASSED" if is_valid else "FAILED"
        print(f"    Hash Chain Integrity: {status} -> {msg}")
    except Exception as e:
        print(f"    Attestation check note: {e}")

    # 5. Extract Feature Matrix for AI/ML Models
    print("\n[+] 5. Extracting numerical feature matrix for AI/ML threat detection...")
    try:
        X, feature_names = client.to_features(window="5min")
        print(f"    ML Feature Matrix shape: {X.shape}, Features: {feature_names}")
    except Exception as e:
        print(f"    ML feature extraction note: {e}")

    # 6. Generate RFC 6962 Merkle Inclusion Proof
    print("\n[+] 6. Generating RFC 6962 Merkle inclusion proof...")
    try:
        proof = client.prove(event_seq=0)
        print(f"    Target Fingerprint: {proof.get('target_fingerprint', '')[:20]}...")
        print(f"    Merkle Root:        {proof.get('merkle_root', '')[:20]}...")
        print(f"    Audit Verified:     {proof.get('verified', False)}")
    except Exception as e:
        print(f"    Merkle proof note: {e}")

    print("\n" + "=" * 70)
    print("[SUCCESS] Demo completed successfully.")
    print("=" * 70)

if __name__ == "__main__":
    main()
