"""
Unit tests for Cryptographic Attestation, Hash Chain, Merkle Tree, and Ed25519 Signatures
Team LunarX - SIH26156 (NTRO)
"""

from core.integrity import jcs_canonicalize, compute_fingerprint, verify_chain
from core.checkpoint import MerkleTree, KeyManager


def test_rfc8785_jcs_canonicalization():
    # Key sorting and whitespace elimination
    data = {"b": 2, "a": 1, "nested": {"z": 10, "y": 20}}
    canonical = jcs_canonicalize(data)
    # Must sort keys lexicographically and remove spaces
    assert canonical == b'{"a":1,"b":2,"nested":{"y":20,"z":10}}'


def test_hash_chain_creation_and_verification():
    events = [
        {"class_uid": 4001, "src_ip": "192.0.2.10", "sequence": 0},
        {"class_uid": 4001, "src_ip": "192.0.2.11", "sequence": 1},
        {"class_uid": 3001, "src_ip": "192.0.2.12", "sequence": 2},
    ]

    prev_fp = "genesis"
    for e in events:
        fp, _ = compute_fingerprint(e, prev_hash=prev_fp)
        e["fingerprint"] = fp
        e["prev_hash"] = prev_fp
        prev_fp = fp

    # Verify untampered chain
    is_valid, msg, broken_seq = verify_chain(events)
    assert is_valid is True
    assert broken_seq is None


def test_rfc6962_merkle_tree_inclusion_proof():
    fingerprints = [f"fp_{i:04d}_{'a'*32}" for i in range(16)]
    tree = MerkleTree(fingerprints)
    root = tree.root

    assert len(root) == 64  # SHA-256 hex digest

    # Generate proof for index 5
    target_idx = 5
    target_fp = fingerprints[target_idx]
    proof = tree.get_inclusion_proof(target_idx)

    # ceil(log2 16) = 4 hashes
    assert len(proof) == 4

    # Verify inclusion proof independently
    verified = MerkleTree.verify_inclusion_proof(
        target_fp=target_fp,
        index=target_idx,
        total_leaves=len(fingerprints),
        proof=proof,
        expected_root=root
    )
    assert verified is True


def test_ed25519_checkpoint_signature():
    km = KeyManager()
    chain_head = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    merkle_root = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"

    cp = km.sign_checkpoint(chain_head, merkle_root, checkpoint_seq=1000)
    assert cp["algorithm"] == "Ed25519"
    assert "signature" in cp
    assert KeyManager.verify_checkpoint(cp) is True

    # Tamper with checkpoint
    cp_tampered = dict(cp)
    cp_tampered["merkle_root"] = "ff" * 32
    assert KeyManager.verify_checkpoint(cp_tampered) is False
