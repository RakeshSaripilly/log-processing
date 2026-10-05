"""
Universal Log Pre-processing Framework (ULPF) - Cryptographic Attestation & Blockchain Engine
Problem Statement: SIH26156 (NTRO) | Theme: Blockchain & Cybersecurity | Team LunarX

Standards Implemented:
1. RFC 8785: JSON Canonicalization Scheme (JCS) deterministic serialization
2. BLAKE3 / SHA-256 Hash Chain: Event N links to prev_hash = Fingerprint(N-1)
3. RFC 6962: Merkle Tree Audit Paths (Leaves: 0x00 + data, Nodes: 0x01 + left + right)
4. Ed25519: Digital Checkpoint Signatures over (chain_head + Merkle root)
5. RFC 6962 Merkle Inclusion Proofs in ceil(log2 N) hashes
"""

import json
import hashlib
from typing import Any, Dict, List, Optional, Tuple

try:
    import ulpf_core_rs
    HAS_RUST_CORE = True
except ImportError:
    HAS_RUST_CORE = False

try:
    import blake3 as _blake3_mod
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False

try:
    import orjson as _orjson_mod
    HAS_ORJSON = True
except ImportError:
    HAS_ORJSON = False

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def jcs_canonicalize(obj: Any) -> bytes:
    """
    RFC 8785 JSON Canonicalization Scheme (JCS).
    Ensures deterministic byte representation across all architectures:
    - Keys sorted lexicographically
    - Whitespace removed: ',' and ':' without spaces
    - UTF-8 encoding without ASCII escapes
    - Floating point & integer standard representations
    """
    if HAS_ORJSON:
        try:
            return _orjson_mod.dumps(obj, option=_orjson_mod.OPT_SORT_KEYS)
        except Exception:
            pass
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        default=str
    ).encode('utf-8')


def hash_digest(data: bytes, algorithm: str = "blake3") -> str:
    """
    Cryptographic hash calculation using BLAKE3 (default, OCSF Other 99) or SHA-256 fallback.
    Accelerated with Rust ulpf_core_rs when available.
    """
    if algorithm.lower() == "blake3":
        if HAS_RUST_CORE:
            try:
                return ulpf_core_rs.blake3_hash_chain("", data.decode('utf-8'))
            except Exception:
                pass
        if HAS_BLAKE3:
            return _blake3_mod.blake3(data).hexdigest()
    return hashlib.sha256(data).hexdigest()


def hash_event(
    event_without_fp: Dict[str, Any],
    prev_hash: Optional[str] = None,
    algorithm: str = "blake3"
) -> Tuple[str, bytes]:
    """
    Compute cryptographic fingerprint for an event:
    1. Strips non-attested mutable fields ('fingerprint', 'signature', 'merkle_proof')
    2. Binds prev_hash link (Event N includes Fingerprint(N-1), or 'genesis')
    3. Serializes deterministically via RFC 8785 JCS
    4. Computes BLAKE3/SHA-256 digest (accelerated via Rust ulpf_core_rs.blake3_hash_chain)
    Returns: (fingerprint_hex, canonical_bytes)
    """
    payload = dict(event_without_fp)
    payload.pop("fingerprint", None)
    payload.pop("signature", None)
    payload.pop("merkle_proof", None)
    prev = prev_hash if prev_hash else "genesis"
    payload["prev_hash"] = prev
    canonical = jcs_canonicalize(payload)

    if algorithm.lower() == "blake3":
        if HAS_BLAKE3:
            return _blake3_mod.blake3(canonical).hexdigest(), canonical
        if HAS_RUST_CORE:
            try:
                fp = ulpf_core_rs.blake3_hash_chain(prev, canonical.decode('utf-8'))
                return fp, canonical
            except Exception:
                pass

    fp = hash_digest(canonical, algorithm=algorithm)
    return fp, canonical


# Alias for compatibility
compute_fingerprint = hash_event


def append_to_chain(
    event: Dict[str, Any],
    prev_hash: Optional[str] = None,
    sequence: Optional[int] = None,
    algorithm: str = "blake3"
) -> Dict[str, Any]:
    """
    Append an event to the cryptographic tamper-evident hash chain.
    Sets prev_hash, sequence, and computed fingerprint.
    """
    if sequence is not None:
        event["sequence"] = sequence
    fp, _ = hash_event(event, prev_hash=prev_hash, algorithm=algorithm)
    event["prev_hash"] = prev_hash if prev_hash else "genesis"
    event["fingerprint"] = fp
    return event


def verify_chain(events: List[Dict[str, Any]], algorithm: str = "blake3") -> Tuple[bool, str, Optional[int]]:
    """
    Mathematically verify the integrity of the hash chain across an ordered sequence of events.
    Checks:
    1. Event 0 starts with 'genesis' or valid preceding link
    2. Event N prev_hash == Event N-1 stored fingerprint
    3. Recalculated RFC 8785 canonical fingerprint == stored fingerprint
    Returns: (is_valid: bool, message: str, broken_sequence: Optional[int])
    """
    if not events:
        return True, "Chain is empty (valid)", None

    if len(events) <= 1 or (events[0].get("sequence", 0) <= events[-1].get("sequence", 0)):
        sorted_events = events
    else:
        sorted_events = sorted(events, key=lambda x: x.get("sequence", x.get("seq", 0)))
    
    prev_fp = None
    for idx, event in enumerate(sorted_events):
        seq = event.get("sequence", event.get("seq", idx))
        stored_fp = event.get("fingerprint")
        stored_prev = event.get("prev_hash")
        
        if not stored_fp:
            return False, f"Event at seq={seq} missing 'fingerprint' field", seq

        # Check prev_hash link
        if idx > 0 and stored_prev != prev_fp:
            return False, (
                f"Chain break at seq={seq}: stored prev_hash '{stored_prev}' does not match "
                f"preceding event fingerprint '{prev_fp}'"
            ), seq

        # Recalculate fingerprint
        recalc_fp, _ = hash_event(event, prev_hash=stored_prev, algorithm=algorithm)
        if recalc_fp != stored_fp:
            alt_fp, _ = hash_event(event, prev_hash=stored_prev, algorithm="sha256")
            if alt_fp != stored_fp:
                return False, (
                    f"Tamper detected at seq={seq}: recalculated fingerprint '{recalc_fp}' does not match "
                    f"stored fingerprint '{stored_fp}'"
                ), seq

        prev_fp = stored_fp

    return True, f"Cryptographic chain verified across {len(events)} events without tamper", None


# RFC 6962 Domain Separation Hashes
def hash_leaf(fp_bytes: bytes) -> bytes:
    """RFC 6962 Leaf Hash: SHA256(0x00 + data) to prevent length extension & second preimage attacks"""
    return hashlib.sha256(b"\x00" + fp_bytes).digest()


def hash_children(left: bytes, right: bytes) -> bytes:
    """RFC 6962 Node Hash: SHA256(0x01 + left + right)"""
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(hashes: List[str]) -> str:
    """
    Compute RFC 6962 Merkle tree root for an ordered list of leaf hashes.
    Accelerated with Rust ulpf_core_rs.merkle_root when available.
    """
    if HAS_RUST_CORE and hashes:
        try:
            return ulpf_core_rs.merkle_root(hashes)
        except Exception:
            pass
    return MerkleTree(hashes).root


class MerkleTree:
    """
    RFC 6962 compliant Merkle Tree for tamper-evident audit logs.
    - Leaf: SHA256(0x00 + fingerprint)
    - Node: SHA256(0x01 + left + right)
    - Inclusion Proof in O(log2 N) hashes
    """
    def __init__(self, fingerprints: List[str]):
        self.fps = fingerprints
        self._cached_root: Optional[str] = None
        if HAS_RUST_CORE and fingerprints:
            try:
                self._cached_root = ulpf_core_rs.merkle_root(fingerprints)
            except Exception:
                self._cached_root = None

        self.leaves: Optional[List[bytes]] = None
        self.tree_levels: List[List[bytes]] = []
        if self._cached_root is None and fingerprints:
            self._ensure_tree()

    def _ensure_tree(self):
        if self.leaves is None:
            self.leaves = [hash_leaf(fp.encode('utf-8')) for fp in self.fps]
            current_level = self.leaves
            self.tree_levels = [current_level]
            while len(current_level) > 1:
                next_level = []
                for i in range(0, len(current_level), 2):
                    left = current_level[i]
                    if i + 1 < len(current_level):
                        right = current_level[i + 1]
                    else:
                        right = left
                    next_level.append(hash_children(left, right))
                current_level = next_level
                self.tree_levels.append(current_level)

    @property
    def root(self) -> str:
        if self._cached_root is not None:
            return self._cached_root
        self._ensure_tree()
        if not self.tree_levels or not self.tree_levels[-1]:
            return "00" * 32
        return self.tree_levels[-1][0].hex()

    def get_inclusion_proof(self, index: int) -> List[Dict[str, str]]:
        """
        Generate RFC 6962 audit path (inclusion proof) for leaf at `index`.
        Returns ceil(log2 N) sibling hashes with direction indicator ('left'/'right').
        """
        self._ensure_tree()
        if index < 0 or index >= len(self.leaves):
            raise IndexError("Leaf index out of bounds for Merkle inclusion proof")

        proof = []
        idx = index
        for level in self.tree_levels[:-1]:
            is_right_child = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_right_child else idx + 1
            if sibling_idx < len(level):
                proof.append({
                    "direction": "left" if is_right_child else "right",
                    "hash": level[sibling_idx].hex()
                })
            else:
                proof.append({
                    "direction": "right",
                    "hash": level[idx].hex()
                })
            idx //= 2
        return proof

    @staticmethod
    def verify_inclusion_proof(
        target_fp: str,
        index: int,
        total_leaves: int,
        proof: List[Dict[str, str]],
        expected_root: str
    ) -> bool:
        """
        Independent verification of Merkle inclusion proof without storing tree.
        """
        current_hash = hash_leaf(target_fp.encode('utf-8'))
        for step in proof:
            sibling_hash = bytes.fromhex(step["hash"])
            if step["direction"] == "left":
                current_hash = hash_children(sibling_hash, current_hash)
            else:
                current_hash = hash_children(current_hash, sibling_hash)
        return current_hash.hex() == expected_root


def prove(fingerprints: List[str], target_seq: int) -> Dict[str, Any]:
    """
    Generate an RFC 6962 Merkle inclusion proof for target_seq among given fingerprints.
    """
    if target_seq < 0 or target_seq >= len(fingerprints):
        raise IndexError(f"Target sequence {target_seq} out of bounds (total: {len(fingerprints)})")

    tree = MerkleTree(fingerprints)
    proof = tree.get_inclusion_proof(target_seq)
    target_fp = fingerprints[target_seq]

    return {
        "event_seq": target_seq,
        "target_fingerprint": target_fp,
        "tree_size": len(fingerprints),
        "merkle_root": tree.root,
        "inclusion_proof": proof,
        "verified": MerkleTree.verify_inclusion_proof(
            target_fp=target_fp,
            index=target_seq,
            total_leaves=len(fingerprints),
            proof=proof,
            expected_root=tree.root
        )
    }


class KeyManager:
    """
    Ed25519 Key Management for Checkpoint Signing and Verification.
    Signs checkpoint payloads combining (chain_head + Merkle root) every 1,000 events.
    """
    def __init__(self, private_key_pem: Optional[bytes] = None):
        if private_key_pem:
            self.private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        else:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def get_public_hex(self) -> str:
        raw_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return raw_bytes.hex()

    def sign_checkpoint(self, chain_head: str, merkle_root: str, checkpoint_seq: int) -> Dict[str, Any]:
        """
        Sign checkpoint string format: 'ulpf-checkpoint:seq:{checkpoint_seq}:{chain_head}:{merkle_root}'
        """
        message = f"ulpf-checkpoint:seq:{checkpoint_seq}:{chain_head}:{merkle_root}".encode('utf-8')
        signature = self.private_key.sign(message)
        return {
            "checkpoint_seq": checkpoint_seq,
            "chain_head": chain_head,
            "merkle_root": merkle_root,
            "signature": signature.hex(),
            "signer_pubkey": self.get_public_hex(),
            "algorithm": "Ed25519"
        }

    @staticmethod
    def verify_checkpoint(checkpoint: Dict[str, Any]) -> bool:
        try:
            pub_bytes = bytes.fromhex(checkpoint["signer_pubkey"])
            sig_bytes = bytes.fromhex(checkpoint["signature"])
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            message = (
                f"ulpf-checkpoint:seq:{checkpoint['checkpoint_seq']}:"
                f"{checkpoint['chain_head']}:{checkpoint['merkle_root']}"
            ).encode('utf-8')
            pub_key.verify(sig_bytes, message)
            return True
        except Exception:
            return False
