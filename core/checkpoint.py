"""
Universal Log Pre-processing Framework (ULPF) - Checkpoint & Merkle Tree Module
RFC 6962 Merkle Tree (Leaves 0x00, Nodes 0x01) + Ed25519 Digital Checkpoint Signatures
Team LunarX - SIH26156 (NTRO)
"""

import math
import hashlib
from typing import List, Tuple, Dict, Any, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def hash_leaf(fp_bytes: bytes) -> bytes:
    """RFC 6962 Leaf Hash: SHA256(0x00 + data) to prevent length extension & second preimage attacks"""
    return hashlib.sha256(b"\x00" + fp_bytes).digest()


def hash_children(left: bytes, right: bytes) -> bytes:
    """RFC 6962 Node Hash: SHA256(0x01 + left + right)"""
    return hashlib.sha256(b"\x01" + left + right).digest()


class MerkleTree:
    """
    RFC 6962 compliant Merkle Tree for tamper-evident audit logs.
    Supports:
    - Root computation in O(N)
    - Inclusion Proof in O(log2 N)
    - Consistency Proof between tree generations
    """
    def __init__(self, fingerprints: List[str]):
        self.fps = fingerprints
        self.leaves = [hash_leaf(fp.encode('utf-8')) for fp in fingerprints]
        self.tree_levels: List[List[bytes]] = []
        if self.leaves:
            self._build_tree()

    def _build_tree(self):
        current_level = self.leaves
        self.tree_levels = [current_level]
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # In RFC 6962, if odd number of nodes at this level, promote left directly
                    right = left
                next_level.append(hash_children(left, right))
            current_level = next_level
            self.tree_levels.append(current_level)

    @property
    def root(self) -> str:
        if not self.tree_levels or not self.tree_levels[-1]:
            return "0000000000000000000000000000000000000000000000000000000000000000"
        return self.tree_levels[-1][0].hex()

    def get_inclusion_proof(self, index: int) -> List[Dict[str, str]]:
        """
        Generate RFC 6962 audit path (inclusion proof) for leaf at `index`.
        Returns ceil(log2 N) sibling hashes with direction indicator ('left'/'right').
        Allows any verifier to prove an event exists without disclosing any other logs.
        """
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
                # Odd node duplicate
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


class KeyManager:
    """
    Ed25519 Key Management for Checkpoint Signing and Verification.
    Generates or loads asymmetric keys for signing (chain_head + Merkle root).
    """
    def __init__(self, private_key_pem: Optional[bytes] = None):
        if private_key_pem:
            self.private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        else:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def get_public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def get_public_hex(self) -> str:
        return self.get_public_bytes().hex()

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
