"""
Universal Log Pre-processing Framework (ULPF) - Cryptographic Integrity Module
RFC 8785 JSON Canonicalization Scheme (JCS) + BLAKE3/SHA-256 Hash Chain
Team LunarX - SIH26156 (NTRO)
"""

from core.attestation import (
    jcs_canonicalize,
    hash_digest,
    hash_event,
    compute_fingerprint,
    append_to_chain,
    verify_chain,
    HAS_BLAKE3
)

__all__ = [
    "jcs_canonicalize",
    "hash_digest",
    "hash_event",
    "compute_fingerprint",
    "append_to_chain",
    "verify_chain",
    "HAS_BLAKE3"
]
