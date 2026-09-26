"""
Universal Log Pre-processing Framework (ULPF) - Cryptographic Integrity Module
RFC 8785 JSON Canonicalization Scheme (JCS) + BLAKE3/SHA-256 Hash Chain
Team LunarX - SIH26156 (NTRO)
"""

import json
import hashlib
from typing import Any, Dict, List, Optional, Tuple

try:
    import blake3 as _blake3_mod
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False


def jcs_canonicalize(obj: Any) -> bytes:
    """
    RFC 8785 JSON Canonicalization Scheme (JCS).
    Ensures deterministic serialization:
    - Sort keys lexicographically
    - Whitespace removed: ',' and ':' separators without spaces
    - UTF-8 encoding without ASCII escaping
    - Floating point & integer standard JSON representation
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        default=str
    ).encode('utf-8')


def hash_digest(data: bytes, algorithm: str = "blake3") -> str:
    """
    Compute cryptographic hash digest using BLAKE3 (default) or SHA-256 fallback.
    """
    if algorithm.lower() == "blake3" and HAS_BLAKE3:
        return _blake3_mod.blake3(data).hexdigest()
    # Fallback to SHA-256
    return hashlib.sha256(data).hexdigest()


def compute_fingerprint(
    event_without_fp: Dict[str, Any],
    prev_hash: Optional[str] = None,
    algorithm: str = "blake3"
) -> Tuple[str, bytes]:
    """
    Compute immutable event fingerprint:
    1. Clone event dictionary and strip any existing fingerprint or signature
    2. Inject 'prev_hash' link (Event N links to Hash(N-1), or 'genesis')
    3. Canonicalize payload via RFC 8785 JCS
    4. Compute digest (BLAKE3 OCSF Algorithm ID 99 'Other' or SHA-256)
    Returns: (fingerprint_hex, canonical_bytes)
    """
    payload = {k: v for k, v in event_without_fp.items() if k not in ("fingerprint", "signature", "merkle_proof")}
    payload["prev_hash"] = prev_hash if prev_hash else "genesis"
    canonical = jcs_canonicalize(payload)
    fp = hash_digest(canonical, algorithm=algorithm)
    return fp, canonical


def verify_chain(events: List[Dict[str, Any]], algorithm: str = "blake3") -> Tuple[bool, str, Optional[int]]:
    """
    Verify the tamper-evident hash chain across an ordered sequence of events.
    Verifies:
    1. Event 0 prev_hash == 'genesis' or starts chain
    2. Event N prev_hash == Event N-1 stored fingerprint
    3. Recalculated RFC 8785 canonical fingerprint == stored fingerprint
    Returns: (is_valid, status_message, broken_sequence_number)
    """
    if not events:
        return True, "Chain is empty (valid)", None

    # Sort events by sequence number or timestamp if present
    sorted_events = sorted(events, key=lambda x: x.get("sequence", x.get("seq", 0)))
    
    prev_fp = None
    for idx, event in enumerate(sorted_events):
        seq = event.get("sequence", event.get("seq", idx))
        stored_fp = event.get("fingerprint")
        stored_prev = event.get("prev_hash")
        
        if not stored_fp:
            return False, f"Event at seq={seq} missing 'fingerprint' field", seq

        # Check prev_hash link
        if idx == 0:
            if stored_prev not in ("genesis", None, ""):
                # If verifying a sub-chain, stored_prev is accepted as start
                pass
        else:
            if stored_prev != prev_fp:
                return False, (
                    f"Chain break at seq={seq}: stored prev_hash '{stored_prev}' does not match "
                    f"preceding event fingerprint '{prev_fp}'"
                ), seq

        # Recalculate fingerprint
        recalc_fp, _ = compute_fingerprint(event, prev_hash=stored_prev, algorithm=algorithm)
        # Also check with sha256 fallback if mismatch
        if recalc_fp != stored_fp:
            alt_fp, _ = compute_fingerprint(event, prev_hash=stored_prev, algorithm="sha256")
            if alt_fp != stored_fp:
                return False, (
                    f"Tamper detected at seq={seq}: recalculated fingerprint '{recalc_fp}' does not match "
                    f"stored fingerprint '{stored_fp}'"
                ), seq

        prev_fp = stored_fp

    return True, f"Cryptographic chain verified across {len(events)} events without tamper", None
