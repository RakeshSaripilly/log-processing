"""
Unit tests for Cryptographic Tamper Detection
Team LunarX - SIH26156 (NTRO)
"""

from core.integrity import compute_fingerprint, verify_chain


def test_tamper_detection_breaks_chain():
    events = []
    prev_fp = "genesis"
    for i in range(10):
        ev = {
            "sequence": i,
            "class_uid": 4001,
            "src_endpoint": {"ip": f"192.0.2.{i}"},
            "activity_name": "Built"
        }
        fp, _ = compute_fingerprint(ev, prev_hash=prev_fp)
        ev["fingerprint"] = fp
        ev["prev_hash"] = prev_fp
        prev_fp = fp
        events.append(ev)

    # Initial verification: MUST PASS
    valid, msg, broken_seq = verify_chain(events)
    assert valid is True

    # Malicious injection: Tamper event 5's IP
    events[5]["src_endpoint"]["ip"] = "198.51.100.99"

    # Verification MUST FAIL at sequence 5
    tampered_valid, tampered_msg, tampered_broken_seq = verify_chain(events)
    assert tampered_valid is False
    assert tampered_broken_seq == 5
    assert "Tamper detected at seq=5" in tampered_msg


def test_tamper_deletion_breaks_chain():
    events = []
    prev_fp = "genesis"
    for i in range(5):
        ev = {"sequence": i, "payload": f"log {i}"}
        fp, _ = compute_fingerprint(ev, prev_hash=prev_fp)
        ev["fingerprint"] = fp
        ev["prev_hash"] = prev_fp
        prev_fp = fp
        events.append(ev)

    # Delete event 2 (log truncation attack)
    del events[2]

    # Verification MUST FAIL due to broken prev_hash link
    tampered_valid, tampered_msg, broken_seq = verify_chain(events)
    assert tampered_valid is False
    assert broken_seq == 3
    assert "Chain break at seq=3" in tampered_msg
