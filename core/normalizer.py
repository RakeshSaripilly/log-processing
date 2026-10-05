"""
Universal Log Pre-processing Framework (ULPF) - OCSF 1.9 Normalizer & 7-Stage Lineage Tracker
Normalizes parsed data into Open Cybersecurity Schema Framework (OCSF 1.9)
Maintains complete 7-stage auditable lineage from raw bytes to normalized event.
Team LunarX - SIH26156 (NTRO)
"""

import time
import hashlib
from typing import Dict, Any, Optional, List

# OCSF 1.9 Category and Class UIDs
CLASS_SYSTEM_ACTIVITY = 1001
CLASS_SECURITY_FINDING = 2001
CLASS_AUTHENTICATION = 3001
CLASS_NETWORK_ACTIVITY = 4001
CLASS_UNMAPPED = 0

# Severity mappings (OCSF 1.9)
SEVERITY_MAP = {
    "unknown": 0, "informational": 1, "info": 1, "low": 2,
    "medium": 3, "warn": 3, "warning": 3, "high": 4, "err": 4, "error": 4,
    "critical": 5, "crit": 5, "fatal": 6, "emerg": 6, "emergency": 6
}

# Disposition mappings (OCSF 1.9 Network Activity)
DISPOSITION_MAP = {
    "allow": 1, "allowed": 1, "permit": 1, "pass": 1, "accept": 1,
    "block": 2, "blocked": 2, "deny": 2, "denied": 2, "drop": 2, "dropped": 2,
    "reject": 3, "rejected": 3,
    "quarantine": 4, "isolate": 5, "alert": 6
}

# Status mappings
STATUS_MAP = {
    "success": 1, "ok": 1, "passed": 1, "succeeded": 1,
    "failure": 2, "failed": 2, "error": 2, "fail": 2,
    "unknown": 0
}


def normalize_to_ocsf(
    extracted_data: Dict[str, Any],
    raw_text: str,
    raw_locator: str,
    pack_metadata: Optional[Dict[str, Any]] = None,
    inferred_mappings: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Transform extracted data into strict OCSF 1.9 structure.
    Always includes raw_payload and RawRef locator in unmapped.ulpf_raw_locator.
    """
    now_ms = int(time.time() * 1000)
    raw_sha256 = hashlib.sha256(raw_text.encode('utf-8')).hexdigest()

    # Determine class UID from pack or inference
    class_uid = CLASS_UNMAPPED
    category_uid = 0
    vendor_name = "Generic"
    product_name = "Unknown"

    if pack_metadata:
        class_uid = pack_metadata.get("class_uid", CLASS_SYSTEM_ACTIVITY)
        category_uid = pack_metadata.get("category_uid", class_uid // 1000)
        vendor_name = pack_metadata.get("vendor", "Generic")
        product_name = pack_metadata.get("product", "Unknown")

    if "device_vendor" in extracted_data:
        vendor_name = str(extracted_data["device_vendor"])
    if "device_product" in extracted_data:
        product_name = str(extracted_data["device_product"])

    # Base OCSF 1.9 event envelope
    ocsf_event: Dict[str, Any] = {
        "metadata": {
            "version": "1.9.0",
            "product": {
                "name": product_name,
                "vendor_name": vendor_name,
                "version": pack_metadata.get("version", "1.0") if pack_metadata else "1.0"
            },
            "profiles": ["host", "security_control"],
            "original_time": str(extracted_data.get("time", extracted_data.get("timestamp", now_ms))),
            "labels": pack_metadata.get("labels", []) if pack_metadata else ["unparsed_salvage"]
        },
        "class_uid": class_uid,
        "category_uid": category_uid,
        "time": now_ms,
        "raw_data": raw_text,
        "unmapped": {
            "ulpf_raw_locator": raw_locator,
            "raw_sha256": raw_sha256
        }
    }

    # Map core endpoints & activity
    src_endpoint = {}
    dst_endpoint = {}
    actor = {}
    device = {}

    # Apply pack mappings or inferred mappings
    all_mappings = {}
    if pack_metadata and "mappings" in pack_metadata:
        all_mappings.update(pack_metadata["mappings"])
    if inferred_mappings:
        all_mappings.update(inferred_mappings)

    for src_key, raw_val in extracted_data.items():
        if src_key in all_mappings:
            target_field = all_mappings[src_key]
            _set_nested(ocsf_event, target_field, raw_val)
        elif src_key in ("src_ip", "srcip", "saddr", "client_ip"):
            src_endpoint["ip"] = str(raw_val)
        elif src_key in ("dst_ip", "dstip", "daddr", "target_ip"):
            dst_endpoint["ip"] = str(raw_val)
        elif src_key in ("src_port", "sport"):
            try: src_endpoint["port"] = int(raw_val)
            except (ValueError, TypeError): pass
        elif src_key in ("dst_port", "dport"):
            try: dst_endpoint["port"] = int(raw_val)
            except (ValueError, TypeError): pass
        elif src_key in ("user", "username", "account"):
            actor["user"] = {"name": str(raw_val)}
        elif src_key in ("hostname", "host"):
            device["hostname"] = str(raw_val)
        elif src_key in ("action", "act"):
            val_lower = str(raw_val).lower()
            ocsf_event["activity_name"] = str(raw_val)
            ocsf_event["disposition_id"] = DISPOSITION_MAP.get(val_lower, 0)
        elif src_key in ("status", "result"):
            val_lower = str(raw_val).lower()
            ocsf_event["status_id"] = STATUS_MAP.get(val_lower, 0)
        elif src_key in ("severity", "level", "pri"):
            val_lower = str(raw_val).lower()
            ocsf_event["severity_id"] = SEVERITY_MAP.get(val_lower, 1)
        elif src_key in ("message", "msg"):
            ocsf_event["message"] = str(raw_val)
        else:
            # Preserve unknown fields under unmapped
            ocsf_event["unmapped"][src_key] = raw_val

    # Unpack extension dict if present (e.g. from CEF / LEEF decoders)
    ext_data = extracted_data.get("extension")
    if isinstance(ext_data, dict):
        for ek, ev in ext_data.items():
            if ek in ("src", "srcip", "saddr", "src_ip"):
                src_endpoint["ip"] = str(ev)
            elif ek in ("dst", "dstip", "daddr", "dst_ip"):
                dst_endpoint["ip"] = str(ev)
            elif ek in ("spt", "src_port", "sport"):
                try: src_endpoint["port"] = int(ev)
                except (ValueError, TypeError): pass
            elif ek in ("dpt", "dst_port", "dport"):
                try: dst_endpoint["port"] = int(ev)
                except (ValueError, TypeError): pass
            elif ek in ("act", "action"):
                val_lower = str(ev).lower()
                ocsf_event["activity_name"] = str(ev)
                ocsf_event["disposition_id"] = DISPOSITION_MAP.get(val_lower, 0)
            elif ek in ("proto", "protocol"):
                _set_nested(ocsf_event, "connection_info.protocol_name", str(ev))

    if src_endpoint:
        ocsf_event["src_endpoint"] = src_endpoint
    if dst_endpoint:
        ocsf_event["dst_endpoint"] = dst_endpoint
    if actor:
        ocsf_event["actor"] = actor
    if device:
        ocsf_event["device"] = device

    # Auto-adjust class_uid if network activity observed
    if class_uid == CLASS_UNMAPPED and (src_endpoint or dst_endpoint):
        ocsf_event["class_uid"] = CLASS_NETWORK_ACTIVITY
        ocsf_event["category_uid"] = 4

    return ocsf_event


def build_7stage_lineage(
    event_id: str,
    raw_bytes: bytes,
    raw_locator: str,
    pack_name: str,
    decoder_name: str,
    extracted_keys: List[str],
    vector_confidence: float,
    ocsf_class: int,
    fingerprint: str,
    prev_hash: str
) -> Dict[str, Any]:
    """
    Construct complete 7-stage lineage record for auditable end-to-end provenance.
    Stages:
    1. Raw Ingest (Vault RawRef, SHA256)
    2. Detection (Pack claimed or Salvage)
    3. Extraction (Decoder used, extracted keys)
    4. Inference (Vector matcher confidence)
    5. Normalization (OCSF class_uid)
    6. Attestation (RFC8785 JCS, BLAKE3 fingerprint, prev_hash chain)
    7. Storage & Sink (Committed to Parquet/DuckDB lake)
    """
    raw_sha = hashlib.sha256(raw_bytes).hexdigest()
    return {
        "event_id": event_id,
        "stage_1_raw": {
            "locator": raw_locator,
            "byte_length": len(raw_bytes),
            "sha256": raw_sha
        },
        "stage_2_detection": {
            "pack": pack_name,
            "status": "CLAIMED" if pack_name != "salvage" else "SALVAGE_FALLBACK"
        },
        "stage_3_extraction": {
            "decoder": decoder_name,
            "field_count": len(extracted_keys),
            "keys": extracted_keys
        },
        "stage_4_inference": {
            "vector_confidence": vector_confidence,
            "confidence_band": "GREEN" if vector_confidence >= 0.85 else ("YELLOW" if vector_confidence >= 0.60 else "RED")
        },
        "stage_5_normalization": {
            "ocsf_version": "1.9.0",
            "class_uid": ocsf_class
        },
        "stage_6_attestation": {
            "canonical_scheme": "RFC8785_JCS",
            "algorithm": "BLAKE3",
            "fingerprint": fingerprint,
            "prev_hash": prev_hash
        },
        "stage_7_sink": {
            "status": "COMMITTED",
            "formats": ["NDJSON", "PARQUET", "DUCKDB"]
        }
    }


def _set_nested(d: Dict[str, Any], path: str, value: Any):
    parts = path.split(".")
    curr = d
    for part in parts[:-1]:
        if part not in curr or not isinstance(curr[part], dict):
            curr[part] = {}
        curr = curr[part]
    curr[parts[-1]] = value
