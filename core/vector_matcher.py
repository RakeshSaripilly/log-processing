"""
Universal Log Pre-processing Framework (ULPF) - Telemetry-Aware Vector Matcher
NOVELTY: Embeds "key | samples: top5 values | type: ip/port/timestamp/enum/hostname/bool/vendor hint"
Cosine similarity against OCSF 1.9 canonical schema embeddings.
Confidence routing: >0.85 auto-map, 0.60-0.85 review queue, <0.60 custom.<vendor>.<field>
NO LLM code generation, deterministic field mappings, 100% air-gapped safe.
Team LunarX - SIH26156 (NTRO)
"""

import re
import os
import math
import numpy as np
from typing import Dict, Any, List, Tuple, Optional

# Regex heuristics for type inference
IPV4_RE = re.compile(r"^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})$")
URL_RE = re.compile(r"^https?://", re.IGNORECASE)
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
ISO_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}")

# OCSF 1.9 Canonical Field Schema with semantic descriptions & typical sample cues
OCSF_CANONICAL_FIELDS: Dict[str, Dict[str, Any]] = {
    "src_endpoint.ip": {
        "desc": "Source IP address initiator of network traffic connection packet",
        "type": "ip",
        "keywords": ["src", "srcip", "source_ip", "sourceip", "client_ip", "saddr", "src_ip", "client"]
    },
    "dst_endpoint.ip": {
        "desc": "Destination IP address target server host receiving network packet",
        "type": "ip",
        "keywords": ["dst", "dstip", "dest_ip", "destination_ip", "destip", "daddr", "server_ip", "target"]
    },
    "src_endpoint.port": {
        "desc": "Source port transport layer socket originating port number",
        "type": "port",
        "keywords": ["src_port", "sport", "source_port", "srcport", "client_port"]
    },
    "dst_endpoint.port": {
        "desc": "Destination port service listening target port number 80 443 22 53",
        "type": "port",
        "keywords": ["dst_port", "dport", "dest_port", "destination_port", "dstport", "service_port"]
    },
    "actor.user.name": {
        "desc": "User account name login identity principal username",
        "type": "string",
        "keywords": ["user", "username", "account", "login", "uname", "user_name", "src_user"]
    },
    "device.hostname": {
        "desc": "Device host system computer machine hostname name",
        "type": "hostname",
        "keywords": ["host", "hostname", "device_name", "computer_name", "sysname", "machine"]
    },
    "activity_name": {
        "desc": "Action activity event disposition operation result Logon Logoff Block Allow Drop",
        "type": "enum",
        "keywords": ["action", "act", "activity", "event_type", "operation", "status", "disposition"]
    },
    "severity_id": {
        "desc": "Event severity priority level emergency alert critical error warning info debug",
        "type": "enum",
        "keywords": ["severity", "level", "priority", "pri", "sev", "log_level"]
    },
    "http_request.url": {
        "desc": "Uniform resource locator web address requested URI path HTTP",
        "type": "url",
        "keywords": ["url", "uri", "path", "request_url", "http_path", "web_url"]
    },
    "http_request.http_method": {
        "desc": "HTTP method verb GET POST PUT DELETE HEAD OPTIONS PATCH",
        "type": "enum",
        "keywords": ["method", "http_method", "verb"]
    },
    "time": {
        "desc": "Timestamp date time event occurrence epoch millisecond UTC",
        "type": "timestamp",
        "keywords": ["timestamp", "time", "date", "datetime", "epoch", "event_time"]
    },
    "file.name": {
        "desc": "File name executable document artifact path target filename",
        "type": "string",
        "keywords": ["filename", "file", "file_name", "path", "doc_name"]
    },
    "file.hashes.sha256": {
        "desc": "Cryptographic SHA256 checksum digest fingerprint of binary or file",
        "type": "string",
        "keywords": ["sha256", "file_hash", "checksum", "hash"]
    },
    "network_endpoint.mac": {
        "desc": "Hardware MAC address physical network interface adapter",
        "type": "mac",
        "keywords": ["mac", "smac", "dmac", "mac_address", "hardware_address"]
    },
    "message": {
        "desc": "Raw event message description payload narrative details text",
        "type": "string",
        "keywords": ["msg", "message", "description", "details", "raw_msg"]
    }
}


def infer_data_type(key: str, samples: List[Any]) -> str:
    """Infer semantic telemetry data type from key name and concrete value samples"""
    lower_key = key.lower()
    sample_strs = [str(s).strip() for s in samples if s is not None and str(s).strip()][:5]
    if not sample_strs:
        if "ip" in lower_key: return "ip"
        if "port" in lower_key: return "port"
        if "time" in lower_key or "date" in lower_key: return "timestamp"
        return "string"

    # Check IPs
    if all(IPV4_RE.match(s) for s in sample_strs):
        return "ip"
    # Check Ports
    if all(s.isdigit() and 1 <= int(s) <= 65535 for s in sample_strs):
        if "port" in lower_key or "sport" in lower_key or "dport" in lower_key or "pt" in lower_key:
            return "port"
    # Check MAC
    if all(MAC_RE.match(s) for s in sample_strs):
        return "mac"
    # Check URL
    if any(URL_RE.match(s) for s in sample_strs):
        return "url"
    # Check Email
    if any(EMAIL_RE.match(s) for s in sample_strs):
        return "email"
    # Check Boolean
    if all(s.lower() in ("true", "false", "0", "1", "yes", "no") for s in sample_strs):
        return "bool"
    # Check Timestamp
    if any(ISO_TIME_RE.match(s) for s in sample_strs) or "time" in lower_key or "date" in lower_key:
        return "timestamp"
    # Check Enum (low cardinality keywords)
    if all(s.lower() in ("allow", "deny", "drop", "reject", "pass", "block", "success", "failed", "info", "warn", "error") for s in sample_strs):
        return "enum"

    return "string"


class TelemetryVectorMatcher:
    """
    Offline telemetry-aware vector matcher for automated log field mapping.
    Uses SentenceTransformer if available offline, with deterministic TF-IDF / Subword Cosine fallback
    so it functions with zero network connectivity or model download lag.
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self.encoder = None
        self.canonical_embeddings: Dict[str, np.ndarray] = {}
        self._init_encoder()
        self._embed_canonical_fields()

    def _init_encoder(self):
        # In strict air-gapped environments, check if a local model folder exists
        model_path = os.environ.get("ULPF_MINILM_PATH", "models/all-MiniLM-L6-v2")
        if os.path.exists(model_path):
            try:
                from sentence_transformers import SentenceTransformer
                self.encoder = SentenceTransformer(model_path, local_files_only=True)
                return
            except Exception:
                pass
        self.encoder = None

    def _embed_text(self, text: str) -> np.ndarray:
        if self.encoder is not None:
            vec = self.encoder.encode(text, normalize_embeddings=True)
            return np.array(vec, dtype=np.float32)

        # Deterministic 384-dimensional hashed character n-gram + token embedding
        vec = np.zeros(384, dtype=np.float32)
        tokens = re.findall(r"[a-zA-Z0-9_]+", text.lower())
        for tok in tokens:
            h = hash(tok)
            idx = abs(h) % 384
            vec[idx] += 1.0
            # Also hash character 3-grams
            for i in range(len(tok) - 2):
                tri = tok[i:i+3]
                th = hash(tri)
                vec[abs(th) % 384] += 0.5

        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm
        return vec

    def _embed_canonical_fields(self):
        for ocsf_field, meta in OCSF_CANONICAL_FIELDS.items():
            text = f"{ocsf_field} | keywords: {','.join(meta['keywords'])} | type: {meta['type']} | {meta['desc']}"
            self.canonical_embeddings[ocsf_field] = self._embed_text(text)

    def map_field(
        self,
        key: str,
        samples: List[Any],
        vendor_hint: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Match unknown field against canonical OCSF 1.9 fields.
        Confidence Routing:
        - >0.85: Auto-map to canonical OCSF field
        - 0.60 - 0.85: Route to Review Queue with top suggestions
        - <0.60: Fallback to custom.<vendor>.<field> (never dropped)
        """
        type_hint = infer_data_type(key, samples)
        sample_snippets = [str(s) for s in samples[:5] if s is not None]
        hint_text = f" | vendor: {vendor_hint}" if vendor_hint else ""
        query_text = f"{key} | samples: {','.join(sample_snippets)} | type: {type_hint}{hint_text}"

        q_vec = self._embed_text(query_text)

        # Exact and synonym keyword boosts
        lower_key = key.lower().replace("-", "_")

        scores: List[Tuple[str, float]] = []
        for ocsf_field, c_vec in self.canonical_embeddings.items():
            cos_sim = float(np.dot(q_vec, c_vec))
            meta = OCSF_CANONICAL_FIELDS[ocsf_field]

            # High precision booster if key name directly matches known synonyms
            if lower_key in meta["keywords"] or lower_key == ocsf_field.split(".")[-1]:
                cos_sim = max(cos_sim, 0.94)
            elif any(kw in lower_key for kw in meta["keywords"]):
                # Substring keyword match (e.g. 'client_address' matching 'client')
                cos_sim = max(cos_sim, 0.72)

            # Type congruence check
            if meta["type"] == type_hint and type_hint in ("ip", "port", "mac", "url", "timestamp"):
                cos_sim = min(1.0, cos_sim + 0.15)
            elif meta["type"] != type_hint and type_hint in ("ip", "port", "mac"):
                # Penalize severe type mismatch (e.g. IP field mapped to port)
                cos_sim = max(0.0, cos_sim - 0.40)

            scores.append((ocsf_field, round(cos_sim, 4)))

        scores.sort(key=lambda x: x[1], reverse=True)
        top_field, top_confidence = scores[0]

        # Confidence routing
        if top_confidence >= 0.85:
            decision = "AUTO_MAP"
            target = top_field
        elif top_confidence >= 0.60:
            decision = "HUMAN_REVIEW"
            target = top_field  # suggested target
        else:
            decision = "CUSTOM_FALLBACK"
            v = vendor_hint.lower() if vendor_hint else "unknown"
            target = f"custom.{v}.{lower_key}"

        return {
            "source_key": key,
            "inferred_type": type_hint,
            "confidence": top_confidence,
            "decision": decision,
            "target_field": target,
            "top_candidates": [{"field": f, "score": s} for f, s in scores[:3]],
            "samples": sample_snippets
        }
