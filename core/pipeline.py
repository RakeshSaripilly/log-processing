"""
Universal Log Pre-processing Framework (ULPF) - Central Pipeline
Orchestrates: Vault Write -> Detect -> Extract -> Vector Match -> Normalize OCSF 1.9 -> Attest Chain -> Sink
Team LunarX - SIH26156 (NTRO)
"""

import time
import uuid
import json
import logging
import threading
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Callable

from core.vault import VaultStorage, RawRef
from core.detector import PackRegistry, CompiledSourcePack
from core.decoders import DECODER_REGISTRY, decode_json, decode_keyvalue
from core.salvage import extract_observables
from core.drain_service import DrainClusterService
from core.vector_matcher import TelemetryVectorMatcher
from core.normalizer import normalize_to_ocsf, build_7stage_lineage
from core.attestation import compute_fingerprint, jcs_canonicalize, MerkleTree, KeyManager
from storage.sinks import LakeStorageEngine, WazuhForwarder

logger = logging.getLogger("ulpf.pipeline")


class ProcessingPipeline:
    """
    High-throughput Universal Log Pre-processing Pipeline.
    Enforces 'Write-Before-Parse', zero raw dropped, cryptographic chain, and telemetry vector matching.
    """

    def __init__(
        self,
        vault_dir: str = "./storage/raw",
        lake_dir: str = "./lake",
        packs_dir: Optional[str] = None,
        passphrase: Optional[str] = None
    ):
        if packs_dir is None:
            packs_path = Path("./parsers/active")
            if packs_path.exists():
                packs_dir = str(packs_path)
            else:
                packs_dir = str(Path(__file__).resolve().parent.parent / "parsers" / "active")
        self.vault = VaultStorage(vault_dir=vault_dir, passphrase=passphrase)
        self.registry = PackRegistry(packs_dir=packs_dir)
        self.drain = DrainClusterService()
        self.vector_matcher = TelemetryVectorMatcher()
        self.lake = LakeStorageEngine(lake_dir=lake_dir)
        self.wazuh = WazuhForwarder()
        self.key_manager = KeyManager()
        self.lock = threading.Lock()

        # Chain state
        self.sequence_counter = 0
        self.prev_fingerprint = "genesis"
        self.pending_fingerprints_for_merkle: List[str] = []
        self.checkpoint_interval = 1000

        # Review queue memory buffer
        self.review_queue: Dict[str, Dict[str, Any]] = {}

        self._restore_chain_state()

    def _restore_chain_state(self):
        """Restore sequence and previous hash from lake if already populated"""
        row = self.lake.con.execute(
            "SELECT sequence, fingerprint FROM parsed_logs ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if row:
            self.sequence_counter = int(row[0]) + 1
            self.prev_fingerprint = str(row[1])
            logger.info(f"Restored chain state: seq={self.sequence_counter}, prev_fp={self.prev_fingerprint[:12]}...")

    def process_raw(self, raw_input: Any, vendor_hint: Optional[str] = None) -> Dict[str, Any]:
        """
        Process a single raw log through the 7-stage ULPF pipeline.
        Returns the finalized OCSF 1.9 normalized event with lineage & fingerprint.
        """
        if isinstance(raw_input, str):
            raw_text = raw_input.strip()
            raw_bytes = raw_text.encode('utf-8')
        else:
            raw_bytes = bytes(raw_input)
            raw_text = raw_bytes.decode('utf-8', errors='replace').strip()

        with self.lock:
            # STAGE 1: VAULT WRITE-BEFORE-PARSE (Order is correctness property)
            res = self.vault.write_raw(raw_bytes)
            if isinstance(res, tuple):
                locator, raw_sha256 = res
            else:
                locator = res
                raw_sha256 = locator.raw_sha256 if hasattr(locator, "raw_sha256") else ""
            locator_str = locator.to_string()

        # STAGE 2: SOURCE PACK DETECTION
        claimed_pack = self.registry.find_matching_pack(raw_text)
        pack_name = claimed_pack.name if claimed_pack else "salvage"
        decoder_used = "none"
        extracted_data: Dict[str, Any] = {}
        inferred_mappings: Dict[str, str] = {}
        max_vector_conf = 1.0

        if claimed_pack:
            # STAGE 3: EXTRACTION VIA PACK DECODER CHAIN
            ext_result = claimed_pack.extract(raw_text)
            if ext_result:
                decoder_used, extracted_data = ext_result
            else:
                claimed_pack = None

        if not claimed_pack:
            # STAGE 3b: SALVAGE FALLBACK EXTRACTION + DRAIN TEMPLATE MINING
            decoder_used = "salvage"
            salvaged_observables = extract_observables(raw_text)
            cluster_info = self.drain.match_or_cluster(raw_text)
            
            extracted_data = {
                "observables": salvaged_observables,
                "cluster_id": cluster_info["cluster_id"],
                "cluster_template": cluster_info["template"],
                "specificity": cluster_info["specificity"]
            }

            # Attempt JSON/KV parse to uncover field candidates for vector matching
            candidate_parsed = decode_json(raw_text) or decode_keyvalue(raw_text)
            if candidate_parsed:
                extracted_data.update(candidate_parsed)
                for k, v in candidate_parsed.items():
                    vm_res = self.vector_matcher.map_field(k, [v], vendor_hint=vendor_hint)
                    max_vector_conf = min(max_vector_conf, vm_res["confidence"])
                    if vm_res["decision"] == "AUTO_MAP":
                        inferred_mappings[k] = vm_res["target_field"]
                    elif vm_res["decision"] == "HUMAN_REVIEW":
                        rev_id = str(uuid.uuid4())[:8]
                        self.review_queue[rev_id] = {
                            "review_id": rev_id,
                            "cluster_id": cluster_info["cluster_id"],
                            "source_key": k,
                            "suggested_target": vm_res["target_field"],
                            "confidence": vm_res["confidence"],
                            "inferred_type": vm_res["inferred_type"],
                            "samples": [str(v)],
                            "template": cluster_info["template"],
                            "status": "PENDING"
                        }
                    else:
                        inferred_mappings[k] = vm_res["target_field"]

        # STAGE 4 & 5: OCSF 1.9 NORMALIZATION
        pack_meta = {
            "name": claimed_pack.product if claimed_pack else "Generic",
            "vendor": claimed_pack.vendor if claimed_pack else (vendor_hint or "Generic"),
            "product": claimed_pack.product if claimed_pack else "Unknown",
            "class_uid": claimed_pack.class_uid if claimed_pack else 0,
            "category_uid": claimed_pack.category_uid if claimed_pack else 0,
            "version": claimed_pack.version if claimed_pack else "1.0",
            "mappings": claimed_pack.mappings if claimed_pack else {}
        }

        ocsf_event = normalize_to_ocsf(
            extracted_data=extracted_data,
            raw_text=raw_text,
            raw_locator=locator_str,
            pack_metadata=pack_meta,
            inferred_mappings=inferred_mappings
        )

        event_seq = self.sequence_counter
        self.sequence_counter += 1
        event_id = str(uuid.uuid4())

        ocsf_event["sequence"] = event_seq
        ocsf_event["event_id"] = event_id

        # STAGE 6: CRYPTOGRAPHIC ATTESTATION (RFC 8785 JCS + prev_hash chain)
        fp, _ = compute_fingerprint(ocsf_event, prev_hash=self.prev_fingerprint, algorithm="blake3")
        ocsf_event["fingerprint"] = fp
        ocsf_event["prev_hash"] = self.prev_fingerprint
        self.prev_fingerprint = fp
        self.pending_fingerprints_for_merkle.append(fp)

        # Ed25519 Checkpoint every 1000 events
        if len(self.pending_fingerprints_for_merkle) >= self.checkpoint_interval:
            self._create_checkpoint()

        # Build 7-stage lineage record
        lineage = build_7stage_lineage(
            event_id=event_id,
            raw_bytes=raw_bytes,
            raw_locator=locator_str,
            pack_name=pack_name,
            decoder_name=decoder_used,
            extracted_keys=list(extracted_data.keys()),
            vector_confidence=max_vector_conf,
            ocsf_class=ocsf_event["class_uid"],
            fingerprint=fp,
            prev_hash=ocsf_event["prev_hash"]
        )

        # STAGE 7: SINK TO LAKE & FORWARDERS
        self.lake.commit_event(ocsf_event, lineage=lineage)
        self.wazuh.forward(ocsf_event)

        return ocsf_event

    def _create_checkpoint(self):
        """Construct Merkle tree over accumulated block of events and sign with Ed25519"""
        if not self.pending_fingerprints_for_merkle:
            return
        tree = MerkleTree(self.pending_fingerprints_for_merkle)
        checkpoint_seq = self.sequence_counter
        cp_data = self.key_manager.sign_checkpoint(
            chain_head=self.prev_fingerprint,
            merkle_root=tree.root,
            checkpoint_seq=checkpoint_seq
        )
        self.lake.con.execute("""
            INSERT OR REPLACE INTO checkpoints VALUES (?, ?, ?, ?, ?, ?)
        """, [
            checkpoint_seq,
            cp_data["chain_head"],
            cp_data["merkle_root"],
            cp_data["signature"],
            cp_data["signer_pubkey"],
            int(time.time() * 1000)
        ])
        self.pending_fingerprints_for_merkle.clear()
        logger.info(f"Signed Ed25519 Checkpoint at seq {checkpoint_seq} with Merkle root {tree.root[:12]}...")

    def approve_review_item(self, review_id: str, approved_target: Optional[str] = None) -> bool:
        """
        HITL Promotion: Approve suggestion from review queue, hot-promoting it to an active mapping.
        """
        item = self.review_queue.get(review_id)
        if not item:
            return False
        
        target = approved_target or item["suggested_target"]
        item["status"] = "APPROVED"
        item["approved_target"] = target
        
        # Inject into DuckDB review_queue
        self.lake.con.execute("""
            INSERT OR REPLACE INTO review_queue VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            review_id, item["cluster_id"], item["source_key"], target,
            item["confidence"], item["inferred_type"], json.dumps(item["samples"]),
            item["template"], "APPROVED", int(time.time() * 1000)
        ])
        return True

    def process_file(
        self,
        file_path: str,
        vendor_hint: Optional[str] = None,
        on_progress: Optional[Callable[[int, Dict[str, Any]], None]] = None
    ) -> List[Dict[str, Any]]:
        """
        Process an entire log file through the 7-stage ULPF pipeline.
        Reuses process_raw() for each line, ensures vault is flushed,
        signs checkpoint, and returns all normalized OCSF events.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Input file does not exist: {file_path}")
        if not path.is_file():
            raise ValueError(f"Input path is not a file: {file_path}")

        events = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for idx, line in enumerate(f):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    ev = self.process_raw(stripped, vendor_hint=vendor_hint)
                    events.append(ev)
                    if on_progress:
                        on_progress(idx, ev)
                except Exception as e:
                    logger.error(f"Error processing line {idx} in {file_path}: {e}")

        # Ensure all buffered logs are permanently written and fsynced
        self.vault.flush()

        # Sign checkpoint for remaining pending events
        if self.pending_fingerprints_for_merkle:
            self._create_checkpoint()

        return events

    def close(self):
        """Cleanly flush and close lake and vault resources."""
        try:
            if hasattr(self, "vault"):
                self.vault.flush()
        except Exception:
            pass
        try:
            if hasattr(self, "lake"):
                self.lake.close()
        except Exception:
            pass

