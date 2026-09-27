"""
Universal Log Pre-processing Framework (ULPF) - FastAPI Engine & Management API
Endpoints: /ingest, /review-queue, /review/{id}/approve, /metrics, /healthz, /prove, /verify, /tamper-test
Team LunarX - SIH26156 (NTRO)
"""

import time
import os
import json
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.pipeline import ProcessingPipeline
from core.integrity import verify_chain
from core.checkpoint import MerkleTree
from core.vault import RawRef

_pipeline: Optional[ProcessingPipeline] = None
_pipeline_lock = threading.Lock()


def get_pipeline() -> ProcessingPipeline:
    global _pipeline
    if _pipeline is None:
        with _pipeline_lock:
            if _pipeline is None:
                _pipeline = ProcessingPipeline()
    return _pipeline


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Eagerly initialize pipeline within worker process
    get_pipeline()
    yield
    # Clean shutdown on exit
    global _pipeline
    if _pipeline and hasattr(_pipeline, "lake"):
        _pipeline.lake.close()


app = FastAPI(
    title="ULPF - Universal Log Pre-processing Framework",
    description="SIH26156 (NTRO) - Team LunarX: Vault-First + Vector Matcher + Hash Chain",
    version="2.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ingest count metrics
METRICS = {
    "ingested_total": 0,
    "bytes_total": 0,
    "packs_claimed_total": 0,
    "salvaged_total": 0,
    "tamper_alerts_total": 0
}


class LogIngestRequest(BaseModel):
    log: Optional[str] = None
    logs: Optional[List[str]] = None
    vendor_hint: Optional[str] = None


class ApproveReviewRequest(BaseModel):
    approved_target: Optional[str] = None


class TamperTestRequest(BaseModel):
    sequence: int
    field_to_corrupt: str = "src_ip"
    tampered_value: str = "66.66.66.66"


@app.get("/healthz")
def healthz():
    return {"status": "ok", "timestamp": int(time.time()), "version": "2.0.0"}


@app.get("/readyz")
def readyz():
    pipeline = get_pipeline()
    return {
        "ready": True,
        "vault_segments": len(list(pipeline.vault.vault_dir.glob("vault_seg_*.ulpf"))),
        "active_packs": len(pipeline.registry.packs),
        "chain_head": pipeline.prev_fingerprint
    }


@app.get("/metrics")
def metrics():
    """Prometheus-compatible plain text metrics"""
    pipeline = get_pipeline()
    lines = [
        "# HELP ulpf_ingested_total Total logs ingested into vault and processed",
        "# TYPE ulpf_ingested_total counter",
        f"ulpf_ingested_total {METRICS['ingested_total']}",
        "# HELP ulpf_bytes_total Total raw bytes written into vault",
        "# TYPE ulpf_bytes_total counter",
        f"ulpf_bytes_total {METRICS['bytes_total']}",
        "# HELP ulpf_packs_claimed_total Total logs claimed by Source Packs",
        "# TYPE ulpf_packs_claimed_total counter",
        f"ulpf_packs_claimed_total {METRICS['packs_claimed_total']}",
        "# HELP ulpf_salvaged_total Total logs processed via Salvage & Drain3 fallback",
        "# TYPE ulpf_salvaged_total counter",
        f"ulpf_salvaged_total {METRICS['salvaged_total']}",
        "# HELP ulpf_tamper_alerts_total Total cryptographic tamper anomalies detected",
        "# TYPE ulpf_tamper_alerts_total counter",
        f"ulpf_tamper_alerts_total {METRICS['tamper_alerts_total']}",
        "# HELP ulpf_active_packs_count Number of compiled active Source Packs",
        "# TYPE ulpf_active_packs_count gauge",
        f"ulpf_active_packs_count {len(pipeline.registry.packs)}"
    ]
    return Response(content="\n".join(lines) + "\n", media_type="text/plain")


@app.post("/ingest")
def ingest_log(payload: LogIngestRequest):
    """
    Ingest a single log or batch of logs.
    Immediately writes to Vault (Write-Before-Parse), normalizes to OCSF 1.9, attests fingerprint, and sinks.
    """
    pipeline = get_pipeline()
    raw_logs = []
    if payload.log:
        raw_logs.append(payload.log)
    if payload.logs:
        raw_logs.extend(payload.logs)

    if not raw_logs:
        raise HTTPException(status_code=400, detail="No logs provided in payload")

    results = []
    for log_str in raw_logs:
        b_len = len(log_str.encode('utf-8'))
        METRICS["ingested_total"] += 1
        METRICS["bytes_total"] += b_len

        res = pipeline.process_raw(log_str, vendor_hint=payload.vendor_hint)
        if res.get("metadata", {}).get("labels") == ["unparsed_salvage"]:
            METRICS["salvaged_total"] += 1
        else:
            METRICS["packs_claimed_total"] += 1

        results.append(res)

    return {"status": "success", "count": len(results), "events": results}


@app.get("/review-queue")
def get_review_queue():
    """
    Retrieve pending field mappings identified by the Telemetry Vector Matcher (confidence 0.60 - 0.85).
    """
    pipeline = get_pipeline()
    pending = [item for item in pipeline.review_queue.values() if item["status"] == "PENDING"]
    top_unknown = pipeline.drain.get_top_unknown_templates(limit=5)
    return {
        "pending_count": len(pending),
        "items": pending,
        "top_unknown_clusters": top_unknown
    }


@app.post("/review/{review_id}/approve")
def approve_review_item(review_id: str, req: ApproveReviewRequest):
    """
    Approve an inferred field mapping. Hot-promotes suggestion into active state.
    """
    pipeline = get_pipeline()
    success = pipeline.approve_review_item(review_id, req.approved_target)
    if not success:
        raise HTTPException(status_code=404, detail=f"Review ID {review_id} not found in queue")
    return {"status": "approved", "review_id": review_id}


@app.get("/raw/{event_id}")
def get_raw_payload(event_id: str):
    """
    Retrieve original byte-exact raw payload from Vault via RawRef locator.
    """
    pipeline = get_pipeline()
    row = pipeline.lake.con.execute(
        "SELECT raw_locator FROM parsed_logs WHERE event_id = ?", [event_id]
    ).fetchone()
    if not row or not row[0]:
        raise HTTPException(status_code=404, detail=f"Event ID {event_id} not found")

    try:
        locator = RawRef.parse(row[0])
        raw_bytes = pipeline.vault.get_raw(locator)
        return Response(content=raw_bytes, media_type="text/plain")
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/lineage/{event_id}")
def get_lineage(event_id: str):
    """
    Retrieve 7-stage lineage audit trail for an event.
    """
    pipeline = get_pipeline()
    row = pipeline.lake.con.execute(
        "SELECT lineage_json FROM lineage_log WHERE event_id = ?", [event_id]
    ).fetchone()
    if row and row[0]:
        return json.loads(row[0])

    row2 = pipeline.lake.con.execute(
        "SELECT event_id, sequence, raw_locator, class_uid, fingerprint, prev_hash FROM parsed_logs WHERE event_id = ?",
        [event_id]
    ).fetchone()
    if not row2:
        raise HTTPException(status_code=404, detail=f"Lineage for event ID {event_id} not found")

    return {
        "event_id": row2[0],
        "sequence": row2[1],
        "stage_1_raw": {"locator": row2[2]},
        "stage_5_normalization": {"class_uid": row2[3]},
        "stage_6_attestation": {"fingerprint": row2[4], "prev_hash": row2[5]}
    }


@app.get("/verify")
def verify_hash_chain(start_seq: int = 0, end_seq: Optional[int] = None):
    """
    Cryptographically verify the hash chain (RFC 8785 canonical fingerprints and prev_hash links).
    """
    pipeline = get_pipeline()
    sql = "SELECT sequence, fingerprint, prev_hash, ocsf_json FROM parsed_logs WHERE sequence >= ?"
    params: List[Any] = [start_seq]
    if end_seq is not None:
        sql += " AND sequence <= ?"
        params.append(end_seq)
    sql += " ORDER BY sequence ASC"

    rows = pipeline.lake.con.execute(sql, params).fetchall()
    if not rows:
        return {
            "verified": True,
            "message": "No events in specified range (empty chain)",
            "broken_sequence": None,
            "chain_head": pipeline.prev_fingerprint,
            "events_checked": 0
        }

    events_to_verify = []
    for r in rows:
        event_obj = json.loads(r[3])
        event_obj["sequence"] = r[0]
        event_obj["fingerprint"] = r[1]
        event_obj["prev_hash"] = r[2]
        events_to_verify.append(event_obj)

    is_valid, msg, broken_seq = verify_chain(events_to_verify)
    if not is_valid:
        METRICS["tamper_alerts_total"] += 1

    return {
        "verified": is_valid,
        "message": msg,
        "broken_sequence": broken_seq,
        "chain_head": pipeline.prev_fingerprint,
        "events_checked": len(events_to_verify)
    }


@app.get("/prove/{event_seq}")
def prove_inclusion(event_seq: int):
    """
    Generate an RFC 6962 Merkle inclusion proof for event at event_seq.
    Proves inclusion in ceil(log2 N) hashes without disclosing other logs.
    """
    pipeline = get_pipeline()
    rows = pipeline.lake.con.execute(
        "SELECT sequence, fingerprint FROM parsed_logs ORDER BY sequence ASC"
    ).fetchall()
    if not rows:
        raise HTTPException(status_code=400, detail="No events available to construct Merkle proof")

    fps = [r[1] for r in rows]
    target_idx = None
    for i, r in enumerate(rows):
        if r[0] == event_seq:
            target_idx = i
            break

    if target_idx is None:
        raise HTTPException(status_code=404, detail=f"Event sequence {event_seq} not found")

    tree = MerkleTree(fps)
    proof = tree.get_inclusion_proof(target_idx)

    return {
        "event_seq": event_seq,
        "target_fingerprint": fps[target_idx],
        "tree_size": len(fps),
        "merkle_root": tree.root,
        "inclusion_proof": proof,
        "verified": MerkleTree.verify_inclusion_proof(
            fps[target_idx], target_idx, len(fps), proof, tree.root
        )
    }


@app.post("/tamper-test")
def simulate_tamper(payload: TamperTestRequest):
    """
    Live Tamper Demo:
    1. Intentionally alters a normalized field in the database at sequence N
    2. Runs verify_chain()
    3. Demonstrates instant mathematical detection of broken hash chain!
    """
    pipeline = get_pipeline()
    row = pipeline.lake.con.execute(
        "SELECT event_id, ocsf_json FROM parsed_logs WHERE sequence = ?", [payload.sequence]
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Event at sequence {payload.sequence} does not exist")

    event_id, ocsf_str = row
    event_obj = json.loads(ocsf_str)
    
    # Tamper the field inside ocsf_json
    if payload.field_to_corrupt == "src_ip":
        if "src_endpoint" not in event_obj:
            event_obj["src_endpoint"] = {}
        event_obj["src_endpoint"]["ip"] = payload.tampered_value
    else:
        event_obj[payload.field_to_corrupt] = payload.tampered_value

    corrupted_json = json.dumps(event_obj)
    
    # Update DuckDB directly to simulate an attacker/insider tampering with database
    pipeline.lake.con.execute(
        f"UPDATE parsed_logs SET {payload.field_to_corrupt} = ?, ocsf_json = ? WHERE sequence = ?",
        [payload.tampered_value, corrupted_json, payload.sequence]
    )

    # Immediately verify chain using same database connection
    rows = pipeline.lake.con.execute(
        "SELECT sequence, fingerprint, prev_hash, ocsf_json FROM parsed_logs ORDER BY sequence ASC"
    ).fetchall()
    events_to_verify = []
    for r in rows:
        ev = json.loads(r[3])
        ev["sequence"] = r[0]
        ev["fingerprint"] = r[1]
        ev["prev_hash"] = r[2]
        events_to_verify.append(ev)

    is_valid, msg, broken_seq = verify_chain(events_to_verify)
    METRICS["tamper_alerts_total"] += 1

    return {
        "status": "TAMPER_SIMULATED",
        "tampered_sequence": payload.sequence,
        "corrupted_field": payload.field_to_corrupt,
        "injected_value": payload.tampered_value,
        "verification_result": {
            "verified": is_valid,
            "broken_sequence": broken_seq,
            "message": msg
        }
    }


@app.get("/lake/logs")
def get_lake_logs(limit: int = 50):
    """Retrieve recent normalized OCSF events from DuckDB"""
    pipeline = get_pipeline()
    rows = pipeline.lake.con.execute(
        "SELECT event_id, sequence, timestamp, class_uid, vendor, product, activity_name, src_ip, dst_ip, fingerprint, prev_hash, raw_locator FROM parsed_logs ORDER BY sequence DESC LIMIT ?",
        [limit]
    ).fetchall()

    items = []
    for r in rows:
        items.append({
            "event_id": r[0],
            "sequence": r[1],
            "timestamp": r[2],
            "class_uid": r[3],
            "vendor": r[4],
            "product": r[5],
            "activity_name": r[6],
            "src_ip": r[7],
            "dst_ip": r[8],
            "fingerprint": r[9],
            "prev_hash": r[10],
            "raw_locator": r[11]
        })
    return {"count": len(items), "logs": items}


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard():
    """Serve the modern ULPF Control Console"""
    dash_path = Path("./dashboard/index.html")
    if dash_path.exists():
        return HTMLResponse(content=dash_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>ULPF Server Running</h1><p>Dashboard UI loading...</p>")
