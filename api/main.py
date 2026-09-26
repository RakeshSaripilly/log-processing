"""
Universal Log Pre-processing Framework (ULPF) - FastAPI Engine & Management API
Endpoints: /ingest, /review-queue, /review/{id}/approve, /metrics, /healthz, /prove, /verify, /tamper-test
Team LunarX - SIH26156 (NTRO)
"""

import time
import os
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response, Depends, Header
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.pipeline import ProcessingPipeline
from core.integrity import verify_chain
from core.checkpoint import MerkleTree

app = FastAPI(
    title="ULPF - Universal Log Pre-processing Framework",
    description="SIH26156 (NTRO) - Team LunarX: Vault-First + Vector Matcher + Hash Chain",
    version="2.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize pipeline singleton
pipeline = ProcessingPipeline()

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
    return {
        "ready": True,
        "vault_segments": len(list(pipeline.vault.vault_dir.glob("vault_seg_*.ulpf"))),
        "active_packs": len(pipeline.registry.packs),
        "chain_head": pipeline.prev_fingerprint
    }


@app.get("/metrics")
def metrics():
    """Prometheus-compatible plain text metrics"""
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
    success = pipeline.approve_review_item(review_id, req.approved_target)
    if not success:
        raise HTTPException(status_code=404, detail=f"Review ID {review_id} not found in queue")
    return {"status": "approved", "review_id": review_id}


@app.get("/raw/{event_id}")
def get_raw_payload(event_id: str):
    """
    Retrieve original byte-exact raw payload from Vault via RawRef locator.
    """
    try:
        from ulpf_py.client import ULPFClient
        client = ULPFClient(lake_path=str(pipeline.lake.lake_dir), vault_path=str(pipeline.vault.vault_dir))
        raw_bytes = client.get_raw(event_id)
        return Response(content=raw_bytes, media_type="text/plain")
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/lineage/{event_id}")
def get_lineage(event_id: str):
    """
    Retrieve 7-stage lineage audit trail for an event.
    """
    try:
        from ulpf_py.client import ULPFClient
        client = ULPFClient(lake_path=str(pipeline.lake.lake_dir), vault_path=str(pipeline.vault.vault_dir))
        return client.get_lineage(event_id)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/verify")
def verify_hash_chain(start_seq: int = 0, end_seq: Optional[int] = None):
    """
    Cryptographically verify the hash chain (RFC 8785 canonical fingerprints and prev_hash links).
    """
    from ulpf_py.client import ULPFClient
    client = ULPFClient(lake_path=str(pipeline.lake.lake_dir), vault_path=str(pipeline.vault.vault_dir))
    is_valid, msg, broken_seq = client.verify_chain(start_seq=start_seq, end_seq=end_seq)
    if not is_valid:
        METRICS["tamper_alerts_total"] += 1
    return {
        "verified": is_valid,
        "message": msg,
        "broken_sequence": broken_seq,
        "chain_head": pipeline.prev_fingerprint,
        "events_checked": pipeline.sequence_counter
    }


@app.get("/prove/{event_seq}")
def prove_inclusion(event_seq: int):
    """
    Generate an RFC 6962 Merkle inclusion proof for event at event_seq.
    Proves inclusion in ceil(log2 N) hashes without disclosing other logs.
    """
    try:
        from ulpf_py.client import ULPFClient
        client = ULPFClient(lake_path=str(pipeline.lake.lake_dir), vault_path=str(pipeline.vault.vault_dir))
        return client.prove(event_seq)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/tamper-test")
def simulate_tamper(payload: TamperTestRequest):
    """
    Live Tamper Demo:
    1. Intentionally alters a normalized field in the database at sequence N
    2. Runs verify_chain()
    3. Demonstrates instant mathematical detection of broken hash chain!
    """
    # Check if target sequence exists
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

    # Immediately verify chain
    from ulpf_py.client import ULPFClient
    client = ULPFClient(lake_path=str(pipeline.lake.lake_dir), vault_path=str(pipeline.vault.vault_dir))
    is_valid, msg, broken_seq = client.verify_chain()

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
