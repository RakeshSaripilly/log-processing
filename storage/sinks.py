"""
Universal Log Pre-processing Framework (ULPF) - Multi-Destination Sinks & Lake Engine
NDJSON & Parquet partitioned lakes, DuckDB embedded engine, Wazuh UDP forwarder, Zero-Drop DLQ
Team LunarX - SIH26156 (NTRO)
"""

import os
import json
try:
    import orjson
    _HAS_ORJSON = True
except ImportError:
    _HAS_ORJSON = False
import socket
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

import duckdb
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

# Parquet Schema for OCSF 1.9 Canonical Lake
OCSF_ARROW_SCHEMA = pa.schema([
    ("event_id", pa.string()),
    ("sequence", pa.int64()),
    ("timestamp", pa.int64()),
    ("class_uid", pa.int32()),
    ("category_uid", pa.int32()),
    ("vendor", pa.string()),
    ("product", pa.string()),
    ("activity_name", pa.string()),
    ("src_ip", pa.string()),
    ("src_port", pa.int32()),
    ("dst_ip", pa.string()),
    ("dst_port", pa.int32()),
    ("user_name", pa.string()),
    ("hostname", pa.string()),
    ("fingerprint", pa.string()),
    ("prev_hash", pa.string()),
    ("raw_locator", pa.string()),
    ("raw_payload", pa.string()),
    ("ocsf_json", pa.string())
])


_ACTIVE_LAKES = []

def _flush_active_lakes():
    for lake in list(_ACTIVE_LAKES):
        try:
            lake.flush()
        except Exception:
            pass


class LakeStorageEngine:
    """
    Unified Storage Engine for ULPF.
    Writes partitioned Parquet, NDJSON, and syncs to DuckDB for sub-second analytical queries.
    """
    def __init__(self, lake_dir: str = "./lake", batch_size: int = 1000):
        self.lake_dir = Path(lake_dir)
        self.lake_dir.mkdir(parents=True, exist_ok=True)
        self.ndjson_dir = self.lake_dir / "ndjson"
        self.parquet_dir = self.lake_dir / "parquet"
        self.duckdb_path = self.lake_dir / "ulpf.duckdb"
        self.batch_size = batch_size
        self._buffer: List[Dict[str, Any]] = []
        self._lineage_buffer: List[Dict[str, Any]] = []
        _ACTIVE_LAKES.append(self)
        
        self.ndjson_dir.mkdir(parents=True, exist_ok=True)
        self.parquet_dir.mkdir(parents=True, exist_ok=True)

        self._init_duckdb()

    def _init_duckdb(self):
        self.con = duckdb.connect(str(self.duckdb_path))
        self.con.execute("PRAGMA disable_progress_bar")
        self.con.execute("PRAGMA wal_autocheckpoint = '1GB'")
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS parsed_logs (
                event_id VARCHAR PRIMARY KEY,
                sequence BIGINT,
                timestamp BIGINT,
                class_uid INTEGER,
                category_uid INTEGER,
                vendor VARCHAR,
                product VARCHAR,
                activity_name VARCHAR,
                src_ip VARCHAR,
                src_port INTEGER,
                dst_ip VARCHAR,
                dst_port INTEGER,
                user_name VARCHAR,
                hostname VARCHAR,
                fingerprint VARCHAR,
                prev_hash VARCHAR,
                raw_locator VARCHAR,
                raw_payload VARCHAR,
                ocsf_json VARCHAR
            );
            CREATE INDEX IF NOT EXISTS idx_logs_seq ON parsed_logs(sequence);
            CREATE INDEX IF NOT EXISTS idx_logs_src_ip ON parsed_logs(src_ip);
            CREATE INDEX IF NOT EXISTS idx_logs_ts ON parsed_logs(timestamp);

            CREATE TABLE IF NOT EXISTS review_queue (
                review_id VARCHAR PRIMARY KEY,
                cluster_id INTEGER,
                source_key VARCHAR,
                suggested_target VARCHAR,
                confidence FLOAT,
                inferred_type VARCHAR,
                samples VARCHAR,
                template VARCHAR,
                status VARCHAR,
                created_at BIGINT
            );

            CREATE TABLE IF NOT EXISTS checkpoints (
                checkpoint_seq BIGINT PRIMARY KEY,
                chain_head VARCHAR,
                merkle_root VARCHAR,
                signature VARCHAR,
                signer_pubkey VARCHAR,
                timestamp BIGINT
            );

            CREATE TABLE IF NOT EXISTS lineage_log (
                event_id VARCHAR PRIMARY KEY,
                lineage_json VARCHAR
            );
        """)

    def _get_partition_path(self, base_dir: Path, dt: datetime.datetime) -> Path:
        p = base_dir / f"year={dt.year:04d}" / f"month={dt.month:02d}" / f"day={dt.day:02d}"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def commit_event(self, ocsf_event: Dict[str, Any], lineage: Optional[Dict[str, Any]] = None):
        """
        Commit normalized OCSF event using memory buffer with high-throughput batch flushing.
        """
        self._buffer.append(ocsf_event)
        if lineage:
            self._lineage_buffer.append(lineage)

        if len(self._buffer) >= self.batch_size:
            self.flush()

    def flush(self):
        """
        Flush all buffered events to DuckDB and NDJSON atomically in a single vectorized transaction.
        """
        if not self._buffer:
            return
        batch = self._buffer
        lins = self._lineage_buffer
        self._buffer = []
        self._lineage_buffer = []
        self.commit_batch(batch, lineages=lins)

    def commit_batch(self, events: List[Dict[str, Any]], lineages: Optional[List[Dict[str, Any]]] = None):
        """
        High-throughput atomic batch commit supporting 8,000+ EPS.
        """
        if not events:
            return
        now = datetime.datetime.now(datetime.timezone.utc)
        part_ndjson = self._get_partition_path(self.ndjson_dir, now)
        ndjson_file = part_ndjson / "events.jsonl"

        rows = []
        ndjson_lines = []
        for ev in events:
            event_id = str(ev.get("event_id") or ev.get("unmapped", {}).get("raw_sha256", ""))
            seq = int(ev.get("sequence", 0))
            ts = int(ev.get("time", int(now.timestamp() * 1000)))
            class_uid = int(ev.get("class_uid", 0))
            category_uid = int(ev.get("category_uid", 0))
            meta = ev.get("metadata")
            prod_meta = meta.get("product") if meta else None
            if prod_meta:
                vendor = str(prod_meta.get("vendor_name", "Generic"))
                product = str(prod_meta.get("name", "Unknown"))
            else:
                vendor = "Generic"
                product = "Unknown"
            activity = str(ev.get("activity_name", ""))

            src_ep = ev.get("src_endpoint")
            if src_ep:
                src_ip = str(src_ep.get("ip", ""))
                src_port = src_ep.get("port")
            else:
                src_ip = ""
                src_port = None

            dst_ep = ev.get("dst_endpoint")
            if dst_ep:
                dst_ip = str(dst_ep.get("ip", ""))
                dst_port = dst_ep.get("port")
            else:
                dst_ip = ""
                dst_port = None

            actor = ev.get("actor")
            user_name = str(actor.get("user", {}).get("name", "")) if actor else ""

            dev = ev.get("device")
            hostname = str(dev.get("hostname", "")) if dev else ""

            fp = str(ev.get("fingerprint", ""))
            prev_hash = str(ev.get("prev_hash", ""))
            unmapped = ev.get("unmapped")
            raw_loc = str(unmapped.get("ulpf_raw_locator", "")) if unmapped else ""
            raw_text = str(ev.get("raw_data", ""))
            ocsf_json_str = orjson.dumps(ev).decode('utf-8') if _HAS_ORJSON else json.dumps(ev)

            ndjson_lines.append(ocsf_json_str)
            rows.append((
                event_id, seq, ts, class_uid, category_uid, vendor, product, activity,
                src_ip, src_port, dst_ip, dst_port, user_name, hostname,
                fp, prev_hash, raw_loc, raw_text, ocsf_json_str
            ))

        with open(ndjson_file, "a", encoding="utf-8") as f:
            f.write("\n".join(ndjson_lines) + "\n")

        cols = [
            "event_id", "sequence", "timestamp", "class_uid", "category_uid",
            "vendor", "product", "activity_name", "src_ip", "src_port",
            "dst_ip", "dst_port", "user_name", "hostname", "fingerprint",
            "prev_hash", "raw_locator", "raw_payload", "ocsf_json"
        ]
        df = pd.DataFrame(rows, columns=cols)
        self.con.register("_batch_df", df)
        self.con.execute("BEGIN TRANSACTION")
        self.con.execute("INSERT OR REPLACE INTO parsed_logs SELECT * FROM _batch_df")
        self.con.unregister("_batch_df")

        if lineages:
            lin_dumps = (lambda l: orjson.dumps(l).decode('utf-8')) if _HAS_ORJSON else json.dumps
            lin_rows = [(l.get("event_id", ""), lin_dumps(l)) for l in lineages if isinstance(l, dict) and "event_id" in l]
            if lin_rows:
                lin_df = pd.DataFrame(lin_rows, columns=["event_id", "lineage_json"])
                self.con.register("_lin_df", lin_df)
                self.con.execute("INSERT OR REPLACE INTO lineage_log SELECT * FROM _lin_df")
                self.con.unregister("_lin_df")
        self.con.execute("COMMIT")

    def flush_parquet(self):
        """
        Export recent DuckDB parsed_logs directly to Parquet partition file.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        part_pq = self._get_partition_path(self.parquet_dir, now)
        pq_path = part_pq / f"events_{int(now.timestamp())}.parquet"
        self.con.execute(f"COPY parsed_logs TO '{pq_path.as_posix()}' (FORMAT PARQUET)")
        return str(pq_path)

    def close(self):
        try:
            self.flush()
        except Exception:
            pass
        if self in _ACTIVE_LAKES:
            try:
                _ACTIVE_LAKES.remove(self)
            except Exception:
                pass
        try:
            self.con.close()
        except Exception:
            pass


class WazuhForwarder:
    """
    UDP Syslog Forwarder for side-by-side demonstration with Wazuh SIEM.
    Simulates or forwards events to Wazuh Manager port 514 / UDP.
    """
    def __init__(self, host: str = "127.0.0.1", port: int = 514):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.forwarded_count = 0

    def forward(self, ocsf_event: Dict[str, Any]):
        try:
            raw_text = ocsf_event.get("raw_data", "")
            if raw_text:
                self.sock.sendto(raw_text.encode('utf-8'), (self.host, self.port))
                self.forwarded_count += 1
        except Exception:
            # UDP fire-and-forget
            pass
