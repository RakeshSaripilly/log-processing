"""
Universal Log Pre-processing Framework (ULPF) - OCSF 1.9 Strict Envelope Model
Provides Pydantic V2 validated OCSF 1.9 data models with 7-stage lineage,
raw byte hash traceability, and cryptographic attestation envelopes.
Team LunarX - SIH26156 (NTRO)
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class ProductMetadata(BaseModel):
    name: str = Field(default="Unknown")
    vendor_name: str = Field(default="Generic")
    version: str = Field(default="1.0")


class OCSFMetadata(BaseModel):
    version: str = Field(default="1.9.0")
    product: ProductMetadata = Field(default_factory=ProductMetadata)
    profiles: List[str] = Field(default_factory=lambda: ["host", "security_control"])
    original_time: str = Field(default="")
    labels: List[str] = Field(default_factory=list)


class Endpoint(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None
    hostname: Optional[str] = None
    mac: Optional[str] = None


class UserActor(BaseModel):
    name: Optional[str] = None
    uid: Optional[str] = None


class Actor(BaseModel):
    user: Optional[UserActor] = None


class UnmappedMetadata(BaseModel):
    ulpf_raw_locator: str = Field(description="Deterministic RawRef locator ulpf:raw:seg:block:off:len")
    raw_sha256: str = Field(description="Cryptographic SHA-256 digest of original raw wire bytes")
    extra: Dict[str, Any] = Field(default_factory=dict)


class Stage1Raw(BaseModel):
    locator: str
    byte_length: int
    sha256: str


class Stage2Detection(BaseModel):
    pack: str
    status: str


class Stage3Extraction(BaseModel):
    decoder: str
    field_count: int
    keys: List[str]


class Stage4Inference(BaseModel):
    vector_confidence: float
    confidence_band: str


class Stage5Normalization(BaseModel):
    ocsf_version: str = "1.9.0"
    class_uid: int


class Stage6Attestation(BaseModel):
    canonical_scheme: str = "RFC8785_JCS"
    algorithm: str = "BLAKE3"
    fingerprint: str
    prev_hash: str


class Stage7Sink(BaseModel):
    status: str = "COMMITTED"
    formats: List[str] = Field(default_factory=lambda: ["NDJSON", "PARQUET", "DUCKDB"])


class SevenStageLineage(BaseModel):
    event_id: str
    stage_1_raw: Stage1Raw
    stage_2_detection: Stage2Detection
    stage_3_extraction: Stage3Extraction
    stage_4_inference: Stage4Inference
    stage_5_normalization: Stage5Normalization
    stage_6_attestation: Stage6Attestation
    stage_7_sink: Stage7Sink


class OCSFEventEnvelope(BaseModel):
    """
    OCSF 1.9 Canonical Event Envelope.
    Enforces lossless raw retention, 7-stage lineage, and cryptographic chain attestation.
    """
    metadata: OCSFMetadata = Field(default_factory=OCSFMetadata)
    class_uid: int = Field(default=0, description="OCSF 1.9 Class UID (e.g., 4001 Network, 3001 Auth)")
    category_uid: int = Field(default=0, description="OCSF 1.9 Category UID")
    time: int = Field(description="Event timestamp epoch in milliseconds")
    raw_data: str = Field(description="Original wire bytes decoded losslessly as text")
    unmapped: UnmappedMetadata = Field(description="RawRef locator and byte-exact SHA-256 hash")
    
    # Core Observables
    src_endpoint: Optional[Endpoint] = None
    dst_endpoint: Optional[Endpoint] = None
    actor: Optional[Actor] = None
    activity_name: Optional[str] = None
    disposition_id: Optional[int] = None
    severity_id: Optional[int] = None
    status_id: Optional[int] = None

    # Cryptographic Attestation Chain
    sequence: int = Field(default=0, description="Monotonically increasing event sequence number")
    event_id: str = Field(description="Unique UUID v4 event identifier")
    fingerprint: str = Field(default="", description="RFC 8785 JCS + BLAKE3 hash digest")
    prev_hash: str = Field(default="genesis", description="Hash of previous event in tamper-evident chain")

    # Auditable Provenance
    lineage: Optional[SevenStageLineage] = None
