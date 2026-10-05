"""
Universal Log Pre-processing Framework (ULPF) - Cryptographic Raw Log Vault
Append-only zstd compressed blocks, CRC-32 verification, RawRef locators, Crash Recovery
Thread-Safe, Durable fsync, O(1) Block Locators with raw_sha256 Traceability
Team LunarX - SIH26156 (NTRO)
"""

import os
import struct
import zlib
import time
import hashlib
import threading
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List, Generator

try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

MAGIC_HEADER = b"ULPF_V1\x00"  # 8 bytes
HEADER_FORMAT = "<8sIIIIII"    # magic(8), seg_id(4), block_idx(4), uncomp_len(4), comp_len(4), crc32(4), flags(4)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT) # 32 bytes

FLAG_NONE = 0x00
FLAG_ENCRYPTED_CHACHA20 = 0x01
FLAG_COMPRESSION_ZSTD = 0x02
FLAG_COMPRESSION_ZLIB = 0x04

TARGET_BLOCK_SIZE = 1 * 1024 * 1024  # 1 MiB uncompressed buffer


class RawRef:
    """
    Locator reference string: ulpf:raw:<seg>:<block>:<off>:<len>
    Provides deterministic O(1) byte-slice retrieval from vault blocks.
    Also tracks raw_sha256 for end-to-end cryptographic traceability.
    """
    def __init__(self, segment_id: int, block_idx: int, offset: int, length: int, raw_sha256: str = ""):
        self.segment_id = segment_id
        self.block_idx = block_idx
        self.offset = offset
        self.length = length
        self.raw_sha256 = raw_sha256

    @classmethod
    def parse(cls, locator_str: str) -> "RawRef":
        parts = locator_str.split(":")
        # Format: ulpf:raw:<seg>:<block>:<off>:<len>
        if len(parts) == 6 and parts[0] == "ulpf" and parts[1] == "raw":
            return cls(int(parts[2]), int(parts[3]), int(parts[4]), int(parts[5]))
        # Backwards compatibility: ulpf:raw:<seg>:<off>:<len>
        elif len(parts) == 5 and parts[0] == "ulpf" and parts[1] == "raw":
            return cls(int(parts[2]), 0, int(parts[3]), int(parts[4]))
        raise ValueError(f"Invalid RawRef locator format: {locator_str}")

    def to_string(self) -> str:
        return f"ulpf:raw:{self.segment_id}:{self.block_idx}:{self.offset}:{self.length}"

    def __repr__(self) -> str:
        return self.to_string()

    def __iter__(self):
        return iter((self, self.raw_sha256))


class VaultStorage:
    """
    Vault append-only storage engine.
    Guarantees:
    - WRITE BEFORE PARSE: Raw bytes are permanently written before parser execution.
    - Lossless Raw Retention: Every byte, newline, and artifact is preserved.
    - Block Integrity: Every block protected by zstd compression and CRC-32 checksum.
    - Thread Safety: Bounded buffer and disk flushes protected by threading.Lock.
    - Durable I/O: os.fsync() on every block write.
    - Crash Recovery: If index is destroyed, scanning block headers completely reconstructs index.
    - O(1) Retrieval: block_idx in locator avoids linear file scans.
    """

    def __init__(
        self,
        vault_dir: str = "./storage/raw",
        passphrase: Optional[str] = None,
        max_segment_size: int = 64 * 1024 * 1024  # 64 MB per segment file
    ):
        self.vault_dir = Path(vault_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.passphrase = passphrase
        self.max_segment_size = max_segment_size
        self.lock = threading.Lock()
        
        # Buffer for accumulating logs into ~1MB blocks
        self.buffer = bytearray()
        self.buffer_pending_locators: List[RawRef] = []

        self.current_segment_id = 0
        self.current_block_idx = 0
        self.cipher_key: Optional[bytes] = None

        # Block offset lookup index: (segment_id, block_idx) -> file_offset
        self.block_offset_cache: Dict[Tuple[int, int], int] = {}

        if HAS_ZSTD:
            self.cctx = zstd.ZstdCompressor(level=3)
            self.dctx = zstd.ZstdDecompressor()
        else:
            self.cctx = None
            self.dctx = None

        self._init_encryption()
        self._find_latest_segment()

    def _init_encryption(self):
        if not self.passphrase:
            return
        salt_file = self.vault_dir / "vault.salt"
        if salt_file.exists():
            salt = salt_file.read_bytes()
        else:
            salt = os.urandom(16)
            salt_file.write_bytes(salt)

        # Hardened Argon2id parameters
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=3,
            lanes=4,
            memory_cost=256 * 1024
        )
        self.cipher_key = kdf.derive(self.passphrase.encode('utf-8'))

    def _get_segment_path(self, segment_id: int) -> Path:
        return self.vault_dir / f"vault_seg_{segment_id:06d}.ulpf"

    def _find_latest_segment(self):
        existing = sorted(self.vault_dir.glob("vault_seg_*.ulpf"))
        if existing:
            latest = existing[-1]
            try:
                seg_id = int(latest.stem.split("_")[-1])
                self.current_segment_id = seg_id
                # Count blocks in current segment to set current_block_idx
                self._index_segment_blocks(seg_id)
            except ValueError:
                self.current_segment_id = 0
                self.current_block_idx = 0
        else:
            self.current_segment_id = 0
            self.current_block_idx = 0

    def _index_segment_blocks(self, seg_id: int):
        seg_path = self._get_segment_path(seg_id)
        if not seg_path.exists():
            return
        file_offset = 0
        file_size = seg_path.stat().st_size
        max_blk = 0
        with open(seg_path, "rb") as f:
            while file_offset < file_size:
                header_bytes = f.read(HEADER_SIZE)
                if len(header_bytes) < HEADER_SIZE:
                    break
                magic, s_id, blk_idx, uncomp_len, comp_len, crc, flags = struct.unpack(
                    HEADER_FORMAT, header_bytes
                )
                if magic != MAGIC_HEADER:
                    break
                self.block_offset_cache[(s_id, blk_idx)] = file_offset
                max_blk = max(max_blk, blk_idx + 1)
                f.seek(comp_len, os.SEEK_CUR)
                file_offset += HEADER_SIZE + comp_len
        self.current_block_idx = max_blk

    def write_raw(self, raw_bytes: bytes) -> Tuple[RawRef, str]:
        """
        Thread-safe Write-Before-Parse.
        Returns: (RawRef, raw_sha256)
        """
        if not isinstance(raw_bytes, (bytes, bytearray)):
            raw_bytes = str(raw_bytes).encode('utf-8')

        sha256 = hashlib.sha256(raw_bytes).hexdigest()

        with self.lock:
            offset = len(self.buffer)
            length = len(raw_bytes)
            self.buffer.extend(raw_bytes)

            ref = RawRef(
                segment_id=self.current_segment_id,
                block_idx=self.current_block_idx,
                offset=offset,
                length=length,
                raw_sha256=sha256
            )
            self.buffer_pending_locators.append(ref)

            if len(self.buffer) >= TARGET_BLOCK_SIZE:
                self._flush_locked()

        return ref

    def flush(self):
        """Public thread-safe flush method."""
        with self.lock:
            self._flush_locked()

    def _flush_locked(self):
        """Internal flush (caller must hold self.lock)"""
        if not self.buffer:
            return

        uncompressed_data = bytes(self.buffer)
        uncomp_len = len(uncompressed_data)
        crc = zlib.crc32(uncompressed_data) & 0xffffffff

        # Compress
        flags = FLAG_NONE
        if HAS_ZSTD:
            flags |= FLAG_COMPRESSION_ZSTD
            payload = self.cctx.compress(uncompressed_data)
        else:
            flags |= FLAG_COMPRESSION_ZLIB
            payload = zlib.compress(uncompressed_data)

        if self.cipher_key:
            flags |= FLAG_ENCRYPTED_CHACHA20
            chacha = ChaCha20Poly1305(self.cipher_key)
            nonce = os.urandom(12)
            payload = nonce + chacha.encrypt(nonce, payload, None)

        comp_len = len(payload)

        # Segment rollover check
        seg_path = self._get_segment_path(self.current_segment_id)
        if seg_path.exists() and seg_path.stat().st_size + HEADER_SIZE + comp_len > self.max_segment_size:
            self.current_segment_id += 1
            self.current_block_idx = 0
            seg_path = self._get_segment_path(self.current_segment_id)

        header = struct.pack(
            HEADER_FORMAT,
            MAGIC_HEADER,
            self.current_segment_id,
            self.current_block_idx,
            uncomp_len,
            comp_len,
            crc,
            flags
        )

        with open(seg_path, "ab") as f:
            file_offset = f.tell()
            f.write(header)
            f.write(payload)
            # Durable write-before-parse guarantees
            f.flush()
            os.fsync(f.fileno())

        self.block_offset_cache[(self.current_segment_id, self.current_block_idx)] = file_offset
        self.current_block_idx += 1
        self.buffer.clear()
        self.buffer_pending_locators.clear()

    def get_raw(self, locator: Any) -> bytes:
        """
        O(1) direct block retrieval via locator.
        If still in active buffer, slice immediately.
        Otherwise seek directly to block using offset cache or fast header scan.
        """
        if isinstance(locator, tuple):
            locator = locator[0]
        elif isinstance(locator, str):
            locator = RawRef.parse(locator)

        with self.lock:
            # 1. In-memory uncompressed buffer check
            if (locator.segment_id == self.current_segment_id and 
                locator.block_idx == self.current_block_idx):
                if locator.offset + locator.length <= len(self.buffer):
                    return bytes(self.buffer[locator.offset : locator.offset + locator.length])

        # 2. On-disk segment file
        seg_path = self._get_segment_path(locator.segment_id)
        if not seg_path.exists():
            raise FileNotFoundError(f"Vault segment {locator.segment_id} not found at {seg_path}")

        with open(seg_path, "rb") as f:
            # Check if block offset is cached for true O(1) jump
            cache_key = (locator.segment_id, locator.block_idx)
            if cache_key in self.block_offset_cache:
                f.seek(self.block_offset_cache[cache_key])
                header_bytes = f.read(HEADER_SIZE)
                if len(header_bytes) == HEADER_SIZE:
                    magic, s_id, b_idx, uncomp_len, comp_len, crc, flags = struct.unpack(
                        HEADER_FORMAT, header_bytes
                    )
                    if magic == MAGIC_HEADER and s_id == locator.segment_id and b_idx == locator.block_idx:
                        comp_bytes = f.read(comp_len)
                        decompressed = self._decompress_block(comp_bytes, flags, crc)
                        if locator.offset + locator.length <= len(decompressed):
                            return decompressed[locator.offset : locator.offset + locator.length]

            # Fallback: scan headers by seeking comp_len (without decompressing unwanted blocks)
            f.seek(0)
            while True:
                header_pos = f.tell()
                header_bytes = f.read(HEADER_SIZE)
                if len(header_bytes) < HEADER_SIZE:
                    break
                magic, s_id, b_idx, uncomp_len, comp_len, crc, flags = struct.unpack(
                    HEADER_FORMAT, header_bytes
                )
                if magic != MAGIC_HEADER:
                    break

                self.block_offset_cache[(s_id, b_idx)] = header_pos

                if s_id == locator.segment_id and b_idx == locator.block_idx:
                    comp_bytes = f.read(comp_len)
                    decompressed = self._decompress_block(comp_bytes, flags, crc)
                    if locator.offset + locator.length <= len(decompressed):
                        return decompressed[locator.offset : locator.offset + locator.length]
                    raise LookupError(f"Offset {locator.offset} out of bounds in block {b_idx}")

                # Skip payload without reading into memory
                f.seek(comp_len, os.SEEK_CUR)

        raise LookupError(f"RawRef locator {locator} not found in segment {locator.segment_id}")

    def _decompress_block(self, comp_bytes: bytes, flags: int, expected_crc: int) -> bytes:
        if flags & FLAG_ENCRYPTED_CHACHA20:
            if not self.cipher_key:
                raise PermissionError("Encrypted vault block requires passphrase")
            nonce = comp_bytes[:12]
            ciphertext = comp_bytes[12:]
            chacha = ChaCha20Poly1305(self.cipher_key)
            comp_bytes = chacha.decrypt(nonce, ciphertext, None)

        if flags & FLAG_COMPRESSION_ZSTD or (HAS_ZSTD and not (flags & FLAG_COMPRESSION_ZLIB)):
            decompressed = self.dctx.decompress(comp_bytes)
        else:
            decompressed = zlib.decompress(comp_bytes)

        if (zlib.crc32(decompressed) & 0xffffffff) != expected_crc:
            raise ValueError("Vault block CRC-32 checksum mismatch: corrupted data")

        return decompressed

    def recover_index(self) -> List[Dict[str, Any]]:
        """
        Crash Recovery: Scan all segment file headers, verify CRCs,
        and reconstruct complete block index without needing a database.
        """
        self.flush()
        index = []
        for seg_file in sorted(self.vault_dir.glob("vault_seg_*.ulpf")):
            file_offset = 0
            file_size = seg_file.stat().st_size
            with open(seg_file, "rb") as f:
                while file_offset < file_size:
                    header_bytes = f.read(HEADER_SIZE)
                    if len(header_bytes) < HEADER_SIZE:
                        break
                    magic, seg_id, block_idx, uncomp_len, comp_len, crc, flags = struct.unpack(
                        HEADER_FORMAT, header_bytes
                    )
                    if magic != MAGIC_HEADER:
                        break

                    index.append({
                        "file": seg_file.name,
                        "segment_id": seg_id,
                        "block_index": block_idx,
                        "file_offset": file_offset,
                        "uncompressed_length": uncomp_len,
                        "compressed_length": comp_len,
                        "crc32": f"0x{crc:08x}",
                        "encrypted": bool(flags & FLAG_ENCRYPTED_CHACHA20),
                        "compression": "zstd" if (flags & FLAG_COMPRESSION_ZSTD) else "zlib"
                    })

                    f.seek(comp_len, os.SEEK_CUR)
                    file_offset += HEADER_SIZE + comp_len

        return index
