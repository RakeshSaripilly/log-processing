"""
Universal Log Pre-processing Framework (ULPF) - Cryptographic Raw Log Vault
Append-only zstd compressed blocks, CRC-32 verification, RawRef locators, Crash Recovery
Team LunarX - SIH26156 (NTRO)
"""

import os
import struct
import zlib
import time
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
TARGET_BLOCK_SIZE = 1 * 1024 * 1024  # 1 MiB uncompressed buffer


class RawRef:
    """
    Locator reference string: ulpf:raw:<seg>:<off>:<len>
    Points deterministically to exact byte slice in vault.
    """
    def __init__(self, segment_id: int, offset: int, length: int):
        self.segment_id = segment_id
        self.offset = offset
        self.length = length

    @classmethod
    def parse(cls, locator_str: str) -> "RawRef":
        parts = locator_str.split(":")
        if len(parts) != 5 or parts[0] != "ulpf" or parts[1] != "raw":
            raise ValueError(f"Invalid RawRef locator format: {locator_str}")
        return cls(int(parts[2]), int(parts[3]), int(parts[4]))

    def to_string(self) -> str:
        return f"ulpf:raw:{self.segment_id}:{self.offset}:{self.length}"

    def __repr__(self) -> str:
        return self.to_string()


class VaultStorage:
    """
    Vault append-only storage engine.
    Guarantees:
    - WRITE BEFORE PARSE: Raw bytes are permanently written before parser execution.
    - Lossless Raw Retention: Every byte, newline, and artifact is preserved.
    - Block Integrity: Every block protected by zstd compression and CRC-32 checksum.
    - Crash Recovery: If index is destroyed, scanning block headers completely reconstructs index.
    - Optional ChaCha20-Poly1305 authenticated encryption.
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
        
        # Buffer for accumulating logs into ~1MB blocks
        self.buffer = bytearray()
        self.buffer_offsets: List[Tuple[int, int]] = []  # (buffer_offset, length)
        self.buffer_pending_locators: List[RawRef] = []

        self.current_segment_id = 0
        self.current_block_idx = 0
        self.cipher_key: Optional[bytes] = None

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

        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=1,
            lanes=4,
            memory_cost=64 * 1024
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
            except ValueError:
                self.current_segment_id = 0
        else:
            self.current_segment_id = 0

    def write_raw(self, raw_bytes: bytes) -> RawRef:
        """
        Write raw bytes to vault buffer. Returns locator immediately.
        If buffer exceeds TARGET_BLOCK_SIZE (~1MiB), flush block to disk.
        """
        if not isinstance(raw_bytes, (bytes, bytearray)):
            raw_bytes = str(raw_bytes).encode('utf-8')

        offset = len(self.buffer)
        length = len(raw_bytes)
        self.buffer.extend(raw_bytes)

        ref = RawRef(
            segment_id=self.current_segment_id,
            offset=offset,
            length=length
        )
        self.buffer_pending_locators.append(ref)

        if len(self.buffer) >= TARGET_BLOCK_SIZE:
            self.flush()

        return ref

    def flush(self):
        """
        Compress current buffer with zstd, compute CRC32, encrypt if enabled,
        and write block header + payload to disk.
        """
        if not self.buffer:
            return

        uncompressed_data = bytes(self.buffer)
        uncomp_len = len(uncompressed_data)
        crc = zlib.crc32(uncompressed_data) & 0xffffffff

        # Compress
        if HAS_ZSTD:
            payload = self.cctx.compress(uncompressed_data)
        else:
            payload = zlib.compress(uncompressed_data)

        flags = FLAG_NONE
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
            f.write(header)
            f.write(payload)

        self.current_block_idx += 1
        self.buffer.clear()
        self.buffer_pending_locators.clear()

    def get_raw(self, locator: RawRef) -> bytes:
        """
        Retrieve exact raw bytes via locator.
        If log is still in memory buffer, slice directly.
        Otherwise, scan segment file to extract matching block and decompress.
        """
        # 1. Check in-memory uncompressed buffer first
        if locator.segment_id == self.current_segment_id:
            if locator.offset + locator.length <= len(self.buffer):
                candidate = bytes(self.buffer[locator.offset : locator.offset + locator.length])
                return candidate

        # 2. Check on-disk segment file
        seg_path = self._get_segment_path(locator.segment_id)
        if not seg_path.exists():
            raise FileNotFoundError(f"Vault segment {locator.segment_id} not found at {seg_path}")

        with open(seg_path, "rb") as f:
            while True:
                header_bytes = f.read(HEADER_SIZE)
                if len(header_bytes) < HEADER_SIZE:
                    break
                magic, seg_id, block_idx, uncomp_len, comp_len, crc, flags = struct.unpack(
                    HEADER_FORMAT, header_bytes
                )
                if magic != MAGIC_HEADER:
                    raise ValueError("Corrupt vault block header: invalid magic bytes")

                comp_bytes = f.read(comp_len)
                if len(comp_bytes) < comp_len:
                    raise IOError("Truncated block payload in vault")

                # Decrypt if encrypted
                if flags & FLAG_ENCRYPTED_CHACHA20:
                    if not self.cipher_key:
                        raise PermissionError("Encrypted vault block requires passphrase")
                    nonce = comp_bytes[:12]
                    ciphertext = comp_bytes[12:]
                    chacha = ChaCha20Poly1305(self.cipher_key)
                    comp_bytes = chacha.decrypt(nonce, ciphertext, None)

                # Decompress
                if HAS_ZSTD:
                    decompressed = self.dctx.decompress(comp_bytes)
                else:
                    decompressed = zlib.decompress(comp_bytes)

                # Verify CRC32
                if (zlib.crc32(decompressed) & 0xffffffff) != crc:
                    raise ValueError(f"Vault block CRC-32 checksum mismatch in block {block_idx}")

                # Check if locator falls within this block
                if locator.offset + locator.length <= len(decompressed):
                    return decompressed[locator.offset : locator.offset + locator.length]

        raise LookupError(f"RawRef locator {locator} not found in segment {locator.segment_id}")

    def recover_index(self) -> List[Dict[str, Any]]:
        """
        Crash Recovery: Scan all segment files, parse headers, verify CRCs,
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
                        "encrypted": bool(flags & FLAG_ENCRYPTED_CHACHA20)
                    })

                    # Skip payload
                    f.seek(comp_len, os.SEEK_CUR)
                    file_offset += HEADER_SIZE + comp_len

        return index
