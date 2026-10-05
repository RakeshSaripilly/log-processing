//! Universal Log Pre-processing Framework (ULPF) - High-Performance Rust Core Engine
//! Accelerated zstd vault chunking, BLAKE3 RFC 8785 hash chaining, and RFC 6962 Merkle tree.
//! Air-Gapped: No network sockets, pure computation.

use std::io::Write;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::PyIOError;
use sha2::{Digest, Sha256};

const TARGET_BLOCK_SIZE: usize = 1024 * 1024; // 1 MiB uncompressed block buffer

/// Compress a block with zstd level 3, ensuring uncompressed content size is embedded in the frame header.
fn compress_block(uncompressed: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = zstd::Encoder::new(Vec::new(), 3)?;
    encoder.set_pledged_src_size(Some(uncompressed.len() as u64))?;
    encoder.include_contentsize(true)?;
    encoder.write_all(uncompressed)?;
    encoder.finish()
}

/// RFC 8785 JSON Canonicalization Scheme (JCS) deterministic serializer.
fn canonicalize_value(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => {
            serde_json::to_string(s).unwrap_or_else(|_| format!("\"{}\"", s))
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonicalize_value).collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            entries.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));
            let items: Vec<String> = entries
                .iter()
                .map(|(k, v)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap(),
                        canonicalize_value(v)
                    )
                })
                .collect();
            format!("{{{}}}", items.join(","))
        }
    }
}

/// Ingests raw lines and batches them into ~1MiB zstd-compressed blocks with CRC-32 checksums.
/// Returns (compressed_blocks: Vec<PyBytes>, locators: Vec<String>, crc32: Vec<u32>).
/// Each locator is formatted as `ulpf:raw:<seg>:<block>:<off>:<len>`.
#[pyfunction]
#[pyo3(signature = (lines, start_seg=0, start_block=0))]
fn vault_append_batch<'py>(
    py: Python<'py>,
    lines: Vec<Vec<u8>>,
    start_seg: Option<u32>,
    start_block: Option<u32>,
) -> PyResult<(Vec<Bound<'py, PyBytes>>, Vec<String>, Vec<u32>)> {
    let mut compressed_blocks: Vec<Bound<'py, PyBytes>> = Vec::new();
    let mut locators: Vec<String> = Vec::with_capacity(lines.len());
    let mut crc32_list: Vec<u32> = Vec::new();

    let seg = start_seg.unwrap_or(0);
    let mut current_block = start_block.unwrap_or(0);
    let mut current_uncompressed: Vec<u8> = Vec::with_capacity(TARGET_BLOCK_SIZE);

    for line in lines {
        let offset = current_uncompressed.len();
        let length = line.len();
        current_uncompressed.extend_from_slice(&line);
        let locator = format!("ulpf:raw:{}:{}:{}:{}", seg, current_block, offset, length);
        locators.push(locator);

        if current_uncompressed.len() >= TARGET_BLOCK_SIZE {
            let crc = crc32fast::hash(&current_uncompressed);
            let comp = compress_block(&current_uncompressed)
                .map_err(|e| PyIOError::new_err(format!("zstd compression failed: {}", e)))?;
            compressed_blocks.push(PyBytes::new_bound(py, &comp));
            crc32_list.push(crc);
            current_uncompressed.clear();
            current_block += 1;
        }
    }

    if !current_uncompressed.is_empty() {
        let crc = crc32fast::hash(&current_uncompressed);
        let comp = compress_block(&current_uncompressed)
            .map_err(|e| PyIOError::new_err(format!("zstd compression failed: {}", e)))?;
        compressed_blocks.push(PyBytes::new_bound(py, &comp));
        crc32_list.push(crc);
    }

    Ok((compressed_blocks, locators, crc32_list))
}

/// RFC 8785 JCS canonicalization + BLAKE3 cryptographic hash chain calculation.
/// Binds `prev_hash` to the canonical JSON representation and returns the hex digest.
#[pyfunction]
fn blake3_hash_chain(prev_hash: String, canonical_json: String) -> PyResult<String> {
    let canonical_str = if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&canonical_json) {
        if let serde_json::Value::Object(ref mut map) = val {
            if !prev_hash.is_empty() {
                map.insert("prev_hash".to_string(), serde_json::Value::String(prev_hash));
            }
            map.remove("fingerprint");
            map.remove("signature");
            map.remove("merkle_proof");
        }
        canonicalize_value(&val)
    } else {
        canonical_json
    };

    let hash = blake3::hash(canonical_str.as_bytes());
    Ok(hash.to_hex().to_string())
}

/// RFC 6962 Domain Separation Hashes:
/// Leaf: SHA256(0x00 + data)
fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&[0x00]);
    hasher.update(data);
    hasher.finalize().into()
}

/// Internal Node: SHA256(0x01 + left + right)
fn hash_children(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&[0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Calculates RFC 6962 Merkle tree root across a batch of event fingerprint hashes.
#[pyfunction]
fn merkle_root(hashes: Vec<String>) -> String {
    if hashes.is_empty() {
        return "00".repeat(32);
    }

    let mut current_level: Vec<[u8; 32]> = hashes
        .iter()
        .map(|h| hash_leaf(h.as_bytes()))
        .collect();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
        for i in (0..current_level.len()).step_by(2) {
            let left = &current_level[i];
            let right = if i + 1 < current_level.len() {
                &current_level[i + 1]
            } else {
                left
            };
            next_level.push(hash_children(left, right));
        }
        current_level = next_level;
    }

    current_level[0]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// PyO3 Python Module exposing the Rust core engine.
#[pymodule]
fn ulpf_core_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(vault_append_batch, m)?)?;
    m.add_function(wrap_pyfunction!(blake3_hash_chain, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_root, m)?)?;
    Ok(())
}
