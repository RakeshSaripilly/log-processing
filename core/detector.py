"""
Universal Log Pre-processing Framework (ULPF) - Source Pack Detector & Compiler
Compiles declarative YAML Source Packs with 400ms debounced hot-reload.
Zero network/model calls on hot path.
Team LunarX - SIH26156 (NTRO)
"""

import os
import re
import time
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from core.decoders import DECODER_REGISTRY

logger = logging.getLogger("ulpf.detector")


class CompiledSourcePack:
    """
    Compiled in-memory representation of a Source Pack YAML.
    Hot path performs fast regex / string checks without disk access.
    """
    def __init__(self, pack_id: str, raw_config: Dict[str, Any]):
        self.pack_id = pack_id
        self.raw_config = raw_config
        self.name = raw_config.get("name", pack_id)
        self.vendor = raw_config.get("vendor", "Generic")
        self.product = raw_config.get("product", "Unknown")
        self.version = str(raw_config.get("version", "1.0"))
        self.class_uid = raw_config.get("class_uid", 1001)
        self.category_uid = raw_config.get("category_uid", self.class_uid // 1000)

        # Detectors
        self.detectors = raw_config.get("detection", {})
        self.contains_keywords = [k.lower() for k in self.detectors.get("contains", [])]
        self.prefix_patterns = self.detectors.get("prefixes", [])
        
        self.regex_detectors = []
        for pat in self.detectors.get("patterns", []):
            try:
                self.regex_detectors.append(re.compile(pat))
            except Exception as e:
                logger.warning(f"Failed to compile detector regex '{pat}' in pack {pack_id}: {e}")

        # Decoder chain
        self.decoder_chain: List[str] = raw_config.get("decoders", ["json"])
        
        # Custom regex extraction pattern if using 'regex' decoder
        self.custom_regex_pattern = raw_config.get("regex_pattern")

        # Field mappings
        self.mappings: Dict[str, str] = raw_config.get("mappings", {})
        self.fixtures: List[Dict[str, Any]] = raw_config.get("fixtures", [])

    def claims(self, raw_text: str) -> bool:
        """
        Fast evaluation of whether this pack claims the raw log text.
        """
        lower_text = raw_text.lower()

        # Check required contains keywords
        if self.contains_keywords:
            if not all(kw in lower_text for kw in self.contains_keywords):
                return False

        # Check prefixes
        if self.prefix_patterns:
            if not any(raw_text.startswith(pfx) for pfx in self.prefix_patterns):
                return False

        # Check regex detectors
        if self.regex_detectors:
            if not any(rgx.search(raw_text) for rgx in self.regex_detectors):
                return False

        # If any criteria matched (or if contains matched), claim it
        return bool(self.contains_keywords or self.prefix_patterns or self.regex_detectors)

    def extract(self, raw_text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Run the configured decoder chain in sequence.
        Returns first successful decoder name and extracted dict.
        """
        for dec_name in self.decoder_chain:
            if dec_name == "regex" and self.custom_regex_pattern:
                fn = DECODER_REGISTRY.get("regex")
                data = fn(raw_text, self.custom_regex_pattern)
                if data:
                    return dec_name, data
            elif dec_name in DECODER_REGISTRY:
                fn = DECODER_REGISTRY[dec_name]
                data = fn(raw_text)
                if data:
                    return dec_name, data
        return None


class PackRegistry:
    """
    Registry of compiled Source Packs.
    Supports directory scanning and 400ms burst-coalescing hot reload.
    """
    def __init__(self, packs_dir: str = "./parsers/active"):
        self.packs_dir = Path(packs_dir)
        self.packs_dir.mkdir(parents=True, exist_ok=True)
        self.packs: Dict[str, CompiledSourcePack] = {}
        self.last_load_time = 0.0
        self.reload_all()

    def reload_all(self):
        loaded = {}
        for yml_path in sorted(self.packs_dir.glob("*.yaml")) + sorted(self.packs_dir.glob("*.yml")):
            pack_id = yml_path.stem
            try:
                content = yml_path.read_text(encoding="utf-8")
                raw_cfg = yaml.safe_load(content)
                if not isinstance(raw_cfg, dict):
                    continue
                pack = CompiledSourcePack(pack_id, raw_cfg)
                loaded[pack_id] = pack
                logger.info(f"Loaded Source Pack: {pack_id} ({pack.name})")
            except Exception as e:
                logger.error(f"Error loading pack '{yml_path.name}': {e} - SKIPPING")

        self.packs = loaded
        self._match_cache: Dict[str, Optional[CompiledSourcePack]] = {}
        self.last_load_time = time.time()

    def find_matching_pack(self, raw_text: str) -> Optional[CompiledSourcePack]:
        """
        Scan compiled packs on hot path with fast prefix cache.
        Returns first pack whose identity detector claims the log.
        """
        prefix = raw_text[:48]
        if prefix in self._match_cache:
            return self._match_cache[prefix]

        for pack in self.packs.values():
            if pack.claims(raw_text):
                if len(self._match_cache) < 4096:
                    self._match_cache[prefix] = pack
                return pack
        if len(self._match_cache) < 4096:
            self._match_cache[prefix] = None
        return None
