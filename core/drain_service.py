"""
Universal Log Pre-processing Framework (ULPF) - Drain Template Mining Service
Fixed-depth parse tree, token specificity calculation, volume ranking
Groups 10,000+ unknown logs into unified cluster templates.
Team LunarX - SIH26156 (NTRO)
"""

import re
from typing import Dict, Any, List, Optional
from collections import Counter

try:
    from drain3 import TemplateMiner
    from drain3.template_miner_config import TemplateMinerConfig
    from drain3.masking import MaskingInstruction
    HAS_DRAIN3 = True
except ImportError:
    HAS_DRAIN3 = False


class DrainClusterService:
    """
    Online log message clustering and template mining.
    Computes:
    - Template string with <*> wildcards
    - Specificity score: ratio of literal tokens to total tokens
    - Cluster size / volume ranking
    """

    def __init__(self, depth: int = 4, sim_th: float = 0.5):
        self.depth = depth
        self.sim_th = sim_th
        self.cluster_counts: Counter = Counter()
        self.cluster_samples: Dict[int, str] = {}
        self.cluster_templates: Dict[int, str] = {}

        if HAS_DRAIN3:
            config = TemplateMinerConfig()
            config.drain_depth = depth
            config.drain_sim_th = sim_th
            config.masking_instructions = [
                MaskingInstruction(pattern=r"\b(?:\d{1,3}\.){3}\d{1,3}\b", mask_with="IP"),
                MaskingInstruction(pattern=r"\b0x[a-fA-F0-9]+\b", mask_with="HEX"),
                MaskingInstruction(pattern=r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", mask_with="UUID"),
                MaskingInstruction(pattern=r"\b\d+\b", mask_with="NUM")
            ]
            self.miner = TemplateMiner(config=config)
        else:
            self.miner = None
            # Fallback simple template cache
            self.fallback_clusters: Dict[str, int] = {}
            self.next_cluster_id = 1

    def match_or_cluster(self, raw_message: str) -> Dict[str, Any]:
        """
        Ingest unknown raw message and return cluster ID, template, and specificity.
        """
        raw_message = raw_message.strip()
        if HAS_DRAIN3 and self.miner:
            result = self.miner.add_log_message(raw_message)
            cluster_id = result["cluster_id"]
            template = result["template_mined"]
        else:
            # High-throughput regex masking fallback
            masked = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<*>", raw_message)
            masked = re.sub(r"\b\d+\b", "<*>", masked)
            masked = re.sub(r"\b0x[0-9a-fA-F]+\b", "<*>", masked)
            template = masked
            if template not in self.fallback_clusters:
                self.fallback_clusters[template] = self.next_cluster_id
                self.next_cluster_id += 1
            cluster_id = self.fallback_clusters[template]

        self.cluster_counts[cluster_id] += 1
        self.cluster_templates[cluster_id] = template
        if cluster_id not in self.cluster_samples:
            self.cluster_samples[cluster_id] = raw_message

        # Specificity calculation: literal tokens vs <*> wildcards
        tokens = template.split()
        if not tokens:
            specificity = 0.0
        else:
            wildcards = sum(1 for t in tokens if "<" in t and ">" in t)
            literals = len(tokens) - wildcards
            specificity = round(max(0.0, min(1.0, literals / len(tokens))), 3)

        return {
            "cluster_id": cluster_id,
            "template": template,
            "specificity": specificity,
            "cluster_size": self.cluster_counts[cluster_id],
            "sample": self.cluster_samples[cluster_id]
        }

    def get_top_unknown_templates(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Return the top N most frequent unknown log clusters ranked by volume.
        Used by the Human Review Queue to prioritize high-impact source pack creation.
        """
        top = []
        for cluster_id, count in self.cluster_counts.most_common(limit):
            tpl = self.cluster_templates.get(cluster_id, "unknown")
            sample = self.cluster_samples.get(cluster_id, "")
            tokens = tpl.split()
            wildcards = sum(1 for t in tokens if "<" in t and ">" in t)
            literals = len(tokens) - wildcards
            specificity = round(literals / len(tokens), 3) if tokens else 0.0
            top.append({
                "cluster_id": cluster_id,
                "template": tpl,
                "count": count,
                "specificity": specificity,
                "sample": sample
            })
        return top
