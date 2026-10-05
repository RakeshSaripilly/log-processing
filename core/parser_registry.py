"""
Universal Log Pre-processing Framework (ULPF) - Declarative Parser Registry
Compiles YAML Source Packs, watches filesystem with 400ms debouncing,
and performs zero-copy hot-path detection.
Team LunarX - SIH26156 (NTRO)
"""

from core.detector import CompiledSourcePack, PackRegistry

# Alias ParserRegistry for standard architectural naming
ParserRegistry = PackRegistry
SourcePack = CompiledSourcePack

__all__ = ["ParserRegistry", "SourcePack", "CompiledSourcePack", "PackRegistry"]
