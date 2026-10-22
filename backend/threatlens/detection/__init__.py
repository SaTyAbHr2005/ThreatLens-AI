"""M4 Behavioral Detection: nine signals comparing each action with the agent's role and history."""

from .baselines import BaselineStore, jensen_shannon
from .describe import contract_phrases, describe
from .detector import Detector, evidence_for
from .embedder import CachedEmbedder, HashingEmbedder, make_embedder
from .repo import load_baselines, persist_periodically, save_baselines

__all__ = [
    "BaselineStore",
    "CachedEmbedder",
    "Detector",
    "HashingEmbedder",
    "contract_phrases",
    "describe",
    "evidence_for",
    "jensen_shannon",
    "load_baselines",
    "make_embedder",
    "persist_periodically",
    "save_baselines",
]
