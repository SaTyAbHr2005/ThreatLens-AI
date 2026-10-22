"""Role vectors for S1: what each Role Contract version 'sounds like', plus its calibration."""

from dataclasses import dataclass

import numpy as np

from threatlens.core.schemas import RoleContract
from threatlens.gateway.catalog import Catalog

from .describe import contract_phrases
from .embedder import CachedEmbedder


@dataclass(frozen=True)
class RoleVectors:
    phrases: list[str]
    vectors: np.ndarray
    t_in: float  # similarity an in-role action typically reaches; below it, S1 starts rising

    def closest(self, v: np.ndarray) -> tuple[float, str]:
        sims = self.vectors @ v
        i = int(np.argmax(sims))
        return float(sims[i]), self.phrases[i]


class RoleIndex:
    def __init__(self, embedder: CachedEmbedder, catalog: Catalog):
        self.embedder, self.catalog = embedder, catalog
        self._cache: dict[tuple[str, int], RoleVectors] = {}

    def get(self, contract: RoleContract) -> RoleVectors:
        key = (contract.role, contract.version)
        if key not in self._cache:
            phrases = contract_phrases(contract, self.catalog)
            vectors = self.embedder.embed(phrases)
            # Leave-one-out: how close each normal phrase is to the rest of the role.
            sims = vectors @ vectors.T
            np.fill_diagonal(sims, -1.0)
            loo = sims.max(axis=1) if len(phrases) > 1 else np.array([1.0])
            t_in = float(np.clip(np.percentile(loo, 25), self.embedder.floor + 0.15, 0.95))
            self._cache[key] = RoleVectors(phrases, vectors, t_in)
        return self._cache[key]
