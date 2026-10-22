"""Sentence embeddings for role conformance (S1).

- FastEmbedder: all-MiniLM-L6-v2 through fastembed (ONNX, no torch, ~90 MB RAM).
  The Docker build downloads it into the image (Render's free plan has no disk).
- HashingEmbedder: deterministic bag-of-words vectors. No model, no network:
  the offline fallback and the unit-test embedder.

`floor` is the similarity of unrelated text for that embedder; S1 calibrates against it.
"""

import hashlib
import logging
import re
from collections import OrderedDict
from pathlib import Path
from typing import Protocol

import numpy as np

log = logging.getLogger(__name__)

_TOKEN = re.compile(r"[a-z0-9]+")
STOP = {"a", "an", "the", "to", "of", "for", "and", "on", "in", "at", "by", "with", "from", "its", "it", "this"}


class Embedder(Protocol):
    name: str
    floor: float

    def embed(self, texts: list[str]) -> np.ndarray: ...


def _normalize(m: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(m, axis=1, keepdims=True)
    return m / np.where(norms == 0, 1, norms)


class HashingEmbedder:
    name = "hashing"
    floor = 0.0

    def __init__(self, dim: int = 1024):
        self.dim = dim

    def embed(self, texts: list[str]) -> np.ndarray:
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for i, text in enumerate(texts):
            words = [w for w in _TOKEN.findall(text.lower()) if w not in STOP]
            features = words + [f"{a}_{b}" for a, b in zip(words, words[1:])]
            for f in features:
                h = int.from_bytes(hashlib.blake2b(f.encode(), digest_size=8).digest(), "little")
                out[i, h % self.dim] += 1.0 if (h >> 63) & 1 else -1.0
        return _normalize(out)


class FastEmbedder:
    floor = 0.1

    def __init__(self, model: str, cache_dir: Path):
        from fastembed import TextEmbedding  # imported lazily: optional at test time

        self.name = model
        self._model = TextEmbedding(model_name=model, cache_dir=str(cache_dir))

    def embed(self, texts: list[str]) -> np.ndarray:
        return _normalize(np.array(list(self._model.embed(texts)), dtype=np.float32))


class CachedEmbedder:
    """LRU per text: the action vocabulary (tool + resource) repeats constantly."""

    def __init__(self, inner: Embedder, size: int = 4096):
        self.inner, self.name, self.floor = inner, inner.name, inner.floor
        self._cache: OrderedDict[str, np.ndarray] = OrderedDict()
        self._size = size
        self.hits = self.misses = 0  # for /metrics

    def embed(self, texts: list[str]) -> np.ndarray:
        missing = [t for t in dict.fromkeys(texts) if t not in self._cache]
        self.misses += len(missing)
        self.hits += len(texts) - len(missing)
        if missing:
            for t, v in zip(missing, self.inner.embed(missing)):
                self._cache[t] = v
            while len(self._cache) > self._size:
                self._cache.popitem(last=False)
        for t in texts:
            self._cache.move_to_end(t)
        return np.stack([self._cache[t] for t in texts])


def make_embedder(backend: str, model: str, cache_dir: Path) -> CachedEmbedder:
    if backend == "fastembed":
        try:
            return CachedEmbedder(FastEmbedder(model, cache_dir))
        except Exception as e:  # missing package, no network on first download, ...
            log.warning("fastembed unavailable (%s); using the hashing embedder", e)
    return CachedEmbedder(HashingEmbedder())


def warm(model: str, cache_dir: str) -> None:
    """Docker build step: download the model into the image."""
    FastEmbedder(model, Path(cache_dir)).embed(["warm up"])
