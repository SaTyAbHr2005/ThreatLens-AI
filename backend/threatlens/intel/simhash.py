"""64-bit SimHash: near-duplicate text gets nearby hashes (small Hamming distance).

Used to recognise the same attack instruction when it is re-worded slightly,
re-hidden with a different trick, or wrapped in a different document.
"""

import hashlib
import re

_WORD = re.compile(r"[a-z0-9]+")


def _features(text: str) -> list[str]:
    words = _WORD.findall(text.lower())
    return words + [f"{a} {b}" for a, b in zip(words, words[1:])]


def simhash(text: str) -> int:
    weights = [0] * 64
    for f in _features(text):
        h = int.from_bytes(hashlib.blake2b(f.encode(), digest_size=8).digest(), "big")
        for i in range(64):
            weights[i] += 1 if (h >> i) & 1 else -1
    return sum(1 << i for i, w in enumerate(weights) if w > 0)


def hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()
