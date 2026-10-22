"""M7 Threat Intelligence Hub: signature feed, fleet immunity, fleet trend, LLM Susceptibility Arena."""

from .arena import Arena, ArenaRun, ModelResult, verdict
from .hub import IntelHub
from .immunity import ImmuneScanner
from .signatures import NEAR_BITS, Signature, SignatureBook, SignatureStatus
from .simhash import hamming, simhash
from .trend import TrendBook, fleet_score

__all__ = [
    "NEAR_BITS",
    "Arena",
    "ArenaRun",
    "ImmuneScanner",
    "IntelHub",
    "ModelResult",
    "Signature",
    "SignatureBook",
    "SignatureStatus",
    "TrendBook",
    "fleet_score",
    "hamming",
    "simhash",
    "verdict",
]
