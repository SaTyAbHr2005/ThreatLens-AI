"""M3 Content Forensics: reveal hidden instructions in what agents read, and score it."""

from .decoder import DecodeResult, decode
from .extract import Extracted, ExtractionError, extract_email, extract_html, extract_pdf
from .forensics import Analysis, ContentForensics, UrlFinding
from .heuristics import injection_score, phishing_score, url_risk
from .promptguard import PromptGuard, PromptGuardUnavailable

__all__ = [
    "Analysis",
    "ContentForensics",
    "DecodeResult",
    "ExtractionError",
    "Extracted",
    "PromptGuard",
    "PromptGuardUnavailable",
    "UrlFinding",
    "decode",
    "extract_email",
    "extract_html",
    "extract_pdf",
    "injection_score",
    "phishing_score",
    "url_risk",
]
