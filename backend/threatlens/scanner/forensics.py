"""M3 Content Forensics: extract → decode → score. Implements the gateway's ContentScanner.

Injection score = max of
  - agent-directed-instruction heuristics on the visible text
  - the same heuristics on revealed (hidden or encoded) text, floored at 0.9 when an
    instruction was hidden: legitimate documents don't hide instructions
  - Llama Prompt Guard 2 (Groq), when available
"""

import base64
import binascii
import hashlib
import logging
from collections import OrderedDict

from pydantic import BaseModel, Field

from threatlens.core.schemas import Carrier, ContentItem, HiddenSpan, TrustLevel

from .decoder import decode
from .extract import Extracted, ExtractionError, extract_email, extract_html, extract_pdf
from .heuristics import URL, injection_score, phishing_score, url_risk
from .promptguard import PromptGuard, PromptGuardUnavailable

log = logging.getLogger(__name__)

HIDDEN_INSTRUCTION_FLOOR = 0.9
HIDDEN_ONLY_SCORE = 0.3  # hidden formatting with no instruction in it: suspicious, not damning
MAX_URLS = 20


class UrlFinding(BaseModel):
    url: str
    risk: float
    findings: list[str]


class Analysis(BaseModel):
    """Full Forensics Lab result. `to_item` condenses it into the ContentItem used as taint."""

    source: str
    carrier: Carrier
    sha256: str
    visible_text: str = Field(description="what a person sees (first 5,000 characters)")
    revealed_text: str = Field(description="hidden or encoded text the LLM would also read")
    techniques: list[str]
    hidden_spans: list[HiddenSpan]
    injection_score: float
    injection_findings: list[str]
    prompt_guard_score: float | None
    phishing_score: float | None = None
    phishing_findings: list[str] = []
    urls: list[UrlFinding] = []
    scored_by: str

    def to_item(self, trust: TrustLevel) -> ContentItem:
        findings = list(dict.fromkeys(self.injection_findings + self.phishing_findings))
        return ContentItem(
            source=self.source,
            carrier=self.carrier,
            trust_level=trust,
            sha256=self.sha256,
            injection_score=self.injection_score,
            phishing_score=self.phishing_score,
            url_risk=max((u.risk for u in self.urls), default=None),
            techniques=self.techniques,
            hidden_spans=self.hidden_spans[:20],
            decoded_text=self.revealed_text[:2000],
            scored_by=self.scored_by,
            findings=findings,
        )


def _looks_like_email(text: str) -> bool:
    head = text[:2000].lower()
    return "\nsubject:" in "\n" + head and ("\nfrom:" in "\n" + head)


def _looks_like_html(text: str) -> bool:
    head = text[:2000].lower()
    return "<html" in head or "<body" in head or "<div" in head or "<!--" in head


class ContentForensics:
    def __init__(self, prompt_guard: PromptGuard | None = None, *, internal_domains: tuple[str, ...] = ("corp.example",),
                 cache_size: int = 512):
        self.prompt_guard = prompt_guard
        self.internal_domains = internal_domains
        self._cache: OrderedDict[str, Analysis] = OrderedDict()
        self._cache_size = cache_size

    async def scan(self, source: str, carrier: Carrier, text: str, trust: TrustLevel,
                   raw: bytes | None = None, media_type: str | None = None) -> ContentItem:
        """ContentScanner protocol (used by the gateway for every untrusted read)."""
        return (await self.analyze(source, carrier, text, raw=raw, media_type=media_type)).to_item(trust)

    async def analyze(self, source: str, carrier: Carrier, text: str | None = None, *,
                      raw: bytes | None = None, media_type: str | None = None) -> Analysis:
        digest = hashlib.sha256(raw if raw is not None else (text or "").encode()).hexdigest()
        cached = self._cache.get(digest)
        if cached:
            self._cache.move_to_end(digest)
            return cached.model_copy(update={"source": source})

        ex = self._extract(carrier, text, raw, media_type)

        # Decode the visible text and every hidden part (white text can also carry zero-width tricks).
        visible = decode(ex.visible)
        spans = list(ex.hidden) + list(visible.hidden)
        techniques = list(dict.fromkeys(ex.techniques + visible.techniques))
        revealed_parts = [s.text for s in ex.hidden if s.text.strip()]
        for s in ex.hidden:
            d = decode(s.text)
            spans += d.hidden
            techniques += [t for t in d.techniques if t not in techniques]
        revealed_parts += [s.text for s in visible.hidden if s.text.strip()]
        revealed = "\n".join(dict.fromkeys(revealed_parts))

        vis_score, vis_findings = injection_score(visible.clean_text, self.internal_domains)
        hid_score, hid_findings = injection_score(decode(revealed).clean_text, self.internal_domains) if revealed else (0.0, [])
        if hid_score >= 0.2:  # an instruction was hidden from people
            hid_score = max(hid_score, HIDDEN_INSTRUCTION_FLOOR)
            hid_findings = ["instructions are hidden from people (" + ", ".join(techniques) + ")"] + hid_findings
        elif techniques:
            hid_score = max(hid_score, HIDDEN_ONLY_SCORE)
            hid_findings = ["uses text-hiding tricks (" + ", ".join(techniques) + ")"]

        pg_score, scored_by = None, "heuristics"
        if self.prompt_guard:
            try:
                pg_score = await self.prompt_guard.score("\n".join(filter(None, [revealed, visible.clean_text])))
                scored_by = "prompt_guard+heuristics"
            except PromptGuardUnavailable as e:
                log.info("prompt guard unavailable (%s); heuristics only", e)

        candidates = [(vis_score, vis_findings), (hid_score, hid_findings)]
        if pg_score is not None:
            candidates.append((pg_score, ["matches known prompt-injection / jailbreak patterns (Prompt Guard)"]
                               if pg_score >= 0.5 else []))
        score = max(c[0] for c in candidates)
        findings = list(dict.fromkeys(f for s, fs in sorted(candidates, key=lambda c: -c[0]) if s > 0 for f in fs))

        urls = [UrlFinding(url=u, risk=r, findings=f) for u in self._urls(ex, visible.clean_text + "\n" + revealed)
                for r, f in [url_risk(u)]]
        phish, phish_findings = (None, [])
        if carrier == "email" and (ex.headers or ex.links):
            phish, phish_findings = phishing_score(ex.headers, ex.visible, ex.links)

        analysis = Analysis(
            source=source,
            carrier=carrier,
            sha256=digest,
            visible_text=visible.clean_text[:5000],
            revealed_text=revealed[:5000],
            techniques=techniques,
            hidden_spans=spans[:100],
            injection_score=round(score, 4),
            injection_findings=findings,
            prompt_guard_score=pg_score,
            phishing_score=phish,
            phishing_findings=phish_findings,
            urls=urls,
            scored_by=scored_by,
        )
        self._cache[digest] = analysis
        if len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)
        return analysis

    @staticmethod
    def _extract(carrier: Carrier, text: str | None, raw: bytes | None, media_type: str | None) -> Extracted:
        if raw is not None and (carrier == "pdf" or (media_type or "").endswith("pdf") or raw[:5] == b"%PDF-"):
            return extract_pdf(raw)
        if raw is not None and text is None:
            text = raw.decode("utf-8", "replace")
        text = text or ""
        if carrier == "email" and _looks_like_email(text):
            return extract_email(text)
        if _looks_like_html(text):
            return extract_html(text)
        return Extracted(visible=text)

    @staticmethod
    def _urls(ex: Extracted, text: str) -> list[str]:
        seen = dict.fromkeys([href for _, href in ex.links if href.startswith("http")] + URL.findall(text))
        return list(seen)[:MAX_URLS]

    async def aclose(self) -> None:
        if self.prompt_guard:
            await self.prompt_guard.aclose()


def decode_b64(data: str | None) -> bytes | None:
    if not data:
        return None
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ExtractionError("content_b64 is not valid base64") from e
