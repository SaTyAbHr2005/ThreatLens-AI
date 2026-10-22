"""Fleet immunity: content matching a known attack starts with that attack's score.

Wraps the M3 scanner. If agent 1 was hit by a poisoned PDF, agent 2 reading the
same file, or the same instruction re-worded or re-hidden elsewhere, is scored as
the known attack immediately. A failure here never breaks scanning.
"""

import logging

from threatlens.core.schemas import Carrier, ContentItem, TrustLevel

from .signatures import SignatureBook, SignatureStatus

log = logging.getLogger(__name__)
CONFIRMED_SCORE = 0.95


class ImmuneScanner:
    def __init__(self, inner, book: SignatureBook):
        self.inner = inner
        self.book = book

    async def scan(self, source: str, carrier: Carrier, text: str, trust: TrustLevel,
                   raw: bytes | None = None, media_type: str | None = None) -> ContentItem:
        item = await self.inner.scan(source, carrier, text, trust, raw, media_type)
        try:
            m = self.book.match(item.sha256, item.instruction)
        except Exception:
            log.exception("signature matching failed; using the scan result as is")
            return item
        if m is None:
            return item
        sig = m.signature
        known = CONFIRMED_SCORE if sig.status is SignatureStatus.confirmed else sig.injection_score
        item.injection_score = round(max(item.injection_score, known), 4)
        seen_by = f" (read by {', '.join(sig.agents[:3])})" if sig.agents else ""
        how = "the same content" if m.exact else f"the same instruction ({m.distance}/64 bits apart)"
        item.findings = [f"matches a known attack first seen in {sig.first_source}{seen_by}: {how}"] + item.findings
        item.scored_by += "+signature"
        item.signature_id = sig.id
        return item

    async def aclose(self) -> None:
        await self.inner.aclose()
