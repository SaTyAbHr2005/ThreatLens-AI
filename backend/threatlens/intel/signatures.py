"""Injection signature feed: every malicious content item becomes a reusable fingerprint.

A signature is created when content scores as an injection (≥ 0.6) or when it is the
confirmed cause of an alert. Analyst feedback keeps the feed honest: an alert marked
harmless turns its signature off; a confirmed attack makes it authoritative.
"""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field
from pymongo.asynchronous.database import AsyncDatabase

from threatlens.core.db import C
from threatlens.core.schemas import ContentItem, new_id, utcnow

from .simhash import hamming, simhash

SIGNATURE_MIN_SCORE = 0.6
# Of 64 bits. Measured on the A1 instruction: variants with 1–3 edits (new opener, new domain,
# dropped sentence) land at 10–16 bits; unrelated text is ≥ 26 from it and ≥ 23 from each other.
# 18 catches those variants with 5 bits of margin. A heavy paraphrase (~23) can't be separated
# from unrelated text by SimHash; behavior detection (M4) still catches that attack.
NEAR_BITS = 18


class SignatureStatus(StrEnum):
    active = "active"
    confirmed = "confirmed"  # analyst confirmed an attack caused by it
    benign = "benign"  # analyst marked it harmless: never matched again


class Signature(BaseModel):
    id: str = Field(default_factory=lambda: new_id("sig"))
    sha256: str
    simhash: str  # hex, 64-bit
    instruction: str
    techniques: list[str] = Field(default_factory=list)
    injection_score: float
    first_source: str
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    hits: int = 1
    agents: list[str] = Field(default_factory=list)  # agents that read it (or a near-duplicate)
    sources: list[str] = Field(default_factory=list)
    status: SignatureStatus = SignatureStatus.active
    confirmed_by_alert: str | None = None

    @property
    def hash_int(self) -> int:
        return int(self.simhash, 16)


class SignatureMatch(BaseModel):
    signature: Signature
    exact: bool
    distance: int


class SignatureBook:
    def __init__(self, db: AsyncDatabase | None = None):
        self.db = db
        self._by_id: dict[str, Signature] = {}

    async def load(self) -> None:
        if self.db is None:
            return
        for doc in await self.db[C.signatures].find({}, {"_id": 0}).to_list(None):
            s = Signature.model_validate(doc)
            self._by_id[s.id] = s

    def all(self, status: SignatureStatus | None = None) -> list[Signature]:
        items = [s for s in self._by_id.values() if status is None or s.status is status]
        return sorted(items, key=lambda s: s.last_seen, reverse=True)

    def get(self, sig_id: str) -> Signature | None:
        return self._by_id.get(sig_id)

    def match(self, sha256: str, instruction: str) -> SignatureMatch | None:
        """Exact content, or the same instruction within NEAR_BITS. Benign signatures never match."""
        live = [s for s in self._by_id.values() if s.status is not SignatureStatus.benign]
        exact = next((s for s in live if s.sha256 == sha256), None)
        if exact:
            return SignatureMatch(signature=exact, exact=True, distance=0)
        if not instruction:
            return None
        h = simhash(instruction)
        best = min(live, key=lambda s: hamming(h, s.hash_int), default=None)
        if best is not None and (d := hamming(h, best.hash_int)) <= NEAR_BITS:
            return SignatureMatch(signature=best, exact=False, distance=d)
        return None

    async def observe(self, item: ContentItem, *, force: bool = False, alert_id: str | None = None) -> Signature | None:
        """Record a scanned item: a hit on an existing signature, or a new signature if it's malicious."""
        m = self.match(item.sha256, item.instruction)
        if m is not None:
            s = m.signature
            s.hits += 1
            s.last_seen = utcnow()
            if item.read_by and item.read_by not in s.agents:
                s.agents.append(item.read_by)
            if item.source not in s.sources:
                s.sources = (s.sources + [item.source])[-20:]
            await self._save(s)
            return s
        if not force and item.injection_score < SIGNATURE_MIN_SCORE:
            return None
        if not item.instruction and not item.decoded_text:
            return None
        s = Signature(
            sha256=item.sha256,
            simhash=f"{simhash(item.instruction or item.decoded_text):016x}",
            instruction=item.instruction or item.decoded_text[:500],
            techniques=item.techniques,
            injection_score=item.injection_score,
            first_source=item.source,
            agents=[item.read_by] if item.read_by else [],
            sources=[item.source],
            confirmed_by_alert=alert_id,
        )
        self._by_id[s.id] = s
        await self._save(s)
        return s

    async def promote(self, item: ContentItem, alert_id: str) -> Signature | None:
        """The item caused an alert: make sure it's a signature, linked to the alert. Not a new hit."""
        m = self.match(item.sha256, item.instruction)
        if m is None:
            return await self.observe(item, force=True, alert_id=alert_id)
        if not m.signature.confirmed_by_alert:
            m.signature.confirmed_by_alert = alert_id
            await self._save(m.signature)
        return m.signature

    async def set_status(self, sig_id: str, status: SignatureStatus) -> Signature | None:
        s = self._by_id.get(sig_id)
        if s:
            s.status = status
            await self._save(s)
        return s

    async def _save(self, s: Signature) -> None:
        if self.db is not None:
            doc = s.model_dump(mode="json")
            doc["first_seen"], doc["last_seen"] = s.first_seen, s.last_seen
            await self.db[C.signatures].replace_one({"id": s.id}, doc, upsert=True)
