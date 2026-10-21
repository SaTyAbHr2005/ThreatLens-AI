"""Reveal text hidden from a human reader but visible to an LLM (ThreatLens v1 decoder).

Techniques:
  zero_width          invisible characters, incl. binary messages spelled in 200B/200C
  unicode_tags        U+E0000–E007F "ASCII smuggling"
  variation_selectors bytes smuggled in variation selectors after a character ("emoji smuggling")
  bidi_override       right-to-left overrides that reorder what a person sees
  homoglyph           Cyrillic/Greek/fullwidth look-alikes mixed into Latin words
  base64 / hex / rot13 encoded payloads that decode to readable instructions
"""

import base64
import binascii
import codecs
import re
import unicodedata
from dataclasses import dataclass, field

from threatlens.core.schemas import HiddenSpan

ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\u2060", "\ufeff", "\u180e"}
BIDI = {chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))}

# Look-alikes that NFKC leaves alone (it already folds fullwidth/compatibility forms).
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "Α": "A", "Β": "B", "Ε": "E", "Ο": "O", "Ρ": "P", "Τ": "T",
})

INSTRUCTION_HINT = re.compile(
    r"\b(ignore|disregard|instruction|assistant|agent|send|post|upload|forward|export|read|reveal|password|"
    r"salar(y|ies)|api[ _-]?key|secret|credential|transfer|execute|system prompt)\b",
    re.I,
)
# A payload may follow "=" (ref=..., token=...), so "=" only ends a match, never blocks its start.
B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")
MAX_SPANS = 100


@dataclass
class DecodeResult:
    clean_text: str  # what a person sees, normalized: invisible chars removed, look-alikes folded
    hidden: list[HiddenSpan] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)

    @property
    def revealed(self) -> str:
        """All hidden or encoded text, in order: what the LLM saw that the person didn't."""
        return "\n".join(s.text for s in self.hidden if s.text.strip())

    def add(self, technique: str, start: int, end: int, text: str) -> None:
        if technique not in self.techniques:
            self.techniques.append(technique)
        if len(self.hidden) < MAX_SPANS:  # a document stuffed with invisible chars can't blow up the result
            self.hidden.append(HiddenSpan(technique=technique, start=start, end=end, text=text[:2000]))


def _printable_ratio(s: str) -> float:
    return sum(c.isprintable() or c in "\n\t" for c in s) / max(len(s), 1)


def _legit_joiner(text: str, i: int) -> bool:
    """ZWJ/ZWNJ between two non-ASCII characters is normal in Hindi, Persian, emoji sequences..."""
    return 0 < i < len(text) - 1 and ord(text[i - 1]) > 0x7F and ord(text[i + 1]) > 0x7F


def _zero_width(text: str, out: DecodeResult) -> None:
    for m in re.finditer("[" + "".join(sorted(ZERO_WIDTH)) + "]+", text):
        run = m.group()
        if (m.start() == 0 and run == "\ufeff") or (run in ("\u200c", "\u200d") and _legit_joiner(text, m.start())):
            continue  # byte-order mark / legitimate joiner
        bits = run.replace("\u200b", "0").replace("\u200c", "1")
        if len(run) >= 8 and set(bits) <= {"0", "1"} and len(bits) % 8 == 0:
            decoded = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)).decode("utf-8", "replace")
            out.add("zero_width", m.start(), m.end(), decoded)
        else:
            # Invisible markers around otherwise-visible text: report the wrapped text.
            out.add("zero_width", m.start(), m.end(), "")
    # Text wrapped between invisible markers is a common way to tag a payload.
    for m in re.finditer(r"[\u200b\u2060\ufeff]([^\u200b\u2060\ufeff]{8,500})[\u200b\u2060\ufeff]", text):
        out.add("zero_width", m.start(), m.end(), m.group(1).strip())


def _unicode_tags(text: str, out: DecodeResult) -> None:
    for m in re.finditer("[\U000E0000-\U000E007F]+", text):
        decoded = "".join(chr(ord(c) - 0xE0000) for c in m.group() if 0x20 <= ord(c) - 0xE0000 < 0x7F)
        out.add("unicode_tags", m.start(), m.end(), decoded)


def _variation_selectors(text: str, out: DecodeResult) -> None:
    for m in re.finditer("[\ufe00-\ufe0f\U000E0100-\U000E01EF]{2,}", text):
        data = bytes(
            (ord(c) - 0xFE00) if ord(c) <= 0xFE0F else (ord(c) - 0xE0100 + 16) for c in m.group()
        )
        decoded = data.decode("utf-8", "replace")
        if _printable_ratio(decoded) > 0.9:
            out.add("variation_selectors", m.start(), m.end(), decoded)


def _bidi(text: str, out: DecodeResult) -> None:
    for m in re.finditer("[" + "".join(sorted(BIDI)) + "]", text):
        out.add("bidi_override", m.start(), m.end(), "")


def _homoglyphs(text: str, out: DecodeResult) -> None:
    for m in re.finditer(r"\w{3,}", text):
        word = m.group()
        folded = word.translate(CONFUSABLES)
        if folded != word and folded.isascii():
            out.add("homoglyph", m.start(), m.end(), folded)


def _encoded(text: str, out: DecodeResult) -> None:
    for m in B64.finditer(text):
        try:
            decoded = base64.b64decode(m.group() + "=" * (-len(m.group()) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if _printable_ratio(decoded) > 0.95 and INSTRUCTION_HINT.search(decoded):
            out.add("base64", m.start(), m.end(), decoded)
    for m in HEX.finditer(text):
        try:
            decoded = bytes.fromhex(m.group()).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(decoded) > 0.95 and INSTRUCTION_HINT.search(decoded):
            out.add("hex", m.start(), m.end(), decoded)
    # ROT13: only report it when the plain text has no instructions but the rotated text clearly does.
    rotated = codecs.decode(text, "rot13")
    hits = {m.group(0).lower() for m in INSTRUCTION_HINT.finditer(rotated)}
    if len(hits) >= 3 and not INSTRUCTION_HINT.search(text):
        out.add("rot13", 0, len(text), rotated[:2000])


def decode(text: str) -> DecodeResult:
    out = DecodeResult(clean_text="")
    _zero_width(text, out)
    _unicode_tags(text, out)
    _variation_selectors(text, out)
    _bidi(text, out)
    _homoglyphs(text, out)
    _encoded(text, out)

    invisible = ZERO_WIDTH | BIDI
    clean = "".join(
        c for c in text
        if c not in invisible and not (0xE0000 <= ord(c) <= 0xE007F)
        and not (0xFE00 <= ord(c) <= 0xFE0F) and not (0xE0100 <= ord(c) <= 0xE01EF)
    )
    out.clean_text = unicodedata.normalize("NFKC", clean).translate(CONFUSABLES)
    return out
