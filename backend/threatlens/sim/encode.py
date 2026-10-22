"""Hide a given test string inside carrier text, the inverse of the M3 decoder.

This is a defensive test harness: it lets an analyst check that the decoder and
detection catch an instruction hidden with a chosen technique. It only re-applies
the exact techniques the decoder already reveals (nothing novel), so a "miss" here
is a gap in our own detection, which is the point of testing it.
"""

import base64

from .pdf import WHITE, make_pdf

ZWSP, ZWNJ = "\u200b", "\u200c"
TECHNIQUES = ("zero_width", "unicode_tags", "white_text_pdf", "base64", "visible")


def _zero_width(secret: str) -> str:
    bits = "".join(f"{b:08b}" for b in secret.encode())
    return "".join(ZWSP if b == "0" else ZWNJ for b in bits)


def _unicode_tags(secret: str) -> str:
    return "".join(chr(0xE0000 + ord(c)) for c in secret if 0x20 <= ord(c) < 0x7F)


def encode(secret: str, technique: str, cover: str = "Supplier quotation: 20 monitors at USD 189 each.") -> dict:
    """Return {"carrier": "text"|"pdf", "text": str|None, "pdf_b64": str|None} for the test harness."""
    if technique not in TECHNIQUES:
        raise ValueError(f"unknown technique {technique!r}; one of {TECHNIQUES}")
    if technique == "visible":
        return {"carrier": "text", "text": f"{cover}\n{secret}", "pdf_b64": None}
    if technique == "zero_width":
        return {"carrier": "text", "text": f"{cover}{ZWSP}{secret}{ZWSP}", "pdf_b64": None}
    if technique == "unicode_tags":
        return {"carrier": "text", "text": f"{cover}{_unicode_tags(secret)}", "pdf_b64": None}
    if technique == "base64":
        return {"carrier": "text", "text": f"{cover}\nref={base64.b64encode(secret.encode()).decode()}", "pdf_b64": None}
    # white_text_pdf: visible cover in black, the secret in white (invisible to a reader)
    pdf = make_pdf([(cover, {"y": 720, "size": 14}), (secret, {"y": 400, "color": WHITE})])
    return {"carrier": "pdf", "text": None, "pdf_b64": base64.b64encode(pdf).decode()}
