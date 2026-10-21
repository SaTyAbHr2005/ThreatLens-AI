"""Pull readable text out of documents, plus the parts a person can't see.

PDF   white or near-white text, text under 2 pt, text placed outside the page
HTML  comments, display:none / visibility:hidden / zero-size or zero-opacity elements,
      [hidden] and aria-hidden elements, <meta> and <script> text
Email headers, plain and HTML bodies (HTML goes through the HTML rules), links
"""

import email
import email.policy
import io
import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Comment

from threatlens.core.schemas import HiddenSpan

MAX_PDF_BYTES = 5_000_000
MAX_PDF_PAGES = 30
TINY_PT = 2.0


@dataclass
class Extracted:
    visible: str
    hidden: list[HiddenSpan] = field(default_factory=list)
    links: list[tuple[str, str]] = field(default_factory=list)  # (shown text, href)
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def techniques(self) -> list[str]:
        return list(dict.fromkeys(h.technique for h in self.hidden))


class ExtractionError(ValueError):
    pass


# ---------------------------------------------------------------- PDF


def _is_whiteish(color) -> bool:
    if color is None:
        return False
    if isinstance(color, (int, float)):
        color = (color,)
    try:
        c = [float(x) for x in color]
    except (TypeError, ValueError):
        return False
    if len(c) == 1:  # gray
        return c[0] >= 0.95
    if len(c) == 3:  # RGB
        return min(c) >= 0.95
    if len(c) == 4:  # CMYK
        return max(c) <= 0.05
    return False


def extract_pdf(data: bytes) -> Extracted:
    from pdfminer.high_level import extract_pages
    from pdfminer.layout import LTChar, LTTextContainer, LTTextLine
    from pdfminer.pdfparser import PDFSyntaxError

    if len(data) > MAX_PDF_BYTES:
        raise ExtractionError(f"PDF is larger than {MAX_PDF_BYTES // 1_000_000} MB")
    visible: list[str] = []
    hidden: dict[str, list[str]] = {"white_text": [], "tiny_text": [], "off_page": []}
    try:
        for page_no, page in enumerate(extract_pages(io.BytesIO(data), maxpages=MAX_PDF_PAGES)):
            x0, y0, x1, y1 = page.bbox
            for box in page:
                if not isinstance(box, LTTextContainer):
                    continue
                for line in box:
                    if not isinstance(line, LTTextLine):
                        continue
                    shown, buckets = [], {k: [] for k in hidden}
                    for ch in line:
                        if not isinstance(ch, LTChar):
                            shown.append(ch.get_text())
                            continue
                        t = ch.get_text()
                        color = getattr(ch.graphicstate, "ncolor", None)
                        if ch.x1 < x0 or ch.x0 > x1 or ch.y1 < y0 or ch.y0 > y1:
                            buckets["off_page"].append(t)
                        elif _is_whiteish(color):
                            buckets["white_text"].append(t)
                        elif ch.size < TINY_PT:
                            buckets["tiny_text"].append(t)
                        else:
                            shown.append(t)
                    visible.append("".join(shown))
                    for k, chars in buckets.items():
                        if "".join(chars).strip():
                            hidden[k].append("".join(chars).strip())
    except PDFSyntaxError as e:
        raise ExtractionError(f"not a readable PDF: {e}") from e

    out = Extracted(visible="".join(visible).strip())
    for technique, parts in hidden.items():
        if parts:
            out.hidden.append(HiddenSpan(technique=technique, start=0, end=0, text=" ".join(parts)[:2000]))
    return out


# ---------------------------------------------------------------- HTML

_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|"
    r"font-size\s*:\s*0(\.0+)?(px|pt|em|rem|%)?\s*(;|$)|opacity\s*:\s*0(\.0+)?\s*(;|$)|"
    r"(?<![-\w])color\s*:\s*(#fff(fff)?|white|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))",
    re.I,
)


def extract_html(html: str) -> Extracted:
    soup = BeautifulSoup(html, "html.parser")
    out = Extracted(visible="")

    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        if c.strip():
            out.hidden.append(HiddenSpan(technique="html_comment", start=0, end=0, text=c.strip()[:2000]))
        c.extract()

    for tag in soup.find_all(["script", "style", "noscript", "template"]):
        text = tag.get_text(" ", strip=True)
        if tag.name in ("noscript", "template") and text:
            out.hidden.append(HiddenSpan(technique="html_hidden", start=0, end=0, text=text[:2000]))
        tag.decompose()

    for meta in soup.find_all("meta"):
        content = (meta.get("content") or "").strip()
        if len(content) > 40:
            out.hidden.append(HiddenSpan(technique="html_meta", start=0, end=0, text=content[:2000]))

    hidden_tags = [
        t for t in soup.find_all(True)
        if t.has_attr("hidden") or t.get("aria-hidden") == "true" or _HIDDEN_STYLE.search(t.get("style") or "")
    ]
    for tag in hidden_tags:
        if tag.decomposed:
            continue
        text = tag.get_text(" ", strip=True)
        if text:
            out.hidden.append(HiddenSpan(technique="html_hidden", start=0, end=0, text=text[:2000]))
        tag.decompose()

    for a in soup.find_all("a", href=True):
        out.links.append((a.get_text(" ", strip=True), a["href"]))
    out.visible = soup.get_text(" ", strip=True)
    return out


# ---------------------------------------------------------------- email


def extract_email(raw: str | bytes) -> Extracted:
    msg = (
        email.message_from_bytes(raw, policy=email.policy.default)
        if isinstance(raw, bytes)
        else email.message_from_string(raw, policy=email.policy.default)
    )
    headers = {k: str(msg.get(k, "")) for k in ("From", "Reply-To", "Return-Path", "To", "Subject")}
    plain, html = [], []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        ctype = part.get_content_type()
        if part.get_content_disposition() == "attachment":
            continue
        try:
            body = part.get_content()
        except (LookupError, ValueError):
            continue
        if not isinstance(body, str):
            continue
        (html if ctype == "text/html" else plain if ctype == "text/plain" else []).append(body)

    out = Extracted(visible="\n".join(plain).strip(), headers=headers)
    for h in html:
        ex = extract_html(h)
        out.hidden.extend(ex.hidden)
        out.links.extend(ex.links)
        if not plain:
            out.visible = (out.visible + "\n" + ex.visible).strip()
    for url in re.findall(r"https?://[^\s<>\"')]+", out.visible):
        out.links.append((url, url))
    return out
