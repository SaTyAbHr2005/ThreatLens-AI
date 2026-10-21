"""Content Forensics Lab API: analyze text, email, HTML, a PDF upload, or a URL by hand."""

from typing import Literal

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from threatlens.core.http import require_operator

from .extract import MAX_PDF_BYTES, ExtractionError
from .forensics import Analysis, ContentForensics, UrlFinding, decode_b64
from .heuristics import url_risk

router = APIRouter(prefix="/v1/forensics", tags=["forensics"], dependencies=[Depends(require_operator)])


class AnalyzeIn(BaseModel):
    kind: Literal["text", "email", "web", "pdf", "url"] = "text"
    content: str | None = Field(None, max_length=2_000_000)
    content_b64: str | None = Field(None, max_length=7_000_000, description="base64 bytes, e.g. a PDF")
    source: str = Field("forensics-lab", max_length=500)


def forensics(request: Request) -> ContentForensics:
    return request.app.state.forensics


@router.post("/analyze", response_model=Analysis | UrlFinding)
async def analyze(body: AnalyzeIn, fx: ContentForensics = Depends(forensics)):
    if body.kind == "url":
        # Judged from the address alone: the server never fetches URLs it's asked about (no SSRF).
        if not body.content:
            raise HTTPException(422, "content must be the URL")
        risk, findings = url_risk(body.content)
        return UrlFinding(url=body.content, risk=risk, findings=findings)
    try:
        raw = decode_b64(body.content_b64)
        if raw is None and body.content is None:
            raise HTTPException(422, "send content or content_b64")
        carrier = "text" if body.kind == "text" else body.kind
        return await fx.analyze(body.source, carrier, body.content, raw=raw)
    except ExtractionError as e:
        raise HTTPException(422, str(e)) from e


@router.post("/analyze-file", response_model=Analysis)
async def analyze_file(file: UploadFile = File(...), fx: ContentForensics = Depends(forensics)):
    data = await file.read(MAX_PDF_BYTES + 1)
    if len(data) > MAX_PDF_BYTES:
        raise HTTPException(413, f"files are limited to {MAX_PDF_BYTES // 1_000_000} MB")
    name = (file.filename or "upload").lower()
    media = file.content_type or ""
    carrier = "pdf" if name.endswith(".pdf") or media.endswith("pdf") or data[:5] == b"%PDF-" else (
        "email" if name.endswith(".eml") else "web" if name.endswith((".html", ".htm")) else "text"
    )
    try:
        if carrier == "pdf":
            return await fx.analyze(file.filename or "upload.pdf", carrier, raw=data, media_type=media)
        return await fx.analyze(file.filename or "upload", carrier, data.decode("utf-8", "replace"))
    except ExtractionError as e:
        raise HTTPException(422, str(e)) from e
