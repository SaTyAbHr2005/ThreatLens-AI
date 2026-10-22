"""Builds small real PDFs (no extra library): each line has its own position, size and colour.

Used for the mock enterprise's documents and by the tests.
"""

def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_pdf(lines: list[tuple[str, dict]]) -> bytes:
    """lines: [(text, {"x": 72, "y": 720, "size": 12, "color": (r, g, b)})] on one 612×792 page."""
    ops = []
    for text, o in lines:
        r, g, b = o.get("color", (0, 0, 0))
        ops.append(f"BT /F1 {o.get('size', 12)} Tf {r} {g} {b} rg {o.get('x', 72)} {o.get('y', 720)} Td "
                   f"({_escape(text)}) Tj ET")
    stream = "\n".join(ops).encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = b"%PDF-1.4\n"
    offsets = []
    for i, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + obj + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return out


WHITE = (1, 1, 1)
