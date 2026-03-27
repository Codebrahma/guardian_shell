#!/usr/bin/env python3

import argparse
import re
import textwrap
from dataclasses import dataclass


PAGE_WIDTH = 612
PAGE_HEIGHT = 792
LEFT = 54
RIGHT = 54
TOP = 60
BOTTOM = 54
FOOTER_GAP = 24


@dataclass
class Line:
    text: str
    font: str
    size: int
    leading: int


def strip_inline_md(text: str) -> str:
    text = re.sub(r"\*\*(.*?)\*\*", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\[(.*?)\]\((.*?)\)", r"\1 (\2)", text)
    return text


def wrap_text(text: str, width: int) -> list[str]:
    if not text:
        return [""]
    return textwrap.wrap(
        text,
        width=width,
        break_long_words=False,
        break_on_hyphens=False,
    ) or [""]


def parse_markdown(content: str) -> list[Line]:
    lines: list[Line] = []
    in_code = False
    paragraph: list[str] = []

    def flush_paragraph() -> None:
        nonlocal paragraph
        if not paragraph:
            return
        text = strip_inline_md(" ".join(s.strip() for s in paragraph))
        for wrapped in wrap_text(text, 88):
            lines.append(Line(wrapped, "F1", 11, 15))
        lines.append(Line("", "F1", 11, 10))
        paragraph = []

    for raw in content.splitlines():
        line = raw.rstrip("\n")

        if line.startswith("```"):
            flush_paragraph()
            in_code = not in_code
            if not in_code:
                lines.append(Line("", "F3", 10, 8))
            continue

        if in_code:
            lines.append(Line(line.rstrip(), "F3", 9, 12))
            continue

        if not line.strip():
            flush_paragraph()
            continue

        if line.startswith("# "):
            flush_paragraph()
            title = strip_inline_md(line[2:].strip())
            lines.append(Line(title, "F2", 20, 24))
            lines.append(Line("", "F1", 11, 10))
            continue

        if line.startswith("## "):
            flush_paragraph()
            title = strip_inline_md(line[3:].strip())
            lines.append(Line(title, "F2", 16, 20))
            lines.append(Line("", "F1", 11, 8))
            continue

        if line.startswith("### "):
            flush_paragraph()
            title = strip_inline_md(line[4:].strip())
            lines.append(Line(title, "F2", 13, 17))
            lines.append(Line("", "F1", 11, 6))
            continue

        if re.match(r"^[-*] ", line) or re.match(r"^\d+\. ", line):
            flush_paragraph()
            item = strip_inline_md(line)
            bullet = item.split(" ", 1)
            prefix = bullet[0]
            rest = bullet[1] if len(bullet) > 1 else ""
            wrapped = wrap_text(rest, 82)
            if wrapped:
                lines.append(Line(f"{prefix} {wrapped[0]}", "F1", 11, 15))
                for cont in wrapped[1:]:
                    lines.append(Line(f"   {cont}", "F1", 11, 15))
            lines.append(Line("", "F1", 11, 6))
            continue

        if line.startswith("---"):
            flush_paragraph()
            lines.append(Line("", "F1", 11, 6))
            lines.append(Line("-" * 80, "F3", 9, 12))
            lines.append(Line("", "F1", 11, 6))
            continue

        paragraph.append(line)

    flush_paragraph()
    return lines


def escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pages(lines: list[Line]) -> list[list[Line]]:
    pages: list[list[Line]] = []
    current: list[Line] = []
    y = PAGE_HEIGHT - TOP
    limit = BOTTOM + FOOTER_GAP

    for line in lines:
        if y - line.leading < limit:
            pages.append(current)
            current = []
            y = PAGE_HEIGHT - TOP
        current.append(line)
        y -= line.leading

    if current:
        pages.append(current)
    return pages


def render_page_content(page_lines: list[Line], page_num: int, page_count: int) -> bytes:
    parts: list[str] = []
    y = PAGE_HEIGHT - TOP

    for line in page_lines:
        if line.text:
            parts.append("BT")
            parts.append(f"/{line.font} {line.size} Tf")
            parts.append(f"1 0 0 1 {LEFT} {y} Tm")
            parts.append(f"({escape_pdf_text(line.text)}) Tj")
            parts.append("ET")
        y -= line.leading

    footer = f"Page {page_num} of {page_count}"
    parts.append("BT")
    parts.append("/F1 10 Tf")
    parts.append(f"1 0 0 1 {PAGE_WIDTH - RIGHT - 70} {BOTTOM - 10} Tm")
    parts.append(f"({escape_pdf_text(footer)}) Tj")
    parts.append("ET")

    return "\n".join(parts).encode("latin-1", errors="replace")


def write_pdf(pages: list[list[Line]], output_path: str) -> None:
    objects: list[bytes] = []

    def add_object(data: bytes) -> int:
        objects.append(data)
        return len(objects)

    font1 = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    font2 = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    font3 = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

    page_ids = []
    content_ids = []

    for idx, page in enumerate(pages, start=1):
        stream = render_page_content(page, idx, len(pages))
        content = (
            f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1")
            + stream
            + b"\nendstream"
        )
        content_ids.append(add_object(content))
        page_ids.append(0)

    pages_obj_id = 0
    for i, content_id in enumerate(content_ids):
        page_obj = (
            f"<< /Type /Page /Parent PLACEHOLDER 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
            f"/Resources << /Font << /F1 {font1} 0 R /F2 {font2} 0 R /F3 {font3} 0 R >> >> "
            f"/Contents {content_id} 0 R >>"
        ).encode("latin-1")
        page_ids[i] = add_object(page_obj)

    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    pages_obj_id = add_object(
        f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids}] >>".encode("latin-1")
    )

    for i, pid in enumerate(page_ids):
        fixed = objects[pid - 1].replace(b"PLACEHOLDER", str(pages_obj_id).encode("latin-1"))
        objects[pid - 1] = fixed

    catalog_id = add_object(f"<< /Type /Catalog /Pages {pages_obj_id} 0 R >>".encode("latin-1"))

    with open(output_path, "wb") as f:
        f.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for i, obj in enumerate(objects, start=1):
            offsets.append(f.tell())
            f.write(f"{i} 0 obj\n".encode("latin-1"))
            f.write(obj)
            f.write(b"\nendobj\n")

        xref_start = f.tell()
        f.write(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
        f.write(b"0000000000 65535 f \n")
        for off in offsets[1:]:
            f.write(f"{off:010d} 00000 n \n".encode("latin-1"))
        f.write(
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode(
                "latin-1"
            )
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Render a simple Markdown file to a basic PDF.")
    parser.add_argument("input")
    parser.add_argument("output")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        content = f.read()

    lines = parse_markdown(content)
    pages = build_pages(lines)
    write_pdf(pages, args.output)


if __name__ == "__main__":
    main()
