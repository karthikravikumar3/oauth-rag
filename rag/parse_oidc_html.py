#!/usr/bin/env python3
"""
Parse the official OpenID Connect Core 1.0 HTML into section-level JSONL records
that use the same schema as parse_rfc.py.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from bs4 import BeautifulSoup, Tag

HEADING_TAGS = ("h1", "h2", "h3", "h4", "h5", "h6")
HEADING_RE = re.compile(r"^(?P<num>\d+(?:\.\d+)*)\.?\s*\n?\s*(?P<title>\S.*?)$")
APPENDIX_RE = re.compile(r"^(?:Appendix\s+)?(?P<num>[A-Z](?:\.\d+)*)\.\s*\n?\s*(?P<title>\S.*?)$")
UNNUMBERED = {
    "abstract": ("abstract", "front_matter"),
    "table of contents": ("table-of-contents", "toc"),
    "acknowledgements": ("acknowledgements", "back_matter"),
    "acknowledgments": ("acknowledgments", "back_matter"),
    "authors' addresses": ("authors-addresses", "boilerplate"),
    "author's address": ("authors-addresses", "boilerplate"),
    "normative references": ("normative-references", "references"),
    "informative references": ("informative-references", "references"),
    "references": ("references", "references"),
}
XREF_RFC_RE = re.compile(r"\[RFC\s?(\d{3,4})\]")
XREF_SEC_RE = re.compile(r"(?:Sections?|§)\s*(\d+(?:\.\d+)*)")
TERMINAL = tuple('.:;!?)"”')
COPYRIGHT_YEAR_RE = re.compile(r"Copyright\s+\(c\)\s+(\d{4})")
TOC_LINK_RE = re.compile(r"^\s*(?:Appendix\s+)?(\d+(?:\.\d+)*|[A-Z](?:\.\d+)*)(?:\.|\s|$)")


def normalize_text(text):
    return re.sub(r"\s+", " ", text).strip()


def normalize_heading_text(text):
    return re.sub(r"\s+", " ", text.replace("\xa0", " ")).strip()


def extract_heading(tag):
    if tag.name == "h1" and "incorporating errata" in tag.get_text(" ", strip=True).lower():
        return None
    text = normalize_heading_text(tag.get_text(" ", strip=True))
    low = text.lower().rstrip(".")
    if low in UNNUMBERED:
        slug, role = UNNUMBERED[low]
        return slug, normalize_heading_text(tag.get_text(" ", strip=True)).rstrip("."), role
    match = HEADING_RE.match(text)
    if match:
        return match.group("num"), match.group("title"), "body"
    match = APPENDIX_RE.match(text)
    if match:
        return match.group("num"), match.group("title"), "appendix"
    return None


def is_code(tag):
    return (
        tag.name == "pre"
        or (tag.name == "div" and tag.find("pre") is not None)
        or "example-box" in (tag.get("class") or [])
    )


def flatten_table(table):
    header = None
    rows = []
    for tr in table.find_all("tr"):
        cells = [normalize_text(cell.get_text(" ", strip=True)) for cell in tr.find_all(["th", "td"], recursive=False)]
        if not any(cells):
            continue
        if all(cell.name == "th" for cell in tr.find_all(["th", "td"], recursive=False)):
            header = cells
        else:
            rows.append(cells)
    if not rows:
        return []
    width = max((len(row) for row in rows), default=0)
    if header and len(header) != width:
        header = None
    lines = []
    for row in rows:
        cells = list(row) + [""] * (width - len(row))
        if header:
            label = f"{header[0]}: {cells[0]}"
            remainder = " | ".join(
                f"{header[i]}: {cells[i]}" for i in range(1, width) if cells[i]
            )
        else:
            label = cells[0]
            remainder = " | ".join(cells[1:])
        lines.append(" | ".join(part for part in (label, remainder) if part))
    return lines


def block_text(tag):
    if tag.name == "pre":
        return tag.get_text("\n", strip=False).replace("\r\n", "\n")
    if tag.name == "div" and tag.find("pre") is not None:
        return tag.find("pre").get_text("\n", strip=False).replace("\r\n", "\n")
    return normalize_text(tag.get_text(" ", strip=True))


def blocks_from_tags(tags):
    blocks = []
    index = 0
    while index < len(tags):
        tag = tags[index]
        if tag.get("class") == ["TOCbug"] or (tag.name == "table" and normalize_text(tag.get_text(" ", strip=True)) == "TOC"):
            index += 1
            continue
        if tag.name == "table" and tag.find("tr") is not None:
            for line in flatten_table(tag):
                blocks.append({"type": "list_item", "text": line})
            index += 1
            continue
        if is_code(tag):
            text = block_text(tag).strip()
            if text:
                blocks.append({"type": "code", "text": text})
            index += 1
            continue
        if tag.name in ("ol", "ul"):
            ordered = tag.name == "ol"
            for number, li in enumerate(tag.find_all("li", recursive=False), 1):
                text = normalize_text(li.get_text(" ", strip=True))
                if text:
                    marker = f"{number}. " if ordered else "- "
                    blocks.append({"type": "list_item", "text": marker + text})
            index += 1
            continue
        if tag.name == "blockquote" and tag.find("dl") is not None:
            for dt, dd in zip(tag.find_all("dt"), tag.find_all("dd")):
                name = normalize_text(dt.get_text(" ", strip=True))
                text = normalize_text(dd.get_text(" ", strip=True))
                if name or text:
                    blocks.append({"type": "list_item", "text": f"{name} {text}".strip()})
            index += 1
            continue
        if tag.name == "blockquote":
            for child in tag.find_all("p", recursive=False):
                text = normalize_text(child.get_text(" ", strip=True))
                if text:
                    blocks.append({"type": "prose", "text": text})
            if not tag.find("p", recursive=False):
                text = normalize_text(tag.get_text(" ", strip=True))
                if text:
                    blocks.append({"type": "prose", "text": text})
            index += 1
            continue
        if tag.name == "p":
            text = normalize_text(tag.get_text(" ", strip=True))
            if text:
                blocks.append({"type": "prose", "text": text})
            index += 1
            continue
        if tag.name in ("dl", "dt", "dd", "li", "tr", "td", "th", "pre", "h1", "h2", "h3", "h4", "h5", "h6"):
            index += 1
            continue
        text = normalize_text(tag.get_text(" ", strip=True))
        if text:
            blocks.append({"type": "prose", "text": text})
        index += 1
    merged = []
    for block in blocks:
        if block["text"] == "TOC":
            continue
        if merged and block["type"] == "prose" and merged[-1]["type"] == "prose":
            previous = merged[-1]
            if not previous["text"].endswith(TERMINAL) or block["text"][:1].islower():
                previous["text"] += " " + block["text"]
                continue
        merged.append(block)
    return merged


def parse_metadata(soup, path):
    title = soup.title.get_text(" ", strip=True) if soup.title else None
    if title:
        title = re.sub(r"^Final:\s*", "", title)
    copyright_match = COPYRIGHT_YEAR_RE.search(soup.get_text(" ", strip=True))
    return {
        "rfc": "oidc-core-1_0",
        "title": title,
        "date": str(copyright_match.group(1)) if copyright_match else None,
        "category": "OpenID Foundation Final Specification",
        "updates": [],
        "obsoletes": [],
        "updated_by": [],
        "obsoleted_by": [],
        "bcp": None,
        "family": "oidc",
        "source_file": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def collect_toc(soup):
    toc_anchor = soup.find("a", attrs={"name": "toc"})
    if toc_anchor is None:
        return set()
    toc_tag = toc_anchor.find_next("p", attrs={"class": "toc"})
    if toc_tag is None:
        return set()
    numbers = set()
    for anchor in toc_tag.find_all("a", href=True):
        match = TOC_LINK_RE.match(anchor.get_text(" ", strip=True))
        if match:
            numbers.add(match.group(1))
    return numbers


def parse_oidc(path):
    raw_html = re.sub(r"<p>\s*</p>", "", path.read_text(encoding="utf-8"), flags=re.MULTILINE)
    raw_html = re.sub(r"<p>\s*\n?\s*<p>", "<p>", raw_html, flags=re.MULTILINE)
    raw_html = re.sub(r"</p>\s*\n?\s*</p>", "</p>", raw_html, flags=re.MULTILINE)
    soup = BeautifulSoup(raw_html, "html.parser")
    meta = parse_metadata(soup, path)
    toc_numbers = collect_toc(soup)
    body = soup.body
    if body is None:
        raise ValueError("HTML has no body")
    headings = [
        (heading, extract_heading(heading))
        for heading in body.find_all(HEADING_TAGS)
        if extract_heading(heading)
    ]
    sections = []
    for position, (heading_tag, (number, title, role)) in enumerate(headings):
        next_heading = headings[position + 1][0] if position + 1 < len(headings) else None
        next_container = next_heading.parent if next_heading is not None else None
        section_tags = []
        for node in heading_tag.next_siblings:
            if next_heading is not None and node is next_heading:
                break
            if next_heading is not None and next_container is not None and node is next_container:
                break
            if getattr(node, "name", None):
                section_tags.append(node)
        sections.append({
            "num": number,
            "title": title,
            "role": role,
            "blocks": blocks_from_tags(section_tags),
        })
    titles = {section["num"]: section["title"] for section in sections}
    roles = {section["num"]: section["role"] for section in sections}
    records = []
    for order, section in enumerate(sections):
        number = section["num"]
        if section["role"] == "toc":
            continue
        role = section["role"]
        parent = number.rsplit(".", 1)[0] if re.match(r"^(\d+|[A-Z])(\.\d+)+$", number) else None
        if parent and roles.get(parent) == "references":
            role = "references"
        blocks = section["blocks"]
        body_text = "\n\n".join(block["text"] for block in blocks)
        path_numbers = []
        cursor = number
        while cursor:
            path_numbers.insert(0, cursor)
            cursor = cursor.rsplit(".", 1)[0] if re.match(r"^(\d+|[A-Z])(\.\d+)+$", cursor) else None
        heading_path = " > ".join(
            ["OIDC Core 1.0"] + [f"{part} {titles.get(part, '')}".strip() for part in path_numbers]
        )
        records.append({
            "id": f"oidc-core-1_0#{number}",
            "doc_id": "oidc-core-1_0",
            "section": number,
            "title": section["title"],
            "parent": f"oidc-core-1_0#{parent}" if parent else None,
            "order": order,
            "role": role,
            "index": role in ("body", "appendix", "front_matter"),
            "heading_path": heading_path,
            "text": body_text,
            "blocks": blocks,
            "char_count": len(body_text),
            "xref_rfcs": sorted(set(XREF_RFC_RE.findall(body_text))),
            "xref_sections": [{"rfc": None, "section": number} for number in sorted(set(XREF_SEC_RE.findall(body_text)))],
            "doc_title": meta["title"],
            "doc_date": meta["date"],
            "doc_category": meta["category"],
            "doc_updates": meta["updates"],
            "doc_obsoletes": meta["obsoletes"],
        })
    records = [record for record in records if record["role"] != "toc"]
    return meta, records, toc_numbers


def validate(meta, records, toc_numbers):
    problems = []
    ids = [record["id"] for record in records]
    if len(ids) != len(set(ids)):
        problems.append("duplicate section ids")
    for record in records:
        if any("<" in block["text"] for block in record["blocks"] if block["type"] == "prose"):
            problems.append(f"markup residue in prose in {record['id']}")
        if any(token in record["text"] for token in ("&nbsp;", "&ldquo;", "&rdquo;", "&amp;")):
            problems.append(f"entity residue in {record['id']}")
        if record["role"] in ("body", "appendix") and record["char_count"] == 0 and not any(
            other["parent"] == record["id"] for other in records
        ):
            problems.append(f"empty leaf section {record['id']}")
        if record["parent"] and record["parent"] not in set(ids):
            problems.append(f"missing parent for {record['id']}")
    parsed = {record["section"] for record in records if record["role"] in ("body", "appendix", "references")}
    if toc_numbers:
        missing = sorted(toc_numbers - parsed)
        extra = sorted(parsed - toc_numbers)
        if missing:
            problems.append(f"in TOC but not parsed: {missing[:10]}")
        if extra:
            problems.append(f"parsed but not in TOC: {extra[:10]}")
    if not meta["title"] or not meta["date"]:
        problems.append("missing document metadata")
    return problems


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    parser.add_argument("--out", default="data/processed")
    args = parser.parse_args()
    source = Path(args.file)
    output = Path(args.out)
    output.mkdir(parents=True, exist_ok=True)
    meta, records, toc = parse_oidc(source)
    problems = validate(meta, records, toc)
    with (output / "oidc-core-1_0.sections.jsonl").open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    documents_path = output / "documents.jsonl"
    existing = []
    if documents_path.exists():
        existing = [
            json.loads(line)
            for line in documents_path.read_text(encoding="utf-8").splitlines()
            if json.loads(line).get("rfc") != meta["rfc"]
        ]
    with documents_path.open("w", encoding="utf-8") as handle:
        for document in existing + [meta]:
            handle.write(json.dumps(document, ensure_ascii=False) + "\n")
    indexable = sum(record["index"] for record in records)
    print(f"OIDC Core: {len(records)} sections ({indexable} indexable), TOC {len(toc)}")
    for problem in problems:
        print("   CHECK FAILED:", problem)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
