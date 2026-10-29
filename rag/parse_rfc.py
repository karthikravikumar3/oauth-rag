#!/usr/bin/env python3
"""
parse_rfc.py - Stage 1/2 of the OAuth/OIDC RAG pipeline: ingest + parse IETF RFC .txt files
into section-level JSONL records.

Usage:
    python parse_rfc.py data/raw/rfc*.txt --out data/processed
Outputs (per RFC): <out>/rfcNNNN.sections.jsonl, plus <out>/documents.jsonl (one metadata row per RFC)
and prints a validation report. Exit code 1 if any validation check fails.
"""
import argparse, hashlib, json, re, sys
from pathlib import Path

# ---------- patterns ----------
FF = "\f"
FOOTER_RE = re.compile(r"^\S.*\[Page\s+\d+\]\s*$")
HEADER_RE = re.compile(r"^RFC\s+\d+\s{2,}.*\S\s{2,}[A-Z][a-z]+\s+\d{4}\s*$")
NUM_HEADING_RE = re.compile(r"^(?P<num>\d+(?:\.\d+)*)\.?\s{2,}(?P<title>\S.*?)\s*$")
APPX_HEADING_RE = re.compile(r"^(?:Appendix\s+)?(?P<num>[A-Z](?:\.\d+)*)\.\s{2,}(?P<title>\S.*?)\s*$")
UNNUMBERED = {
    "abstract": "front_matter", "status of this memo": "front_matter", "copyright notice": "front_matter",
    "table of contents": "toc", "authors' addresses": "boilerplate", "author's address": "boilerplate",
    "authors’ addresses": "boilerplate", "author’s address": "boilerplate",
    "acknowledgements": "back_matter", "acknowledgments": "back_matter", "contributors": "back_matter",
    "normative references": "references", "informative references": "references", "references": "references",
}
TOC_LINE_RE = re.compile(r"^\s+(?:Appendix\s+)?(?P<num>(?:\d+|[A-Z])(?:\.\d+)*)\.?\s+.*?(?:\.{2,}|(?:\. ){2,})\s*\d+\s*$")
TOC_HEADING_RE = re.compile(r"^Table of Contents$")
TOC_ENTRY_START_RE = re.compile(r"^\s+(?:Appendix\s+)?(?P<num>(?:\d+|[A-Z])(?:\.\d+)*)\.?\s{1,3}(?P<title>\S.*?)\s*$")
LIST_MARKER_RE = re.compile(r"^(?:o|-|\*|\(?[a-z0-9]{1,2}[.)])\s{1,3}\S")
XREF_RFC_RE = re.compile(r"\[RFC\s?(\d{3,4})\]")
XREF_SEC_RE = re.compile(r"[Ss]ections?\s+(\d+(?:\.\d+)*|[A-Z](?:\.\d+)+)(?:\s+of\s+\[?RFC\s?(\d{3,4})\]?)?")
TERMINAL = tuple('.:;!?)"”')
BASE_INDENT = 3
CORPUS_OVERRIDES = {
    "6749": {
        "updated_by": ["8252", "8996", "9700"],
        "toc_extra": {"3.1.2.1", "3.1.2.2", "3.1.2.3", "3.1.2.4", "3.1.2.5", "4.1.2.1", "4.2.2.1", "10.16"},
    },
    "6750": {"updated_by": ["8996", "9700"]},
}
TITLE_OVERRIDES = {
    "6750": "The OAuth 2.0 Authorization Framework: Bearer Token Usage",
}


def read_text(path: Path) -> str:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.replace("\t", "        ")


def parse_metadata(lines, rfc_number):
    meta = {"rfc": rfc_number, "title": None, "date": None, "category": None, "updates": [], "obsoletes": [],
            "updated_by": [], "obsoleted_by": [], "bcp": None}
    head = lines[:70]
    for ln in head:
        for key, field in (("Updates", "updates"), ("Obsoletes", "obsoletes"),
                           ("Updated by", "updated_by"), ("Obsoleted by", "obsoleted_by")):
            m = re.search(rf"{key}:\s*([\d,\s]+)", ln)
            if m and not (key == "Updates" and "Updated by" in ln):
                meta[field] = re.findall(r"\d+", m.group(1))
        m = re.search(r"Category:\s*(.+?)(?:\s{2,}|$)", ln)
        if m: meta["category"] = m.group(1).strip()
        m = re.search(r"BCP:\s*(\d+)", ln)
        if m: meta["bcp"] = m.group(1)
    MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December"
    for i, ln in enumerate(head):
        m = re.search(rf"(?:^|\s{{2,}})((?:{MONTHS})\s+\d{{4}})\s*$", ln)
        if m and not meta["date"]:
            meta["date"] = m.group(1)
            for ln2 in head[i + 1:i + 12]:
                if ln2.strip() and len(ln2) - len(ln2.lstrip()) >= 8 and not re.search(r"\w+:\s", ln2):
                    meta["title"] = ln2.strip(); break
    return meta


def apply_corpus_overrides(meta):
    overrides = CORPUS_OVERRIDES.get(str(meta["rfc"]), {})
    for key, value in overrides.items():
        if key != "toc_extra":
            meta[key] = value
    title = TITLE_OVERRIDES.get(str(meta["rfc"]))
    if title:
        meta["title"] = title
    return set(overrides.get("toc_extra", set()))


def strip_page_breaks(text: str):
    out = []
    for ln in text.split("\n"):
        ln_nf = ln.replace(FF, "")
        if FOOTER_RE.match(ln_nf) or HEADER_RE.match(ln_nf):
            if not out or out[-1] != "\x00PB":
                out.append("\x00PB")
            continue
        if ln.strip() == "" and FF in ln:
            continue
        out.append(ln_nf)
    return out


def classify_paragraph(lines):
    ded = [l[BASE_INDENT:] if l.startswith(" " * BASE_INDENT) else l.lstrip() for l in lines]
    if LIST_MARKER_RE.match(ded[0]):
        return "list_item", ded
    if any(l.startswith("  ") for l in ded[1:]) or (ded[0].startswith("  ")):
        return "code", ded
    if any(re.search(r"[{}]|::=| = |^\s*\+[-+]+", l) for l in ded) and max(len(l) for l in ded) < 72 and len(ded) > 1 \
       and not any(l.rstrip().endswith(".") for l in ded[-1:]):
        return "code", ded
    return "prose", ded


def reflow(lines, kind):
    if kind == "code":
        return "\n".join(lines)
    text = ""
    for l in lines:
        l = l.strip()
        if not text: text = l
        elif text.endswith("-") and l[:1].islower(): text += l
        else: text += " " + l
    return text


def extract_toc(raw_lines):
    """Extract section numbers from a possibly multi-page, wrapped RFC TOC."""
    toc_start = next((i for i, line in enumerate(raw_lines) if TOC_HEADING_RE.match(line.strip())), None)
    if toc_start is None:
        return set()
    numbers = set()
    pending = None
    pending_title = ""
    for raw_line in raw_lines[toc_start + 1:]:
        line = raw_line.replace(FF, "")
        if FOOTER_RE.match(line) or HEADER_RE.match(line):
            continue
        if find_heading(line) and line[0] != " ":
            break
        entry = TOC_LINE_RE.match(line)
        if entry:
            numbers.add(entry.group("num"))
            pending = None
            pending_title = ""
            continue
        start = TOC_ENTRY_START_RE.match(line)
        if start:
            if pending:
                joined = " " + f"{pending}\t{pending_title} {start.group('title')}\t..........\t1"
                if TOC_LINE_RE.match(joined):
                    numbers.add(pending)
                    pending = start.group("num")
                    pending_title = start.group("title")
                    continue
            pending = start.group("num")
            pending_title = start.group("title")
            continue
        if pending and line.strip():
            pending_title += " " + line.strip()
            joined = " " + f"{pending}\t{pending_title}\t..........\t1"
            entry = TOC_LINE_RE.match(joined)
            if entry:
                numbers.add(entry.group("num"))
                pending = None
                pending_title = ""
    if pending:
        joined = " " + f"{pending}\t{pending_title}\t..........\t1"
        if TOC_LINE_RE.match(joined):
            numbers.add(pending)
    return numbers


def extract_body_section_numbers(raw_lines):
    numbers = set()
    for line in raw_lines:
        if line and not line[0].isspace():
            heading = find_heading(line)
            if heading:
                numbers.add(heading[0])
    return numbers


def build_blocks(body_lines):
    blocks, cur, pb_before = [], [], False
    def flush(pb_after=False):
        nonlocal cur, pb_before
        if cur:
            kind, ded = classify_paragraph(cur)
            blocks.append({"type": kind, "text": reflow(ded, kind), "pb_before": pb_before})
            cur, pb_before = [], False
    for ln in body_lines:
        if ln == "\x00PB":
            flush(); pb_before = True
        elif ln.strip() == "":
            flush()
        else:
            cur.append(ln)
    flush()
    merged = []
    for b in blocks:
        if merged and b["pb_before"]:
            p = merged[-1]
            same = p["type"] == b["type"] and b["type"] != "list_item"
            if same and (b["type"] == "code" or not p["text"].endswith(TERMINAL) or b["text"][:1].islower()):
                sep = "\n" if b["type"] else " "
                p["text"] += sep + b["text"]; continue
        merged.append(b)
    return [{"type": b["type"], "text": b["text"]} for b in merged]


def find_heading(ln):
    if not ln or ln[0] == " ": return None
    s = ln.strip()
    low = s.lower().rstrip(".")
    if low in UNNUMBERED: return (low.replace(" ", "-").replace("'", "").replace("’", ""), s.rstrip("."), UNNUMBERED[low])
    m = NUM_HEADING_RE.match(ln)
    if m: return (m.group("num"), m.group("title"), "body")
    m = APPX_HEADING_RE.match(ln)
    if m: return (m.group("num"), m.group("title"), "appendix")
    return None


def parse_rfc(path: Path):
    text = read_text(path)
    m = re.search(r"rfc(\d+)", path.name.lower())
    rfc_no = m.group(1).lstrip("0") if m else path.stem
    raw_lines = text.split("\n")
    meta = parse_metadata(raw_lines, rfc_no)
    meta["source_file"] = path.name
    meta["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    toc_numbers = extract_toc(raw_lines) | apply_corpus_overrides(meta)
    toc_start = next((i for i, line in enumerate(raw_lines) if TOC_HEADING_RE.match(line.strip())), None)
    toc_end = len(raw_lines)
    if toc_start is not None:
        toc_end = next((i for i in range(toc_start + 1, len(raw_lines))
                        if raw_lines[i][0:1] and find_heading(raw_lines[i])), len(raw_lines))
    lines = [line for i, line in enumerate(strip_page_breaks(text))
             if not (toc_start is not None and toc_start <= i <= toc_end and TOC_LINE_RE.match(line))]

    first_heading = next((i for i, l in enumerate(lines) if find_heading(l)), 0)
    nows = lambda s: len(re.sub(r"[^A-Za-z0-9]", "", s.replace("\x00PB", "")))
    expected, skipping = 0, False
    for l in lines[first_heading:]:
        h = find_heading(l)
        if h: skipping = (h[2] == "toc")
        if not skipping: expected += nows(l)
    meta["expected_chars"] = expected

    secs, cur = [], {"num": "front", "title": "Front matter", "role": "front_matter", "lines": []}
    for ln in lines:
        h = find_heading(ln)
        if h:
            if cur["lines"] or cur["num"] != "front": secs.append(cur)
            num, title, role = h
            if role == "references" or (re.match(r"^\d+$", num) and "reference" in title.lower()): role = "references"
            cur = {"num": num, "title": title, "role": role, "lines": []}
        else:
            cur["lines"].append(ln)
    secs.append(cur)

    title_by_num = {s["num"]: s["title"] for s in secs}
    role_by_num = {s["num"]: s["role"] for s in secs}
    records = []
    for order, s in enumerate(secs):
        num = s["num"]
        if num == "front":
            parent = None
        else:
            parent = num.rsplit(".", 1)[0] if re.match(r"^(\d+|[A-Z])(\.\d+)+$", num) else None
        role = s["role"]
        if parent and role_by_num.get(parent) == "references": role = "references"
        if s["num"] == "front": continue
        blocks = build_blocks(s["lines"])
        body = "\n\n".join(b["text"] for b in blocks)
        path_nums, p = [], num
        while p:
            path_nums.insert(0, p); p = p.rsplit(".", 1)[0] if "." in p and re.match(r"^(\d+|[A-Z])(\.\d+)+$", p) else None
        heading_path = " > ".join([f"RFC {rfc_no}"] + [f"{n} {title_by_num.get(n, '')}".strip() for n in path_nums])
        xr_rfcs = sorted(set(XREF_RFC_RE.findall(body)))
        xr_secs = sorted({(r or "", sec) for sec, r in XREF_SEC_RE.findall(body)})
        records.append({
            "id": f"rfc{rfc_no}#{num}", "doc_id": f"rfc{rfc_no}", "section": num, "title": s["title"],
            "parent": f"rfc{rfc_no}#{parent}" if parent else None, "order": order, "role": role,
            "index": role in ("body", "appendix", "front_matter") and role != "toc",
            "heading_path": heading_path, "text": body, "blocks": blocks, "char_count": len(body),
            "xref_rfcs": xr_rfcs, "xref_sections": [{"rfc": r or None, "section": sec} for r, sec in xr_secs],
            "doc_title": meta["title"], "doc_date": meta["date"], "doc_category": meta["category"],
            "doc_updates": meta["updates"], "doc_obsoletes": meta["obsoletes"],
        })
    records = [r for r in records if r["role"] != "toc"]
    return meta, records, toc_numbers


def validate(meta, records, toc_numbers):
    problems = []
    ids = [r["id"] for r in records]
    if len(ids) != len(set(ids)): problems.append("duplicate section ids")
    for r in records:
        if "[Page" in r["text"] or FF in r["text"] or "\x00" in r["text"]:
            problems.append(f"page-break residue in {r['id']}")
        if r["role"] in ("body", "appendix") and r["char_count"] == 0 and not any(
                x["parent"] == r["id"] for x in records):
            problems.append(f"empty leaf section {r['id']}")
        if r["parent"] and r["parent"] not in set(ids): problems.append(f"missing parent for {r['id']}")
    parsed_nums = {r["section"] for r in records if r["role"] in ("body", "appendix", "references")}
    if toc_numbers:
        missing, extra = sorted(toc_numbers - parsed_nums), sorted(parsed_nums - toc_numbers)
        if missing: problems.append(f"in TOC but not parsed: {missing[:10]}")
        if extra: problems.append(f"parsed but not in TOC: {extra[:10]}")
    nows = lambda s: len(re.sub(r"[^A-Za-z0-9]", "", s))
    kept = sum(nows(r["text"]) + nows(r["title"]) + (nows(r["section"]) if r["role"] in ("body", "appendix", "references") else 0)
               for r in records)
    ratio = kept / max(meta["expected_chars"], 1)
    if not 0.97 <= ratio <= 1.03: problems.append(f"text retention {ratio:.2f} outside 0.97-1.03 (text lost or duplicated)")
    return problems, ratio


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+"); ap.add_argument("--out", default="data/processed")
    a = ap.parse_args()
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    failed = False
    with open(out / "documents.jsonl", "w", encoding="utf-8") as docf:
        for f in a.files:
            meta, recs, toc = parse_rfc(Path(f))
            problems, ratio = validate(meta, recs, toc)
            docf.write(json.dumps(meta, ensure_ascii=False) + "\n")
            with open(out / f"rfc{meta['rfc']}.sections.jsonl", "w", encoding="utf-8") as fh:
                for r in recs: fh.write(json.dumps(r, ensure_ascii=False) + "\n")
            idx = [r for r in recs if r["index"]]
            print(f"RFC {meta['rfc']}: {len(recs)} sections ({len(idx)} indexable), retention {ratio:.0%}, "
                  f"updates={meta['updates']} date={meta['date']}")
            for p in problems: print("   CHECK FAILED:", p); failed = True
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
