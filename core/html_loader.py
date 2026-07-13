"""Local HTML loader for AtlasRecon Committee.

Reads only local HTML files from target_html/. Performs no network access,
no live fetching, and no crawling of any kind.
"""

import os
import re

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False


def extract_text_from_html(raw_html):
    """Strip markup from raw HTML and return clean readable text."""
    if _HAS_BS4:
        soup = BeautifulSoup(raw_html, "html.parser")
        for tag in soup(["script", "style"]):
            tag.decompose()
        text = soup.get_text(separator=" ")
    else:
        text = re.sub(r"<!--.*?-->", " ", raw_html, flags=re.DOTALL)
        text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", text)
        text = re.sub(r"(?s)<[^>]+>", " ", text)

    text = re.sub(r"\s+", " ", text).strip()
    return text


def load_html_files(target_dir="target_html"):
    """Read all .html files in target_dir (skipping README.md) and return
    a list of dicts describing each file's raw and extracted content.
    """
    results = []

    if not os.path.isdir(target_dir):
        return results

    for filename in sorted(os.listdir(target_dir)):
        if filename.lower() == "readme.md":
            continue
        if not filename.lower().endswith(".html"):
            continue

        path = os.path.join(target_dir, filename)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw_html = f.read()

        extracted_text = extract_text_from_html(raw_html)

        results.append({
            "filename": filename,
            "path": path,
            "raw_html_length": len(raw_html),
            "extracted_text": extracted_text,
            "extracted_text_length": len(extracted_text),
        })

    return results
