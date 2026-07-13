"""Validation script for local target_html/ files.

Reads only local files via core.html_loader. Performs no network access,
no live fetching, and no crawling of any kind.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.html_loader import load_html_files

PLACEHOLDER_MARKERS = ["placeholder", "must be replaced", "manually save"]
SHORT_TEXT_THRESHOLD = 1000


def main():
    files = load_html_files("target_html")

    print("=" * 60)
    print("AtlasRecon Committee - target_html Validation Report")
    print("=" * 60)

    if not files:
        print("\nERROR: No HTML files found in target_html/.")
        print("Place downloaded Hugging Face HTML files there before running the pipeline.")
        sys.exit(1)

    print(f"\nFiles discovered: {len(files)}\n")

    for entry in files:
        print("-" * 60)
        print(f"File: {entry['filename']}")
        print(f"Path: {entry['path']}")
        print(f"Raw HTML length: {entry['raw_html_length']} characters")
        print(f"Extracted text length: {entry['extracted_text_length']} characters")
        print("First 300 characters of extracted text:")
        print(entry["extracted_text"][:300])

        lowered = entry["extracted_text"].lower()
        is_placeholder = any(marker in lowered for marker in PLACEHOLDER_MARKERS)
        if is_placeholder:
            print("WARNING: This file looks like a placeholder, not a real downloaded page.")

        if entry["extracted_text_length"] < SHORT_TEXT_THRESHOLD:
            print(f"WARNING: Extracted text is very short (< {SHORT_TEXT_THRESHOLD} characters).")

    print("-" * 60)
    print("\nValidation complete.")


if __name__ == "__main__":
    main()
