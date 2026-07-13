# target_html

This directory holds **manually downloaded** Hugging Face HTML pages used for offline reconnaissance. Nothing in this pipeline fetches, crawls, or scans Hugging Face (or any other live site) — every file here must be saved by hand, in a browser, before any agent runs.

## Target model

Qwen/Qwen2.5-0.5B-Instruct

## How to save the pages

1. Open the Hugging Face page in your browser (e.g. the model page, the Files and versions tab, the Discussions tab).
2. Use your browser's **Save As** function.
3. Recommended format: **Webpage, HTML Only**.
4. Save the file into this directory using the exact filename listed below.

## Required local filenames

- `model_page.html` — the model card page
- `files_page.html` — the "Files and versions" page
- `discussions_page.html` — the Discussions/Community tab (if available)

## Partial sets are fine

If only some of these pages are useful or available, the pipeline can still run on whatever local HTML files are present. Agents should work with whatever subset exists in this directory rather than requiring all files.

## Safety rule

The recon pipeline must analyze **only** these local HTML files. It must never crawl, scrape, or fetch live Hugging Face pages.

## Verification

Confirm the placeholder/saved files are present with:

```bash
ls -lh target_html
```

## Warning

**Do not run live crawling, scraping, or active scanning against Hugging Face or any other live target.** All analysis in this project is performed strictly offline against the static HTML files placed in this directory.
