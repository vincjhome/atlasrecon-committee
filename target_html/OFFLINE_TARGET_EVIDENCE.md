# Offline Target Evidence

## Target

Qwen/Qwen2.5-0.5B-Instruct

## What was originally analyzed

The full local analysis for AtlasRecon Committee used three manually downloaded, offline Hugging Face HTML files saved into this directory:

- `target_html/model_page.html`
- `target_html/files_page.html`
- `target_html/discussions_page.html`

No live crawling, scraping, or active scanning was performed against Hugging Face or any other live target at any point in this project. Every finding produced by the four recon agents traces back to text extracted from these three local files.

## Why the raw HTML files are excluded from the published repository

The raw HTML files are large (hundreds of kilobytes each) and contain full Hugging Face page markup
that is not needed to understand or run the pipeline. They are gitignored to keep the repository
lean. This does not mean the analysis didn't happen — all findings in `outputs/` were produced from
these files, and the validation statistics below document the source material.

The published repository includes instead:

- Source code for all four recon agents and the report agent
- The orchestrator
- The final ATLAS-mapped intelligence report (`outputs/atlas_recon_report.md`)
- Pre-generated agent findings (`outputs/agent_findings/*.json`)
- Screenshots of a live pipeline run

## Original validation facts (from the raw local HTML files)

These figures were captured by `tests/validate_target_html.py` when run against the original raw files in this directory:

| File | Raw HTML length | Extracted text length |
| - | - | - |
| `model_page.html` | 264,170 characters | 40,453 characters |
| `files_page.html` | 171,582 characters | 20,165 characters |
| `discussions_page.html` | 214,888 characters | 12,738 characters |
