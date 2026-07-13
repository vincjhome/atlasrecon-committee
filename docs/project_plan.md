# Project Plan

## Safety boundary

This system analyzes manually downloaded, offline Hugging Face HTML files only. It must never perform live reconnaissance, crawling, scraping, or active scanning against Hugging Face or any other live target. All agents operate solely on local HTML files placed in `target_html/`.

## Target

Model: **Qwen/Qwen2.5-0.5B-Instruct**

## Architecture

```text
offline Hugging Face HTML files (target_html/)
        │
        ▼
   HTML loader
        │
        ▼
   orchestrator
        │
        ▼
  four recon agents (run per-page, in parallel or sequence)
        │
        ▼
   report agent
        │
        ▼
 outputs/atlas_recon_report.md
```

## The four recon agents

1. **Model Card Recon Agent** — reads the model card content (description, intended use, training data notes, authorship, organization) for victim-owned information disclosure.
2. **Artifact Recon Agent** — examines the files/versions listing for downloadable artifacts (weights, tokenizer files, configs, checkpoints) that could be acquired and reused.
3. **Technical Exposure Recon Agent** — extracts technical details (framework versions, library dependencies, config parameters, hardware/runtime hints) exposed in the page content.
4. **Vulnerability Analysis Recon Agent** — scans discussion/community content for reported bugs, issues, security concerns, or known weaknesses discussed publicly.

## The report agent (fifth agent)

The **Report Agent** does not analyze HTML directly. It collects the structured findings produced by the four recon agents, synthesizes them, maps them against MITRE ATLAS tactics/techniques (see `docs/atlas_mapping.md`), and writes the final consolidated report.

## Data flow between agents

- Each recon agent produces structured JSON findings and writes them to `outputs/agent_findings/` (e.g. `model_card_findings.json`, `artifact_findings.json`, `technical_exposure_findings.json`, `vulnerability_analysis_findings.json`).
- The report agent reads all JSON findings files from `outputs/agent_findings/`, synthesizes them into a single narrative mapped to MITRE ATLAS, and writes the result to `outputs/atlas_recon_report.md`.

## Agent Output Contract

Every recon agent must produce its findings as `ReconFinding` objects (`core/evidence_schema.py`) and persist them via `save_findings()`. Each finding requires:

- `agent_name` — which agent produced the finding
- `atlas_tactic`, `atlas_technique_id`, `atlas_technique_name` — the MITRE ATLAS mapping from `docs/atlas_mapping.md`
- `finding_title` — a short human-readable label for the finding
- `severity` — how serious the exposure is
- `confidence` — how certain the agent is in the finding
- `summary` — a plain-language description of what was found
- `evidence` — the literal text/snippets pulled from the local HTML that support the finding
- `source_files` — which file(s) in `target_html/` the evidence came from
- `adversary_value` — why this finding would be useful to an attacker
- `defensive_recommendation` — what the model owner could do to mitigate it

`evidence` and `source_files` exist specifically for **traceability**: every finding in the final report must be traceable back to the exact offline HTML file and exact text that produced it. This keeps the pipeline auditable — a reviewer can open `target_html/model_page.html`, find the quoted evidence, and verify the agent's conclusion, rather than trusting an unverifiable claim.
