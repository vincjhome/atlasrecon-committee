# AtlasRecon Committee

AtlasRecon Committee is a Python-based multi-agent MITRE ATLAS reconnaissance pipeline that
profiles public AI model repositories for security-relevant exposure. It runs four specialized recon
agents against manually saved offline HTML evidence and generates a structured, ATLAS-mapped
intelligence report with a numeric attack surface score — entirely without live crawling or network
access.

**Safety note:** This project performs offline analysis only. It does not crawl, scrape, scan, or
attack live Hugging Face pages or model endpoints.

## What it does

Given locally saved HTML pages from a Hugging Face model repository, AtlasRecon Committee:

1. Extracts identity, licensing, and intended-use metadata from the model card
2. Enumerates downloadable artifacts (weights, tokenizer, configs) that an adversary could acquire
3. Surfaces architecture details, context length, and deployment metadata that aid adversary planning
4. Analyzes the artifact and behavior surface for offline adversarial evaluation risk
5. Synthesizes all findings into a single ATLAS-mapped Markdown report with severity ratings,
   evidence snippets, adversary value assessments, and defensive recommendations

## Architecture

```text
offline HTML files (target_html/)
        │
        ▼
   html_loader (core/html_loader.py)
        │
        ▼
  four recon agents (run in sequence via orchestrator.py)
  ├── Model Card Recon Agent      → AML.T0003 Search Victim-Owned Websites
  ├── Artifact Recon Agent        → AML.T0002 Acquire Public AI Artifacts
  ├── Technical Exposure Agent    → AML.T0000 Search Open Technical Databases
  └── Vulnerability Analysis Agent → AML.T0001 Search Open AI Vulnerability Analysis
        │
        ▼
  structured JSON findings (outputs/agent_findings/)
        │
        ▼
   Report Agent (agents/report_agent.py)
        │
        ▼
  outputs/atlas_recon_report.md
```

All four recon agents output `ReconFinding` objects (defined in `core/evidence_schema.py`) with
uniform fields: `atlas_technique_id`, `severity`, `confidence`, `evidence`, `source_files`,
`adversary_value`, and `defensive_recommendation`. This uniform schema lets the report agent
synthesize findings from any agent without special-casing, and makes every finding traceable back to
the exact HTML file and text snippet that produced it.

## How to run

**Prerequisites:** Python 3.9+. `beautifulsoup4` is optional (improves HTML extraction quality);
the pipeline runs on the standard library without it.

```bash
# 1. (Optional) install beautifulsoup4
pip install -r requirements.txt

# 2. Place locally saved HTML pages in target_html/
#    Required filenames: model_page.html, files_page.html, discussions_page.html
#    See target_html/README.md for how to save them from your browser.

# 3. Run the full pipeline
python3 orchestrator.py

# 4. Read the report
cat outputs/atlas_recon_report.md
```

To run individual agents for development or testing:

```bash
python3 tests/run_model_card_agent.py
python3 tests/run_artifact_agent.py
python3 tests/run_technical_exposure_agent.py
python3 tests/run_vulnerability_analysis_agent.py
```

## Sample output

The `outputs/` directory contains a pre-generated run against
[Qwen/Qwen2.5-0.5B-Instruct](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct):

- `outputs/atlas_recon_report.md` — full ATLAS-mapped intelligence report (Attack Surface Score:
  7/10 — Elevated)
- `outputs/agent_findings/*.json` — raw structured findings from each of the four agents (16
  findings total)

## MITRE ATLAS mapping

| Agent | ATLAS Technique |
| - | - |
| Model Card Recon Agent | AML.T0003 — Search Victim-Owned Websites |
| Artifact Recon Agent | AML.T0002 — Acquire Public AI Artifacts |
| Technical Exposure Recon Agent | AML.T0000 — Search Open Technical Databases |
| Vulnerability Analysis Recon Agent | AML.T0001 — Search Open AI Vulnerability Analysis |

## Limitations

- Analysis is based on statically saved HTML pages and keyword/regex scanning — not live inference,
  exploitation, or model interaction. Findings describe what is publicly visible, not confirmed
  vulnerabilities.
- Coverage is limited to the four agents implemented. This is not an exhaustive security assessment.
- Evidence reflects the state of the HTML at the time the pages were saved; live repository state
  may differ.

## Future improvements

- Add a fifth agent that reads `config.json` and `tokenizer_config.json` directly (currently these
  are found via HTML pattern matching rather than parsed from the JSON source)
- Implement `core/llm_client.py` to optionally run a local LLM over extracted text for
  natural-language finding generation
- Add support for targeting private/gated model repositories via authenticated sessions
- Extend the ATLAS mapping to cover AML.T0006 (Develop Capabilities) and AML.T0043 (Craft
  Adversarial Data)

## Docs

- [Architecture](docs/architecture.md)
- [ATLAS mapping rationale](docs/atlas_mapping.md)
- [Pipeline design](docs/project_plan.md)
- [Threat analysis for the sample run](docs/threat_analysis.md)
