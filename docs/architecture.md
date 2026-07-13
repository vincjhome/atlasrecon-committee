# Architecture

## Pipeline overview

```text
offline HTML files (target_html/)
        │
        ▼
   html_loader
        │
        ▼
  four recon agents (model card, artifact, technical exposure, vulnerability analysis)
        │
        ▼
 structured JSON findings (outputs/agent_findings/)
        │
        ▼
   report agent
        │
        ▼
 outputs/atlas_recon_report.md
```

`html_loader` reads only the manually saved, local HTML files in `target_html/` and extracts clean text — it never fetches or crawls a live site. Each of the four recon agents reads that extracted text and produces its findings; the report agent then reads every agent's output and synthesizes the final report.

## Shared finding format

All four recon agents output their results as `ReconFinding` objects (defined in `core/evidence_schema.py`), serialized to JSON via `save_findings()`. The report agent never reads raw HTML or agent internals directly — it only consumes these structured JSON findings via `load_all_findings()`.

Using one shared dataclass across every agent means:

- Report generation is **deterministic**: the report agent always receives the same field set (`agent_name`, `atlas_technique_id`, `severity`, `evidence`, etc.) regardless of which agent produced it, so synthesis logic doesn't need agent-specific branching.
- Output is **screenshot-friendly**: `print_findings_summary()` renders a consistent one-line-per-finding format, and the saved JSON files have a uniform, readable structure suitable for documenting pipeline runs.

See `docs/project_plan.md` for the full agent output contract and `docs/atlas_mapping.md` for how technique IDs map to each agent.
