# Repo Cleanup Summary

This document records the changes made to prepare the AtlasRecon Committee repository for public
portfolio presentation.

## Files removed from tracking

These files were removed from git tracking and from disk. They are preserved in the
`cleanup-portfolio-version` branch and in the original git history (initial commit).

| File | Reason |
| - | - |
| `SUBMISSION_NOTES.md` | Assignment submission cover page; grader-facing |
| `assignment/deliverables_checklist.md` | Class deliverables checklist with grading checkboxes |
| `assignment/reflection.md` | Assignment reflection; content preserved in `docs/threat_analysis.md` |
| `assignment/screenshot_plan.md` | Assignment screenshot requirements |
| `screenshots/04_final_submission_validator.png` | Screenshot of submission validator; grading artifact |
| `scripts/create_portal_slim_zip.py` | Assignment portal ZIP builder |
| `scripts/create_submission_zip.py` | Assignment submission ZIP builder for grader |
| `tests/validate_submission.py` | Assignment submission validation script |

## Files added

| File | Purpose |
| - | - |
| `docs/threat_analysis.md` | Security analysis content from `assignment/reflection.md`, reframed as standalone threat analysis |
| `requirements.txt` | Lists `beautifulsoup4` as optional dependency |
| `docs/repo_cleanup_summary.md` | This file |

## Files edited

| File | Change |
| - | - |
| `README.md` | Full portfolio rewrite: removed grading/submission language; added architecture diagram, how-to-run, sample output, ATLAS table, limitations, future improvements |
| `docs/project_plan.md` | Removed "This assignment requires" opener; reframed as project constraint |
| `target_html/OFFLINE_TARGET_EVIDENCE.md` | Removed "assignment portal rejected" language; reframed as general distribution note |
| `outputs/screenshots/README.md` | Removed "required for assignment deliverables" and reference to deleted checklist |
| `.gitignore` | Added `assignment/`, `grading/` patterns |

## Files kept as-is

All core source files, agents, docs, and outputs were kept without modification:

- `orchestrator.py`
- `agents/` (all 5 agents + README)
- `core/` (evidence_schema.py, html_loader.py, llm_client.py, README)
- `docs/architecture.md`, `docs/atlas_mapping.md`
- `outputs/atlas_recon_report.md`, `outputs/agent_findings/*.json`
- `screenshots/01_architecture_agents_directory.png`
- `screenshots/02_pipeline_run_orchestrator.png`
- `screenshots/03_vulnerability_findings_output.png`
- `tests/run_*.py`, `tests/validate_target_html.py`
- `target_html/README.md`

## Files intentionally excluded from tracking (gitignored)

- `target_html/*.html` — raw Hugging Face HTML pages (large, locally required for analysis runs)
- `__pycache__/`, `*.pyc` — Python bytecode
- `.DS_Store` — macOS metadata
- `submission/`, `*.zip` — build artifacts
- `assignment/`, `grading/` — class-context folders

## Git history note

The removed files are no longer present in the latest commit and will not appear on GitHub after
push. However, they still exist in the original initial commit (`cdf58a3`). Anyone who checks out
that commit or runs `git log -p` will see them.

To remove them from history entirely requires a history rewrite using `git filter-repo` or starting
from a clean repository. This was intentionally deferred — do not proceed with history rewrite
without explicit approval.

## Remaining concerns

- `core/llm_client.py` is an unimplemented stub ("Not yet implemented"). It is kept because it
  signals a future extension point and is not assignment-specific.
- The `outputs/` directory contains pre-generated findings. These are intentionally kept to let
  visitors see example output without needing to download target HTML files.
